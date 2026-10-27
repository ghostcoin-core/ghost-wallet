//! Restore: from the 24 words alone, find the accounts of a wallet and their
//! balances by asking for each account's current state at one block.
//!
//! The words become a `ghost_client::account::WalletSeed`, held in memory for
//! the restore only (it is wiped when the restore is dropped) and never
//! stored. The restore derives the rescue-key accounts
//! (`WalletSeed::rescue_account`) 0, 1, 2 and on, and for each one asks the
//! caller's [`AccountLookup`] for its balance and nonce at the tip's block
//! hash. Every account is asked about at that one hash, so the balances all
//! belong to the same chain state.
//!
//! Each answer is reported as soon as it arrives: [`RestoreLookup::look_up_next`]
//! looks up one account and returns it, so the first balance shows after one
//! lookup, not after the whole restore. Nothing walks the chain: the current
//! state already holds every way an account got its coins, whether it was
//! funded long ago and never touched again, paid by a contract (an internal
//! transfer, with no transaction of its own) or paid a mining reward.
//!
//! An account is used if its nonce or its balance is above zero. The restore
//! goes on until [`GAP_LIMIT`] unused accounts follow the last used one.
//! [`RestoreLookup::search_further`] looks [`GAP_LIMIT`] accounts past that,
//! and [`RestoreLookup::look_up_account`] looks up any one account by index.
//!
//! The tip is plain data, a height and a block hash, from wherever the caller
//! took it (on the phone: the header sync's best header).
//!
//! # What is not proved
//!
//! Ghost's client library has no check of an account's balance or nonce (no
//! state proof), so both are the node's report, unproved: every account of
//! the result is marked `unverified` and the result says so in its note.
//! Nothing here works around that.
//!
//! No network code lives here, nothing is written anywhere and nothing secret
//! is logged or formatted: error messages never hold the words.

use core::fmt;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

use ghost_client::account::{SeedError, WalletSeed};

use crate::to_hex_address;

/// How many unused accounts past the last used one are looked up. An account
/// further out than that is not found unless the caller searches further.
pub const GAP_LIMIT: u32 = 20;

/// The note of every result: why its balances are unverified.
pub const UNVERIFIED_NOTE: &str = "Balances and nonces are the node's report, not proved: Ghost's client library \
has no account state proof yet. Every account is marked unverified.";

/// One account's state at a block, as the lookup reports it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountState {
    /// Its balance, in wei, big-endian, at most 32 bytes.
    pub balance: Vec<u8>,
    /// Its nonce: how many transactions it has sent.
    pub nonce: u64,
}

/// Where the restore gets account states: on the phone, the node's
/// `eth_getBalance` and `eth_getTransactionCount` at a block hash. Every call
/// of one restore asks at the same block hash.
#[uniffi::export(callback_interface)]
pub trait AccountLookup: Send + Sync {
    /// The state of the 20-byte `address` at the block with the 32-byte hash
    /// `block_hash`; [`RestoreError::Lookup`] if it cannot be had.
    fn account_state(&self, address: Vec<u8>, block_hash: Vec<u8>) -> Result<AccountState, RestoreError>;
}

/// One account derived from the words: public data only.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DerivedAccount {
    /// The account index.
    pub index: u32,
    /// Its address, `0x` and 40 lowercase hex digits.
    pub address: String,
    /// Its public rescue-key account key (ML-DSA-44 then SLH-DSA).
    pub rescue_public_key: Vec<u8>,
}

/// One account looked up.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RestoredAccount {
    /// The account index.
    pub index: u32,
    /// Its address, `0x` and 40 lowercase hex digits.
    pub address: String,
    /// Its balance at the tip, in wei, as a decimal number.
    pub balance: String,
    /// Its nonce at the tip.
    pub nonce: u64,
    /// Whether its nonce or its balance is above zero.
    pub used: bool,
    /// The balance and nonce are the node's report, not proved (see the note).
    pub unverified: bool,
}

/// Where a restore stands.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RestoreResult {
    /// Every account looked up so far, in index order.
    pub accounts: Vec<RestoredAccount>,
    /// Whether [`GAP_LIMIT`] unused accounts (or more, after a search
    /// further) follow the last used one: nothing is left to look up.
    pub complete: bool,
    /// The index [`RestoreLookup::look_up_next`] looks up next.
    pub next_index: u64,
    /// The tip every account was looked up at: its height.
    pub tip_height: u64,
    /// And its 32-byte block hash.
    pub tip_hash: Vec<u8>,
    /// What the balances rest on.
    pub note: String,
}

/// Why a restore could not start or a lookup failed. The messages never hold
/// the words.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum RestoreError {
    /// The words are not a valid wallet seed.
    Words { reason: String },
    /// The tip's block hash is not 32 bytes.
    BadTip { reason: String },
    /// The lookup could not give an account's state.
    Lookup { reason: String },
    /// The lookup gave a state that is malformed.
    BadState { index: u32, reason: String },
    /// No account has this index.
    NoSuchAccount { index: u64 },
}

impl fmt::Display for RestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Words { reason } => write!(f, "invalid account words: {reason}"),
            Self::BadTip { reason } => write!(f, "the tip is not a block: {reason}"),
            Self::Lookup { reason } => write!(f, "the account lookup failed: {reason}"),
            Self::BadState { index, reason } => write!(f, "the state of account {index} is malformed: {reason}"),
            Self::NoSuchAccount { index } => write!(f, "there is no account {index}"),
        }
    }
}

impl std::error::Error for RestoreError {}

impl From<SeedError> for RestoreError {
    fn from(error: SeedError) -> Self {
        RestoreError::Words { reason: error.to_string() }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for RestoreError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        RestoreError::Lookup { reason: error.reason }
    }
}

struct State {
    seed: WalletSeed,
    /// The address of every account derived so far.
    addresses: HashMap<u32, [u8; 20]>,
    /// Every account looked up so far.
    found: BTreeMap<u32, RestoredAccount>,
    /// The next index of the run from account 0.
    next_index: u64,
    /// The run goes on at least this far: [`GAP_LIMIT`] at the start, more
    /// after a search further.
    search_floor: u64,
}

/// A restore from the 24 words, by current-state lookup at one tip.
#[derive(uniffi::Object)]
pub struct RestoreLookup {
    lookup: Box<dyn AccountLookup>,
    tip_height: u64,
    tip_hash: [u8; 32],
    state: Mutex<State>,
}

#[uniffi::export]
impl RestoreLookup {
    /// Starts a restore of the wallet of `words`, looking every account up
    /// with `lookup` at the block `tip_hash` (32 bytes) at `tip_height`.
    #[uniffi::constructor]
    pub fn new(
        words: String,
        lookup: Box<dyn AccountLookup>,
        tip_height: u64,
        tip_hash: Vec<u8>,
    ) -> Result<Arc<Self>, RestoreError> {
        let tip_hash: [u8; 32] = tip_hash
            .as_slice()
            .try_into()
            .map_err(|_| RestoreError::BadTip { reason: "the block hash is not 32 bytes".to_owned() })?;
        let seed = WalletSeed::from_words(&words)?;
        let state = State {
            seed,
            addresses: HashMap::new(),
            found: BTreeMap::new(),
            next_index: 0,
            search_floor: u64::from(GAP_LIMIT),
        };
        Ok(Arc::new(Self { lookup, tip_height, tip_hash, state: Mutex::new(state) }))
    }

    /// Looks up the next account of the run from account 0 and returns it,
    /// or `None` once [`GAP_LIMIT`] unused accounts follow the last used one.
    /// An account already looked up with [`RestoreLookup::look_up_account`]
    /// is passed over. A failed lookup changes nothing: call again to retry.
    pub fn look_up_next(&self) -> Result<Option<RestoredAccount>, RestoreError> {
        let (index, address) = {
            let mut state = self.state();
            loop {
                if state.next_index >= state.search_end() {
                    return Ok(None);
                }
                let Ok(index) = u32::try_from(state.next_index) else { return Ok(None) };
                if !state.found.contains_key(&index) {
                    break (index, state.address(index));
                }
                state.next_index += 1;
            }
        };
        let account = self.look_up(index, address)?;
        let mut state = self.state();
        if state.next_index == u64::from(index) {
            state.next_index += 1;
        }
        Ok(Some(account))
    }

    /// Looks up account `index`, whatever the gap, and returns it. If it is
    /// used, the run from account 0 goes on to [`GAP_LIMIT`] past it.
    pub fn look_up_account(&self, index: u32) -> Result<RestoredAccount, RestoreError> {
        let address = self.state().address(index);
        self.look_up(index, address)
    }

    /// Searches [`GAP_LIMIT`] accounts further than the run would go now:
    /// once it is complete, past the gap.
    pub fn search_further(&self) {
        let mut state = self.state();
        state.search_floor = state.search_end().max(state.next_index).saturating_add(u64::from(GAP_LIMIT));
    }

    /// Derives account `index` from the words: public data only. Nothing is
    /// looked up.
    pub fn derive_account(&self, index: u32) -> DerivedAccount {
        let state = self.state();
        let key = state.seed.rescue_account(index);
        DerivedAccount { index, address: to_hex_address(key.address()), rescue_public_key: key.public_key().to_vec() }
    }

    /// Every account looked up so far and whether the run is complete.
    pub fn result(&self) -> RestoreResult {
        let state = self.state();
        RestoreResult {
            accounts: state.found.values().cloned().collect(),
            complete: state.next_index >= state.search_end(),
            next_index: state.next_index,
            tip_height: self.tip_height,
            tip_hash: self.tip_hash.to_vec(),
            note: UNVERIFIED_NOTE.to_owned(),
        }
    }
}

impl RestoreLookup {
    fn state(&self) -> MutexGuard<'_, State> {
        // Every call checks everything before it changes the state, so a
        // panic leaves it as it was.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Asks the lookup about one account, without holding the state, and
    /// records the answer.
    fn look_up(&self, index: u32, address: [u8; 20]) -> Result<RestoredAccount, RestoreError> {
        let answer = self.lookup.account_state(address.to_vec(), self.tip_hash.to_vec())?;
        let balance = balance_from_be(&answer.balance).ok_or_else(|| RestoreError::BadState {
            index,
            reason: "the balance is longer than 32 bytes or does not fit in 128 bits".to_owned(),
        })?;
        let account = RestoredAccount {
            index,
            address: to_hex_address(&address),
            balance: balance.to_string(),
            nonce: answer.nonce,
            used: answer.nonce > 0 || balance > 0,
            unverified: true,
        };
        self.state().found.insert(index, account.clone());
        Ok(account)
    }
}

impl State {
    /// The address of account `index`, derived once.
    fn address(&mut self, index: u32) -> [u8; 20] {
        let seed = &self.seed;
        *self.addresses.entry(index).or_insert_with(|| *seed.rescue_account(index).address())
    }

    /// Where the run from account 0 ends: [`GAP_LIMIT`] past the last used
    /// account, or the search floor if that is further.
    fn search_end(&self) -> u64 {
        let used_end = self.found.values().rev().find(|account| account.used).map_or(0, |a| u64::from(a.index) + 1);
        (used_end + u64::from(GAP_LIMIT)).max(self.search_floor)
    }
}

/// A big-endian balance of at most 32 bytes that fits in 128 bits.
fn balance_from_be(bytes: &[u8]) -> Option<u128> {
    if bytes.len() > 32 {
        return None;
    }
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let digits = &bytes[first..];
    if digits.len() > 16 {
        return None;
    }
    Some(digits.iter().fold(0u128, |n, &b| n << 8 | u128::from(b)))
}
