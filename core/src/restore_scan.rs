//! Restore scan: from the 24 words alone, find every account of a wallet and
//! its balance by walking the chain block by block, on headers the header
//! sync has checked.
//!
//! The words become a `ghost_client::account::WalletSeed`, held in memory for
//! the scan only (it is wiped when the scan is dropped) and never stored. The
//! scan derives the rescue-key accounts (`WalletSeed::rescue_account`) 0 up
//! to [`GAP_LIMIT`] past the last used one and keeps only their public data:
//! the index, the address and the public rescue key.
//!
//! The caller feeds the blocks in height order, each with its header (RLP)
//! and the addresses its transactions touched, with each one's balance after
//! the block as the node reports it. The tip comes from a [`HeaderSync`]: its
//! best height and hash. Every fed header must carry its height and link to
//! the one fed before it, and the header at the tip must be the sync's best
//! header, so the fed blocks are exactly the checked chain. Until every block
//! up to the tip has been fed, [`RestoreScan::result`] is
//! [`RestoreResult::Incomplete`] and shows no balance at all, never a zero.
//!
//! # What is not proved
//!
//! Ghost's client library checks a block's receipts against its header
//! (`check_block_receipts_against_header`), but receipts only hold coin tree
//! records. It has no check of an account's balance (no state proof) and no
//! check of which accounts a block's transactions touched (no transactions
//! root check). So which accounts are used and their balances come from the
//! node, unproved: every balance of the result is marked `unverified` and the
//! result says so in its note. Nothing here works around that.
//!
//! No network code lives here, nothing is written anywhere and nothing secret
//! is logged or formatted: error messages never hold the words.

use core::fmt;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use ghost_client::account::{SeedError, WalletSeed};
use ghost_client::seal::header_fields;

use crate::header_sync::HeaderSync;
use crate::to_hex_address;

/// How many unused accounts past the last used one are derived and watched.
/// An account further out than that is not found: the scan ends there.
pub const GAP_LIMIT: u32 = 20;

/// The note of a complete result: why its balances are unverified.
pub const UNVERIFIED_NOTE: &str = "Balances and account use are the node's report, not proved: Ghost's client \
library has no account state proof and no transactions root check yet. Every balance is marked unverified.";

/// One account the scan derived: public data only.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DerivedAccount {
    /// The account index.
    pub index: u32,
    /// Its address, `0x` and 40 lowercase hex digits.
    pub address: String,
    /// Its public rescue-key account key (ML-DSA-44 then SLH-DSA).
    pub rescue_public_key: Vec<u8>,
}

/// An address a block touched, with its balance after the block.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TouchedAddress {
    /// The 20-byte address.
    pub address: Vec<u8>,
    /// Its balance after the block, in wei, big-endian.
    pub balance: Vec<u8>,
}

/// One account of a complete scan.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RestoredAccount {
    /// The account index.
    pub index: u32,
    /// Its address, `0x` and 40 lowercase hex digits.
    pub address: String,
    /// Whether any fed block touched it.
    pub used: bool,
    /// Its balance after the last block that touched it, in wei, as a
    /// decimal number; "0" for an account no block touched.
    pub balance: String,
    /// The balance is the node's report, not proved (see the note).
    pub unverified: bool,
}

/// Where a scan stands.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum RestoreResult {
    /// Not every block up to the tip has been fed: no balance is known yet.
    Incomplete {
        /// The height of the next block to feed.
        next_height: u64,
        /// The tip, once it is set.
        tip: Option<u64>,
    },
    /// Every block up to the tip has been fed.
    Complete {
        /// Every derived account, in index order: the used ones and the
        /// unused ones up to the gap limit past the last used one.
        accounts: Vec<RestoredAccount>,
        /// What the balances rest on.
        note: String,
    },
}

/// Why a scan could not start or refused a call. The messages never hold the
/// words.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum RestoreScanError {
    /// The words are not a valid wallet seed.
    Words { reason: String },
    /// A block was fed above the next height: a block would be passed over.
    HeightPassedOver { expected: u64, got: u64 },
    /// A block was fed below the next height: it was fed already.
    RepeatedHeight { expected: u64, got: u64 },
    /// A block was fed above the tip, or before a tip was set.
    AboveTip { height: u64, tip: Option<u64> },
    /// The tip is below the blocks already fed.
    TipBelowFed { tip: u64, fed: u64 },
    /// A header does not decode, does not carry its height, does not link to
    /// the header fed before it or, at the tip, is not the checked tip.
    NotTheCheckedChain { height: u64, reason: String },
    /// A touched address or balance is malformed.
    BadTouched { height: u64, reason: String },
}

impl fmt::Display for RestoreScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Words { reason } => write!(f, "invalid account words: {reason}"),
            Self::HeightPassedOver { expected, got } => {
                write!(f, "block {got} was fed where block {expected} is next: a block would be passed over")
            }
            Self::RepeatedHeight { expected, got } => {
                write!(f, "block {got} was fed already; block {expected} is next")
            }
            Self::AboveTip { height, tip: Some(tip) } => write!(f, "block {height} is above the tip {tip}"),
            Self::AboveTip { height, tip: None } => write!(f, "block {height} was fed before the tip was set"),
            Self::TipBelowFed { tip, fed } => write!(f, "the tip {tip} is below block {fed}, already fed"),
            Self::NotTheCheckedChain { height, reason } => {
                write!(f, "block {height} is not on the checked header chain: {reason}")
            }
            Self::BadTouched { height, reason } => write!(f, "block {height} has a bad touched address: {reason}"),
        }
    }
}

impl std::error::Error for RestoreScanError {}

impl From<SeedError> for RestoreScanError {
    fn from(error: SeedError) -> Self {
        RestoreScanError::Words { reason: error.to_string() }
    }
}

/// The checked tip: the header sync's best height and hash.
#[derive(Clone, Copy)]
struct Tip {
    height: u64,
    hash: [u8; 32],
}

struct Account {
    address: [u8; 20],
    rescue_public_key: Vec<u8>,
}

struct State {
    seed: WalletSeed,
    accounts: Vec<Account>,
    /// The last reported balance of every address any fed block touched,
    /// ours or not: an account derived later may have been touched earlier.
    touched: HashMap<[u8; 20], u128>,
    next_height: u64,
    /// The hash of the last fed header.
    last_hash: Option<[u8; 32]>,
    tip: Option<Tip>,
}

/// A restore scan from the 24 words, fed block by block.
#[derive(uniffi::Object)]
pub struct RestoreScan {
    state: Mutex<State>,
}

#[uniffi::export]
impl RestoreScan {
    /// Starts a scan of the wallet of `words` at block `first_height`, the
    /// first block after the header sync's pinned start.
    #[uniffi::constructor]
    pub fn new(words: String, first_height: u64) -> Result<Arc<Self>, RestoreScanError> {
        let seed = WalletSeed::from_words(&words)?;
        let mut state = State {
            seed,
            accounts: Vec::new(),
            touched: HashMap::new(),
            next_height: first_height,
            last_hash: None,
            tip: None,
        };
        state.extend();
        Ok(Arc::new(Self { state: Mutex::new(state) }))
    }

    /// The accounts derived so far, in index order: public data only.
    pub fn accounts(&self) -> Vec<DerivedAccount> {
        let state = self.state();
        state
            .accounts
            .iter()
            .enumerate()
            .map(|(index, account)| DerivedAccount {
                index: index as u32,
                address: to_hex_address(&account.address),
                rescue_public_key: account.rescue_public_key.clone(),
            })
            .collect()
    }

    /// Takes the tip from the header sync: its best height and hash.
    pub fn set_tip(&self, sync: Arc<HeaderSync>) -> Result<(), RestoreScanError> {
        let height = sync.best_height();
        let hash: [u8; 32] = sync.best_hash().try_into().expect("a header hash is 32 bytes");
        let mut state = self.state();
        if let Some(fed) = state.next_height.checked_sub(1).filter(|_| state.last_hash.is_some()) {
            if height < fed {
                return Err(RestoreScanError::TipBelowFed { tip: height, fed });
            }
            if height == fed && state.last_hash != Some(hash) {
                return Err(RestoreScanError::NotTheCheckedChain {
                    height,
                    reason: "the block fed at the tip is not the checked tip".to_owned(),
                });
            }
        }
        state.tip = Some(Tip { height, hash });
        Ok(())
    }

    /// Feeds the block at `height`: its header's RLP and the addresses it
    /// touched with their balances after it. A refused block changes nothing.
    pub fn feed_block(
        &self,
        height: u64,
        header: Vec<u8>,
        touched: Vec<TouchedAddress>,
    ) -> Result<(), RestoreScanError> {
        let mut state = self.state();
        let expected = state.next_height;
        if height > expected {
            return Err(RestoreScanError::HeightPassedOver { expected, got: height });
        }
        if height < expected {
            return Err(RestoreScanError::RepeatedHeight { expected, got: height });
        }
        let tip = state.tip;
        match tip {
            Some(tip) if height <= tip.height => {}
            _ => return Err(RestoreScanError::AboveTip { height, tip: tip.map(|t| t.height) }),
        }
        let not_checked = |reason: &str| RestoreScanError::NotTheCheckedChain { height, reason: reason.to_owned() };
        let fields = header_fields(&header).map_err(|_| not_checked("the header does not decode"))?;
        if fields.number != height {
            return Err(not_checked("the header carries another height"));
        }
        if state.last_hash.is_some_and(|last| last != fields.parent_hash) {
            return Err(not_checked("the header does not link to the block fed before it"));
        }
        if tip.is_some_and(|tip| tip.height == height && tip.hash != fields.hash) {
            return Err(not_checked("the header at the tip is not the checked tip"));
        }
        let mut balances = Vec::with_capacity(touched.len());
        for entry in &touched {
            let address: [u8; 20] = entry.address.as_slice().try_into().map_err(|_| {
                RestoreScanError::BadTouched { height, reason: "an address is not 20 bytes".to_owned() }
            })?;
            let balance = balance_from_be(&entry.balance).ok_or_else(|| RestoreScanError::BadTouched {
                height,
                reason: "a balance is longer than 32 bytes or does not fit in 128 bits".to_owned(),
            })?;
            balances.push((address, balance));
        }

        state.touched.extend(balances);
        state.last_hash = Some(fields.hash);
        state.next_height = height + 1;
        state.extend();
        Ok(())
    }

    /// `Incomplete` until every block up to the tip has been fed, then
    /// `Complete` with every derived account.
    pub fn result(&self) -> RestoreResult {
        let state = self.state();
        let complete = state.tip.is_some_and(|tip| state.next_height > tip.height);
        if !complete {
            return RestoreResult::Incomplete { next_height: state.next_height, tip: state.tip.map(|t| t.height) };
        }
        let accounts = state
            .accounts
            .iter()
            .enumerate()
            .map(|(index, account)| {
                let balance = state.touched.get(&account.address);
                RestoredAccount {
                    index: index as u32,
                    address: to_hex_address(&account.address),
                    used: balance.is_some(),
                    balance: balance.copied().unwrap_or(0).to_string(),
                    unverified: true,
                }
            })
            .collect();
        RestoreResult::Complete { accounts, note: UNVERIFIED_NOTE.to_owned() }
    }
}

impl RestoreScan {
    fn state(&self) -> MutexGuard<'_, State> {
        // Every call checks everything before it changes the state, so a
        // panic leaves it as it was.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl State {
    /// Derives accounts until [`GAP_LIMIT`] unused ones follow the last used
    /// one. A newly derived account may have been touched already, so this
    /// repeats until nothing changes.
    fn extend(&mut self) {
        loop {
            let used = self.accounts.iter().rposition(|account| self.touched.contains_key(&account.address));
            let wanted = used.map_or(0, |last| last + 1) + GAP_LIMIT as usize;
            if self.accounts.len() >= wanted {
                return;
            }
            while self.accounts.len() < wanted {
                let key = self.seed.rescue_account(self.accounts.len() as u32);
                self.accounts.push(Account { address: *key.address(), rescue_public_key: key.public_key().to_vec() });
            }
        }
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
