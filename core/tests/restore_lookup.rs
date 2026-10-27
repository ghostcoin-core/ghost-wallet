//! The current-state restore of `restore_scan`, from Ghost's counting-bytes
//! test seed, against a fake lookup over a fake chain built here.
//!
//! The fake chain is a list of events by height: plain transfers (the sender's
//! nonce goes up), contract payments (an internal transfer: no transaction of
//! the account's own) and mining rewards. The fake lookup answers an
//! account's balance and nonce after every event up to the block it is asked
//! at, and refuses a block hash it does not know. It records every question.
//!
//! An account funded long before the checkpoint height and never touched
//! again, an account past 3 unused ones, a contract-paid account and a
//! mining-reward account are all found, each with its balance at the tip, and
//! every question is asked at the tip's hash.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ghost_client::account::WalletSeed;
use ghost_wallet_core::{
    AccountLookup, AccountState, GAP_LIMIT, RestoreError, RestoreLookup, RestoreResult, RestoredAccount,
};

/// Ghost's counting-bytes test seed: the bytes 0 to 31.
const COUNTING: [u8; 32] = {
    let mut bytes = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        bytes[i] = i as u8;
        i += 1;
    }
    bytes
};

/// The height a release checkpoint would pin, and the tip.
const CHECKPOINT: u64 = 1_000;
const TIP: u64 = 5_000;
const GHOST: u128 = 1_000_000_000_000_000_000;

/// An address of nobody in this wallet, funded at genesis.
const STRANGER: [u8; 20] = [0xab; 20];
/// A contract, funded at genesis.
const CONTRACT: [u8; 20] = [0xcc; 20];

fn counting_words() -> String {
    WalletSeed::from_bytes(COUNTING).to_words().as_str().to_owned()
}

fn address(index: u32) -> [u8; 20] {
    *WalletSeed::from_bytes(COUNTING).rescue_account(index).address()
}

fn hex(address: &[u8; 20]) -> String {
    address.iter().fold(String::from("0x"), |mut out, byte| {
        out.push_str(&format!("{byte:02x}"));
        out
    })
}

/// The fake block hash at `height`.
fn block_hash(height: u64) -> [u8; 32] {
    let mut hash = [0x5a; 32];
    hash[..8].copy_from_slice(&height.to_be_bytes());
    hash
}

#[derive(Clone, Copy)]
enum Event {
    /// A transaction from `from` to `to`: `from`'s nonce goes up.
    Transfer { from: [u8; 20], to: [u8; 20], value: u128 },
    /// A contract pays `to` from inside its code: no nonce changes.
    ContractPays { to: [u8; 20], value: u128 },
    /// The block's miner gets `value`: no nonce changes.
    Reward { to: [u8; 20], value: u128 },
}

/// The events of the fake chain, by height, and every question asked.
struct FakeLookup {
    events: Vec<(u64, Event)>,
    asked: Arc<Mutex<Vec<([u8; 20], [u8; 32])>>>,
}

impl AccountLookup for FakeLookup {
    fn account_state(&self, address: Vec<u8>, block_hash_bytes: Vec<u8>) -> Result<AccountState, RestoreError> {
        let address: [u8; 20] = address.as_slice().try_into().expect("the restore asks with 20-byte addresses");
        let hash: [u8; 32] = block_hash_bytes.as_slice().try_into().expect("the restore asks at 32-byte hashes");
        self.asked.lock().unwrap().push((address, hash));
        let Some(height) = (0..=TIP).find(|&h| block_hash(h) == hash) else {
            return Err(RestoreError::Lookup { reason: "unknown block".to_owned() });
        };
        let mut balances: HashMap<[u8; 20], u128> =
            HashMap::from([(STRANGER, 1_000 * GHOST), (CONTRACT, 1_000 * GHOST)]);
        let mut nonces: HashMap<[u8; 20], u64> = HashMap::new();
        for &(at, event) in self.events.iter().filter(|(at, _)| *at <= height) {
            assert!(at <= TIP);
            match event {
                Event::Transfer { from, to, value } => {
                    *nonces.entry(from).or_default() += 1;
                    *balances.entry(from).or_default() -= value;
                    *balances.entry(to).or_default() += value;
                }
                Event::ContractPays { to, value } => {
                    *balances.entry(CONTRACT).or_default() -= value;
                    *balances.entry(to).or_default() += value;
                }
                Event::Reward { to, value } => *balances.entry(to).or_default() += value,
            }
        }
        let balance = balances.get(&address).copied().unwrap_or(0);
        let bytes = balance.to_be_bytes();
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(16);
        Ok(AccountState { balance: bytes[first..].to_vec(), nonce: nonces.get(&address).copied().unwrap_or(0) })
    }
}

struct Run {
    /// The accounts in the order they were reported.
    reported: Vec<RestoredAccount>,
    result: RestoreResult,
    asked: Vec<([u8; 20], [u8; 32])>,
}

fn new_restore(events: &[(u64, Event)]) -> (Arc<RestoreLookup>, Arc<Mutex<Vec<([u8; 20], [u8; 32])>>>) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let lookup = FakeLookup { events: events.to_vec(), asked: asked.clone() };
    let restore = RestoreLookup::new(counting_words(), Box::new(lookup), TIP, block_hash(TIP).to_vec()).unwrap();
    (restore, asked)
}

/// Looks up account after account until the gap ends the run.
fn restore_all(events: &[(u64, Event)]) -> Run {
    let (restore, asked) = new_restore(events);
    let mut reported = Vec::new();
    while let Some(account) = restore.look_up_next().unwrap() {
        reported.push(account);
    }
    let result = restore.result();
    let asked = asked.lock().unwrap().clone();
    Run { reported, result, asked }
}

fn used(result: &RestoreResult) -> Vec<(u32, String, String, u64)> {
    result
        .accounts
        .iter()
        .filter(|a| a.used)
        .map(|a| (a.index, a.address.clone(), a.balance.clone(), a.nonce))
        .collect()
}

fn check_complete(run: &Run, looked_up: usize) {
    assert!(run.result.complete);
    assert_eq!(run.result.accounts.len(), looked_up);
    assert_eq!(run.reported, run.result.accounts, "every account is reported once, in index order");
    assert_eq!(run.result.tip_height, TIP);
    assert_eq!(run.result.tip_hash, block_hash(TIP).to_vec());
    assert!(run.result.note.contains("unverified"));
    for (i, account) in run.result.accounts.iter().enumerate() {
        assert_eq!(account.index, i as u32);
        assert_eq!(account.address, hex(&address(i as u32)));
        assert!(account.unverified, "no balance is proved yet");
    }
    // One question per account, all at the tip's one block hash.
    assert_eq!(run.asked.len(), looked_up);
    assert!(run.asked.iter().all(|(_, hash)| *hash == block_hash(TIP)));
}

#[test]
fn an_account_funded_before_the_checkpoint_and_untouched_since_is_found() {
    let early = 12;
    assert!(early < CHECKPOINT);
    let run = restore_all(&[(early, Event::Transfer { from: STRANGER, to: address(0), value: 5 * GHOST })]);
    assert_eq!(used(&run.result), vec![(0, hex(&address(0)), (5 * GHOST).to_string(), 0)]);
    check_complete(&run, 1 + GAP_LIMIT as usize);
}

#[test]
fn an_account_past_3_unused_ones_is_found() {
    // Account 0 used, 1 to 3 unused, 4 used.
    let run = restore_all(&[
        (1_200, Event::Transfer { from: STRANGER, to: address(0), value: 7 }),
        (4_800, Event::Transfer { from: STRANGER, to: address(4), value: 9 }),
    ]);
    assert_eq!(
        used(&run.result),
        vec![(0, hex(&address(0)), "7".to_owned(), 0), (4, hex(&address(4)), "9".to_owned(), 0)]
    );
    check_complete(&run, 5 + GAP_LIMIT as usize);

    // Accounts 0 to 3 unused: account 4 alone is found.
    let run = restore_all(&[(4_800, Event::Transfer { from: STRANGER, to: address(4), value: 9 })]);
    assert_eq!(used(&run.result), vec![(4, hex(&address(4)), "9".to_owned(), 0)]);
    check_complete(&run, 5 + GAP_LIMIT as usize);
}

#[test]
fn a_contract_paid_account_is_found() {
    // Account 2 never sent or got a transaction of its own: a contract paid it.
    let run = restore_all(&[(3_000, Event::ContractPays { to: address(2), value: 3 * GHOST })]);
    assert_eq!(used(&run.result), vec![(2, hex(&address(2)), (3 * GHOST).to_string(), 0)]);
    check_complete(&run, 3 + GAP_LIMIT as usize);
}

#[test]
fn a_mining_reward_account_is_found() {
    // Account 1 mined blocks before and after the checkpoint height.
    let run = restore_all(&[
        (40, Event::Reward { to: address(1), value: 2 * GHOST }),
        (2_500, Event::Reward { to: address(1), value: 2 * GHOST }),
    ]);
    assert_eq!(used(&run.result), vec![(1, hex(&address(1)), (4 * GHOST).to_string(), 0)]);
    check_complete(&run, 2 + GAP_LIMIT as usize);
}

#[test]
fn an_emptied_account_is_used_and_the_search_goes_past_it() {
    // Account 0 sent everything away: balance 0, nonce 1. Account 15 is
    // found because the run goes 20 past account 0, and 30 past 15.
    let run = restore_all(&[
        (10, Event::Transfer { from: STRANGER, to: address(0), value: 4 }),
        (20, Event::Transfer { from: address(0), to: STRANGER, value: 4 }),
        (30, Event::Reward { to: address(15), value: 1 }),
        (40, Event::ContractPays { to: address(30), value: 6 }),
    ]);
    assert_eq!(
        used(&run.result),
        vec![
            (0, hex(&address(0)), "0".to_owned(), 1),
            (15, hex(&address(15)), "1".to_owned(), 0),
            (30, hex(&address(30)), "6".to_owned(), 0),
        ]
    );
    check_complete(&run, 31 + GAP_LIMIT as usize);
}

#[test]
fn every_kind_of_funding_together() {
    let run = restore_all(&[
        (5, Event::Transfer { from: STRANGER, to: address(0), value: 10 }),
        (600, Event::Reward { to: address(3), value: 20 }),
        (1_500, Event::Transfer { from: STRANGER, to: STRANGER, value: 1 }),
        (2_000, Event::ContractPays { to: address(7), value: 30 }),
        (4_999, Event::Transfer { from: address(0), to: address(7), value: 4 }),
    ]);
    assert_eq!(
        used(&run.result),
        vec![
            (0, hex(&address(0)), "6".to_owned(), 1),
            (3, hex(&address(3)), "20".to_owned(), 0),
            (7, hex(&address(7)), "34".to_owned(), 0),
        ]
    );
    check_complete(&run, 8 + GAP_LIMIT as usize);
    // The stranger is asked about by nobody.
    assert!(run.asked.iter().all(|(address, _)| *address != STRANGER));
}

#[test]
fn each_balance_is_reported_as_soon_as_it_arrives() {
    let (restore, asked) = new_restore(&[(12, Event::Transfer { from: STRANGER, to: address(0), value: 5 * GHOST })]);
    let first = restore.look_up_next().unwrap().expect("account 0 is looked up first");
    assert_eq!((first.index, first.balance.as_str(), first.used), (0, "5000000000000000000", true));
    // One question so far, and the result already shows the balance.
    assert_eq!(asked.lock().unwrap().len(), 1);
    let result = restore.result();
    assert!(!result.complete);
    assert_eq!(result.next_index, 1);
    assert_eq!(result.accounts, vec![first]);
}

#[test]
fn a_restore_at_a_block_the_lookup_does_not_know_fails_and_shows_nothing() {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let lookup = FakeLookup { events: vec![], asked: asked.clone() };
    let restore =
        RestoreLookup::new(counting_words(), Box::new(lookup), TIP + 1, block_hash(TIP + 1).to_vec()).unwrap();
    assert_eq!(restore.look_up_next(), Err(RestoreError::Lookup { reason: "unknown block".to_owned() }));
    assert!(restore.result().accounts.is_empty());
    assert_eq!(restore.result().next_index, 0);
}
