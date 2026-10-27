//! The calls of the restore of `restore_scan`, from Ghost's counting-bytes
//! test seed, with a fake lookup that holds a fixed state per address.
//!
//! Derived accounts hold public data only; the gap ends the run at exactly 20
//! unused accounts; a search further goes past it and any account can be
//! looked up by index; a malformed tip, malformed words and a malformed state
//! are refused, the words never echoed; a failed lookup changes nothing and
//! can be retried; two restores of the same words agree.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use ghost_client::account::WalletSeed;
use ghost_wallet_core::{AccountLookup, AccountState, GAP_LIMIT, RestoreError, RestoreLookup, RestoreResult};

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

const TIP: u64 = 77;
const TIP_HASH: [u8; 32] = [0x7e; 32];

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

/// A fixed state per address; every other address is unused. While `down`
/// is set, every lookup fails.
#[derive(Clone, Default)]
struct FakeLookup {
    states: HashMap<[u8; 20], AccountState>,
    down: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
}

impl AccountLookup for FakeLookup {
    fn account_state(&self, address: Vec<u8>, block_hash: Vec<u8>) -> Result<AccountState, RestoreError> {
        assert_eq!(block_hash, TIP_HASH.to_vec(), "every lookup is at the tip's hash");
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.down.load(Ordering::SeqCst) {
            return Err(RestoreError::Lookup { reason: "the fake node is down".to_owned() });
        }
        let address: [u8; 20] = address.try_into().unwrap();
        Ok(self.states.get(&address).cloned().unwrap_or(AccountState { balance: vec![], nonce: 0 }))
    }
}

/// A fake lookup with these accounts holding (balance, nonce).
fn lookup(used: &[(u32, u128, u64)]) -> FakeLookup {
    let states = used
        .iter()
        .map(|&(index, balance, nonce)| {
            (address(index), AccountState { balance: balance.to_be_bytes().to_vec(), nonce })
        })
        .collect();
    FakeLookup { states, ..FakeLookup::default() }
}

fn new_restore(lookup: FakeLookup) -> Arc<RestoreLookup> {
    RestoreLookup::new(counting_words(), Box::new(lookup), TIP, TIP_HASH.to_vec()).unwrap()
}

fn run(restore: &RestoreLookup) -> RestoreResult {
    while restore.look_up_next().unwrap().is_some() {}
    restore.result()
}

fn used_indexes(result: &RestoreResult) -> Vec<u32> {
    result.accounts.iter().filter(|a| a.used).map(|a| a.index).collect()
}

#[test]
fn derived_accounts_hold_public_data_only() {
    let restore = new_restore(FakeLookup::default());
    let seed = WalletSeed::from_bytes(COUNTING);
    for index in [0, 1, 19, 20, 500] {
        let account = restore.derive_account(index);
        let key = seed.rescue_account(index);
        assert_eq!(account.index, index);
        assert_eq!(account.address, hex(key.address()));
        assert_eq!(account.rescue_public_key, key.public_key().to_vec());
    }
    assert_eq!(restore.derive_account(0).address, "0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd");
    // Deriving looks nothing up.
    assert!(restore.result().accounts.is_empty());
}

#[test]
fn nothing_is_shown_before_the_first_lookup() {
    let restore = new_restore(lookup(&[(0, 5, 0)]));
    let result = restore.result();
    assert!(result.accounts.is_empty());
    assert!(!result.complete);
    assert_eq!(result.next_index, 0);
    assert_eq!((result.tip_height, result.tip_hash), (TIP, TIP_HASH.to_vec()));
}

#[test]
fn twenty_unused_accounts_end_the_run() {
    // 0 to 18 unused, 19 used: found, and the run goes to 39.
    let result = run(&new_restore(lookup(&[(19, 1, 0)])));
    assert_eq!(used_indexes(&result), vec![19]);
    assert_eq!(result.accounts.len(), 20 + GAP_LIMIT as usize);
    assert!(result.complete);

    // 0 to 19 unused, 20 used: not found.
    let result = run(&new_restore(lookup(&[(20, 1, 0)])));
    assert!(used_indexes(&result).is_empty());
    assert_eq!(result.accounts.len(), GAP_LIMIT as usize);
    assert!(result.accounts.iter().all(|a| a.balance == "0" && a.nonce == 0));
    assert!(result.complete);
}

#[test]
fn an_account_is_used_by_its_nonce_or_its_balance() {
    let result = run(&new_restore(lookup(&[(0, 0, 3), (1, 8, 0), (2, 0, 0)])));
    assert_eq!(used_indexes(&result), vec![0, 1]);
    let account = |index: usize| (result.accounts[index].balance.clone(), result.accounts[index].nonce);
    assert_eq!(account(0), ("0".to_owned(), 3));
    assert_eq!(account(1), ("8".to_owned(), 0));
    assert_eq!(account(2), ("0".to_owned(), 0));
    assert_eq!(result.accounts.len(), 2 + GAP_LIMIT as usize);
}

#[test]
fn search_further_goes_past_the_gap() {
    let fake = lookup(&[(3, 10, 1), (30, 20, 0), (60, 30, 0)]);
    let calls = fake.calls.clone();
    let restore = new_restore(fake);
    let result = run(&restore);
    assert_eq!(used_indexes(&result), vec![3]);
    assert_eq!(result.accounts.len(), 4 + GAP_LIMIT as usize);
    assert!(result.complete);
    assert_eq!(restore.look_up_next(), Ok(None), "a complete run looks nothing more up");
    assert_eq!(calls.load(Ordering::SeqCst), 24);

    // 20 further: 24 to 43 holds 30, which takes the run to 50.
    restore.search_further();
    assert!(!restore.result().complete);
    let result = run(&restore);
    assert_eq!(used_indexes(&result), vec![3, 30]);
    assert_eq!(result.accounts.len(), 31 + GAP_LIMIT as usize);
    assert_eq!(calls.load(Ordering::SeqCst), 51, "no account is looked up twice");

    // 60 is 29 past 30: one more search further reaches it.
    restore.search_further();
    let result = run(&restore);
    assert_eq!(used_indexes(&result), vec![3, 30, 60]);
    assert_eq!(result.accounts.len(), 61 + GAP_LIMIT as usize);
    for (i, account) in result.accounts.iter().enumerate() {
        assert_eq!(account.index, i as u32);
        assert_eq!(account.address, hex(&address(i as u32)));
    }
}

#[test]
fn any_account_can_be_looked_up_by_index() {
    let fake = lookup(&[(45, 12, 2)]);
    let calls = fake.calls.clone();
    let restore = new_restore(fake);
    let result = run(&restore);
    assert!(used_indexes(&result).is_empty());

    let account = restore.look_up_account(45).unwrap();
    assert_eq!((account.index, account.address.clone()), (45, hex(&address(45))));
    assert_eq!((account.balance.as_str(), account.nonce, account.used), ("12", 2, true));
    // A used account takes the run to 20 past it; 45 is not looked up again.
    let result = restore.result();
    assert!(!result.complete);
    let before = calls.load(Ordering::SeqCst);
    let result = run(&restore);
    assert_eq!(used_indexes(&result), vec![45]);
    assert_eq!(result.accounts.len(), 46 + GAP_LIMIT as usize);
    assert_eq!(calls.load(Ordering::SeqCst) - before, 46 + GAP_LIMIT as usize - 20 - 1);
}

#[test]
fn a_failed_lookup_changes_nothing_and_can_be_retried() {
    let fake = lookup(&[(0, 5, 0), (2, 6, 0)]);
    let down = fake.down.clone();
    let restore = new_restore(fake);
    assert_eq!(restore.look_up_next().unwrap().map(|a| a.index), Some(0));
    down.store(true, Ordering::SeqCst);
    assert_eq!(restore.look_up_next(), Err(RestoreError::Lookup { reason: "the fake node is down".to_owned() }));
    assert_eq!(restore.look_up_account(2), Err(RestoreError::Lookup { reason: "the fake node is down".to_owned() }));
    let result = restore.result();
    assert_eq!(result.accounts.len(), 1);
    assert_eq!(result.next_index, 1);
    down.store(false, Ordering::SeqCst);
    assert_eq!(restore.look_up_next().unwrap().map(|a| a.index), Some(1));
    assert_eq!(used_indexes(&run(&restore)), vec![0, 2]);
}

#[test]
fn a_malformed_state_is_refused() {
    let mut fake = FakeLookup::default();
    fake.states.insert(address(0), AccountState { balance: vec![1; 33], nonce: 0 });
    fake.states.insert(address(1), AccountState { balance: vec![1; 17], nonce: 0 });
    let mut wide = vec![0; 16];
    wide.extend([0xff; 16]);
    fake.states.insert(address(2), AccountState { balance: wide, nonce: 0 });
    let restore = new_restore(fake);
    assert!(matches!(restore.look_up_next(), Err(RestoreError::BadState { index: 0, .. })));
    assert!(matches!(restore.look_up_account(1), Err(RestoreError::BadState { index: 1, .. })));
    assert!(restore.result().accounts.is_empty());
    // 32 bytes with leading zeros fit.
    assert_eq!(restore.look_up_account(2).unwrap().balance, u128::MAX.to_string());
}

#[test]
fn a_tip_hash_that_is_not_32_bytes_is_refused() {
    for hash in [vec![], vec![0x7e; 31], vec![0x7e; 33]] {
        let error = RestoreLookup::new(counting_words(), Box::new(FakeLookup::default()), TIP, hash).err();
        assert!(matches!(error, Some(RestoreError::BadTip { .. })));
    }
}

#[test]
fn short_or_invalid_words_are_refused_without_echoing_them() {
    let words = counting_words();
    let list: Vec<&str> = words.split(' ').collect();

    let short = list[..23].join(" ");
    let mut unknown = list.clone();
    unknown[5] = "notaword";
    let unknown = unknown.join(" ");
    let mut swapped = list.clone();
    swapped.swap(0, 1);
    let swapped = swapped.join(" ");

    for bad in [short, unknown, swapped, String::new()] {
        let error = RestoreLookup::new(bad.clone(), Box::new(FakeLookup::default()), TIP, TIP_HASH.to_vec())
            .err()
            .expect("the words are refused");
        let RestoreError::Words { reason } = &error else { panic!("not a words error: {error:?}") };
        assert!(!reason.is_empty());
        let shown = format!("{error} {error:?}");
        for word in bad.split(' ').filter(|w| w.len() > 2) {
            assert!(!shown.contains(word), "the error repeats a word");
        }
    }
}

#[test]
fn two_restores_of_the_same_words_agree() {
    let used = &[(0, 5, 1), (3, 1_000_000_000_000_000_000, 0), (7, 1, 0)];
    let first = run(&new_restore(lookup(used)));
    let second = run(&new_restore(lookup(used)));
    assert_eq!(first, second);
    assert_eq!(used_indexes(&first), vec![0, 3, 7]);
    assert_ne!(first, run(&new_restore(lookup(&[(1, 5, 0)]))));
}
