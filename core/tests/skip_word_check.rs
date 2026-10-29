//! Skipping the word check: only by an explicit call, made when the person
//! ticked "Skip the check", for a new account and for a new Phantom Key; and
//! checking three words of a saved account later. The exported calls share
//! one store and one held key for the process, so they are walked in one test.

use ghost_client::account::WalletSeed;
use ghost_wallet_core::{
    AccountError, AccountVault, CHECKED_KEY_WORDS, CHECKED_WORDS, KeyVault, MemoryStore, SeedStore, TEST_CHAIN_ID,
    VanishError, check_saved_account_words, confirm_phantom_key_saved, confirm_phantom_key_saved_unchecked,
    has_account, new_account_words, prepare_vanish, save_new_account, save_new_account_unchecked,
    saved_account_words, take_phantom_key_words,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

const ONE_GHOST: u128 = 1_000_000_000_000_000_000;

fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

fn vault() -> AccountVault<MemoryStore> {
    AccountVault::new(MemoryStore::default())
}

/// A word of the list that is not `word`.
fn other_than(word: &str) -> &'static str {
    if word == "zoo" { "abandon" } else { "zoo" }
}

/// A Keychain that refuses every save, as a locked phone would.
#[derive(Default)]
struct RefusingStore;

impl SeedStore for RefusingStore {
    fn contains(&self) -> Result<bool, AccountError> {
        Ok(false)
    }
    fn load(&self) -> Result<Option<WalletSeed>, AccountError> {
        Ok(None)
    }
    fn save(&self, _seed: &WalletSeed) -> Result<(), AccountError> {
        Err(AccountError::Keychain { status: -25308 })
    }
}

#[test]
fn the_checked_save_still_refuses_while_the_unchecked_one_saves() {
    let vault = vault();
    assert_eq!(vault.save_new_account_unchecked(), Err(AccountError::NoNewAccount));
    let words = vault.new_account_words_with(&mut rng(1)).unwrap();
    // The check stays the default: without three words, the save is refused.
    assert_eq!(vault.save_new_account(), Err(AccountError::NotChecked { checked: 0, needed: CHECKED_WORDS }));
    assert!(vault.holds_new_account());

    vault.save_new_account_unchecked().unwrap();
    assert!(!vault.holds_new_account());
    assert!(vault.has_account().unwrap());
    assert_eq!(vault.saved_account_words().unwrap(), words);
    // Saved once: nothing is held to save again, and no account is overwritten.
    assert_eq!(vault.save_new_account_unchecked(), Err(AccountError::NoNewAccount));
    assert_eq!(vault.new_account_words_with(&mut rng(2)), Err(AccountError::AccountExists));
}

#[test]
fn an_unchecked_save_the_store_refuses_keeps_the_account_held() {
    let vault = AccountVault::new(RefusingStore);
    vault.new_account_words_with(&mut rng(3)).unwrap();
    assert_eq!(vault.save_new_account_unchecked(), Err(AccountError::Keychain { status: -25308 }));
    assert!(vault.holds_new_account());
}

#[test]
fn the_saved_words_can_be_checked_later_and_say_only_whether_all_match() {
    let vault = vault();
    assert_eq!(vault.check_saved_account_words(&[(1, "a"), (2, "b"), (3, "c")]), Err(AccountError::NoAccount));
    let words = vault.new_account_words_with(&mut rng(4)).unwrap();
    vault.save_new_account_unchecked().unwrap();

    let right = |position: u32| words[position as usize - 1].as_str();
    let typed = format!(" {} ", right(11).to_uppercase());
    assert!(vault.check_saved_account_words(&[(2, right(2)), (11, typed.as_str()), (24, right(24))]).unwrap());
    // One wrong word fails the whole check, wherever it is.
    for wrong in 0..3 {
        let mut checks = vec![(2, right(2)), (11, right(11)), (24, right(24))];
        checks[wrong].1 = other_than(checks[wrong].1);
        assert!(!vault.check_saved_account_words(&checks).unwrap());
    }

    // Exactly three different positions, each 1 to 24.
    assert_eq!(
        vault.check_saved_account_words(&[(2, right(2)), (11, right(11))]),
        Err(AccountError::CheckCount { asked: 2, needed: CHECKED_WORDS })
    );
    assert_eq!(
        vault.check_saved_account_words(&[(2, right(2)), (2, right(2)), (11, right(11))]),
        Err(AccountError::CheckCount { asked: 2, needed: CHECKED_WORDS })
    );
    assert_eq!(
        vault.check_saved_account_words(&[(1, right(1)), (2, right(2)), (3, right(3)), (4, right(4))]),
        Err(AccountError::CheckCount { asked: 4, needed: CHECKED_WORDS })
    );
    assert_eq!(
        vault.check_saved_account_words(&[(0, "abandon"), (2, right(2)), (11, right(11))]),
        Err(AccountError::BadPosition { position: 0 })
    );
    assert_eq!(
        vault.check_saved_account_words(&[(25, "abandon"), (2, right(2)), (11, right(11))]),
        Err(AccountError::BadPosition { position: 25 })
    );
}

#[test]
fn a_phantom_key_is_dropped_unchecked_only_after_its_words_were_shown() {
    let vault = KeyVault::new();
    assert_eq!(vault.confirm_saved_unchecked(), Err(VanishError::NoKeyHeld));
    vault.prepare_with(TEST_CHAIN_ID, ONE_GHOST, &mut rng(5)).unwrap();
    // Never dropped unseen.
    assert_eq!(vault.confirm_saved_unchecked(), Err(VanishError::NotChecked { checked: 0, needed: CHECKED_KEY_WORDS }));
    assert!(vault.holds_key());
    vault.take_words().unwrap();
    // The checked confirm still wants three words typed back.
    assert_eq!(vault.confirm_saved(), Err(VanishError::NotChecked { checked: 0, needed: CHECKED_KEY_WORDS }));
    vault.confirm_saved_unchecked().unwrap();
    assert!(!vault.holds_key());
    assert_eq!(vault.confirm_saved_unchecked(), Err(VanishError::NoKeyHeld));
}

#[test]
fn the_exported_skip_calls_save_the_account_and_drop_the_key() {
    // The new account.
    assert!(!has_account().unwrap());
    let words = new_account_words().unwrap();
    assert_eq!(save_new_account(), Err(AccountError::NotChecked { checked: 0, needed: CHECKED_WORDS }));
    save_new_account_unchecked().unwrap();
    assert!(has_account().unwrap());
    assert_eq!(saved_account_words().unwrap(), words);

    let typed = |positions: &[u32]| positions.iter().map(|p| words[*p as usize - 1].clone()).collect::<Vec<_>>();
    assert!(check_saved_account_words(vec![1, 12, 24], typed(&[1, 12, 24])).unwrap());
    let mut wrong = typed(&[1, 12, 24]);
    wrong[1] = other_than(&wrong[1]).to_owned();
    assert!(!check_saved_account_words(vec![1, 12, 24], wrong).unwrap());
    assert_eq!(
        check_saved_account_words(vec![1, 12, 24], typed(&[1, 12])),
        Err(AccountError::CheckCount { asked: 2, needed: CHECKED_WORDS })
    );

    // The new Phantom Key.
    assert_eq!(confirm_phantom_key_saved_unchecked(), Err(VanishError::NoKeyHeld));
    prepare_vanish(TEST_CHAIN_ID, ONE_GHOST.to_string()).unwrap();
    assert!(matches!(confirm_phantom_key_saved_unchecked(), Err(VanishError::NotChecked { .. })));
    take_phantom_key_words().unwrap();
    assert!(matches!(confirm_phantom_key_saved(), Err(VanishError::NotChecked { .. })));
    confirm_phantom_key_saved_unchecked().unwrap();
    assert_eq!(confirm_phantom_key_saved(), Err(VanishError::NoKeyHeld));
}
