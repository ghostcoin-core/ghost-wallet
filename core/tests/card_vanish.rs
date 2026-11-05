//! A card Vanish with no words: a card-only Phantom Key never hands its
//! words out or answers a guess at them, goes to a card without being shown,
//! and is dropped only once it is on the card. A words key never goes on a
//! card, before or after its words were shown.

use ghost_client::PhantomKey;
use ghost_wallet_core::{
    CHECKED_KEY_WORDS, KeyVault, TEST_CHAIN_ID, VanishError, check_phantom_key_word, confirm_phantom_key_saved,
    confirm_phantom_key_saved_unchecked, forget_phantom_key, prepare_card_vanish, prepare_vanish,
    take_phantom_key_words,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

const ONE_GHOST: u128 = 1_000_000_000_000_000_000;

fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

fn copy(words: &str) -> Option<String> {
    Some(words.to_owned())
}

#[test]
fn a_card_only_key_never_hands_out_its_words_or_answers_a_word_check() {
    let vault = KeyVault::new();
    vault.prepare_card_with(TEST_CHAIN_ID, ONE_GHOST, &mut rng(40)).unwrap();
    assert_eq!(vault.take_words(), Err(VanishError::CardOnly));
    // Asked again, still refused: nothing was handed out the first time.
    assert_eq!(vault.take_words(), Err(VanishError::CardOnly));
    for position in [1, 12, 24] {
        assert_eq!(vault.check_word(position, "abandon"), Err(VanishError::CardOnly));
    }
    // A bad position is refused as before, before the key is looked at.
    assert!(matches!(vault.check_word(0, "abandon"), Err(VanishError::Malformed { .. })));
    // Refusing does not drop it: the Vanish can still go to a card.
    assert!(vault.holds_key());
}

#[test]
fn a_card_only_key_goes_to_a_card_unshown_and_is_dropped_only_after() {
    let vault = KeyVault::new();
    vault.prepare_card_with(TEST_CHAIN_ID, ONE_GHOST, &mut rng(41)).unwrap();
    // Before the card export, the confirm is refused and the key stays held.
    assert_eq!(vault.confirm_saved(), Err(VanishError::CardOnly));
    assert!(vault.holds_key());
    // The skip is never a way to drop a card-only key.
    assert_eq!(vault.confirm_saved_unchecked(), Err(VanishError::CardOnly));
    assert!(vault.holds_key());

    // The card export takes it with no showing: its words are a Phantom Key.
    let words = vault.with_card_words(copy).unwrap().expect("the words were copied");
    assert_eq!(words.split_whitespace().count(), 24);
    assert!(PhantomKey::parse(&words).is_ok());
    // Still held for the Vanish, still no words handed out and no skip.
    assert!(vault.holds_key());
    assert_eq!(vault.take_words(), Err(VanishError::CardOnly));
    assert_eq!(vault.confirm_saved_unchecked(), Err(VanishError::CardOnly));
    assert!(vault.holds_key());

    vault.confirm_saved().unwrap();
    assert!(!vault.holds_key());
    assert_eq!(vault.confirm_saved(), Err(VanishError::NoKeyHeld));
}

#[test]
fn a_card_copy_that_did_not_fit_leaves_a_card_only_key_unconfirmed() {
    let vault = KeyVault::new();
    vault.prepare_card_with(TEST_CHAIN_ID, ONE_GHOST, &mut rng(42)).unwrap();
    assert_eq!(vault.with_card_words(|_| None::<isize>).unwrap(), None);
    assert_eq!(vault.confirm_saved(), Err(VanishError::CardOnly));
    assert!(vault.holds_key());
    // A retry with a card that takes it then succeeds.
    assert!(vault.with_card_words(copy).unwrap().is_some());
    vault.confirm_saved().unwrap();
    assert!(!vault.holds_key());
}

#[test]
fn a_words_key_never_goes_on_a_card_shown_or_not() {
    let vault = KeyVault::new();
    vault.prepare_with(TEST_CHAIN_ID, ONE_GHOST, &mut rng(43)).unwrap();
    assert_eq!(vault.with_card_words(copy), Err(VanishError::NotCardOnly));
    assert_eq!(vault.confirm_saved(), Err(VanishError::NotChecked { checked: 0, needed: CHECKED_KEY_WORDS }));
    vault.take_words().unwrap();
    assert_eq!(vault.with_card_words(copy), Err(VanishError::NotCardOnly));
    // The refused export does not stand in for the word check.
    assert_eq!(vault.confirm_saved(), Err(VanishError::NotChecked { checked: 0, needed: CHECKED_KEY_WORDS }));
    assert!(vault.holds_key());
}

#[test]
fn a_new_vanish_replaces_the_card_only_mark() {
    let vault = KeyVault::new();
    vault.prepare_card_with(TEST_CHAIN_ID, ONE_GHOST, &mut rng(44)).unwrap();
    // A words Vanish after it holds a words key: its words are shown once.
    vault.prepare_with(TEST_CHAIN_ID, ONE_GHOST, &mut rng(45)).unwrap();
    assert_eq!(vault.take_words().unwrap().len(), 24);
    // And a card Vanish after a words one is card-only again.
    vault.prepare_card_with(TEST_CHAIN_ID, ONE_GHOST, &mut rng(46)).unwrap();
    assert_eq!(vault.take_words(), Err(VanishError::CardOnly));
}

#[test]
fn the_exported_card_vanish_holds_a_card_only_key() {
    // The exported calls share one held key for the process: walked in one test.
    assert!(matches!(prepare_card_vanish(1, ONE_GHOST.to_string()), Err(VanishError::WrongChain { .. })));
    assert!(matches!(prepare_card_vanish(TEST_CHAIN_ID, "0".to_owned()), Err(VanishError::Amount { .. })));
    let commit = prepare_card_vanish(TEST_CHAIN_ID, ONE_GHOST.to_string()).unwrap();
    assert_eq!(commit.amount_wei, ONE_GHOST.to_string());
    assert_eq!(commit.commitment.len(), 32);
    assert_eq!(take_phantom_key_words(), Err(VanishError::CardOnly));
    assert_eq!(check_phantom_key_word(1, "abandon".to_owned()), Err(VanishError::CardOnly));
    assert_eq!(confirm_phantom_key_saved(), Err(VanishError::CardOnly));
    assert_eq!(confirm_phantom_key_saved_unchecked(), Err(VanishError::CardOnly));
    forget_phantom_key();
    assert_eq!(confirm_phantom_key_saved(), Err(VanishError::NoKeyHeld));

    // The words Vanish is unchanged.
    prepare_vanish(TEST_CHAIN_ID, ONE_GHOST.to_string()).unwrap();
    assert_eq!(take_phantom_key_words().unwrap().len(), 24);
    forget_phantom_key();
}
