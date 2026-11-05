//! Only a card-only Phantom Key goes on a card. A words key, whose words were
//! shown or could be, is refused by the card export before and after its
//! words were taken, so no one can keep its 24 words and hand its card over
//! as if the card were the only copy. A words key still needs its three-word
//! check (or the skip) to be dropped.

use ghost_client::PhantomKey;
use ghost_wallet_core::card::{CARD_NO_KEY, ghost_wallet_card_copy_new_key};
use ghost_wallet_core::{
    CHECKED_KEY_WORDS, KeyVault, TEST_CHAIN_ID, VanishError, confirm_phantom_key_saved, forget_phantom_key,
    prepare_card_vanish, prepare_vanish, take_phantom_key_words,
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

/// Types back the held key's words at `positions` from `words`.
fn type_back(vault: &KeyVault, words: &[String], positions: &[u32]) {
    for &position in positions {
        assert_eq!(vault.check_word(position, &words[position as usize - 1]), Ok(true));
    }
}

#[test]
fn a_words_key_is_refused_by_the_card_before_its_words_were_taken() {
    let vault = KeyVault::new();
    vault.prepare_with(TEST_CHAIN_ID, ONE_GHOST, &mut rng(60)).unwrap();
    let mut called = false;
    let refused = vault.with_card_words(|words| {
        called = true;
        copy(words)
    });
    assert_eq!(refused, Err(VanishError::NotCardOnly));
    // The words never reached the card writer.
    assert!(!called);
    // Still held, and its words are still shown once.
    assert!(vault.holds_key());
    assert_eq!(vault.take_words().unwrap().len(), 24);
}

#[test]
fn a_words_key_is_refused_by_the_card_after_its_words_were_taken() {
    let vault = KeyVault::new();
    vault.prepare_with(TEST_CHAIN_ID, ONE_GHOST, &mut rng(61)).unwrap();
    let words = vault.take_words().unwrap();
    let mut called = false;
    let refused = vault.with_card_words(|words| {
        called = true;
        copy(words)
    });
    assert_eq!(refused, Err(VanishError::NotCardOnly));
    assert!(!called);
    // A refused card does not stand in for the word check: no shortcut.
    assert_eq!(vault.confirm_saved(), Err(VanishError::NotChecked { checked: 0, needed: CHECKED_KEY_WORDS }));
    assert!(vault.holds_key());
    // Even with some words typed back, the card is still refused.
    type_back(&vault, &words, &[2, 9]);
    assert_eq!(vault.with_card_words(copy), Err(VanishError::NotCardOnly));
    assert_eq!(vault.confirm_saved(), Err(VanishError::NotChecked { checked: 2, needed: CHECKED_KEY_WORDS }));
    // And after all three, too: a words key never goes on a card.
    type_back(&vault, &words, &[17]);
    assert_eq!(vault.with_card_words(copy), Err(VanishError::NotCardOnly));
    assert!(vault.holds_key());
}

#[test]
fn a_card_only_key_is_accepted_by_the_card() {
    let vault = KeyVault::new();
    vault.prepare_card_with(TEST_CHAIN_ID, ONE_GHOST, &mut rng(62)).unwrap();
    let words = vault.with_card_words(copy).unwrap().expect("the words were copied");
    assert_eq!(words.split_whitespace().count(), 24);
    assert!(PhantomKey::parse(&words).is_ok());
    // Its words are still never handed out, and once on the card it may go.
    assert_eq!(vault.take_words(), Err(VanishError::CardOnly));
    vault.confirm_saved().unwrap();
    assert!(!vault.holds_key());
}

#[test]
fn a_words_key_still_confirms_after_three_checked_words() {
    let vault = KeyVault::new();
    vault.prepare_with(TEST_CHAIN_ID, ONE_GHOST, &mut rng(63)).unwrap();
    let words = vault.take_words().unwrap();
    type_back(&vault, &words, &[1, 12]);
    assert_eq!(vault.confirm_saved(), Err(VanishError::NotChecked { checked: 2, needed: CHECKED_KEY_WORDS }));
    // A wrong word counts for nothing.
    assert_eq!(vault.check_word(24, "not-a-key-word"), Ok(false));
    assert_eq!(vault.confirm_saved(), Err(VanishError::NotChecked { checked: 2, needed: CHECKED_KEY_WORDS }));
    type_back(&vault, &words, &[24]);
    vault.confirm_saved().unwrap();
    assert!(!vault.holds_key());
}

#[test]
fn a_words_key_still_confirms_by_the_skip_once_shown() {
    let vault = KeyVault::new();
    vault.prepare_with(TEST_CHAIN_ID, ONE_GHOST, &mut rng(64)).unwrap();
    assert!(matches!(vault.confirm_saved_unchecked(), Err(VanishError::NotChecked { .. })));
    vault.take_words().unwrap();
    vault.confirm_saved_unchecked().unwrap();
    assert!(!vault.holds_key());
}

#[test]
fn the_card_bridge_copies_only_a_card_only_key() {
    // The exported calls share one held key for the process: walked in one test.
    let mut buffer = [0u8; 512];

    prepare_vanish(TEST_CHAIN_ID, ONE_GHOST.to_string()).unwrap();
    // SAFETY: `buffer` holds 512 bytes.
    assert_eq!(unsafe { ghost_wallet_card_copy_new_key(buffer.as_mut_ptr(), buffer.len()) }, CARD_NO_KEY);
    assert_eq!(take_phantom_key_words().unwrap().len(), 24);
    // SAFETY: as above.
    assert_eq!(unsafe { ghost_wallet_card_copy_new_key(buffer.as_mut_ptr(), buffer.len()) }, CARD_NO_KEY);
    assert!(buffer.iter().all(|byte| *byte == 0));
    // The refused copy marked nothing: the words key still needs its check.
    assert!(matches!(confirm_phantom_key_saved(), Err(VanishError::NotChecked { .. })));
    forget_phantom_key();

    prepare_card_vanish(TEST_CHAIN_ID, ONE_GHOST.to_string()).unwrap();
    // SAFETY: as above.
    let written = unsafe { ghost_wallet_card_copy_new_key(buffer.as_mut_ptr(), buffer.len()) };
    assert!(written > 0);
    let words = core::str::from_utf8(&buffer[..written as usize]).unwrap();
    assert!(PhantomKey::parse(words).is_ok());
    confirm_phantom_key_saved().unwrap();
    assert_eq!(confirm_phantom_key_saved(), Err(VanishError::NoKeyHeld));
}
