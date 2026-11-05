//! The card bridge: a card gets only a card-only key (a words key is always
//! refused), and the key a card hands back finds its coin like a typed key.

use ghost_client::account::WalletSeed;
use ghost_client::{KeyFormat, PhantomKey};
use ghost_wallet_core::card::{
    CARD_NO_KEY, CARD_NULL, CARD_TOO_SMALL, find_card_key_coins, forget_card_key, ghost_wallet_card_copy_new_key,
    ghost_wallet_card_hold_key, has_card_key, hold_card_words,
};
use ghost_wallet_core::{
    CHECKED_KEY_WORDS, CoinLeaf, KeyVault, TEST_CHAIN_ID, VanishError, commit_leaf, vanish_commit_with,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

const ONE_GHOST: u128 = 1_000_000_000_000_000_000;

fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

fn key(seed: u64) -> PhantomKey {
    PhantomKey::generate(KeyFormat::Words, &mut rng(seed))
}

fn words_of(key: &PhantomKey) -> String {
    key.format_words().expect("a words key").as_str().to_owned()
}

fn tree_with(key: &PhantomKey, wei: u128) -> Vec<CoinLeaf> {
    let other = vanish_commit_with(&self::key(900), TEST_CHAIN_ID, 5 * ONE_GHOST, &mut rng(901)).unwrap();
    let ours = vanish_commit_with(key, TEST_CHAIN_ID, wei, &mut rng(31)).unwrap();
    vec![
        commit_leaf(other.commit_data, other.amount_wei).unwrap(),
        commit_leaf(ours.commit_data, ours.amount_wei).unwrap(),
    ]
}

fn copy(words: &str) -> Option<String> {
    Some(words.to_owned())
}

#[test]
fn a_card_gets_only_a_card_only_key_and_never_a_words_key() {
    let vault = KeyVault::new();
    assert!(matches!(vault.with_card_words(copy), Err(VanishError::NoKeyHeld)));
    vault.prepare_with(TEST_CHAIN_ID, ONE_GHOST, &mut rng(30)).unwrap();
    // A words key never goes on a card, before or after its words were shown.
    assert_eq!(vault.with_card_words(copy), Err(VanishError::NotCardOnly));
    vault.take_words().unwrap();
    assert_eq!(vault.with_card_words(copy), Err(VanishError::NotCardOnly));
    // The refused card is no shortcut: the word check is still needed.
    assert_eq!(vault.confirm_saved(), Err(VanishError::NotChecked { checked: 0, needed: CHECKED_KEY_WORDS }));
    assert!(vault.holds_key());

    // A card-only key goes on the card with no words shown, then may be dropped.
    vault.prepare_card_with(TEST_CHAIN_ID, ONE_GHOST, &mut rng(35)).unwrap();
    let written = vault.with_card_words(copy).unwrap().expect("the words were copied");
    assert!(PhantomKey::parse(&written).is_ok());
    assert!(vault.holds_key());
    vault.confirm_saved().unwrap();
    assert!(!vault.holds_key());
}

#[test]
fn a_card_copy_that_did_not_fit_does_not_count_as_on_a_card() {
    let vault = KeyVault::new();
    vault.prepare_card_with(TEST_CHAIN_ID, ONE_GHOST, &mut rng(34)).unwrap();
    assert_eq!(vault.with_card_words(|_| None::<isize>).unwrap(), None);
    assert_eq!(vault.confirm_saved(), Err(VanishError::CardOnly));
    assert!(vault.holds_key());
}

#[test]
fn the_c_bridge_refuses_null_pointers_and_hands_out_no_unchecked_key() {
    let mut buffer = [0u8; 512];
    // SAFETY: null is refused before any read or write.
    assert_eq!(unsafe { ghost_wallet_card_copy_new_key(core::ptr::null_mut(), 0) }, CARD_NULL);
    assert_eq!(unsafe { ghost_wallet_card_hold_key(core::ptr::null(), 0) }, CARD_NULL);
    // No Vanish ran in this test binary: nothing is held.
    // SAFETY: `buffer` holds 512 bytes.
    assert_eq!(unsafe { ghost_wallet_card_copy_new_key(buffer.as_mut_ptr(), buffer.len()) }, CARD_NO_KEY);
    assert!(CARD_TOO_SMALL < 0);
}

#[test]
fn the_key_a_card_hands_back_finds_its_coin_and_is_forgotten() {
    let held = key(32);
    let leaves = tree_with(&held, 2 * ONE_GHOST);

    // Account words and other text are never held as a card key.
    let account = WalletSeed::from_bytes([7u8; 32]).to_words().as_str().to_owned();
    assert!(!hold_card_words(account));
    assert!(!hold_card_words("not a key".to_owned()));
    let bytes = [0xffu8, 0xfe];
    // SAFETY: `bytes` holds two bytes.
    assert_eq!(unsafe { ghost_wallet_card_hold_key(bytes.as_ptr(), bytes.len()) }, CARD_NO_KEY);
    assert!(!has_card_key());
    assert!(matches!(find_card_key_coins(TEST_CHAIN_ID, leaves.clone(), vec![]), Err(VanishError::NoKeyHeld)));

    let words = words_of(&held);
    // SAFETY: `words` is valid for its length.
    assert_eq!(unsafe { ghost_wallet_card_hold_key(words.as_ptr(), words.len()) }, 0);
    assert!(has_card_key());
    let coins = find_card_key_coins(TEST_CHAIN_ID, leaves.clone(), vec![]).unwrap();
    assert_eq!(coins.status, "found");
    assert_eq!(coins.amount_wei, (2 * ONE_GHOST).to_string());
    // Still held after a lookup, for the proof.
    assert!(has_card_key());

    // Another key replaces it.
    assert!(hold_card_words(words_of(&key(33))));
    assert_eq!(find_card_key_coins(TEST_CHAIN_ID, leaves.clone(), vec![]).unwrap().status, "not-found");

    forget_card_key();
    assert!(!has_card_key());
    assert!(matches!(find_card_key_coins(TEST_CHAIN_ID, leaves, vec![]), Err(VanishError::NoKeyHeld)));
}
