//! The account words: create, check, save, discard and import, against a
//! store in memory.

use ghost_client::account::{SeedError, WalletSeed};
use ghost_client::wordlist::WORDLIST;
use ghost_wallet_core::{AccountError, AccountVault, CHECKED_WORDS, MemoryStore, SeedStore, is_listed_word};
use rand::SeedableRng;
use rand::rngs::StdRng;

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

/// Account 0 of the counting-bytes test seed (see tests/address.rs).
const COUNTING_ADDRESS: &str = "0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd";

fn counting_words() -> String {
    WalletSeed::from_bytes(COUNTING).to_words().as_str().to_owned()
}

fn vault() -> AccountVault<MemoryStore> {
    AccountVault::new(MemoryStore::default())
}

fn address_of(words: &str) -> String {
    ghost_wallet_core::account_zero_address(words.to_owned()).unwrap()
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

/// Types the words at positions 1 to `count` right.
fn check_first<S: SeedStore>(vault: &AccountVault<S>, words: &[String], count: u32) {
    for position in 1..=count {
        assert!(vault.check_new_account_word(position, &words[position as usize - 1]).unwrap());
    }
}

/// The whole words of every message of an error, for checking that it holds
/// no account word.
fn message_words(error: &AccountError) -> Vec<String> {
    format!("{error} {error:?}")
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

#[test]
fn new_account_words_are_24_valid_words() {
    let vault = vault();
    let words = vault.new_account_words_with(&mut StdRng::seed_from_u64(1)).unwrap();
    assert_eq!(words.len(), 24);
    assert!(words.iter().all(|word| is_listed_word(word)));
    // ghost_client's own seed, from the same generator.
    let expected = WalletSeed::generate(&mut StdRng::seed_from_u64(1));
    assert_eq!(words.join(" "), expected.to_words().as_str());
    assert!(WalletSeed::from_words(&words.join(" ")).is_ok());
    assert!(vault.holds_new_account());
    // Not saved until checked.
    assert!(!vault.has_account().unwrap());
}

#[test]
fn new_account_words_from_the_system_differ_each_time() {
    let vault = vault();
    let first = vault.new_account_words().unwrap();
    let second = vault.new_account_words().unwrap();
    assert_eq!(first.len(), 24);
    assert_ne!(first, second);
    // The second account replaced the first: the first's words no longer check.
    let differs = (1..=24u32).find(|position| first[*position as usize - 1] != second[*position as usize - 1]).unwrap();
    assert!(!vault.check_new_account_word(differs, &first[differs as usize - 1]).unwrap());
    assert!(vault.check_new_account_word(differs, &second[differs as usize - 1]).unwrap());
}

#[test]
fn check_new_account_word_compares_the_held_word() {
    let vault = vault();
    let words = vault.new_account_words_with(&mut StdRng::seed_from_u64(2)).unwrap();
    for position in 1..=24u32 {
        let word = &words[position as usize - 1];
        assert!(vault.check_new_account_word(position, word).unwrap(), "word {position}");
        let other = &words[(position as usize) % 24];
        if other != word {
            assert!(!vault.check_new_account_word(position, other).unwrap(), "word {position} took another word");
        }
    }
    // Case and surrounding spaces do not matter; anything else does.
    let first = &words[0];
    assert!(vault.check_new_account_word(1, &format!("  {}\n", first.to_uppercase())).unwrap());
    assert!(!vault.check_new_account_word(1, &first[..first.len() - 1]).unwrap());
    assert!(!vault.check_new_account_word(1, &format!("{first}s")).unwrap());
    assert!(!vault.check_new_account_word(1, "").unwrap());
}

#[test]
fn check_new_account_word_refuses_positions_outside_1_to_24() {
    let vault = vault();
    let words = vault.new_account_words_with(&mut StdRng::seed_from_u64(3)).unwrap();
    assert_eq!(vault.check_new_account_word(0, &words[0]), Err(AccountError::BadPosition { position: 0 }));
    assert_eq!(vault.check_new_account_word(25, &words[23]), Err(AccountError::BadPosition { position: 25 }));
    assert_eq!(
        vault.check_new_account_word(u32::MAX, &words[0]),
        Err(AccountError::BadPosition { position: u32::MAX })
    );
}

#[test]
fn nothing_to_check_or_save_without_a_new_account() {
    let vault = vault();
    assert_eq!(vault.check_new_account_word(1, "abandon"), Err(AccountError::NoNewAccount));
    assert_eq!(vault.save_new_account(), Err(AccountError::NoNewAccount));
}

#[test]
fn save_new_account_needs_three_different_words_typed_right() {
    let vault = vault();
    let words = vault.new_account_words_with(&mut StdRng::seed_from_u64(4)).unwrap();
    assert_eq!(vault.save_new_account(), Err(AccountError::NotChecked { checked: 0, needed: CHECKED_WORDS }));

    // The same word three times is one word checked.
    for _ in 0..3 {
        assert!(vault.check_new_account_word(5, &words[4]).unwrap());
    }
    assert_eq!(vault.save_new_account(), Err(AccountError::NotChecked { checked: 1, needed: CHECKED_WORDS }));

    // A wrong word checks nothing.
    let wrong = if words[6] == "abandon" { "zoo" } else { "abandon" };
    assert!(!vault.check_new_account_word(7, wrong).unwrap());
    assert!(vault.check_new_account_word(9, &words[8]).unwrap());
    assert_eq!(vault.save_new_account(), Err(AccountError::NotChecked { checked: 2, needed: CHECKED_WORDS }));
    assert!(!vault.has_account().unwrap());

    assert!(vault.check_new_account_word(20, &words[19]).unwrap());
    vault.save_new_account().unwrap();
    assert!(vault.has_account().unwrap());
}

#[test]
fn saved_new_account_is_the_shown_words_and_is_forgotten() {
    let vault = vault();
    let words = vault.new_account_words_with(&mut StdRng::seed_from_u64(5)).unwrap();
    check_first(&vault, &words, CHECKED_WORDS);
    vault.save_new_account().unwrap();

    assert_eq!(vault.saved_account_zero_address().unwrap(), address_of(&words.join(" ")));
    assert!(!vault.holds_new_account());
    assert_eq!(vault.check_new_account_word(1, &words[0]), Err(AccountError::NoNewAccount));
    assert_eq!(vault.save_new_account(), Err(AccountError::NoNewAccount));
}

#[test]
fn discard_new_account_forgets_it_unsaved() {
    let vault = vault();
    let words = vault.new_account_words_with(&mut StdRng::seed_from_u64(6)).unwrap();
    check_first(&vault, &words, CHECKED_WORDS);
    vault.discard_new_account();
    assert!(!vault.holds_new_account());
    assert_eq!(vault.save_new_account(), Err(AccountError::NoNewAccount));
    assert!(!vault.has_account().unwrap());
    assert_eq!(vault.saved_account_zero_address(), Err(AccountError::NoAccount));
    // Discarding twice is harmless.
    vault.discard_new_account();
}

#[test]
fn a_refused_save_keeps_the_new_account_held() {
    let vault = AccountVault::new(RefusingStore);
    let words = vault.new_account_words_with(&mut StdRng::seed_from_u64(7)).unwrap();
    check_first(&vault, &words, CHECKED_WORDS);
    assert_eq!(vault.save_new_account(), Err(AccountError::Keychain { status: -25308 }));
    assert!(vault.holds_new_account());
    assert!(vault.check_new_account_word(1, &words[0]).unwrap());
}

#[test]
fn import_account_words_saves_valid_words() {
    let vault = vault();
    vault.import_account_words(&counting_words()).unwrap();
    assert!(vault.has_account().unwrap());
    assert_eq!(vault.saved_account_zero_address().unwrap(), COUNTING_ADDRESS);
}

#[test]
fn import_account_words_takes_any_spacing_and_case() {
    let vault = vault();
    let typed = format!("  {}\n", counting_words().to_uppercase().replace(' ', "\n  "));
    vault.import_account_words(&typed).unwrap();
    assert_eq!(vault.saved_account_zero_address().unwrap(), COUNTING_ADDRESS);
}

#[test]
fn import_account_words_refuses_invalid_words_without_repeating_them() {
    let words = counting_words();
    let list: Vec<&str> = words.split(' ').collect();

    let short = list[..23].join(" ");
    // A last word that breaks the checksum (about 255 in 256 do).
    let bad_checksum = WORDLIST
        .iter()
        .map(|last| format!("{} {last}", list[..23].join(" ")))
        .find(|typed| matches!(WalletSeed::from_words(typed), Err(SeedError::Checksum)))
        .unwrap();
    let mut unknown = list.clone();
    unknown[4] = "ghostly";
    let with_digits = format!("{} 7", list[..23].join(" "));

    for typed in [short, bad_checksum, unknown.join(" "), with_digits, String::new()] {
        let vault = vault();
        let error = vault.import_account_words(&typed).unwrap_err();
        let AccountError::Words { reason } = &error else { panic!("not a words error: {error:?}") };
        assert!(!reason.is_empty());
        let shown = message_words(&error);
        for word in typed.split_whitespace() {
            assert!(!shown.iter().any(|shown| shown == word), "an error repeated a typed word");
        }
        assert!(!vault.has_account().unwrap());
    }
}

#[test]
fn import_account_words_forgets_a_held_new_account() {
    let vault = vault();
    vault.new_account_words_with(&mut StdRng::seed_from_u64(8)).unwrap();
    vault.import_account_words(&counting_words()).unwrap();
    assert!(!vault.holds_new_account());
}

#[test]
fn a_saved_account_is_never_overwritten() {
    let vault = vault();
    vault.import_account_words(&counting_words()).unwrap();

    assert_eq!(vault.new_account_words_with(&mut StdRng::seed_from_u64(9)), Err(AccountError::AccountExists));
    assert_eq!(vault.new_account_words().unwrap_err(), AccountError::AccountExists);

    let other = WalletSeed::from_bytes([7u8; 32]).to_words().as_str().to_owned();
    assert_eq!(vault.import_account_words(&other), Err(AccountError::AccountExists));
    assert_eq!(vault.saved_account_zero_address().unwrap(), COUNTING_ADDRESS);
}

#[test]
fn a_new_account_cannot_be_saved_over_an_import() {
    let vault = vault();
    let words = vault.new_account_words_with(&mut StdRng::seed_from_u64(10)).unwrap();
    check_first(&vault, &words, CHECKED_WORDS);
    // Another screen imports an account meanwhile: the new one is gone.
    vault.import_account_words(&counting_words()).unwrap();
    assert_eq!(vault.save_new_account(), Err(AccountError::NoNewAccount));
    assert_eq!(vault.saved_account_zero_address().unwrap(), COUNTING_ADDRESS);
}

#[test]
fn memory_store_refuses_a_second_seed() {
    let store = MemoryStore::default();
    store.save(&WalletSeed::from_bytes(COUNTING)).unwrap();
    assert_eq!(store.save(&WalletSeed::from_bytes([1u8; 32])), Err(AccountError::AccountExists));
    assert_eq!(store.load().unwrap().unwrap().as_bytes(), &COUNTING);
}

#[test]
fn is_listed_word_looks_up_one_word() {
    let words = counting_words();
    for word in words.split(' ') {
        assert!(is_listed_word(word), "a listed word was refused");
        assert!(is_listed_word(&format!(" {} ", word.to_uppercase())));
    }
    for word in ["", " ", "ghostly", "abandonx", "aband", "abandon amount", "abandonabandonabandon", "7", "Ábandon"] {
        assert!(!is_listed_word(word), "an unlisted word was taken");
    }
}

#[test]
fn errors_name_no_words() {
    let errors = [
        AccountError::Words { reason: "word 5 is not in the word list".to_owned() },
        AccountError::NoNewAccount,
        AccountError::BadPosition { position: 25 },
        AccountError::NotChecked { checked: 1, needed: 3 },
        AccountError::AccountExists,
        AccountError::NoAccount,
        AccountError::Randomness,
        AccountError::BadSavedAccount,
        AccountError::Keychain { status: -25308 },
    ];
    let words = counting_words();
    for error in &errors {
        let shown = message_words(error);
        assert!(!shown.is_empty());
        assert!(words.split(' ').all(|word| !shown.iter().any(|shown| shown == word)), "{shown:?}");
    }
}
