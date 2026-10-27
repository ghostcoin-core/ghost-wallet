//! Account 0 address for Ghost's counting-bytes test seed.
//!
//! The expected value is the first vector of `client/tests/rescue_accounts.rs`
//! in the ghost repository: rescue-key scheme `0x0003`, seed bytes 0 to 31,
//! account index 0.

use ghost_client::account::{SCHEME_RESCUE_KEY, WalletSeed, account_address};
use ghost_wallet_core::WordsError;
use ghost_wallet_core::account_zero_address as derive_address;

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

const EXPECTED_ADDRESS: &str = "0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd";

/// The fixed test words the app shows on its home screen.
const APP_TEST_WORDS: &str = include_str!("../../modules/ghost-core/test-words.ts");

fn counting_words() -> String {
    WalletSeed::from_bytes(COUNTING).to_words().as_str().to_owned()
}

#[test]
fn account_zero_address() {
    let words = counting_words();
    assert_eq!(words.split(' ').count(), 24);

    let address = derive_address(words.clone()).expect("the test words are valid");
    assert_eq!(address, EXPECTED_ADDRESS);

    // Same answer as Ghost's client crate gives directly.
    let account = WalletSeed::from_words(&words).unwrap().rescue_account(0);
    assert_eq!(*account.address(), account_address(SCHEME_RESCUE_KEY, account.public_key()));
    let direct = account.address().iter().fold(String::from("0x"), |mut out, byte| {
        out.push_str(&format!("{byte:02x}"));
        out
    });
    assert_eq!(address, direct);
}

#[test]
fn account_zero_address_test_words_in_the_app() {
    let quoted = format!("'{}'", counting_words());
    assert!(
        APP_TEST_WORDS.contains(&quoted),
        "modules/ghost-core/test-words.ts must hold the words of the counting-bytes test seed"
    );
}

#[test]
fn account_zero_address_differs_for_other_words() {
    let mut other = COUNTING;
    other[31] = 0xff;
    let words = WalletSeed::from_bytes(other).to_words().as_str().to_owned();
    assert_ne!(derive_address(words).unwrap(), EXPECTED_ADDRESS);
}

#[test]
fn account_zero_address_rejects_invalid_words() {
    let words = counting_words();
    let short: Vec<&str> = words.split(' ').take(23).collect();
    let error = derive_address(short.join(" ")).unwrap_err();
    let WordsError::Invalid { reason } = &error;
    assert!(!reason.is_empty());
    // The error never repeats the words.
    assert!(!error.to_string().contains(&short[..3].join(" ")));
}
