//! A send from the saved account, signed in the native core: a plain account
//! transaction (`0x52`) of the rescue-key scheme `0x0003`, ML-DSA-44, checked
//! with Ghost's own envelope verifier.

use ghost_client::account::{SCHEME_RESCUE_KEY, WalletSeed, verify_envelope};
use ghost_wallet_core::{
    AccountSend, RESCUE_TRANSFER_GAS, SendError, TEST_CHAIN_ID, sign_send, sign_send_with, transaction_hash,
};
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

/// Account 3 of the test words.
const RECIPIENT: [u8; 20] = [
    0xac, 0xf1, 0xb0, 0x34, 0x42, 0x24, 0x4b, 0xc1, 0x49, 0x82, 0xf1, 0xaa, 0xe0, 0xa1, 0x1d, 0x76, 0xe1, 0x85, 0x0e,
    0x09,
];
const GENESIS: [u8; 32] = [0x47; 32];

fn send() -> AccountSend {
    AccountSend {
        chain_id: TEST_CHAIN_ID,
        genesis_hash: GENESIS.to_vec(),
        nonce: 7,
        recipient: RECIPIENT.to_vec(),
        // 25 GHOST: more than a u64 of wei holds.
        amount_wei: "25000000000000000000".to_owned(),
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 3_000_000_000,
        gas_limit: RESCUE_TRANSFER_GAS,
    }
}

fn seed() -> WalletSeed {
    WalletSeed::from_bytes(COUNTING)
}

#[test]
fn account_zero_signs_a_plain_send_ghost_accepts() {
    let signed = sign_send_with(&seed(), 0, &send(), &mut StdRng::seed_from_u64(1)).expect("the send signs");
    assert_eq!(signed.envelope[0], 0x52);
    assert_eq!(signed.transaction_hash, transaction_hash(signed.envelope.clone()));
    let verified = verify_envelope(&signed.envelope, TEST_CHAIN_ID, &GENESIS).expect("the envelope verifies");
    assert_eq!(verified.scheme, SCHEME_RESCUE_KEY);
    assert_eq!(verified.sender.to_vec(), signed.sender);
    assert_eq!(&signed.sender[..], seed().rescue_account(0).address());
    let tx = verified.tx;
    assert_eq!(tx.nonce, 7);
    assert_eq!(tx.to, Some(RECIPIENT));
    assert_eq!(tx.value, 25_000_000_000_000_000_000);
    assert_eq!(tx.gas_limit, RESCUE_TRANSFER_GAS);
    assert!(tx.data.is_empty());
}

#[test]
fn amounts_that_are_not_more_than_nothing_in_wei_are_refused() {
    for amount in ["0", "", "1.5", "-1", "0x10", "1 000", "999999999999999999999999999999999999999999"] {
        let case = AccountSend { amount_wei: amount.to_owned(), ..send() };
        let error = sign_send_with(&seed(), 0, &case, &mut StdRng::seed_from_u64(1)).unwrap_err();
        assert!(matches!(error, SendError::Malformed { .. }), "{amount:?}: {error}");
    }
}

#[test]
fn only_the_test_chain_and_well_formed_sends_are_signed() {
    let error = sign_send_with(&seed(), 0, &AccountSend { chain_id: 1, ..send() }, &mut StdRng::seed_from_u64(1));
    assert_eq!(error.unwrap_err(), SendError::WrongChain { expected: TEST_CHAIN_ID, found: 1 });
    for case in [
        AccountSend { recipient: vec![0xac; 19], ..send() },
        AccountSend { genesis_hash: vec![0x47; 31], ..send() },
        AccountSend { gas_limit: RESCUE_TRANSFER_GAS - 1, ..send() },
        AccountSend { max_fee_per_gas: 1, ..send() },
    ] {
        let error = sign_send_with(&seed(), 0, &case, &mut StdRng::seed_from_u64(1)).unwrap_err();
        assert!(matches!(error, SendError::Malformed { .. }), "{case:?}: {error}");
    }
}

#[test]
fn with_no_saved_account_nothing_is_signed() {
    // Off the phone the core keeps accounts in memory, and none is saved here.
    let error = sign_send(send()).unwrap_err();
    assert!(matches!(error, SendError::Account { .. }), "{error}");
}

#[test]
fn the_signed_send_shows_no_signature_when_formatted() {
    let signed = sign_send_with(&seed(), 0, &send(), &mut StdRng::seed_from_u64(1)).unwrap();
    let text = format!("{signed:?}");
    assert!(text.contains("envelope_len"));
    let tail: String = signed.envelope[signed.envelope.len() - 16..].iter().map(|b| format!("{b:02x}")).collect();
    assert!(!text.contains(&tail));
}
