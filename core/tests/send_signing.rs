//! A test-chain send signed in the native core: an account transaction
//! (`0x52`) of the rescue-key scheme `0x0003` from account 0 of Ghost's
//! counting-bytes test seed, checked with Ghost's own envelope verifier.

use ghost_client::account::{
    ACCOUNT_TX_TYPE, AccountTxError, RESCUE_PUBLIC_KEY_BYTES, SCHEME_RESCUE_KEY, SIGNATURE_BYTES, WalletSeed,
    verify_envelope,
};
use ghost_wallet_core::{
    RESCUE_TRANSFER_GAS, SendError, SignedTestSend, TEST_CHAIN_ID, TestSend, sign_test_send, sign_test_send_with,
    test_send_sender, transaction_hash,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use tiny_keccak::{Hasher, Keccak};

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

const SENDER: &str = "0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd";
/// Account 3 of the test words, funded on the test chain like account 0.
const RECIPIENT: [u8; 20] = [
    0xac, 0xf1, 0xb0, 0x34, 0x42, 0x24, 0x4b, 0xc1, 0x49, 0x82, 0xf1, 0xaa, 0xe0, 0xa1, 0x1d, 0x76, 0xe1, 0x85, 0x0e,
    0x09,
];
/// A stand-in genesis hash for the tests.
const GENESIS: [u8; 32] = [0x47; 32];

fn test_words() -> String {
    WalletSeed::from_bytes(COUNTING).to_words().as_str().to_owned()
}

fn send() -> TestSend {
    TestSend {
        chain_id: TEST_CHAIN_ID,
        genesis_hash: GENESIS.to_vec(),
        nonce: 5,
        recipient: RECIPIENT.to_vec(),
        value: 1_000_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 3_000_000_000,
        gas_limit: RESCUE_TRANSFER_GAS,
    }
}

fn sign() -> SignedTestSend {
    sign_test_send(test_words(), 0, send()).expect("the test send signs")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// The last three RLP items of the envelope: scheme, public key, signature.
/// Both long items have a two-byte length (`0xb9`).
fn tail(envelope: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let sig_at = envelope.len() - SIGNATURE_BYTES;
    assert_eq!(&envelope[sig_at - 3..sig_at], &[0xb9, 0x09, 0x74], "a 2,420-byte signature item");
    let key_at = sig_at - 3 - RESCUE_PUBLIC_KEY_BYTES;
    assert_eq!(&envelope[key_at - 3..key_at], &[0xb9, 0x05, 0x40], "a 1,344-byte public key item");
    let scheme_at = key_at - 3 - 2;
    assert_eq!(envelope[scheme_at - 1], 0x82, "a 2-byte scheme item");
    (&envelope[scheme_at..scheme_at + 2], &envelope[key_at..key_at + RESCUE_PUBLIC_KEY_BYTES], &envelope[sig_at..])
}

#[test]
fn the_plain_transfer_gas_is_84256() {
    assert_eq!(RESCUE_TRANSFER_GAS, 84_256);
}

#[test]
fn account_zero_signs_a_rescue_key_account_transaction() {
    let signed = sign();
    assert_eq!(signed.envelope[0], 0x52);
    assert_eq!(signed.envelope[0], ACCOUNT_TX_TYPE);
    let (scheme, key, signature) = tail(&signed.envelope);
    assert_eq!(scheme, &[0x00, 0x03]);
    assert_eq!(key.len(), 1_344);
    assert_eq!(signature.len(), 2_420);
    let account = WalletSeed::from_bytes(COUNTING).rescue_account(0);
    assert_eq!(key, account.public_key().as_slice(), "account 0's 0x0003 public key");
    // About 3.8 KB in all.
    assert!((3_700..3_900).contains(&signed.envelope.len()), "{}", signed.envelope.len());
}

#[test]
fn the_sender_is_account_zero() {
    let signed = sign();
    assert_eq!(format!("0x{}", hex(&signed.sender)), SENDER);
    assert_eq!(test_send_sender(test_words(), 0).unwrap(), SENDER);
    let other = sign_test_send(test_words(), 3, send()).unwrap();
    assert_eq!(other.sender, RECIPIENT.to_vec(), "account 3 is the recipient");
}

#[test]
fn ghost_accepts_the_envelope_for_the_test_chain() {
    let signed = sign();
    let verified = verify_envelope(&signed.envelope, 6_777_971, &GENESIS).expect("the envelope verifies");
    assert_eq!(verified.scheme, SCHEME_RESCUE_KEY);
    assert_eq!(verified.sender.to_vec(), signed.sender);
    assert_eq!(verified.hash.to_vec(), signed.transaction_hash);
    let tx = verified.tx;
    assert_eq!(tx.chain_id, 6_777_971);
    assert_eq!(tx.nonce, 5);
    assert_eq!(tx.to, Some(RECIPIENT));
    assert_eq!(tx.value, 1_000_000_000_000);
    assert_eq!(tx.max_priority_fee_per_gas, 1_000_000_000);
    assert_eq!(tx.max_fee_per_gas, 3_000_000_000);
    assert_eq!(tx.gas_limit, 84_256);
    assert!(tx.data.is_empty() && tx.access_list.is_empty());
}

#[test]
fn the_hash_is_keccak_of_the_envelope() {
    let signed = sign();
    assert_eq!(signed.transaction_hash, keccak256(&signed.envelope).to_vec());
    assert_eq!(signed.transaction_hash, transaction_hash(signed.envelope.clone()));
}

#[test]
fn two_signings_of_one_transaction_differ() {
    let first = sign();
    let second = sign();
    assert_ne!(first.envelope, second.envelope, "hedged: fresh randomness each time");
    assert_ne!(first.transaction_hash, second.transaction_hash);
    assert_eq!(first.sender, second.sender);
    for signed in [&first, &second] {
        verify_envelope(&signed.envelope, TEST_CHAIN_ID, &GENESIS).expect("both verify");
    }
    // Only the signature differs.
    let (a, b) = (tail(&first.envelope), tail(&second.envelope));
    assert_eq!(a.0, b.0);
    assert_eq!(a.1, b.1);
    assert_ne!(a.2, b.2);
    assert_eq!(
        first.envelope[..first.envelope.len() - SIGNATURE_BYTES],
        second.envelope[..second.envelope.len() - SIGNATURE_BYTES]
    );
}

#[test]
fn the_caller_generator_drives_the_signature() {
    let words = test_words();
    let with = |seed: u64| sign_test_send_with(&words, 0, &send(), &mut StdRng::seed_from_u64(seed)).unwrap();
    assert_eq!(with(1), with(1), "the same generator state signs the same bytes");
    assert_ne!(with(1).envelope, with(2).envelope);
    verify_envelope(&with(2).envelope, TEST_CHAIN_ID, &GENESIS).unwrap();
}

#[test]
fn a_wrong_chain_id_or_genesis_hash_fails_verification() {
    let signed = sign();
    assert_eq!(verify_envelope(&signed.envelope, 1, &GENESIS).unwrap_err(), AccountTxError::ChainId);
    assert_eq!(verify_envelope(&signed.envelope, TEST_CHAIN_ID + 1, &GENESIS).unwrap_err(), AccountTxError::ChainId);
    let mut other = GENESIS;
    other[0] ^= 1;
    assert_eq!(verify_envelope(&signed.envelope, TEST_CHAIN_ID, &other).unwrap_err(), AccountTxError::Signature);
    // A changed byte in the signed fields breaks the signature.
    let mut changed = signed.envelope.clone();
    // The value, 10^12 wei: `0x85 e8d4a51000`.
    let value_at = changed.windows(6).position(|w| w == [0x85, 0xe8, 0xd4, 0xa5, 0x10, 0x00]).unwrap();
    changed[value_at + 1] ^= 1;
    assert!(verify_envelope(&changed, TEST_CHAIN_ID, &GENESIS).is_err());
}

#[test]
fn only_the_test_chain_is_signed_for() {
    for chain_id in [1, 6_777_970, 6_777_972] {
        let error = sign_test_send(test_words(), 0, TestSend { chain_id, ..send() }).unwrap_err();
        assert_eq!(error, SendError::WrongChain { expected: 6_777_971, found: chain_id });
    }
}

#[test]
fn malformed_inputs_are_refused_with_a_plain_error() {
    let cases = [
        TestSend { genesis_hash: vec![0x47; 31], ..send() },
        TestSend { genesis_hash: Vec::new(), ..send() },
        TestSend { recipient: vec![0xac; 19], ..send() },
        TestSend { recipient: vec![0xac; 32], ..send() },
        TestSend { gas_limit: 21_000, ..send() },
        TestSend { gas_limit: RESCUE_TRANSFER_GAS - 1, ..send() },
        TestSend { max_fee_per_gas: 999_999_999, ..send() },
    ];
    for case in cases {
        let error = sign_test_send(test_words(), 0, case.clone()).unwrap_err();
        assert!(matches!(error, SendError::Malformed { .. }), "{case:?}: {error}");
    }
    let words = test_words();
    let short: Vec<&str> = words.split(' ').take(23).collect();
    let error = sign_test_send(short.join(" "), 0, send()).unwrap_err();
    assert!(matches!(error, SendError::Words { .. }), "{error}");
    assert!(test_send_sender(short.join(" "), 0).is_err());
}

#[test]
fn nothing_formatted_holds_the_words_key_or_signature() {
    let words = test_words();
    let signed = sign();
    let (_, key, signature) = tail(&signed.envelope);
    let account = WalletSeed::from_bytes(COUNTING).rescue_account(0);
    let secrets: Vec<String> = vec![
        hex(&key[..16]),
        hex(&key[RESCUE_PUBLIC_KEY_BYTES - 16..]),
        hex(&account.public_key()[..16]),
        hex(&signature[..16]),
        hex(&signature[SIGNATURE_BYTES - 16..]),
        hex(&COUNTING[..16]),
        hex(&COUNTING[16..]),
    ];
    let first_words: Vec<&str> = words.split(' ').take(3).collect();

    let debug = format!("{signed:?} {signed:#?}");
    assert!(debug.contains("envelope_len"));
    assert!(debug.contains(&hex(&signed.transaction_hash)), "the hash is fine to show");
    let mut texts = vec![debug];
    let short: Vec<&str> = words.split(' ').take(23).collect();
    let mut wrong = words.clone();
    wrong.push_str(" abandon");
    for bad_words in [short.join(" "), wrong, words.replacen(first_words[0], "zzzz", 1)] {
        let error = sign_test_send(bad_words.clone(), 0, send()).unwrap_err();
        texts.push(format!("{error} {error:?}"));
        let error = test_send_sender(bad_words, 0).unwrap_err();
        texts.push(format!("{error} {error:?}"));
    }
    for case in [TestSend { chain_id: 1, ..send() }, TestSend { gas_limit: 0, ..send() }] {
        let error = sign_test_send(words.clone(), 0, case).unwrap_err();
        texts.push(format!("{error} {error:?}"));
    }
    for text in &texts {
        assert!(!text.contains(&first_words.join(" ")), "no words in {text}");
        for word in words.split(' ').filter(|word| word.len() > 4) {
            assert!(!text.split(|c: char| !c.is_ascii_alphabetic()).any(|t| t == word), "no word {word} in {text}");
        }
        for secret in &secrets {
            assert!(!text.contains(secret.as_str()), "no key, seed or signature bytes in {text}");
        }
        assert!(!text.contains(&format!("{:?}", &signature[..8])), "no signature bytes in {text}");
        assert!(!text.contains(&format!("{:?}", &key[..8])), "no key bytes in {text}");
    }
}
