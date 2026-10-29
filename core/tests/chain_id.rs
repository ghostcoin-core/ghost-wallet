//! The chains the core signs and proves for: the local test chain of dev
//! builds (6777971) and the Ghost public test network of release builds
//! (6777972). The app passes its build's chain; any other is refused. The
//! test-words send of the benchmark stays on the local test chain.

use ghost_client::account::{AccountTxError, WalletSeed, verify_envelope};
use ghost_client::{KeyFormat, PhantomKey};
use ghost_wallet_core::{
    AccountSend, COMMIT_ENTRY, PUBLIC_TEST_CHAIN_ID, RESCUE_TRANSFER_GAS, SendError, TEST_CHAIN_ID, TestSend,
    VANISH_GAS_LIMIT, VanishError, VanishSend, WALLET_CHAIN_IDS, forget_phantom_key, is_wallet_chain, prepare_vanish,
    sign_send_with, sign_test_send_with, sign_vanish_with, test_chain_id, vanish_commit_with,
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
const GENESIS: [u8; 32] = [0x47; 32];
const RECIPIENT: [u8; 20] = [0xac; 20];
const ONE_GHOST: u128 = 1_000_000_000_000_000_000;
/// Chains next to the two test chains, and mainnet-like ids: all refused.
const OTHER_CHAINS: [u64; 5] = [0, 1, 6_777_970, 6_777_973, 1234];

fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

fn seed() -> WalletSeed {
    WalletSeed::from_bytes(COUNTING)
}

fn account_send(chain_id: u64) -> AccountSend {
    AccountSend {
        chain_id,
        genesis_hash: GENESIS.to_vec(),
        nonce: 3,
        recipient: RECIPIENT.to_vec(),
        amount_wei: ONE_GHOST.to_string(),
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 3_000_000_000,
        gas_limit: RESCUE_TRANSFER_GAS,
    }
}

fn vanish_send(chain_id: u64, commit_data: Vec<u8>) -> VanishSend {
    VanishSend {
        chain_id,
        genesis_hash: GENESIS.to_vec(),
        nonce: 4,
        commit_data,
        amount_wei: ONE_GHOST.to_string(),
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 3_000_000_000,
        gas_limit: VANISH_GAS_LIMIT,
    }
}

#[test]
fn the_dev_and_public_test_chains_have_their_own_ids() {
    assert_eq!(TEST_CHAIN_ID, 6_777_971);
    assert_eq!(PUBLIC_TEST_CHAIN_ID, 6_777_972);
    assert_eq!(WALLET_CHAIN_IDS, [6_777_971, 6_777_972]);
    // The benchmark's test-words send stays on the local test chain.
    assert_eq!(test_chain_id(), 6_777_971);
    assert!(is_wallet_chain(TEST_CHAIN_ID));
    assert!(is_wallet_chain(PUBLIC_TEST_CHAIN_ID));
    for chain_id in OTHER_CHAINS {
        assert!(!is_wallet_chain(chain_id), "{chain_id}");
    }
}

#[test]
fn a_send_is_signed_for_the_chain_the_app_passes() {
    for chain_id in WALLET_CHAIN_IDS {
        let signed = sign_send_with(&seed(), 0, &account_send(chain_id), &mut rng(1)).expect("the send signs");
        let verified = verify_envelope(&signed.envelope, chain_id, &GENESIS).expect("the envelope verifies");
        assert_eq!(verified.tx.chain_id, chain_id);
        assert_eq!(verified.tx.to, Some(RECIPIENT));
        // Signed for that chain only: the other test chain refuses it.
        let other = if chain_id == TEST_CHAIN_ID { PUBLIC_TEST_CHAIN_ID } else { TEST_CHAIN_ID };
        assert_eq!(verify_envelope(&signed.envelope, other, &GENESIS).unwrap_err(), AccountTxError::ChainId);
    }
}

#[test]
fn a_send_on_any_other_chain_is_refused() {
    for chain_id in OTHER_CHAINS {
        let error = sign_send_with(&seed(), 0, &account_send(chain_id), &mut rng(1)).unwrap_err();
        assert_eq!(error, SendError::WrongChain { expected: TEST_CHAIN_ID, found: chain_id });
    }
}

#[test]
fn a_test_words_send_stays_on_the_local_test_chain() {
    let words = seed().to_words().as_str().to_owned();
    let send = TestSend {
        chain_id: PUBLIC_TEST_CHAIN_ID,
        genesis_hash: GENESIS.to_vec(),
        nonce: 0,
        recipient: RECIPIENT.to_vec(),
        value: 1,
        max_priority_fee_per_gas: 1,
        max_fee_per_gas: 2,
        gas_limit: RESCUE_TRANSFER_GAS,
    };
    let error = sign_test_send_with(&words, 0, &send, &mut rng(2)).unwrap_err();
    assert_eq!(error, SendError::WrongChain { expected: TEST_CHAIN_ID, found: PUBLIC_TEST_CHAIN_ID });
    let local = TestSend { chain_id: TEST_CHAIN_ID, ..send };
    assert!(sign_test_send_with(&words, 0, &local, &mut rng(2)).is_ok());
}

#[test]
fn a_vanish_is_signed_for_the_public_test_network() {
    let key = PhantomKey::generate(KeyFormat::Words, &mut rng(5));
    let commit = vanish_commit_with(&key, PUBLIC_TEST_CHAIN_ID, ONE_GHOST, &mut rng(6)).unwrap();
    let send = vanish_send(PUBLIC_TEST_CHAIN_ID, commit.commit_data.clone());
    let signed = sign_vanish_with(&seed(), 0, &send, &mut rng(7)).expect("the Vanish signs");
    let verified = verify_envelope(&signed.envelope, PUBLIC_TEST_CHAIN_ID, &GENESIS).expect("Ghost accepts the Vanish");
    assert_eq!(verified.tx.chain_id, PUBLIC_TEST_CHAIN_ID);
    assert_eq!(verified.tx.to, Some(COMMIT_ENTRY));
    assert_eq!(verified.tx.data, commit.commit_data);

    for chain_id in OTHER_CHAINS {
        let error = sign_vanish_with(&seed(), 0, &vanish_send(chain_id, commit.commit_data.clone()), &mut rng(7));
        assert_eq!(error.unwrap_err(), VanishError::WrongChain { expected: TEST_CHAIN_ID, found: chain_id });
    }
}

#[test]
fn a_vanish_is_prepared_for_either_test_chain_only() {
    for chain_id in WALLET_CHAIN_IDS {
        assert!(prepare_vanish(chain_id, ONE_GHOST.to_string()).is_ok(), "{chain_id}");
        forget_phantom_key();
    }
    for chain_id in OTHER_CHAINS {
        let error = prepare_vanish(chain_id, ONE_GHOST.to_string()).unwrap_err();
        assert_eq!(error, VanishError::WrongChain { expected: TEST_CHAIN_ID, found: chain_id });
    }
}
