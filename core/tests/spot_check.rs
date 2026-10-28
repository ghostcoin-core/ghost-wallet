//! The spot check of `spot_check`: one header's proof of work, checked under
//! a fresh RandomX cache against a minimum difficulty.
//!
//! The header is the sealed example of Ghost's own seal tests
//! (`client/tests/seal_check.rs`, spec 08): spec 05's block one example at
//! test difficulty 256 with a zero mix digest and nonce 109, sealed under the
//! hash of spec 05's genesis example as the key. Each check builds a 256 MiB
//! RandomX cache, so the tests run one at a time.

use std::sync::{Mutex, MutexGuard};

use ghost_client::seal::header_fields;
use ghost_wallet_core::{SpotCheckError, SpotCheckKey, spot_check_header, spot_check_seed_height};

static ONE_CACHE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn one_cache() -> MutexGuard<'static, ()> {
    ONE_CACHE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner())
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

/// A test-side RLP encoder, written apart from the client's decoder.
fn int(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    bytes[first..].to_vec()
}

fn rlp_length(len: usize, base: u8) -> Vec<u8> {
    if len < 56 {
        return vec![base + len as u8];
    }
    let digits = int(len as u64);
    let mut out = vec![base + 55 + digits.len() as u8];
    out.extend(digits);
    out
}

fn rlp_list(fields: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::new();
    for field in fields {
        if field.len() == 1 && field[0] < 0x80 {
            payload.push(field[0]);
        } else {
            payload.extend(rlp_length(field.len(), 0x80));
            payload.extend(field);
        }
    }
    let mut out = rlp_length(payload.len(), 0xc0);
    out.extend(payload);
    out
}

/// The hash of spec 05's genesis example: the sealed header's key block.
const GENESIS_HASH: &str = "039d14f59db29e2e76c8ed76f90b70de42e48f8a67dba060b363501af50e3ba4";
/// The hash of spec 05's block one example, used as a wrong key.
const BLOCK_ONE_HASH: &str = "81ca961404b518ee3ded78ebee1c4e23eba18b7c86515b6471e970cfed8538f4";
/// The sealed example's difficulty and nonce.
const SEALED_DIFFICULTY: u64 = 256;
const SEALED_NONCE: u64 = 109;
const COIN_TREE_ROOT: usize = 16;
const MIX_DIGEST: usize = 13;

/// Spec 05's `header-block-one-example` fields, sealed at difficulty 256.
fn sealed_fields() -> Vec<Vec<u8>> {
    let mut coinbase = vec![0u8; 20];
    coinbase[18..].copy_from_slice(&[0x04, 0xd2]);
    vec![
        unhex(GENESIS_HASH),
        unhex("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
        coinbase,
        vec![0x11; 32],
        vec![0x22; 32],
        vec![0x33; 32],
        vec![0; 256],
        int(SEALED_DIFFICULTY),
        int(1),
        int(30_000_000),
        int(126_000),
        int(1_798_767_630),
        vec![],
        vec![0; 32],
        SEALED_NONCE.to_be_bytes().to_vec(),
        int(875_000_000),
        unhex("142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5"),
        unhex("dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a"),
        unhex("f121b372119409a7d6fda684a14ab815c7ef9a07ba48f50ff59ea5fc62d36e4f"),
    ]
}

fn sealed_header() -> Vec<u8> {
    rlp_list(&sealed_fields())
}

fn key() -> Vec<u8> {
    unhex(GENESIS_HASH)
}

#[test]
fn good_header_passes() {
    let _one = one_cache();
    let header = sealed_header();
    let report = spot_check_header(header.clone(), key(), int(SEALED_DIFFICULTY)).unwrap();
    assert!(report.passed, "{:?}", report.failure);
    assert_eq!(report.failure, None);
    assert_eq!(report.height, 1);
    assert_eq!(report.hash, header_fields(&header).unwrap().hash.to_vec());
    assert_eq!(report.difficulty, vec![1, 0]);
    // Both steps ran and were timed: the cache build is the long one.
    assert!(report.cache_seconds > 0.0);
    assert!(report.hash_seconds > 0.0);

    // A lower minimum, and one written with leading zero bytes, pass too.
    let lower = spot_check_header(header.clone(), key(), vec![1]).unwrap();
    assert!(lower.passed);
    let padded = spot_check_header(header, key(), vec![0, 0, 1, 0]).unwrap();
    assert!(padded.passed);
}

#[test]
fn broken_seal_fails() {
    let _one = one_cache();
    // One bit of the coin tree root: the seal no longer meets its target.
    let mut fields = sealed_fields();
    fields[COIN_TREE_ROOT][31] ^= 0x01;
    let report = spot_check_header(rlp_list(&fields), key(), vec![1]).unwrap();
    assert!(!report.passed);
    assert_eq!(report.failure.as_deref(), Some("the seal's hash is above the target"));
    assert!(report.hash_seconds > 0.0);

    // The right header under another key block fails the same way.
    let wrong_key = spot_check_header(sealed_header(), unhex(BLOCK_ONE_HASH), vec![1]).unwrap();
    assert!(!wrong_key.passed);
    assert_eq!(wrong_key.failure.as_deref(), Some("the seal's hash is above the target"));

    // A non-zero mix digest is not a valid seal.
    let mut mixed = sealed_fields();
    mixed[MIX_DIGEST] = vec![0x44; 32];
    let report = spot_check_header(rlp_list(&mixed), key(), vec![1]).unwrap();
    assert!(!report.passed);
    assert_eq!(report.failure.as_deref(), Some("the header's mix digest is not zero"));
}

#[test]
fn header_under_the_minimum_fails() {
    let _one = one_cache();
    // The seal is good at the header's own difficulty, 256, but the minimum is higher.
    for minimum in [int(SEALED_DIFFICULTY + 1), int(1 << 20), vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0]] {
        let report = spot_check_header(sealed_header(), key(), minimum.clone()).unwrap();
        assert!(!report.passed, "minimum {minimum:?}");
        assert_eq!(
            report.failure.as_deref(),
            Some("the header's difficulty is below the minimum"),
            "minimum {minimum:?}"
        );
        assert_eq!(report.difficulty, vec![1, 0]);
    }
}

#[test]
fn unusable_input_is_refused_before_any_cache() {
    // None of these builds a cache, so they need no turn.
    let refused = |header: Vec<u8>, key: Vec<u8>, minimum: Vec<u8>| {
        matches!(spot_check_header(header, key, minimum), Err(SpotCheckError::Input { .. }))
    };
    assert!(refused(sealed_header(), key(), vec![]));
    assert!(refused(sealed_header(), key(), vec![0, 0]));
    assert!(refused(sealed_header(), key(), vec![1; 33]));
    let mut trailing = sealed_header();
    trailing.push(0);
    assert!(refused(trailing, key(), vec![1]));
    let mut short = key();
    short.pop();
    assert!(refused(sealed_header(), short, vec![1]));
}

#[test]
fn held_key_checks_until_released() {
    let _one = one_cache();
    let held = SpotCheckKey::new(key()).unwrap();
    assert!(held.is_held());
    assert!(held.cache_seconds() > 0.0);
    let report = held.check(sealed_header(), int(SEALED_DIFFICULTY)).unwrap();
    assert!(report.passed);
    assert_eq!(report.cache_seconds, held.cache_seconds());

    assert!(held.release());
    assert!(!held.is_held());
    assert!(!held.release());
    assert_eq!(held.check(sealed_header(), vec![1]), Err(SpotCheckError::Released));
}

#[test]
fn seed_height_follows_ghost() {
    assert_eq!(spot_check_seed_height(1), 0);
    assert_eq!(spot_check_seed_height(8448), 0);
    assert_eq!(spot_check_seed_height(8449), 8192);
    assert_eq!(spot_check_seed_height(16_641), 16_384);
}
