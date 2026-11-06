//! TEST ONLY: release keys for the tests, each made from a fixed one-byte
//! pattern in this file. None of them is the release key: the real release
//! key's private half is held offline and is never in the repository, an
//! enclave image or any other fixture, and the image trusts only the public
//! key compiled into it (`RELEASE_KEY_HEX`), never one of these.
#![allow(dead_code)]

use ghost_seal::measurements::{MeasurementList, RELEASE_CONTEXT, ReleaseKey};
use ml_dsa::{ExpandedSigningKey, MlDsa65, Seed};

/// The pattern of the tests' stand-in for the release key.
pub const TEST_ONLY_RELEASE_PATTERN: u8 = 0x5e;
/// The pattern of a key that is not the release key (an attacker's).
pub const TEST_ONLY_OTHER_PATTERN: u8 = 0x6f;

/// A test-only ML-DSA-65 signing key that stands in for the release key.
pub struct TestOnlyReleaseKey {
    key: ExpandedSigningKey<MlDsa65>,
}

impl TestOnlyReleaseKey {
    /// The tests' stand-in for the release key.
    pub fn new() -> TestOnlyReleaseKey {
        TestOnlyReleaseKey::from_pattern(TEST_ONLY_RELEASE_PATTERN)
    }

    /// A key that is not the stand-in release key.
    pub fn other() -> TestOnlyReleaseKey {
        TestOnlyReleaseKey::from_pattern(TEST_ONLY_OTHER_PATTERN)
    }

    fn from_pattern(pattern: u8) -> TestOnlyReleaseKey {
        TestOnlyReleaseKey { key: ExpandedSigningKey::<MlDsa65>::from_seed(&Seed::from([pattern; 32])) }
    }

    /// Its public half, as an enclave would hold it.
    pub fn release_key(&self) -> ReleaseKey {
        ReleaseKey::from_bytes(&self.key.verifying_key().encode()).expect("an ML-DSA-65 verifying key")
    }

    /// The signature over `list_text`'s builds, as lowercase hex.
    pub fn signature_hex(&self, list_text: &str) -> String {
        let list = MeasurementList::parse(list_text).expect("the list to sign parses");
        let signature = self.key.sign_deterministic(&list.signing_message(), RELEASE_CONTEXT).expect("signs");
        signature.encode().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `list_text` with a `"signature"` field over its builds.
    pub fn sign(&self, list_text: &str) -> String {
        with_signature(list_text, &self.signature_hex(list_text))
    }
}

/// `list_text` (a JSON object) with `"signature": signature_hex` added.
pub fn with_signature(list_text: &str, signature_hex: &str) -> String {
    let body = list_text.trim_start().strip_prefix('{').expect("a JSON object");
    format!("{{\"signature\": \"{signature_hex}\", {body}")
}
