//! The attestation phones get: proof that the Seal's answer-signing key and
//! its ML-KEM key belong to an enclave running a published build.
//!
//! Layout: `GPA1` || document length (u32, big endian) || Nitro document ||
//! the Seal's ML-DSA-65 verifying key ([`ANSWER_KEY_BYTES`]) || its
//! ML-KEM-768 encapsulation key ([`KEM_KEY_BYTES`]). The document's
//! `user_data` is SHA3-256([`PHONE_ATTESTATION_DOMAIN`] || verifying key ||
//! encapsulation key || the phone's 32-byte challenge), so the document is
//! fresh for this challenge and binds both keys to the enclave's PCRs.
//!
//! [`verify`] is the reference check (the app's own check, in native code,
//! is a later step): the document against the pinned root, its PCRs against
//! the pinned list, the binding, and both keys well formed.

use core::fmt;

use ml_dsa::{EncodedVerifyingKey, MlDsa65};
use ml_kem::{EncapsulationKey, MlKem768, TryKeyInit};

use crate::answer::AnswerSigner;
use crate::attestation::{AttestationError, AttestationRejected, AttestationSource, AttestationVerifier, AttestedDocument};
use crate::measurements::{Build, MeasurementList, MeasurementRefused};
use crate::primitives::{ct_eq, sha3_256};
use crate::release::PHONE_KEY_BYTES;
use crate::secrets::MasterKey;

/// The domain of the document's user data.
pub const PHONE_ATTESTATION_DOMAIN: &[u8] = b"ghost-seal/v1/phone-attestation";
/// An encoded ML-DSA-65 verifying key's length.
pub const ANSWER_KEY_BYTES: usize = 1952;
/// An ML-KEM-768 encapsulation key's length.
pub const KEM_KEY_BYTES: usize = PHONE_KEY_BYTES;
/// The phone's challenge length.
pub const CHALLENGE_BYTES: usize = 32;

const MAGIC: &[u8; 4] = b"GPA1";

/// The `user_data` a phone attestation's document carries.
pub fn binding(answer_key: &[u8], kem_key: &[u8], challenge: &[u8; CHALLENGE_BYTES]) -> [u8; 32] {
    sha3_256(&[PHONE_ATTESTATION_DOMAIN, answer_key, kem_key, challenge])
}

/// The Seal's encoded answer-signing key (ML-DSA-65), derived from M as
/// every answer's signature is.
pub fn answer_key(master: &MasterKey) -> Vec<u8> {
    AnswerSigner::derive(master).verifying_key()
}

/// Why no phone attestation could be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhoneAttestationError {
    /// A key of the wrong length.
    BadKey,
    /// The NSM gave no document.
    Attestation(AttestationError),
}

impl fmt::Display for PhoneAttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PhoneAttestationError::BadKey => f.write_str("a key of the wrong length"),
            PhoneAttestationError::Attestation(why) => write!(f, "phone attestation: {why}"),
        }
    }
}

impl std::error::Error for PhoneAttestationError {}

/// Makes the attestation for one phone `challenge`.
pub fn make(
    source: &mut dyn AttestationSource,
    answer_key: &[u8],
    kem_key: &[u8],
    challenge: &[u8; CHALLENGE_BYTES],
) -> Result<Vec<u8>, PhoneAttestationError> {
    if answer_key.len() != ANSWER_KEY_BYTES || kem_key.len() != KEM_KEY_BYTES {
        return Err(PhoneAttestationError::BadKey);
    }
    let document =
        source.attest(&binding(answer_key, kem_key, challenge), &[]).map_err(PhoneAttestationError::Attestation)?;
    let mut out = Vec::with_capacity(8 + document.len() + ANSWER_KEY_BYTES + KEM_KEY_BYTES);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(document.len() as u32).to_be_bytes());
    out.extend_from_slice(&document);
    out.extend_from_slice(answer_key);
    out.extend_from_slice(kem_key);
    Ok(out)
}

/// A Seal a phone may talk to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSeal {
    /// The ML-DSA-65 key the Seal's answers verify under.
    pub answer_key: Vec<u8>,
    /// The ML-KEM-768 key to encrypt to the Seal.
    pub kem_key: Vec<u8>,
    /// The pinned build it runs.
    pub build: Build,
    /// What its document says.
    pub document: AttestedDocument,
}

/// Why a phone attestation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhoneAttestationRejected {
    /// Not this layout, or a key that does not decode.
    Malformed(&'static str),
    /// The document does not verify.
    Document(AttestationRejected),
    /// The build is not allowed by the pinned list.
    Measurement(MeasurementRefused),
    /// The document does not bind these keys and this challenge.
    Binding,
}

impl fmt::Display for PhoneAttestationRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PhoneAttestationRejected::Malformed(what) => write!(f, "phone attestation: malformed: {what}"),
            PhoneAttestationRejected::Document(why) => write!(f, "phone attestation: {why}"),
            PhoneAttestationRejected::Measurement(why) => write!(f, "phone attestation: {why}"),
            PhoneAttestationRejected::Binding => f.write_str("phone attestation: the document binds other keys or another challenge"),
        }
    }
}

impl std::error::Error for PhoneAttestationRejected {}

/// Checks a phone attestation for `challenge` at `now_unix` against the
/// verifier's root and the pinned `list`.
pub fn verify(
    bytes: &[u8],
    challenge: &[u8; CHALLENGE_BYTES],
    verifier: &dyn AttestationVerifier,
    list: &MeasurementList,
    now_unix: u64,
) -> Result<VerifiedSeal, PhoneAttestationRejected> {
    if bytes.len() < 8 || &bytes[..4] != MAGIC {
        return Err(PhoneAttestationRejected::Malformed("not a phone attestation"));
    }
    let length = u32::from_be_bytes(bytes[4..8].try_into().expect("4 bytes")) as usize;
    if length == 0 || bytes.len() != 8 + length + ANSWER_KEY_BYTES + KEM_KEY_BYTES {
        return Err(PhoneAttestationRejected::Malformed("the length is wrong"));
    }
    let document = &bytes[8..8 + length];
    let answer_key = &bytes[8 + length..8 + length + ANSWER_KEY_BYTES];
    let kem_key = &bytes[8 + length + ANSWER_KEY_BYTES..];

    let attested = verifier.verify(document, now_unix).map_err(PhoneAttestationRejected::Document)?;
    let build = list.check(&attested.pcrs).map_err(PhoneAttestationRejected::Measurement)?.clone();
    let expected = binding(answer_key, kem_key, challenge);
    if !attested.user_data.as_deref().is_some_and(|data| ct_eq(data, &expected)) {
        return Err(PhoneAttestationRejected::Binding);
    }
    EncodedVerifyingKey::<MlDsa65>::try_from(answer_key)
        .map_err(|_| PhoneAttestationRejected::Malformed("not an ML-DSA-65 key"))?;
    <EncapsulationKey<MlKem768> as TryKeyInit>::new_from_slice(kem_key)
        .map_err(|_| PhoneAttestationRejected::Malformed("not an ML-KEM-768 key"))?;
    Ok(VerifiedSeal { answer_key: answer_key.to_vec(), kem_key: kem_key.to_vec(), build, document: attested })
}
