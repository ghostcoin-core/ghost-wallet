//! The attestation phones get: proof that the Seal's answer-signing key, its
//! ML-KEM key and the TLS certificate it serves belong to an enclave running
//! a published build.
//!
//! Layout (`GPA2`): `GPA2` || document length (u32, big endian) || Nitro
//! document || the Seal's ML-DSA-65 verifying key ([`ANSWER_KEY_BYTES`]) ||
//! its ML-KEM-768 encapsulation key ([`KEM_KEY_BYTES`]) || the SHA-256 of the
//! DER of the TLS certificate the enclave serves ([`CERTIFICATE_HASH_BYTES`]).
//! The document's `user_data` is SHA3-256([`PHONE_ATTESTATION_DOMAIN`] ||
//! verifying key || encapsulation key || certificate hash || the phone's
//! 32-byte challenge), so the document is fresh for this challenge and binds
//! both keys and the certificate to the enclave's PCRs.
//!
//! The certificate is made fresh inside the enclave at each start and is
//! trusted on nothing but this binding: a phone accepts a connection only
//! when the hash of the certificate that connection used is the one
//! [`verify`] returns (the app's check). A man in the middle with any other
//! certificate cannot swap the phone key of an Open.
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
pub const PHONE_ATTESTATION_DOMAIN: &[u8] = b"ghost-seal/v2/phone-attestation";
/// An encoded ML-DSA-65 verifying key's length.
pub const ANSWER_KEY_BYTES: usize = 1952;
/// An ML-KEM-768 encapsulation key's length.
pub const KEM_KEY_BYTES: usize = PHONE_KEY_BYTES;
/// The length of the TLS certificate's hash (SHA-256 of its DER).
pub const CERTIFICATE_HASH_BYTES: usize = 32;
/// The phone's challenge length.
pub const CHALLENGE_BYTES: usize = 32;
/// The layout's first four bytes.
pub const MAGIC: &[u8; 4] = b"GPA2";

/// The `user_data` a phone attestation's document carries.
pub fn binding(
    answer_key: &[u8],
    kem_key: &[u8],
    certificate_hash: &[u8; CERTIFICATE_HASH_BYTES],
    challenge: &[u8; CHALLENGE_BYTES],
) -> [u8; 32] {
    sha3_256(&[PHONE_ATTESTATION_DOMAIN, answer_key, kem_key, certificate_hash, challenge])
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

/// Makes the attestation for one phone `challenge`, binding the hash of the
/// TLS certificate the enclave serves.
pub fn make(
    source: &mut dyn AttestationSource,
    answer_key: &[u8],
    kem_key: &[u8],
    certificate_hash: &[u8; CERTIFICATE_HASH_BYTES],
    challenge: &[u8; CHALLENGE_BYTES],
) -> Result<Vec<u8>, PhoneAttestationError> {
    if answer_key.len() != ANSWER_KEY_BYTES || kem_key.len() != KEM_KEY_BYTES {
        return Err(PhoneAttestationError::BadKey);
    }
    let document = source
        .attest(&binding(answer_key, kem_key, certificate_hash, challenge), &[])
        .map_err(PhoneAttestationError::Attestation)?;
    let mut out =
        Vec::with_capacity(8 + document.len() + ANSWER_KEY_BYTES + KEM_KEY_BYTES + CERTIFICATE_HASH_BYTES);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(document.len() as u32).to_be_bytes());
    out.extend_from_slice(&document);
    out.extend_from_slice(answer_key);
    out.extend_from_slice(kem_key);
    out.extend_from_slice(certificate_hash);
    Ok(out)
}

/// A Seal a phone may talk to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSeal {
    /// The ML-DSA-65 key the Seal's answers verify under.
    pub answer_key: Vec<u8>,
    /// The ML-KEM-768 key to encrypt to the Seal.
    pub kem_key: Vec<u8>,
    /// The SHA-256 of the DER of the TLS certificate the Seal serves. A
    /// connection whose certificate has another hash is not this Seal.
    pub certificate_hash: [u8; CERTIFICATE_HASH_BYTES],
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
    /// The document does not bind these keys, this certificate and this
    /// challenge.
    Binding,
    /// The attestation is for another TLS certificate than the one the
    /// connection used.
    Certificate,
}

impl fmt::Display for PhoneAttestationRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PhoneAttestationRejected::Malformed(what) => write!(f, "phone attestation: malformed: {what}"),
            PhoneAttestationRejected::Document(why) => write!(f, "phone attestation: {why}"),
            PhoneAttestationRejected::Measurement(why) => write!(f, "phone attestation: {why}"),
            PhoneAttestationRejected::Binding => {
                f.write_str("phone attestation: the document binds other keys, another certificate or another challenge")
            }
            PhoneAttestationRejected::Certificate => {
                f.write_str("phone attestation: it is for another TLS certificate than this connection's")
            }
        }
    }
}

impl std::error::Error for PhoneAttestationRejected {}

/// Checks a phone attestation for `challenge` at `now_unix` against the
/// verifier's root and the pinned `list`, and that it binds
/// `connection_certificate_hash`: the SHA-256 of the DER of the certificate
/// the TLS connection it came over used. Returns the Seal, with the hash.
pub fn verify(
    bytes: &[u8],
    challenge: &[u8; CHALLENGE_BYTES],
    connection_certificate_hash: &[u8; CERTIFICATE_HASH_BYTES],
    verifier: &dyn AttestationVerifier,
    list: &MeasurementList,
    now_unix: u64,
) -> Result<VerifiedSeal, PhoneAttestationRejected> {
    if bytes.len() < 8 || &bytes[..4] != MAGIC {
        return Err(PhoneAttestationRejected::Malformed("not a phone attestation"));
    }
    let length = u32::from_be_bytes(bytes[4..8].try_into().expect("4 bytes")) as usize;
    if length == 0 || bytes.len() != 8 + length + ANSWER_KEY_BYTES + KEM_KEY_BYTES + CERTIFICATE_HASH_BYTES {
        return Err(PhoneAttestationRejected::Malformed("the length is wrong"));
    }
    let document = &bytes[8..8 + length];
    let keys_at = 8 + length;
    let answer_key = &bytes[keys_at..keys_at + ANSWER_KEY_BYTES];
    let kem_key = &bytes[keys_at + ANSWER_KEY_BYTES..keys_at + ANSWER_KEY_BYTES + KEM_KEY_BYTES];
    let certificate_hash: [u8; CERTIFICATE_HASH_BYTES] =
        bytes[keys_at + ANSWER_KEY_BYTES + KEM_KEY_BYTES..].try_into().expect("the hash's length");

    let attested = verifier.verify(document, now_unix).map_err(PhoneAttestationRejected::Document)?;
    let build = list.check(&attested.pcrs).map_err(PhoneAttestationRejected::Measurement)?.clone();
    let expected = binding(answer_key, kem_key, &certificate_hash, challenge);
    if !attested.user_data.as_deref().is_some_and(|data| ct_eq(data, &expected)) {
        return Err(PhoneAttestationRejected::Binding);
    }
    if !ct_eq(&certificate_hash, connection_certificate_hash) {
        return Err(PhoneAttestationRejected::Certificate);
    }
    EncodedVerifyingKey::<MlDsa65>::try_from(answer_key)
        .map_err(|_| PhoneAttestationRejected::Malformed("not an ML-DSA-65 key"))?;
    <EncapsulationKey<MlKem768> as TryKeyInit>::new_from_slice(kem_key)
        .map_err(|_| PhoneAttestationRejected::Malformed("not an ML-KEM-768 key"))?;
    Ok(VerifiedSeal {
        answer_key: answer_key.to_vec(),
        kem_key: kem_key.to_vec(),
        certificate_hash,
        build,
        document: attested,
    })
}
