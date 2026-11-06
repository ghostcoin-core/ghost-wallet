//! The phone's check of the Seal's Nitro attestation (`docs/seal-app-attestation.md`).
//!
//! The Seal hands a phone a `GPA2` phone attestation: `GPA2` || document
//! length (u32, big endian) || Nitro attestation document || the Seal's
//! ML-DSA-65 verifying key ([`VERIFYING_KEY_BYTES`]) || its ML-KEM-768
//! encapsulation key ([`KEM_KEY_BYTES`]) || the SHA-256 of the DER of the TLS
//! certificate the Seal serves ([`CERT_HASH_BYTES`]). The document's
//! `user_data` is SHA3-256([`PHONE_ATTESTATION_DOMAIN`] || verifying key ||
//! encapsulation key || certificate hash || the phone's 32-byte challenge).
//! The Seal's own reference is `binding` and `verify` in
//! `seal/src/phone_attestation.rs`.
//!
//! [`verify_seal_attestation`] accepts one only when:
//!
//! - the document verifies as AWS's Nitro verifier does (this file ports
//!   `NitroVerifier` of `seal/src/attestation.rs`, verify only, with its
//!   X.509, DER and CBOR readers): the bundle starts with the pinned AWS root
//!   (its SHA-256), every certificate is signed by the one above it, each
//!   issuer is a CA allowed to sign certificates within its path length,
//!   every certificate is valid now, an unknown critical extension refuses
//!   a certificate, the header is ES384 and nothing else, the payload has
//!   exactly AWS's fields (SHA384 digest, 48-byte PCRs, PCR0, PCR1 and PCR2
//!   present), the ECDSA P-384 signature verifies under the document's
//!   certificate, and the document is at most 300 seconds old;
//! - its PCR0, PCR1 and PCR2 all equal one allowed build of the app's
//!   pinned list (none is all zeros, as a debug-mode enclave reports; a
//!   revoked build is refused; an empty list refuses every Seal);
//! - its `user_data` binds exactly these two keys, this certificate hash and
//!   the challenge the phone just sent, and both keys decode;
//! - the certificate the phone's connection was actually presented is the
//!   one the document binds.
//!
//! Anything else is a refusal with one reason, and gives no key. Nothing
//! here panics on any input. The code only verifies AWS's ECDSA signatures
//! (`p384`, verify only); no key of any curve is made or held here. The
//! code is copied from `seal/` (which depends on this crate, so this crate
//! cannot depend on it); the tests on both sides keep the two in step.

use core::fmt;

use ml_dsa::{EncodedVerifyingKey, MlDsa65, VerifyingKey as MlDsaVerifyingKey};
use ml_kem::{EncapsulationKey, MlKem768, TryKeyInit};
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use rand::TryRng;
use rand::rngs::SysRng;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

/// The SHA-256 fingerprint of the AWS Nitro Enclaves root certificate
/// (Root-G1, `CN=aws.nitro-enclaves, C=US, O=Amazon, OU=AWS`), as AWS
/// publishes it: `64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B`.
pub const AWS_NITRO_ROOT_SHA256: [u8; 32] = [
    0x64, 0x1a, 0x03, 0x21, 0xa3, 0xe2, 0x44, 0xef, 0xe4, 0x56, 0x46, 0x31, 0x95, 0xd6, 0x06, 0x31, 0x7e, 0xd7, 0xcd,
    0xcc, 0x3c, 0x17, 0x56, 0xe0, 0x98, 0x93, 0xf3, 0xc6, 0x8f, 0x79, 0xbb, 0x5b,
];

/// The domain of the document's user data.
pub const PHONE_ATTESTATION_DOMAIN: &[u8] = b"ghost-seal/v2/phone-attestation";
/// The phone attestation's magic.
pub const PHONE_ATTESTATION_MAGIC: &[u8; 4] = b"GPA2";
/// An encoded ML-DSA-65 verifying key's length.
pub const VERIFYING_KEY_BYTES: usize = 1952;
/// An ML-KEM-768 encapsulation key's length.
pub const KEM_KEY_BYTES: usize = 1184;
/// The length of the TLS certificate's SHA-256.
pub const CERT_HASH_BYTES: usize = 32;
/// The phone's challenge length.
pub const CHALLENGE_BYTES: usize = 32;
/// A PCR's length (SHA-384).
pub const PCR_BYTES: usize = 48;
/// The longest phone attestation taken, in bytes (what the fetch takes too).
pub const MAX_ATTESTATION_BYTES: usize = 32 * 1024;

/// The oldest a document may be when it is checked, in seconds.
pub const MAX_AGE_SECS: u64 = 300;
/// How far ahead of the phone's clock a document's time may be, in seconds.
pub const CLOCK_SKEW_SECS: u64 = 60;
/// The longest document accepted, in bytes.
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024;
/// The longest `user_data`, `nonce` or `public_key` the NSM takes.
const MAX_USER_DATA_BYTES: usize = 1024;
/// The longest certificate in a document.
const MAX_CERTIFICATE_BYTES: usize = 1024;

/// One build of the app's pinned list (`lib/seal/pinned-measurements.ts`),
/// revoked builds included.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PinnedSealBuild {
    /// The build's name.
    pub name: String,
    /// PCR0, 48 bytes.
    pub pcr0: Vec<u8>,
    /// PCR1, 48 bytes.
    pub pcr1: Vec<u8>,
    /// PCR2, 48 bytes.
    pub pcr2: Vec<u8>,
    /// `true` for an allowed build, `false` for a revoked one.
    pub allowed: bool,
}

/// What the phone checks a Seal attestation against.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SealAttestationCheck {
    /// The `GPA2` phone attestation, as the Seal answered it.
    pub attestation: Vec<u8>,
    /// The 32-byte challenge the phone sent with the request.
    pub challenge: Vec<u8>,
    /// The SHA-256 of the DER of the certificate the phone's connection to
    /// the Seal presented, measured in native code (32 bytes).
    pub tls_cert_sha256: Vec<u8>,
    /// The app's pinned builds.
    pub pinned_builds: Vec<PinnedSealBuild>,
    /// Now, in Unix seconds.
    pub now: u64,
}

/// A Seal the phone may talk to: public keys and names only.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VerifiedSeal {
    /// The Seal's encoded ML-DSA-65 verifying key (its answers verify under it).
    pub verifying_key: Vec<u8>,
    /// The Seal's ML-KEM-768 encapsulation key.
    pub kem_key: Vec<u8>,
    /// PCR0 of the Seal's build: its answers carry this measurement.
    pub measurement: Vec<u8>,
    /// The name of the pinned build it runs.
    pub build_name: String,
}

/// The verdict: `refusal` is empty and `seal` set only when it was accepted.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SealAttestationVerdict {
    /// `""` when accepted, else one of [`AttestationRefusal::code`]'s codes.
    pub refusal: String,
    /// The verified Seal, only when accepted.
    pub seal: Option<VerifiedSeal>,
}

/// Why an attestation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationRefusal {
    /// Not the `GPA2` layout, not CBOR or COSE, a field of the wrong type or
    /// size, an unknown or missing field, or an input of the wrong length.
    Malformed,
    /// The bundle does not start with the pinned root, or a certificate is
    /// not signed by the one above it or may not issue.
    BadChain,
    /// The document's signature does not verify.
    BadSignature,
    /// The document is older than allowed, or a certificate has expired.
    Expired,
    /// The document or a certificate is from the future.
    NotYetValid,
    /// PCR0, PCR1 and PCR2 do not all equal one pinned build.
    NotPinned,
    /// The pinned build is revoked.
    Revoked,
    /// A PCR is all zeros: an enclave started in debug mode.
    DebugMode,
    /// The document does not bind these keys, this challenge and this
    /// certificate hash, or a key does not decode.
    KeysNotBound,
    /// The certificate the connection presented is not the one bound.
    TlsMismatch,
}

impl AttestationRefusal {
    /// The refusal's code, as JavaScript sees it.
    pub fn code(self) -> &'static str {
        match self {
            AttestationRefusal::Malformed => "malformed",
            AttestationRefusal::BadChain => "bad-chain",
            AttestationRefusal::BadSignature => "bad-signature",
            AttestationRefusal::Expired => "expired",
            AttestationRefusal::NotYetValid => "not-yet-valid",
            AttestationRefusal::NotPinned => "not-pinned",
            AttestationRefusal::Revoked => "revoked",
            AttestationRefusal::DebugMode => "debug-mode",
            AttestationRefusal::KeysNotBound => "keys-not-bound",
            AttestationRefusal::TlsMismatch => "tls-mismatch",
        }
    }
}

impl fmt::Display for AttestationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for AttestationRefusal {}

/// Checks the Seal's phone attestation against the AWS Nitro root, the
/// app's pinned builds, the phone's challenge and the certificate the
/// connection presented. Any failure is a refusal with no key.
#[uniffi::export]
pub fn verify_seal_attestation(check: SealAttestationCheck) -> SealAttestationVerdict {
    verdict(verify_with_root(&check, &AWS_NITRO_ROOT_SHA256))
}

/// A fresh challenge for an attestation request: 32 bytes from the operating
/// system's random source (public; it only makes the document fresh). Empty
/// when the random source fails, which the app treats as no Seal.
#[uniffi::export]
pub fn seal_attestation_challenge() -> Vec<u8> {
    let mut challenge = vec![0u8; CHALLENGE_BYTES];
    if SysRng.try_fill_bytes(&mut challenge).is_err() {
        return Vec::new();
    }
    challenge
}

/// [`verify_seal_attestation`] trusting the root whose SHA-256 is
/// `root_sha256`. Only the tests pass another root (their test authority's);
/// the app always goes through [`verify_seal_attestation`]. Not exported to
/// the app.
#[doc(hidden)]
pub fn verify_with_root(check: &SealAttestationCheck, root_sha256: &[u8; 32]) -> Result<VerifiedSeal, AttestationRefusal> {
    use AttestationRefusal as R;

    let challenge: &[u8; CHALLENGE_BYTES] = check.challenge.as_slice().try_into().map_err(|_| R::Malformed)?;
    if check.tls_cert_sha256.len() != CERT_HASH_BYTES {
        return Err(R::Malformed);
    }
    let layout = Layout::parse(&check.attestation)?;

    let document = verify_document(layout.document, root_sha256, check.now)?;

    let pcrs = &document.pcrs;
    if is_zero(&pcrs.pcr0) || is_zero(&pcrs.pcr1) || is_zero(&pcrs.pcr2) {
        return Err(R::DebugMode);
    }
    let mut matched: Option<&PinnedSealBuild> = None;
    for build in &check.pinned_builds {
        if build.pcr0 == pcrs.pcr0 && build.pcr1 == pcrs.pcr1 && build.pcr2 == pcrs.pcr2 {
            if !build.allowed {
                return Err(R::Revoked);
            }
            if matched.is_none() {
                matched = Some(build);
            }
        }
    }
    let build = matched.ok_or(R::NotPinned)?;

    let expected = binding(layout.verifying_key, layout.kem_key, layout.cert_hash, challenge);
    if document.user_data.as_deref() != Some(&expected[..]) {
        return Err(R::KeysNotBound);
    }
    let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(layout.verifying_key).map_err(|_| R::KeysNotBound)?;
    let _ = MlDsaVerifyingKey::<MlDsa65>::decode(&encoded);
    <EncapsulationKey<MlKem768> as TryKeyInit>::new_from_slice(layout.kem_key).map_err(|_| R::KeysNotBound)?;

    if layout.cert_hash != check.tls_cert_sha256.as_slice() {
        return Err(R::TlsMismatch);
    }
    Ok(VerifiedSeal {
        verifying_key: layout.verifying_key.to_vec(),
        kem_key: layout.kem_key.to_vec(),
        measurement: pcrs.pcr0.to_vec(),
        build_name: build.name.clone(),
    })
}

fn verdict(result: Result<VerifiedSeal, AttestationRefusal>) -> SealAttestationVerdict {
    match result {
        Ok(seal) => SealAttestationVerdict { refusal: String::new(), seal: Some(seal) },
        Err(refusal) => SealAttestationVerdict { refusal: refusal.code().to_owned(), seal: None },
    }
}

/// The `user_data` a phone attestation's document carries.
fn binding(verifying_key: &[u8], kem_key: &[u8], cert_hash: &[u8], challenge: &[u8; CHALLENGE_BYTES]) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    for part in [PHONE_ATTESTATION_DOMAIN, verifying_key, kem_key, cert_hash, challenge] {
        hash.update(part);
    }
    hash.finalize().into()
}

fn is_zero(pcr: &Pcr) -> bool {
    pcr.iter().all(|b| *b == 0)
}

/// The parts of a `GPA2` phone attestation.
struct Layout<'a> {
    document: &'a [u8],
    verifying_key: &'a [u8],
    kem_key: &'a [u8],
    cert_hash: &'a [u8],
}

impl<'a> Layout<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Layout<'a>, AttestationRefusal> {
        let bad = AttestationRefusal::Malformed;
        if bytes.len() > MAX_ATTESTATION_BYTES || bytes.len() < 8 || &bytes[..4] != PHONE_ATTESTATION_MAGIC {
            return Err(bad);
        }
        let length = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let tail = VERIFYING_KEY_BYTES + KEM_KEY_BYTES + CERT_HASH_BYTES;
        if length == 0 || length > MAX_DOCUMENT_BYTES || bytes.len() != 8 + length + tail {
            return Err(bad);
        }
        let (document, rest) = bytes[8..].split_at(length);
        let (verifying_key, rest) = rest.split_at(VERIFYING_KEY_BYTES);
        let (kem_key, cert_hash) = rest.split_at(KEM_KEY_BYTES);
        Ok(Layout { document, verifying_key, kem_key, cert_hash })
    }
}

// ---------------------------------------------------------------------------
// The Nitro document check: ported from `seal/src/attestation.rs`.

type Pcr = [u8; PCR_BYTES];

struct Pcrs {
    pcr0: Pcr,
    pcr1: Pcr,
    pcr2: Pcr,
}

/// What a verified document says that the phone uses.
struct AttestedDocument {
    pcrs: Pcrs,
    user_data: Option<Vec<u8>>,
}

/// Why a document was refused, as the seal-side verifier says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rejected {
    Malformed,
    WrongRoot,
    BadChain,
    BadSignature,
    Expired,
    NotYetValid,
}

impl From<Rejected> for AttestationRefusal {
    fn from(rejected: Rejected) -> Self {
        match rejected {
            Rejected::Malformed => AttestationRefusal::Malformed,
            Rejected::WrongRoot | Rejected::BadChain => AttestationRefusal::BadChain,
            Rejected::BadSignature => AttestationRefusal::BadSignature,
            Rejected::Expired => AttestationRefusal::Expired,
            Rejected::NotYetValid => AttestationRefusal::NotYetValid,
        }
    }
}

fn certificate_fingerprint(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

fn verify_document(document: &[u8], root_sha256: &[u8; 32], now_unix: u64) -> Result<AttestedDocument, AttestationRefusal> {
    let cose = CoseSign1::parse(document)?;
    let payload = Payload::parse(&cose.payload)?;
    if cose.signature.len() != 96 {
        return Err(Rejected::Malformed.into());
    }

    // The chain: root (pinned), intermediates, then the document's certificate.
    let root_der = payload.cabundle.first().ok_or(Rejected::Malformed)?;
    if certificate_fingerprint(root_der) != *root_sha256 {
        return Err(Rejected::WrongRoot.into());
    }
    let mut chain = Vec::with_capacity(payload.cabundle.len() + 1);
    for der in &payload.cabundle {
        chain.push(x509::Certificate::parse(der)?);
    }
    chain.push(x509::Certificate::parse(&payload.certificate)?);
    let root = &chain[0];
    if root.issuer != root.subject {
        return Err(Rejected::BadChain.into());
    }
    root.verify_signed_by(root)?;
    let issuers = chain.len() - 1;
    for i in 0..issuers {
        let (parent, child) = (&chain[i], &chain[i + 1]);
        if !parent.is_ca {
            return Err(Rejected::BadChain.into());
        }
        if parent.key_cert_sign == Some(false) {
            return Err(Rejected::BadChain.into());
        }
        if let Some(limit) = parent.path_len {
            // CAs below this one, not counting the document's certificate.
            let below = (issuers - 1 - i) as u64;
            if below > limit {
                return Err(Rejected::BadChain.into());
            }
        }
        if child.issuer != parent.subject {
            return Err(Rejected::BadChain.into());
        }
        child.verify_signed_by(parent)?;
    }
    for cert in &chain {
        if now_unix < cert.not_before {
            return Err(Rejected::NotYetValid.into());
        }
        if now_unix > cert.not_after {
            return Err(Rejected::Expired.into());
        }
    }

    // The document's own signature, by the document's certificate.
    let leaf = chain.last().ok_or(Rejected::Malformed)?;
    let key = VerifyingKey::from_sec1_bytes(leaf.public_key).map_err(|_| Rejected::BadChain)?;
    let signature = Signature::from_slice(&cose.signature).map_err(|_| Rejected::BadSignature)?;
    key.verify(&cose.signed_bytes(), &signature).map_err(|_| Rejected::BadSignature)?;

    check_time(payload.timestamp_ms, now_unix)?;
    Ok(AttestedDocument { pcrs: payload.pcrs, user_data: payload.user_data })
}

fn check_time(timestamp_ms: u64, now_unix: u64) -> Result<(), Rejected> {
    let made = timestamp_ms / 1000;
    if made > now_unix.saturating_add(CLOCK_SKEW_SECS) {
        return Err(Rejected::NotYetValid);
    }
    if now_unix.saturating_sub(made) > MAX_AGE_SECS {
        return Err(Rejected::Expired);
    }
    Ok(())
}

/// A parsed COSE_Sign1 structure.
struct CoseSign1 {
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl CoseSign1 {
    fn parse(document: &[u8]) -> Result<CoseSign1, Rejected> {
        if document.len() > MAX_DOCUMENT_BYTES {
            return Err(Rejected::Malformed);
        }
        let value = cbor::decode(document).map_err(|_| Rejected::Malformed)?;
        let value = match value {
            cbor::Value::Tag(18, inner) => *inner,
            cbor::Value::Tag(..) => return Err(Rejected::Malformed),
            other => other,
        };
        let cbor::Value::Array(items) = value else {
            return Err(Rejected::Malformed);
        };
        let [protected, unprotected, payload, signature]: [cbor::Value; 4] =
            items.try_into().map_err(|_| Rejected::Malformed)?;
        let cbor::Value::Bytes(protected) = protected else {
            return Err(Rejected::Malformed);
        };
        let header = cbor::decode(&protected).map_err(|_| Rejected::Malformed)?;
        // {1: -35}: alg ES384, and nothing else.
        if header != cbor::Value::Map(vec![(cbor::Value::Unsigned(1), cbor::Value::Negative(34))]) {
            return Err(Rejected::Malformed);
        }
        if unprotected != cbor::Value::Map(Vec::new()) {
            return Err(Rejected::Malformed);
        }
        let cbor::Value::Bytes(payload) = payload else {
            return Err(Rejected::Malformed);
        };
        let cbor::Value::Bytes(signature) = signature else {
            return Err(Rejected::Malformed);
        };
        Ok(CoseSign1 { protected, payload, signature })
    }

    /// The Sig_structure the signature covers: `["Signature1", protected, h'', payload]`.
    fn signed_bytes(&self) -> Vec<u8> {
        cbor::encode(&cbor::Value::Array(vec![
            cbor::Value::Text("Signature1".into()),
            cbor::Value::Bytes(self.protected.clone()),
            cbor::Value::Bytes(Vec::new()),
            cbor::Value::Bytes(self.payload.clone()),
        ]))
    }
}

/// The payload of a document, with every field checked.
struct Payload {
    timestamp_ms: u64,
    pcrs: Pcrs,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    user_data: Option<Vec<u8>>,
}

const PAYLOAD_FIELDS: [&str; 9] =
    ["module_id", "digest", "timestamp", "pcrs", "certificate", "cabundle", "public_key", "user_data", "nonce"];

impl Payload {
    fn parse(bytes: &[u8]) -> Result<Payload, Rejected> {
        let bad = Rejected::Malformed;
        let value = cbor::decode(bytes).map_err(|_| bad)?;
        let cbor::Value::Map(fields) = value else {
            return Err(bad);
        };
        for (key, _) in &fields {
            match key {
                cbor::Value::Text(key) if PAYLOAD_FIELDS.contains(&key.as_str()) => {}
                _ => return Err(bad),
            }
        }
        let get = |name: &'static str| -> Option<&cbor::Value> {
            fields.iter().find(|(k, _)| matches!(k, cbor::Value::Text(t) if t == name)).map(|(_, v)| v)
        };
        let need = |name: &'static str| get(name).ok_or(bad);

        match need("module_id")? {
            cbor::Value::Text(text) if !text.is_empty() => {}
            _ => return Err(bad),
        }
        match need("digest")? {
            cbor::Value::Text(text) if text == "SHA384" => {}
            _ => return Err(bad),
        }
        let timestamp_ms = match need("timestamp")? {
            cbor::Value::Unsigned(n) if *n > 0 => *n,
            _ => return Err(bad),
        };
        let cbor::Value::Map(pcr_map) = need("pcrs")? else {
            return Err(bad);
        };
        if pcr_map.is_empty() || pcr_map.len() > 32 {
            return Err(bad);
        }
        let mut pcrs: [Option<Pcr>; 3] = [None; 3];
        for (index, value) in pcr_map {
            let cbor::Value::Unsigned(index) = index else {
                return Err(bad);
            };
            if *index >= 32 {
                return Err(bad);
            }
            let pcr: Pcr = match value {
                cbor::Value::Bytes(bytes) => bytes.as_slice().try_into().map_err(|_| bad)?,
                _ => return Err(bad),
            };
            if let Some(slot) = pcrs.get_mut(*index as usize) {
                *slot = Some(pcr);
            }
        }
        let [Some(pcr0), Some(pcr1), Some(pcr2)] = pcrs else {
            return Err(bad);
        };
        let certificate = match need("certificate")? {
            cbor::Value::Bytes(der) if (1..=MAX_CERTIFICATE_BYTES).contains(&der.len()) => der.clone(),
            _ => return Err(bad),
        };
        let cbor::Value::Array(bundle) = need("cabundle")? else {
            return Err(bad);
        };
        if bundle.is_empty() || bundle.len() > 8 {
            return Err(bad);
        }
        let mut cabundle = Vec::with_capacity(bundle.len());
        for der in bundle {
            match der {
                cbor::Value::Bytes(der) if (1..=MAX_CERTIFICATE_BYTES).contains(&der.len()) => cabundle.push(der.clone()),
                _ => return Err(bad),
            }
        }
        let optional = |name: &'static str| -> Result<Option<Vec<u8>>, Rejected> {
            match get(name) {
                None | Some(cbor::Value::Null) => Ok(None),
                Some(cbor::Value::Bytes(bytes)) if bytes.len() <= MAX_USER_DATA_BYTES => Ok(Some(bytes.clone())),
                Some(_) => Err(bad),
            }
        };
        optional("public_key")?;
        optional("nonce")?;
        Ok(Payload { timestamp_ms, pcrs: Pcrs { pcr0, pcr1, pcr2 }, certificate, cabundle, user_data: optional("user_data")? })
    }
}

/// Just enough X.509 (RFC 5280) for the Nitro chain: P-384 keys,
/// ecdsa-with-SHA384 signatures, validity, names compared as DER bytes,
/// basic constraints and key usage. Any unknown critical extension refuses
/// the certificate.
mod x509 {
    use super::der::{self, Tlv};
    use super::*;

    const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
    const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    const OID_SECP384R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
    const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
    const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];

    pub(super) struct Certificate<'a> {
        tbs: &'a [u8],
        signature: &'a [u8],
        pub(super) issuer: &'a [u8],
        pub(super) subject: &'a [u8],
        pub(super) not_before: u64,
        pub(super) not_after: u64,
        pub(super) public_key: &'a [u8],
        pub(super) is_ca: bool,
        pub(super) path_len: Option<u64>,
        pub(super) key_cert_sign: Option<bool>,
    }

    const BAD: Rejected = Rejected::BadChain;

    fn ecdsa_sha384(algorithm: Tlv<'_>) -> Result<(), Rejected> {
        let mut inner = algorithm.sequence().map_err(|_| BAD)?;
        let oid = inner.next(der::OID).map_err(|_| BAD)?;
        if oid.content != OID_ECDSA_SHA384 || !inner.is_empty() {
            return Err(BAD);
        }
        Ok(())
    }

    impl<'a> Certificate<'a> {
        pub(super) fn parse(bytes: &'a [u8]) -> Result<Certificate<'a>, Rejected> {
            let whole = der::read_all(bytes).map_err(|_| BAD)?;
            let mut cert = whole.sequence().map_err(|_| BAD)?;
            let tbs_tlv = cert.next(der::SEQUENCE).map_err(|_| BAD)?;
            ecdsa_sha384(cert.next(der::SEQUENCE).map_err(|_| BAD)?)?;
            let signature_bits = cert.next(der::BIT_STRING).map_err(|_| BAD)?;
            if !cert.is_empty() {
                return Err(BAD);
            }
            let signature = signature_bits.bits().map_err(|_| BAD)?;

            let mut tbs = tbs_tlv.sequence().map_err(|_| BAD)?;
            let version = tbs.next(0xa0).map_err(|_| BAD)?;
            if version.content != [der::INTEGER, 0x01, 0x02] {
                return Err(BAD);
            }
            tbs.next(der::INTEGER).map_err(|_| BAD)?;
            ecdsa_sha384(tbs.next(der::SEQUENCE).map_err(|_| BAD)?)?;
            let issuer = tbs.next(der::SEQUENCE).map_err(|_| BAD)?.whole;
            let mut validity = tbs.next(der::SEQUENCE).map_err(|_| BAD)?.sequence().map_err(|_| BAD)?;
            let not_before = der::time(validity.any().map_err(|_| BAD)?).map_err(|_| BAD)?;
            let not_after = der::time(validity.any().map_err(|_| BAD)?).map_err(|_| BAD)?;
            if !validity.is_empty() || not_after < not_before {
                return Err(BAD);
            }
            let subject = tbs.next(der::SEQUENCE).map_err(|_| BAD)?.whole;
            let mut spki = tbs.next(der::SEQUENCE).map_err(|_| BAD)?.sequence().map_err(|_| BAD)?;
            let mut algorithm = spki.next(der::SEQUENCE).map_err(|_| BAD)?.sequence().map_err(|_| BAD)?;
            let key_type = algorithm.next(der::OID).map_err(|_| BAD)?;
            let curve = algorithm.next(der::OID).map_err(|_| BAD)?;
            if key_type.content != OID_EC_PUBLIC_KEY || curve.content != OID_SECP384R1 || !algorithm.is_empty() {
                return Err(BAD);
            }
            let public_key = spki.next(der::BIT_STRING).map_err(|_| BAD)?.bits().map_err(|_| BAD)?;
            if !spki.is_empty() {
                return Err(BAD);
            }

            let mut is_ca = false;
            let mut path_len = None;
            let mut key_cert_sign = None;
            while !tbs.is_empty() {
                let field = tbs.any().map_err(|_| BAD)?;
                match field.tag {
                    // issuerUniqueID and subjectUniqueID: carry nothing used here.
                    0x81 | 0x82 => {}
                    0xa3 => {
                        let mut wrapper = field.sequence_inside().map_err(|_| BAD)?;
                        let mut extensions =
                            wrapper.next(der::SEQUENCE).map_err(|_| BAD)?.sequence().map_err(|_| BAD)?;
                        if !wrapper.is_empty() {
                            return Err(BAD);
                        }
                        let mut seen: Vec<&[u8]> = Vec::new();
                        while !extensions.is_empty() {
                            let mut extension =
                                extensions.next(der::SEQUENCE).map_err(|_| BAD)?.sequence().map_err(|_| BAD)?;
                            let id = extension.next(der::OID).map_err(|_| BAD)?.content;
                            if seen.contains(&id) {
                                return Err(BAD);
                            }
                            seen.push(id);
                            let mut critical = false;
                            let mut value = extension.any().map_err(|_| BAD)?;
                            if value.tag == der::BOOLEAN {
                                critical = value.boolean().map_err(|_| BAD)?;
                                value = extension.next(der::OCTET_STRING).map_err(|_| BAD)?;
                            } else if value.tag != der::OCTET_STRING {
                                return Err(BAD);
                            }
                            if !extension.is_empty() {
                                return Err(BAD);
                            }
                            if id == OID_BASIC_CONSTRAINTS {
                                let inner = der::read_all(value.content).map_err(|_| BAD)?;
                                let mut constraints = inner.sequence().map_err(|_| BAD)?;
                                if let Ok(flag) = constraints.next(der::BOOLEAN) {
                                    is_ca = flag.boolean().map_err(|_| BAD)?;
                                }
                                if let Ok(limit) = constraints.next(der::INTEGER) {
                                    path_len = Some(limit.small_unsigned().map_err(|_| BAD)?);
                                }
                                if !constraints.is_empty() {
                                    return Err(BAD);
                                }
                            } else if id == OID_KEY_USAGE {
                                let inner = der::read_all(value.content).map_err(|_| BAD)?;
                                if inner.tag != der::BIT_STRING || inner.content.len() < 2 {
                                    return Err(BAD);
                                }
                                // keyCertSign is bit 5 of the first byte (MSB is bit 0).
                                key_cert_sign = Some(inner.content[1] & 0x04 != 0);
                            } else if critical {
                                return Err(BAD);
                            }
                        }
                    }
                    _ => return Err(BAD),
                }
            }
            Ok(Certificate {
                tbs: tbs_tlv.whole,
                signature,
                issuer,
                subject,
                not_before,
                not_after,
                public_key,
                is_ca,
                path_len,
                key_cert_sign,
            })
        }

        /// Checks this certificate's signature under `issuer`'s key.
        pub(super) fn verify_signed_by(&self, issuer: &Certificate<'_>) -> Result<(), Rejected> {
            let key = VerifyingKey::from_sec1_bytes(issuer.public_key).map_err(|_| BAD)?;
            let signature = Signature::from_der(self.signature).map_err(|_| BAD)?;
            key.verify(self.tbs, &signature).map_err(|_| BAD)
        }
    }
}

/// A strict DER (X.690) reader: single-byte tags, definite minimal lengths.
mod der {
    pub(super) const BOOLEAN: u8 = 0x01;
    pub(super) const INTEGER: u8 = 0x02;
    pub(super) const BIT_STRING: u8 = 0x03;
    pub(super) const OCTET_STRING: u8 = 0x04;
    pub(super) const OID: u8 = 0x06;
    pub(super) const UTC_TIME: u8 = 0x17;
    pub(super) const GENERALIZED_TIME: u8 = 0x18;
    pub(super) const SEQUENCE: u8 = 0x30;

    #[derive(Debug)]
    pub(super) struct Bad;

    #[derive(Clone, Copy)]
    pub(super) struct Tlv<'a> {
        pub(super) tag: u8,
        pub(super) content: &'a [u8],
        pub(super) whole: &'a [u8],
    }

    /// Reads one TLV from the front of `input`.
    fn read(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), Bad> {
        let (&tag, rest) = input.split_first().ok_or(Bad)?;
        if tag & 0x1f == 0x1f {
            return Err(Bad);
        }
        let (&first, mut rest) = rest.split_first().ok_or(Bad)?;
        let length = if first < 0x80 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 3 || rest.len() < count {
                return Err(Bad);
            }
            let mut length = 0usize;
            for &b in &rest[..count] {
                length = length << 8 | usize::from(b);
            }
            if rest[0] == 0 || length < 0x80 {
                return Err(Bad);
            }
            rest = &rest[count..];
            length
        };
        if rest.len() < length {
            return Err(Bad);
        }
        let header = input.len() - rest.len();
        let tlv = Tlv { tag, content: &rest[..length], whole: &input[..header + length] };
        Ok((tlv, &rest[length..]))
    }

    /// Reads exactly one TLV, with nothing after it.
    pub(super) fn read_all(input: &[u8]) -> Result<Tlv<'_>, Bad> {
        let (tlv, rest) = read(input)?;
        if rest.is_empty() { Ok(tlv) } else { Err(Bad) }
    }

    pub(super) struct Items<'a> {
        rest: &'a [u8],
    }

    impl<'a> Items<'a> {
        pub(super) fn any(&mut self) -> Result<Tlv<'a>, Bad> {
            let (tlv, rest) = read(self.rest)?;
            self.rest = rest;
            Ok(tlv)
        }

        /// The next item if it has `tag`; otherwise nothing is consumed.
        pub(super) fn next(&mut self, tag: u8) -> Result<Tlv<'a>, Bad> {
            let (tlv, rest) = read(self.rest)?;
            if tlv.tag != tag {
                return Err(Bad);
            }
            self.rest = rest;
            Ok(tlv)
        }

        pub(super) fn is_empty(&self) -> bool {
            self.rest.is_empty()
        }
    }

    impl<'a> Tlv<'a> {
        pub(super) fn sequence(&self) -> Result<Items<'a>, Bad> {
            if self.tag != SEQUENCE {
                return Err(Bad);
            }
            Ok(Items { rest: self.content })
        }

        /// The items inside an explicit context tag.
        pub(super) fn sequence_inside(&self) -> Result<Items<'a>, Bad> {
            if self.tag & 0x20 == 0 {
                return Err(Bad);
            }
            Ok(Items { rest: self.content })
        }

        /// A BIT STRING's bytes; it must have no unused bits.
        pub(super) fn bits(&self) -> Result<&'a [u8], Bad> {
            match self.content.split_first() {
                Some((0, bits)) if self.tag == BIT_STRING => Ok(bits),
                _ => Err(Bad),
            }
        }

        pub(super) fn boolean(&self) -> Result<bool, Bad> {
            match (self.tag, self.content) {
                (BOOLEAN, [0x00]) => Ok(false),
                (BOOLEAN, [0xff]) => Ok(true),
                _ => Err(Bad),
            }
        }

        /// A non-negative INTEGER of up to 7 bytes.
        pub(super) fn small_unsigned(&self) -> Result<u64, Bad> {
            let c = self.content;
            if self.tag != INTEGER || c.is_empty() || c.len() > 7 || c[0] & 0x80 != 0 {
                return Err(Bad);
            }
            if c.len() > 1 && c[0] == 0 && c[1] & 0x80 == 0 {
                return Err(Bad);
            }
            Ok(c.iter().fold(0u64, |n, b| n << 8 | u64::from(*b)))
        }
    }

    /// A UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSSZ`)
    /// as seconds since the Unix epoch.
    pub(super) fn time(tlv: Tlv<'_>) -> Result<u64, Bad> {
        let text = tlv.content;
        let digits = |range: core::ops::Range<usize>| -> Result<u64, Bad> {
            let mut n = 0u64;
            for &c in text.get(range).ok_or(Bad)? {
                if !c.is_ascii_digit() {
                    return Err(Bad);
                }
                n = n * 10 + u64::from(c - b'0');
            }
            Ok(n)
        };
        let (year, at) = match (tlv.tag, text.len()) {
            (UTC_TIME, 13) => {
                let yy = digits(0..2)?;
                (if yy < 50 { 2000 + yy } else { 1900 + yy }, 2)
            }
            (GENERALIZED_TIME, 15) => (digits(0..4)?, 4),
            _ => return Err(Bad),
        };
        if text[text.len() - 1] != b'Z' {
            return Err(Bad);
        }
        let month = digits(at..at + 2)?;
        let day = digits(at + 2..at + 4)?;
        let hour = digits(at + 4..at + 6)?;
        let minute = digits(at + 6..at + 8)?;
        let second = digits(at + 8..at + 10)?;
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 59 || year < 1970 {
            return Err(Bad);
        }
        Ok(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
    }

    /// Days since 1970-01-01 of a proleptic Gregorian date (year >= 1970).
    fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
        let y = if month <= 2 { year - 1 } else { year };
        let era = y / 400;
        let yoe = y - era * 400;
        let mp = (month + 9) % 12;
        let doy = (153 * mp + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }
}

/// A small CBOR (RFC 8949) reader and writer for attestation documents:
/// definite lengths only, no floats, simple values limited to false, true
/// and null, nesting at most 16 deep, no duplicate map keys. The writer
/// always uses the shortest heads.
mod cbor {
    const MAX_DEPTH: usize = 16;

    /// A CBOR value.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) enum Value {
        Unsigned(u64),
        /// Major type 1: the value is `-1 - n`.
        Negative(u64),
        Bytes(Vec<u8>),
        Text(String),
        Array(Vec<Value>),
        /// Major type 5, in the order written.
        Map(Vec<(Value, Value)>),
        Tag(u64, Box<Value>),
        Bool(bool),
        Null,
    }

    /// Bytes that are not CBOR this reader takes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct CborError;

    fn head(out: &mut Vec<u8>, major: u8, n: u64) {
        let m = major << 5;
        match n {
            0..=23 => out.push(m | n as u8),
            24..=0xff => out.extend_from_slice(&[m | 24, n as u8]),
            0x100..=0xffff => {
                out.push(m | 25);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                out.push(m | 26);
                out.extend_from_slice(&(n as u32).to_be_bytes());
            }
            _ => {
                out.push(m | 27);
                out.extend_from_slice(&n.to_be_bytes());
            }
        }
    }

    fn write(out: &mut Vec<u8>, value: &Value) {
        match value {
            Value::Unsigned(n) => head(out, 0, *n),
            Value::Negative(n) => head(out, 1, *n),
            Value::Bytes(b) => {
                head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Value::Text(t) => {
                head(out, 3, t.len() as u64);
                out.extend_from_slice(t.as_bytes());
            }
            Value::Array(items) => {
                head(out, 4, items.len() as u64);
                for item in items {
                    write(out, item);
                }
            }
            Value::Map(fields) => {
                head(out, 5, fields.len() as u64);
                for (k, v) in fields {
                    write(out, k);
                    write(out, v);
                }
            }
            Value::Tag(tag, inner) => {
                head(out, 6, *tag);
                write(out, inner);
            }
            Value::Bool(false) => out.push(0xf4),
            Value::Bool(true) => out.push(0xf5),
            Value::Null => out.push(0xf6),
        }
    }

    /// Encodes `value`.
    pub(super) fn encode(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        write(&mut out, value);
        out
    }

    /// Decodes exactly one value from all of `bytes`.
    pub(super) fn decode(bytes: &[u8]) -> Result<Value, CborError> {
        let mut reader = Reader { bytes, at: 0 };
        let value = reader.value(0)?;
        if reader.at != bytes.len() {
            return Err(CborError);
        }
        Ok(value)
    }

    struct Reader<'a> {
        bytes: &'a [u8],
        at: usize,
    }

    impl Reader<'_> {
        fn take(&mut self, n: usize) -> Result<&[u8], CborError> {
            let end = self.at.checked_add(n).ok_or(CborError)?;
            let out = self.bytes.get(self.at..end).ok_or(CborError)?;
            self.at = end;
            Ok(out)
        }

        fn fixed<const N: usize>(&mut self) -> Result<[u8; N], CborError> {
            self.take(N)?.try_into().map_err(|_| CborError)
        }

        fn argument(&mut self, info: u8) -> Result<u64, CborError> {
            Ok(match info {
                0..=23 => u64::from(info),
                24 => u64::from(self.fixed::<1>()?[0]),
                25 => u64::from(u16::from_be_bytes(self.fixed()?)),
                26 => u64::from(u32::from_be_bytes(self.fixed()?)),
                27 => u64::from_be_bytes(self.fixed()?),
                _ => return Err(CborError),
            })
        }

        fn length(&mut self, info: u8) -> Result<usize, CborError> {
            let n = self.argument(info)?;
            // No item can be longer than what is left of the input.
            if n > (self.bytes.len() - self.at) as u64 {
                return Err(CborError);
            }
            Ok(n as usize)
        }

        fn value(&mut self, depth: usize) -> Result<Value, CborError> {
            if depth > MAX_DEPTH {
                return Err(CborError);
            }
            let initial = self.fixed::<1>()?[0];
            let (major, info) = (initial >> 5, initial & 0x1f);
            Ok(match major {
                0 => Value::Unsigned(self.argument(info)?),
                1 => Value::Negative(self.argument(info)?),
                2 => {
                    let n = self.length(info)?;
                    Value::Bytes(self.take(n)?.to_vec())
                }
                3 => {
                    let n = self.length(info)?;
                    let text = core::str::from_utf8(self.take(n)?).map_err(|_| CborError)?;
                    Value::Text(text.to_owned())
                }
                4 => {
                    let n = self.length(info)?;
                    let mut items = Vec::with_capacity(n);
                    for _ in 0..n {
                        items.push(self.value(depth + 1)?);
                    }
                    Value::Array(items)
                }
                5 => {
                    let n = self.length(info)?;
                    let mut fields: Vec<(Value, Value)> = Vec::with_capacity(n);
                    for _ in 0..n {
                        let key = self.value(depth + 1)?;
                        if fields.iter().any(|(k, _)| *k == key) {
                            return Err(CborError);
                        }
                        let value = self.value(depth + 1)?;
                        fields.push((key, value));
                    }
                    Value::Map(fields)
                }
                6 => {
                    let tag = self.argument(info)?;
                    Value::Tag(tag, Box::new(self.value(depth + 1)?))
                }
                _ => match info {
                    20 => Value::Bool(false),
                    21 => Value::Bool(true),
                    22 => Value::Null,
                    _ => return Err(CborError),
                },
            })
        }
    }
}
