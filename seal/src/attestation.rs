//! Nitro attestation documents: checking one (the [`AttestationVerifier`]
//! trait, the real [`NitroVerifier`] and a [`fake`] for tests) and asking
//! the Nitro Secure Module for one (the [`AttestationSource`] trait and the
//! NSM-backed [`NsmSource`]).
//!
//! A document is a COSE_Sign1 structure (RFC 9052, CBOR, tag 18 optional):
//! `[protected {1: -35}, unprotected {}, payload, signature]`, signed with
//! ECDSA P-384 and SHA-384 (ES384) by the key of the document's
//! `certificate`, which chains through `cabundle` to the AWS Nitro root. The
//! payload is a CBOR map with exactly the fields AWS documents: `module_id`,
//! `timestamp` (milliseconds), `digest` ("SHA384"), `pcrs`, `certificate`,
//! `cabundle`, and the optional `public_key`, `user_data` and `nonce`.
//!
//! [`NitroVerifier`] checks, in order: the CBOR and COSE structure and the
//! ES384 header; that `cabundle[0]` is the pinned root (its SHA-256 equals
//! the pinned fingerprint, and it signs itself); that every certificate of
//! `cabundle` is signed by the one before it, is a CA where it issues, and
//! that the document's certificate is signed by the last; that every
//! certificate is valid now; that the document's signature verifies under
//! the document's certificate; that the payload has exactly the documented
//! fields with their documented sizes, digest SHA384, 48-byte PCRs and PCR0,
//! PCR1 and PCR2 present; and that the document is no older than its
//! allowed age. Whether its PCRs are a published build is the caller's
//! check ([`crate::measurements::MeasurementList::check`]).
//!
//! A document that is not CBOR says why: the refusal carries the decoder's
//! reason and the byte it stopped at (`the payload is not CBOR: truncated at
//! byte 4012 of 4385`). The text names a position and a rule only, never any
//! of the document's bytes.
//!
//! This module only verifies AWS's signatures; it never signs.

use core::fmt;
use std::borrow::Cow;

use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::measurements::{Pcr, Pcrs};
use crate::primitives::sha3_256;

/// The SHA-256 fingerprint of the AWS Nitro Enclaves root certificate
/// (Root-G1, `CN=aws.nitro-enclaves, C=US, O=Amazon, OU=AWS`), as AWS
/// publishes it: `64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B`.
pub const AWS_NITRO_ROOT_SHA256: [u8; 32] = [
    0x64, 0x1a, 0x03, 0x21, 0xa3, 0xe2, 0x44, 0xef, 0xe4, 0x56, 0x46, 0x31, 0x95, 0xd6, 0x06, 0x31, 0x7e, 0xd7, 0xcd,
    0xcc, 0x3c, 0x17, 0x56, 0xe0, 0x98, 0x93, 0xf3, 0xc6, 0x8f, 0x79, 0xbb, 0x5b,
];

/// The oldest a document may be when it is checked, in seconds.
pub const DEFAULT_MAX_AGE_SECS: u64 = 300;
/// How far ahead of the checker's clock a document's time may be, in seconds.
pub const CLOCK_SKEW_SECS: u64 = 60;
/// The longest document accepted, in bytes.
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024;
/// The longest `user_data`, `nonce` or `public_key` the NSM takes.
pub const MAX_USER_DATA_BYTES: usize = 1024;
/// The longest certificate in a document.
pub const MAX_CERTIFICATE_BYTES: usize = 1024;

/// SHA3-256 of a whole document, as protocols bind it.
pub fn document_hash(document: &[u8]) -> [u8; 32] {
    sha3_256(&[b"ghost-seal/v1/attestation-document", document])
}

/// SHA-256 of a certificate, to compare with a pinned fingerprint.
pub fn certificate_fingerprint(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

/// What a verified document says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedDocument {
    /// The issuing Nitro module.
    pub module_id: String,
    /// When the NSM made the document, milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// PCR0, PCR1 and PCR2.
    pub pcrs: Pcrs,
    /// The `public_key` field, if set.
    pub public_key: Option<Vec<u8>>,
    /// The `user_data` field, if set.
    pub user_data: Option<Vec<u8>>,
    /// The `nonce` field, if set.
    pub nonce: Option<Vec<u8>>,
    /// [`document_hash`] of the whole document.
    pub hash: [u8; 32],
}

/// Why a document was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationRejected {
    /// Not CBOR, not COSE_Sign1, or a field of the wrong type or size. For
    /// bytes that are not CBOR, the text has the decoder's reason and the
    /// byte it stopped at.
    Malformed(Cow<'static, str>),
    /// A field the format requires is absent.
    MissingField(&'static str),
    /// A field the format does not have.
    UnknownField,
    /// The digest is not SHA384.
    WrongDigest,
    /// The bundle does not start with the pinned root.
    WrongRoot,
    /// A certificate is not signed by the one above it, or may not issue.
    BadChain(&'static str),
    /// The document's signature does not verify.
    BadSignature,
    /// The document is older than allowed, or a certificate has expired.
    Expired,
    /// The document or a certificate is from the future.
    NotYetValid,
}

impl fmt::Display for AttestationRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttestationRejected::Malformed(what) => write!(f, "malformed attestation document: {what}"),
            AttestationRejected::MissingField(what) => write!(f, "attestation document has no {what}"),
            AttestationRejected::UnknownField => f.write_str("attestation document has an unknown field"),
            AttestationRejected::WrongDigest => f.write_str("attestation document digest is not SHA384"),
            AttestationRejected::WrongRoot => f.write_str("attestation document does not chain to the pinned root"),
            AttestationRejected::BadChain(what) => write!(f, "attestation certificate chain: {what}"),
            AttestationRejected::BadSignature => f.write_str("attestation document signature does not verify"),
            AttestationRejected::Expired => f.write_str("attestation document or certificate has expired"),
            AttestationRejected::NotYetValid => f.write_str("attestation document or certificate is not yet valid"),
        }
    }
}

impl std::error::Error for AttestationRejected {}

impl AttestationRejected {
    /// [`AttestationRejected::Malformed`] with a fixed text.
    pub const fn malformed(what: &'static str) -> AttestationRejected {
        AttestationRejected::Malformed(Cow::Borrowed(what))
    }

    /// [`AttestationRejected::Malformed`] for `part`, which did not decode:
    /// `<part>: <reason> at byte N of LENGTH`.
    pub fn not_cbor(part: &'static str, error: cbor::CborError) -> AttestationRejected {
        AttestationRejected::Malformed(Cow::Owned(format!("{part}: {error}")))
    }
}

/// Checks attestation documents.
pub trait AttestationVerifier {
    /// Verifies `document` at `now_unix` (seconds since the Unix epoch).
    fn verify(&self, document: &[u8], now_unix: u64) -> Result<AttestedDocument, AttestationRejected>;
}

/// The real verifier: the AWS Nitro chain, from a pinned root fingerprint.
#[derive(Debug, Clone)]
pub struct NitroVerifier {
    root_sha256: [u8; 32],
    max_age_secs: u64,
}

impl NitroVerifier {
    /// The verifier for real enclaves: the AWS Nitro root.
    pub fn aws() -> NitroVerifier {
        NitroVerifier::with_root(AWS_NITRO_ROOT_SHA256)
    }

    /// A verifier trusting the root whose SHA-256 is `root_sha256` (tests
    /// pass their own test root; nothing else should).
    pub fn with_root(root_sha256: [u8; 32]) -> NitroVerifier {
        NitroVerifier { root_sha256, max_age_secs: DEFAULT_MAX_AGE_SECS }
    }

    /// The same verifier with another allowed document age.
    pub fn max_age(mut self, secs: u64) -> NitroVerifier {
        self.max_age_secs = secs;
        self
    }
}

impl AttestationVerifier for NitroVerifier {
    fn verify(&self, document: &[u8], now_unix: u64) -> Result<AttestedDocument, AttestationRejected> {
        let cose = CoseSign1::parse(document)?;
        let payload = Payload::parse(&cose.payload)?;
        if cose.signature.len() != 96 {
            return Err(AttestationRejected::malformed("an ES384 signature is 96 bytes"));
        }

        // The chain: root (pinned), intermediates, then the document's certificate.
        let root_der = &payload.cabundle[0];
        if certificate_fingerprint(root_der) != self.root_sha256 {
            return Err(AttestationRejected::WrongRoot);
        }
        let mut chain = Vec::with_capacity(payload.cabundle.len() + 1);
        for der in &payload.cabundle {
            chain.push(x509::Certificate::parse(der)?);
        }
        chain.push(x509::Certificate::parse(&payload.certificate)?);
        let root = &chain[0];
        if root.issuer != root.subject {
            return Err(AttestationRejected::BadChain("the root does not issue itself"));
        }
        root.verify_signed_by(root)?;
        let issuers = chain.len() - 1;
        for i in 0..issuers {
            let (parent, child) = (&chain[i], &chain[i + 1]);
            if !parent.is_ca {
                return Err(AttestationRejected::BadChain("an issuer is not a CA"));
            }
            if parent.key_cert_sign == Some(false) {
                return Err(AttestationRejected::BadChain("an issuer may not sign certificates"));
            }
            if let Some(limit) = parent.path_len {
                // CAs below this one, not counting the document's certificate.
                let below = (issuers - 1 - i) as u64;
                if below > limit {
                    return Err(AttestationRejected::BadChain("a path length limit is exceeded"));
                }
            }
            if child.issuer != parent.subject {
                return Err(AttestationRejected::BadChain("an issuer name does not match"));
            }
            child.verify_signed_by(parent)?;
        }
        for cert in &chain {
            if now_unix < cert.not_before {
                return Err(AttestationRejected::NotYetValid);
            }
            if now_unix > cert.not_after {
                return Err(AttestationRejected::Expired);
            }
        }

        // The document's own signature, by the document's certificate.
        let leaf = chain.last().expect("the chain has the document's certificate");
        let key = VerifyingKey::from_sec1_bytes(leaf.public_key)
            .map_err(|_| AttestationRejected::BadChain("a public key is not a P-384 point"))?;
        let signature = Signature::from_slice(&cose.signature).map_err(|_| AttestationRejected::BadSignature)?;
        key.verify(&cose.signed_bytes(), &signature).map_err(|_| AttestationRejected::BadSignature)?;

        check_time(payload.timestamp_ms, now_unix, self.max_age_secs)?;
        Ok(payload.into_document(document))
    }
}

fn check_time(timestamp_ms: u64, now_unix: u64, max_age_secs: u64) -> Result<(), AttestationRejected> {
    let made = timestamp_ms / 1000;
    if made > now_unix.saturating_add(CLOCK_SKEW_SECS) {
        return Err(AttestationRejected::NotYetValid);
    }
    if now_unix.saturating_sub(made) > max_age_secs {
        return Err(AttestationRejected::Expired);
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
    fn parse(document: &[u8]) -> Result<CoseSign1, AttestationRejected> {
        if document.len() > MAX_DOCUMENT_BYTES {
            return Err(AttestationRejected::malformed("the document is too long"));
        }
        let value = cbor::decode(document).map_err(|e| AttestationRejected::not_cbor("the document is not CBOR", e))?;
        let value = match value {
            cbor::Value::Tag(18, inner) => *inner,
            cbor::Value::Tag(..) => return Err(AttestationRejected::malformed("not a COSE_Sign1 tag")),
            other => other,
        };
        let cbor::Value::Array(items) = value else {
            return Err(AttestationRejected::malformed("COSE_Sign1 is not an array"));
        };
        let [protected, unprotected, payload, signature]: [cbor::Value; 4] =
            items.try_into().map_err(|_| AttestationRejected::malformed("COSE_Sign1 has four parts"))?;
        let cbor::Value::Bytes(protected) = protected else {
            return Err(AttestationRejected::malformed("the protected header is not bytes"));
        };
        let header = cbor::decode(&protected)
            .map_err(|e| AttestationRejected::not_cbor("the protected header is not CBOR", e))?;
        // {1: -35}: alg ES384, and nothing else.
        if header != cbor::Value::Map(vec![(cbor::Value::Unsigned(1), cbor::Value::Negative(34))]) {
            return Err(AttestationRejected::malformed("the algorithm is not ES384"));
        }
        if unprotected != cbor::Value::Map(Vec::new()) {
            return Err(AttestationRejected::malformed("the unprotected header is not empty"));
        }
        let cbor::Value::Bytes(payload) = payload else {
            return Err(AttestationRejected::malformed("the payload is not bytes"));
        };
        let cbor::Value::Bytes(signature) = signature else {
            return Err(AttestationRejected::malformed("the signature is not bytes"));
        };
        Ok(CoseSign1 { protected, payload, signature })
    }

    /// The Sig_structure the signature covers.
    fn signed_bytes(&self) -> Vec<u8> {
        sig_structure(&self.protected, &self.payload)
    }
}

/// The COSE Sig_structure: `["Signature1", protected, h'', payload]`.
pub fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    cbor::encode(&cbor::Value::Array(vec![
        cbor::Value::Text("Signature1".into()),
        cbor::Value::Bytes(protected.to_vec()),
        cbor::Value::Bytes(Vec::new()),
        cbor::Value::Bytes(payload.to_vec()),
    ]))
}

/// The protected header of an ES384 COSE_Sign1: `{1: -35}`.
pub fn es384_protected_header() -> Vec<u8> {
    cbor::encode(&cbor::Value::Map(vec![(cbor::Value::Unsigned(1), cbor::Value::Negative(34))]))
}

/// The payload of a document, with every field checked.
struct Payload {
    module_id: String,
    timestamp_ms: u64,
    pcrs: Pcrs,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

const PAYLOAD_FIELDS: [&str; 9] =
    ["module_id", "digest", "timestamp", "pcrs", "certificate", "cabundle", "public_key", "user_data", "nonce"];

impl Payload {
    fn parse(bytes: &[u8]) -> Result<Payload, AttestationRejected> {
        let value = cbor::decode(bytes).map_err(|e| AttestationRejected::not_cbor("the payload is not CBOR", e))?;
        let cbor::Value::Map(fields) = value else {
            return Err(AttestationRejected::malformed("the payload is not a map"));
        };
        for (key, _) in &fields {
            match key {
                cbor::Value::Text(key) if PAYLOAD_FIELDS.contains(&key.as_str()) => {}
                _ => return Err(AttestationRejected::UnknownField),
            }
        }
        let get = |name: &'static str| -> Option<&cbor::Value> {
            fields.iter().find(|(k, _)| matches!(k, cbor::Value::Text(t) if t == name)).map(|(_, v)| v)
        };
        let need = |name: &'static str| get(name).ok_or(AttestationRejected::MissingField(name));

        let module_id = match need("module_id")? {
            cbor::Value::Text(text) if !text.is_empty() => text.clone(),
            _ => return Err(AttestationRejected::malformed("module_id is not a non-empty text")),
        };
        match need("digest")? {
            cbor::Value::Text(text) if text == "SHA384" => {}
            cbor::Value::Text(_) => return Err(AttestationRejected::WrongDigest),
            _ => return Err(AttestationRejected::malformed("digest is not text")),
        }
        let timestamp_ms = match need("timestamp")? {
            cbor::Value::Unsigned(n) if *n > 0 => *n,
            _ => return Err(AttestationRejected::malformed("timestamp is not a positive integer")),
        };
        let cbor::Value::Map(pcr_map) = need("pcrs")? else {
            return Err(AttestationRejected::malformed("pcrs is not a map"));
        };
        if pcr_map.is_empty() || pcr_map.len() > 32 {
            return Err(AttestationRejected::malformed("pcrs has 1 to 32 entries"));
        }
        let mut pcrs: [Option<Pcr>; 3] = [None; 3];
        for (index, value) in pcr_map {
            let cbor::Value::Unsigned(index) = index else {
                return Err(AttestationRejected::malformed("a PCR index is not an integer"));
            };
            if *index >= 32 {
                return Err(AttestationRejected::malformed("a PCR index is 0 to 31"));
            }
            let pcr: Pcr = match value {
                cbor::Value::Bytes(bytes) => bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| AttestationRejected::malformed("a SHA384 PCR is 48 bytes"))?,
                _ => return Err(AttestationRejected::malformed("a PCR is not bytes")),
            };
            if let Some(slot) = pcrs.get_mut(*index as usize) {
                *slot = Some(pcr);
            }
        }
        let [Some(pcr0), Some(pcr1), Some(pcr2)] = pcrs else {
            return Err(AttestationRejected::MissingField("PCR0, PCR1 and PCR2"));
        };
        let certificate = match need("certificate")? {
            cbor::Value::Bytes(der) if (1..=MAX_CERTIFICATE_BYTES).contains(&der.len()) => der.clone(),
            _ => return Err(AttestationRejected::malformed("certificate is not 1 to 1024 bytes")),
        };
        let cbor::Value::Array(bundle) = need("cabundle")? else {
            return Err(AttestationRejected::malformed("cabundle is not an array"));
        };
        if bundle.is_empty() || bundle.len() > 8 {
            return Err(AttestationRejected::malformed("cabundle has 1 to 8 certificates"));
        }
        let mut cabundle = Vec::with_capacity(bundle.len());
        for der in bundle {
            match der {
                cbor::Value::Bytes(der) if (1..=MAX_CERTIFICATE_BYTES).contains(&der.len()) => cabundle.push(der.clone()),
                _ => return Err(AttestationRejected::malformed("a cabundle certificate is not 1 to 1024 bytes")),
            }
        }
        let optional = |name: &'static str| -> Result<Option<Vec<u8>>, AttestationRejected> {
            match get(name) {
                None | Some(cbor::Value::Null) => Ok(None),
                Some(cbor::Value::Bytes(bytes)) if bytes.len() <= MAX_USER_DATA_BYTES => Ok(Some(bytes.clone())),
                Some(_) => Err(AttestationRejected::malformed("public_key, user_data or nonce is not up to 1024 bytes")),
            }
        };
        Ok(Payload {
            module_id,
            timestamp_ms,
            pcrs: Pcrs { pcr0, pcr1, pcr2 },
            certificate,
            cabundle,
            public_key: optional("public_key")?,
            user_data: optional("user_data")?,
            nonce: optional("nonce")?,
        })
    }

    fn into_document(self, document: &[u8]) -> AttestedDocument {
        AttestedDocument {
            module_id: self.module_id,
            timestamp_ms: self.timestamp_ms,
            pcrs: self.pcrs,
            public_key: self.public_key,
            user_data: self.user_data,
            nonce: self.nonce,
            hash: document_hash(document),
        }
    }
}

/// The payload map of a document, as the NSM writes it (and as test
/// authorities write theirs).
pub fn encode_payload(
    module_id: &str,
    timestamp_ms: u64,
    pcrs: &[(u64, Vec<u8>)],
    certificate: &[u8],
    cabundle: &[Vec<u8>],
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> Vec<u8> {
    let bytes_or_null = |v: Option<&[u8]>| v.map_or(cbor::Value::Null, |b| cbor::Value::Bytes(b.to_vec()));
    cbor::encode(&cbor::Value::Map(vec![
        (cbor::Value::Text("module_id".into()), cbor::Value::Text(module_id.into())),
        (cbor::Value::Text("digest".into()), cbor::Value::Text("SHA384".into())),
        (cbor::Value::Text("timestamp".into()), cbor::Value::Unsigned(timestamp_ms)),
        (
            cbor::Value::Text("pcrs".into()),
            cbor::Value::Map(pcrs.iter().map(|(i, v)| (cbor::Value::Unsigned(*i), cbor::Value::Bytes(v.clone()))).collect()),
        ),
        (cbor::Value::Text("certificate".into()), cbor::Value::Bytes(certificate.to_vec())),
        (
            cbor::Value::Text("cabundle".into()),
            cbor::Value::Array(cabundle.iter().map(|c| cbor::Value::Bytes(c.clone())).collect()),
        ),
        (cbor::Value::Text("public_key".into()), cbor::Value::Null),
        (cbor::Value::Text("user_data".into()), bytes_or_null(user_data)),
        (cbor::Value::Text("nonce".into()), bytes_or_null(nonce)),
    ]))
}

/// A COSE_Sign1 document (tag 18) from its parts.
pub fn encode_cose_sign1(protected: &[u8], payload: &[u8], signature: &[u8]) -> Vec<u8> {
    cbor::encode(&cbor::Value::Tag(
        18,
        Box::new(cbor::Value::Array(vec![
            cbor::Value::Bytes(protected.to_vec()),
            cbor::Value::Map(Vec::new()),
            cbor::Value::Bytes(payload.to_vec()),
            cbor::Value::Bytes(signature.to_vec()),
        ])),
    ))
}

/// Why no document could be had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    /// `user_data` or `nonce` is longer than the NSM takes.
    TooLong,
    /// The NSM device could not be reached or refused the call.
    Device(String),
    /// The NSM answered something that is not an attestation; for an answer
    /// that is not CBOR, with the decoder's reason and the byte it stopped at.
    BadResponse(Cow<'static, str>),
}

impl AttestationError {
    /// [`AttestationError::BadResponse`] with a fixed text.
    pub const fn bad_response(what: &'static str) -> AttestationError {
        AttestationError::BadResponse(Cow::Borrowed(what))
    }
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttestationError::TooLong => f.write_str("user data or nonce is longer than 1024 bytes"),
            AttestationError::Device(what) => write!(f, "the NSM device: {what}"),
            AttestationError::BadResponse(what) => write!(f, "the NSM answered: {what}"),
        }
    }
}

impl std::error::Error for AttestationError {}

/// Where an enclave gets its own attestation documents.
pub trait AttestationSource {
    /// A document binding `user_data` and `nonce` (each at most
    /// [`MAX_USER_DATA_BYTES`]).
    fn attest(&mut self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, AttestationError>;
}

/// The Nitro Secure Module's device: one CBOR request in, one CBOR answer
/// out. The enclave program backs it with the `/dev/nsm` ioctl; tests use a
/// stand-in.
pub trait NsmDevice {
    /// Sends one request.
    fn call(&mut self, request: &[u8]) -> Result<Vec<u8>, AttestationError>;
}

/// The NSM-backed [`AttestationSource`]: asks the NSM for an `Attestation`.
pub struct NsmSource<D: NsmDevice> {
    device: D,
}

impl<D: NsmDevice> NsmSource<D> {
    /// A source on `device`.
    pub fn new(device: D) -> NsmSource<D> {
        NsmSource { device }
    }

    /// The NSM's request for an attestation document:
    /// `{"Attestation": {"user_data": ..., "nonce": ..., "public_key": null}}`.
    pub fn request(user_data: &[u8], nonce: &[u8]) -> Vec<u8> {
        cbor::encode(&cbor::Value::Map(vec![(
            cbor::Value::Text("Attestation".into()),
            cbor::Value::Map(vec![
                (cbor::Value::Text("user_data".into()), cbor::Value::Bytes(user_data.to_vec())),
                (cbor::Value::Text("nonce".into()), cbor::Value::Bytes(nonce.to_vec())),
                (cbor::Value::Text("public_key".into()), cbor::Value::Null),
            ]),
        )]))
    }

    /// Reads the NSM's answer: `{"Attestation": {"document": bytes}}`, or
    /// `{"Error": text}`. The document is a byte string as the NSM writes it;
    /// written as an array of unsigned integers each below 256 (how a CBOR
    /// writer that does not know the bytes are bytes would write them) it is
    /// taken too, the same bytes either way.
    pub fn read_response(response: &[u8]) -> Result<Vec<u8>, AttestationError> {
        let value = cbor::decode(response)
            .map_err(|e| AttestationError::BadResponse(Cow::Owned(format!("not CBOR: {e}"))))?;
        let cbor::Value::Map(mut fields) = value else {
            return Err(AttestationError::bad_response("not a map"));
        };
        if fields.len() != 1 {
            return Err(AttestationError::bad_response("not one answer"));
        }
        match fields.remove(0) {
            (cbor::Value::Text(kind), cbor::Value::Map(inner)) if kind == "Attestation" => {
                match inner.into_iter().find(|(k, _)| matches!(k, cbor::Value::Text(t) if t == "document")) {
                    Some((_, cbor::Value::Bytes(document))) => Ok(document),
                    Some((_, cbor::Value::Array(items))) => items
                        .into_iter()
                        .map(|item| match item {
                            cbor::Value::Unsigned(byte) => u8::try_from(byte).ok(),
                            _ => None,
                        })
                        .collect::<Option<Vec<u8>>>()
                        .ok_or(AttestationError::bad_response("a document array holds more than bytes")),
                    Some(_) => Err(AttestationError::bad_response("the document is not bytes")),
                    None => Err(AttestationError::bad_response("no document")),
                }
            }
            (cbor::Value::Text(kind), cbor::Value::Text(error)) if kind == "Error" => {
                Err(AttestationError::Device(error))
            }
            (cbor::Value::Text(kind), _) if kind == "Error" => Err(AttestationError::bad_response("an unreadable error")),
            _ => Err(AttestationError::bad_response("not an attestation")),
        }
    }
}

impl<D: NsmDevice> AttestationSource for NsmSource<D> {
    fn attest(&mut self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, AttestationError> {
        if user_data.len() > MAX_USER_DATA_BYTES || nonce.len() > MAX_USER_DATA_BYTES {
            return Err(AttestationError::TooLong);
        }
        let response = self.device.call(&Self::request(user_data, nonce))?;
        Self::read_response(&response)
    }
}

/// A stand-in attestation authority for tests: documents of the real
/// payload format whose COSE signature is replaced by an HMAC-SHA3-256 tag
/// under a key the test picks. It proves nothing about any enclave; the
/// enclave program never builds one and always uses [`NitroVerifier::aws`].
pub mod fake {
    use super::*;
    use crate::primitives::{ct_eq, hmac_sha3_256};
    use crate::traits::Clock;

    const FAKE_LABEL: &[u8] = b"ghost-seal/test-only/fake-attestation";

    /// A fake enclave's attestation source: it "measures" as `pcrs`.
    pub struct FakeSource {
        key: [u8; 32],
        pcrs: Pcrs,
        clock: Box<dyn Clock + Send>,
    }

    impl FakeSource {
        /// A source signing with test key `key`, reporting `pcrs`.
        pub fn new(key: [u8; 32], pcrs: Pcrs, clock: Box<dyn Clock + Send>) -> FakeSource {
            FakeSource { key, pcrs, clock }
        }
    }

    impl AttestationSource for FakeSource {
        fn attest(&mut self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, AttestationError> {
            if user_data.len() > MAX_USER_DATA_BYTES || nonce.len() > MAX_USER_DATA_BYTES {
                return Err(AttestationError::TooLong);
            }
            let pcrs = vec![
                (0, self.pcrs.pcr0.to_vec()),
                (1, self.pcrs.pcr1.to_vec()),
                (2, self.pcrs.pcr2.to_vec()),
            ];
            let payload = encode_payload(
                "fake-module",
                self.clock.now_unix() * 1000,
                &pcrs,
                b"fake certificate",
                &[b"fake root".to_vec()],
                Some(user_data),
                Some(nonce),
            );
            let protected = es384_protected_header();
            let tag = hmac_sha3_256(&self.key, &[FAKE_LABEL, &sig_structure(&protected, &payload)]);
            Ok(encode_cose_sign1(&protected, &payload, &tag))
        }
    }

    /// Verifies [`FakeSource`] documents made with the same test key.
    pub struct FakeVerifier {
        key: [u8; 32],
    }

    impl FakeVerifier {
        /// A verifier for test key `key`.
        pub fn new(key: [u8; 32]) -> FakeVerifier {
            FakeVerifier { key }
        }
    }

    impl AttestationVerifier for FakeVerifier {
        fn verify(&self, document: &[u8], now_unix: u64) -> Result<AttestedDocument, AttestationRejected> {
            let cose = CoseSign1::parse(document)?;
            let tag = hmac_sha3_256(&self.key, &[FAKE_LABEL, &cose.signed_bytes()]);
            if !ct_eq(&tag, &cose.signature) {
                return Err(AttestationRejected::BadSignature);
            }
            let payload = Payload::parse(&cose.payload)?;
            check_time(payload.timestamp_ms, now_unix, DEFAULT_MAX_AGE_SECS)?;
            Ok(payload.into_document(document))
        }
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

    fn bad(what: &'static str) -> AttestationRejected {
        AttestationRejected::BadChain(what)
    }

    fn ecdsa_sha384(algorithm: Tlv<'_>) -> Result<(), AttestationRejected> {
        let mut inner = algorithm.sequence().map_err(|_| bad("an algorithm is not a sequence"))?;
        let oid = inner.next(der::OID).map_err(|_| bad("an algorithm has no OID"))?;
        if oid.content != OID_ECDSA_SHA384 || !inner.is_empty() {
            return Err(bad("a signature is not ecdsa-with-SHA384"));
        }
        Ok(())
    }

    impl<'a> Certificate<'a> {
        pub(super) fn parse(bytes: &'a [u8]) -> Result<Certificate<'a>, AttestationRejected> {
            let whole = der::read_all(bytes).map_err(|_| bad("a certificate is not DER"))?;
            let mut cert = whole.sequence().map_err(|_| bad("a certificate is not a sequence"))?;
            let tbs_tlv = cert.next(der::SEQUENCE).map_err(|_| bad("no tbsCertificate"))?;
            ecdsa_sha384(cert.next(der::SEQUENCE).map_err(|_| bad("no signatureAlgorithm"))?)?;
            let signature_bits = cert.next(der::BIT_STRING).map_err(|_| bad("no signatureValue"))?;
            if !cert.is_empty() {
                return Err(bad("data after a certificate's signature"));
            }
            let signature = signature_bits.bits().map_err(|_| bad("a signature is not whole bytes"))?;

            let mut tbs = tbs_tlv.sequence().map_err(|_| bad("tbsCertificate is not a sequence"))?;
            let version = tbs.next(0xa0).map_err(|_| bad("not an X.509 v3 certificate"))?;
            if version.content != [der::INTEGER, 0x01, 0x02] {
                return Err(bad("not an X.509 v3 certificate"));
            }
            tbs.next(der::INTEGER).map_err(|_| bad("no serial number"))?;
            ecdsa_sha384(tbs.next(der::SEQUENCE).map_err(|_| bad("no signature algorithm"))?)?;
            let issuer = tbs.next(der::SEQUENCE).map_err(|_| bad("no issuer"))?.whole;
            let mut validity = tbs
                .next(der::SEQUENCE)
                .map_err(|_| bad("no validity"))?
                .sequence()
                .map_err(|_| bad("validity is not a sequence"))?;
            let not_before = der::time(validity.any().map_err(|_| bad("no notBefore"))?).map_err(|_| bad("bad notBefore"))?;
            let not_after = der::time(validity.any().map_err(|_| bad("no notAfter"))?).map_err(|_| bad("bad notAfter"))?;
            if !validity.is_empty() || not_after < not_before {
                return Err(bad("bad validity"));
            }
            let subject = tbs.next(der::SEQUENCE).map_err(|_| bad("no subject"))?.whole;
            let mut spki = tbs
                .next(der::SEQUENCE)
                .map_err(|_| bad("no public key"))?
                .sequence()
                .map_err(|_| bad("bad public key"))?;
            let mut algorithm = spki
                .next(der::SEQUENCE)
                .map_err(|_| bad("no key algorithm"))?
                .sequence()
                .map_err(|_| bad("bad key algorithm"))?;
            let key_type = algorithm.next(der::OID).map_err(|_| bad("no key type"))?;
            let curve = algorithm.next(der::OID).map_err(|_| bad("no curve"))?;
            if key_type.content != OID_EC_PUBLIC_KEY || curve.content != OID_SECP384R1 || !algorithm.is_empty() {
                return Err(bad("a public key is not P-384"));
            }
            let public_key = spki
                .next(der::BIT_STRING)
                .map_err(|_| bad("no public key bits"))?
                .bits()
                .map_err(|_| bad("bad public key bits"))?;
            if !spki.is_empty() {
                return Err(bad("data after a public key"));
            }

            let mut is_ca = false;
            let mut path_len = None;
            let mut key_cert_sign = None;
            while !tbs.is_empty() {
                let field = tbs.any().map_err(|_| bad("bad tbsCertificate"))?;
                match field.tag {
                    // issuerUniqueID and subjectUniqueID: carry nothing we use.
                    0x81 | 0x82 => {}
                    0xa3 => {
                        let mut wrapper = field.sequence_inside().map_err(|_| bad("bad extensions"))?;
                        let mut extensions =
                            wrapper.next(der::SEQUENCE).map_err(|_| bad("bad extensions"))?.sequence().map_err(|_| bad("bad extensions"))?;
                        if !wrapper.is_empty() {
                            return Err(bad("bad extensions"));
                        }
                        let mut seen: Vec<&[u8]> = Vec::new();
                        while !extensions.is_empty() {
                            let mut extension = extensions
                                .next(der::SEQUENCE)
                                .map_err(|_| bad("bad extension"))?
                                .sequence()
                                .map_err(|_| bad("bad extension"))?;
                            let id = extension.next(der::OID).map_err(|_| bad("an extension has no OID"))?.content;
                            if seen.contains(&id) {
                                return Err(bad("an extension appears twice"));
                            }
                            seen.push(id);
                            let mut critical = false;
                            let mut value = extension.any().map_err(|_| bad("an extension has no value"))?;
                            if value.tag == der::BOOLEAN {
                                critical = value.boolean().map_err(|_| bad("bad critical flag"))?;
                                value = extension.next(der::OCTET_STRING).map_err(|_| bad("an extension has no value"))?;
                            } else if value.tag != der::OCTET_STRING {
                                return Err(bad("an extension has no value"));
                            }
                            if !extension.is_empty() {
                                return Err(bad("data after an extension"));
                            }
                            if id == OID_BASIC_CONSTRAINTS {
                                let inner = der::read_all(value.content).map_err(|_| bad("bad basic constraints"))?;
                                let mut constraints = inner.sequence().map_err(|_| bad("bad basic constraints"))?;
                                if let Ok(flag) = constraints.next(der::BOOLEAN) {
                                    is_ca = flag.boolean().map_err(|_| bad("bad basic constraints"))?;
                                }
                                if let Ok(limit) = constraints.next(der::INTEGER) {
                                    path_len = Some(limit.small_unsigned().map_err(|_| bad("bad path length"))?);
                                }
                                if !constraints.is_empty() {
                                    return Err(bad("bad basic constraints"));
                                }
                            } else if id == OID_KEY_USAGE {
                                let inner = der::read_all(value.content).map_err(|_| bad("bad key usage"))?;
                                if inner.tag != der::BIT_STRING || inner.content.len() < 2 {
                                    return Err(bad("bad key usage"));
                                }
                                // keyCertSign is bit 5 of the first byte (MSB is bit 0).
                                key_cert_sign = Some(inner.content[1] & 0x04 != 0);
                            } else if critical {
                                return Err(bad("an unknown critical extension"));
                            }
                        }
                    }
                    _ => return Err(bad("an unknown tbsCertificate field")),
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
        pub(super) fn verify_signed_by(&self, issuer: &Certificate<'_>) -> Result<(), AttestationRejected> {
            let key = VerifyingKey::from_sec1_bytes(issuer.public_key)
                .map_err(|_| bad("a public key is not a P-384 point"))?;
            let signature = Signature::from_der(self.signature).map_err(|_| bad("a certificate signature is not DER"))?;
            key.verify(self.tbs, &signature).map_err(|_| bad("a certificate signature does not verify"))
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

/// A small CBOR (RFC 8949) reader and writer for attestation documents and
/// NSM requests: definite lengths only, no floats, simple values limited to
/// false, true and null, nesting at most 16 deep, no duplicate map keys.
/// The writer always uses the shortest heads.
pub mod cbor {
    use core::fmt;

    const MAX_DEPTH: usize = 16;

    /// A CBOR value.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Value {
        /// Major type 0.
        Unsigned(u64),
        /// Major type 1: the value is `-1 - n`.
        Negative(u64),
        /// Major type 2.
        Bytes(Vec<u8>),
        /// Major type 3.
        Text(String),
        /// Major type 4.
        Array(Vec<Value>),
        /// Major type 5, in the order written.
        Map(Vec<(Value, Value)>),
        /// Major type 6.
        Tag(u64, Box<Value>),
        /// false or true.
        Bool(bool),
        /// null.
        Null,
    }

    /// Bytes that are not CBOR this reader takes: which rule they break, and
    /// where.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CborError {
        /// The rule broken.
        pub reason: &'static str,
        /// The offset of the item that broke it (of the head byte, for an
        /// item whose length or content is wrong), from the start of the
        /// bytes decoded.
        pub at: usize,
        /// How many bytes were decoded.
        pub length: usize,
    }

    impl fmt::Display for CborError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{} at byte {} of {}", self.reason, self.at, self.length)
        }
    }

    impl std::error::Error for CborError {}

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
    pub fn encode(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        write(&mut out, value);
        out
    }

    /// Decodes exactly one value from all of `bytes`.
    pub fn decode(bytes: &[u8]) -> Result<Value, CborError> {
        let mut reader = Reader { bytes, at: 0, item: 0 };
        let value = reader.value(0)?;
        if reader.at != bytes.len() {
            reader.item = reader.at;
            return Err(reader.error("data after the value"));
        }
        Ok(value)
    }

    struct Reader<'a> {
        bytes: &'a [u8],
        at: usize,
        /// Where the item being read starts.
        item: usize,
    }

    impl Reader<'_> {
        fn error(&self, reason: &'static str) -> CborError {
            CborError { reason, at: self.item, length: self.bytes.len() }
        }

        fn take(&mut self, n: usize) -> Result<&[u8], CborError> {
            let end = self.at.checked_add(n).ok_or(self.error("too long"))?;
            let out = self.bytes.get(self.at..end).ok_or(self.error("truncated"))?;
            self.at = end;
            Ok(out)
        }

        fn argument(&mut self, info: u8) -> Result<u64, CborError> {
            Ok(match info {
                0..=23 => u64::from(info),
                24 => u64::from(self.take(1)?[0]),
                25 => u64::from(u16::from_be_bytes(self.take(2)?.try_into().expect("2 bytes"))),
                26 => u64::from(u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes"))),
                27 => u64::from_be_bytes(self.take(8)?.try_into().expect("8 bytes")),
                _ => return Err(self.error("indefinite or reserved length")),
            })
        }

        fn length(&mut self, info: u8) -> Result<usize, CborError> {
            let n = self.argument(info)?;
            // No item can be longer than what is left of the input.
            if n > (self.bytes.len() - self.at) as u64 {
                return Err(self.error("a length runs past the end"));
            }
            Ok(n as usize)
        }

        fn value(&mut self, depth: usize) -> Result<Value, CborError> {
            self.item = self.at;
            if depth > MAX_DEPTH {
                return Err(self.error("nested too deep"));
            }
            let initial = self.take(1)?[0];
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
                    let error = self.error("text is not UTF-8");
                    let text = core::str::from_utf8(self.take(n)?).map_err(|_| error)?;
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
                            // At the second key: the item just read.
                            return Err(self.error("a map key appears twice"));
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
                    _ => return Err(self.error("a float or simple value")),
                },
            })
        }
    }
}
