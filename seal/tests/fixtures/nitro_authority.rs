//! A test attestation authority: a P-384 root, an intermediate and a
//! document-signing certificate, built as real X.509 DER, and Nitro-format
//! COSE_Sign1 documents signed with them. Test code only: the keys are fixed
//! test patterns, and nothing outside the tests ever signs.
#![allow(dead_code)]

use std::cell::Cell;
use std::rc::Rc;

use ghost_seal::attestation::cbor::{self, Value};
use ghost_seal::attestation::{
    AttestationError, AttestationSource, NitroVerifier, certificate_fingerprint, encode_cose_sign1,
    es384_protected_header, sig_structure,
};
use ghost_seal::measurements::Pcrs;
use p384::ecdsa::signature::Signer;
use p384::ecdsa::{Signature, SigningKey};

/// 2027-01-15, the tests' "now".
pub const NOW: u64 = 1_800_000_000;

const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_SECP384R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
    out
}

pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn unsigned_integer(bytes: &[u8]) -> Vec<u8> {
    let mut b = bytes;
    while b.len() > 1 && b[0] == 0 && b[1] & 0x80 == 0 {
        b = &b[1..];
    }
    let mut content = Vec::new();
    if b[0] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(b);
    tlv(0x02, &content)
}

fn algorithm() -> Vec<u8> {
    seq(&[tlv(0x06, OID_ECDSA_SHA384)])
}

pub fn name(common_name: &str) -> Vec<u8> {
    seq(&[tlv(0x31, &seq(&[tlv(0x06, OID_COMMON_NAME), tlv(0x0c, common_name.as_bytes())]))])
}

fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

pub fn time(unix: u64) -> Vec<u8> {
    let unix = unix as i64;
    let (year, month, day) = civil(unix.div_euclid(86_400));
    let rest = unix.rem_euclid(86_400);
    let (h, m, s) = (rest / 3600, rest % 3600 / 60, rest % 60);
    if (1950..2050).contains(&year) {
        tlv(0x17, format!("{:02}{month:02}{day:02}{h:02}{m:02}{s:02}Z", year % 100).as_bytes())
    } else {
        tlv(0x18, format!("{year:04}{month:02}{day:02}{h:02}{m:02}{s:02}Z").as_bytes())
    }
}

/// ECDSA r || s as a DER `SEQUENCE { INTEGER r, INTEGER s }`.
fn signature_der(signature: &Signature) -> Vec<u8> {
    let raw = signature.to_bytes();
    seq(&[unsigned_integer(&raw[..48]), unsigned_integer(&raw[48..])])
}

pub fn public_key_point(key: &SigningKey) -> Vec<u8> {
    key.verifying_key().to_sec1_point(false).as_bytes().to_vec()
}

/// A test signing key from a one-byte pattern (test only).
pub fn test_key(pattern: u8) -> SigningKey {
    let mut bytes = [pattern; 48];
    bytes[0] = 0x01;
    SigningKey::from_slice(&bytes).expect("a test scalar below the order")
}

/// What a certificate says, before it is signed.
#[derive(Clone)]
pub struct CertSpec {
    pub serial: u8,
    pub issuer: String,
    pub subject: String,
    pub not_before: u64,
    pub not_after: u64,
    /// `Some(path length)` for a CA, `None` for the document's certificate.
    pub ca: Option<Option<u8>>,
    pub key_cert_sign: bool,
    /// Extra extensions: (OID, critical, value).
    pub extra_extensions: Vec<(Vec<u8>, bool, Vec<u8>)>,
}

pub fn certificate(spec: &CertSpec, subject_key: &SigningKey, issuer_key: &SigningKey) -> Vec<u8> {
    let spki = seq(&[
        seq(&[tlv(0x06, OID_EC_PUBLIC_KEY), tlv(0x06, OID_SECP384R1)]),
        tlv(0x03, &[&[0u8][..], &public_key_point(subject_key)].concat()),
    ]);
    let constraints = match spec.ca {
        Some(Some(limit)) => seq(&[tlv(0x01, &[0xff]), tlv(0x02, &[limit])]),
        Some(None) => seq(&[tlv(0x01, &[0xff])]),
        None => seq(&[]),
    };
    let usage = if spec.key_cert_sign { tlv(0x03, &[0x01, 0x06]) } else { tlv(0x03, &[0x07, 0x80]) };
    let mut extensions = vec![
        seq(&[tlv(0x06, OID_BASIC_CONSTRAINTS), tlv(0x01, &[0xff]), tlv(0x04, &constraints)]),
        seq(&[tlv(0x06, OID_KEY_USAGE), tlv(0x01, &[0xff]), tlv(0x04, &usage)]),
    ];
    for (oid, critical, value) in &spec.extra_extensions {
        let mut parts = vec![tlv(0x06, oid)];
        if *critical {
            parts.push(tlv(0x01, &[0xff]));
        }
        parts.push(tlv(0x04, value));
        extensions.push(seq(&parts));
    }
    let tbs = seq(&[
        tlv(0xa0, &tlv(0x02, &[0x02])),
        tlv(0x02, &[spec.serial]),
        algorithm(),
        name(&spec.issuer),
        seq(&[time(spec.not_before), time(spec.not_after)]),
        name(&spec.subject),
        spki,
        tlv(0xa3, &seq(&extensions)),
    ]);
    let signature: Signature = issuer_key.sign(&tbs);
    seq(&[tbs, algorithm(), tlv(0x03, &[&[0u8][..], &signature_der(&signature)].concat())])
}

/// The three certificates' specs, which a test may change before building.
#[derive(Clone)]
pub struct Profile {
    pub root: CertSpec,
    pub intermediate: CertSpec,
    pub leaf: CertSpec,
    /// Sign the leaf with this key instead of the intermediate's.
    pub leaf_signed_by: Option<u8>,
}

impl Profile {
    pub fn standard(now: u64) -> Profile {
        let year = 365 * 86_400;
        Profile {
            root: CertSpec {
                serial: 1,
                issuer: "test.nitro-root".into(),
                subject: "test.nitro-root".into(),
                not_before: now - 5 * year,
                not_after: now + 25 * year,
                ca: Some(None),
                key_cert_sign: true,
                extra_extensions: Vec::new(),
            },
            intermediate: CertSpec {
                serial: 2,
                issuer: "test.nitro-root".into(),
                subject: "test.region".into(),
                not_before: now - 86_400,
                not_after: now + 30 * 86_400,
                ca: Some(Some(0)),
                key_cert_sign: true,
                extra_extensions: Vec::new(),
            },
            leaf: CertSpec {
                serial: 3,
                issuer: "test.region".into(),
                subject: "test.enclave-host".into(),
                not_before: now - 3600,
                not_after: now + 3 * 3600,
                ca: None,
                key_cert_sign: false,
                extra_extensions: Vec::new(),
            },
            leaf_signed_by: None,
        }
    }
}

/// A test Nitro authority.
pub struct Authority {
    pub root: Vec<u8>,
    pub intermediate: Vec<u8>,
    pub leaf: Vec<u8>,
    leaf_key: SigningKey,
    pub now: u64,
}

impl Authority {
    /// An authority whose keys come from `seed` (test patterns).
    pub fn new(seed: u8) -> Authority {
        Authority::with_profile(seed, Profile::standard(NOW))
    }

    pub fn with_profile(seed: u8, profile: Profile) -> Authority {
        let root_key = test_key(seed);
        let intermediate_key = test_key(seed.wrapping_add(1));
        let leaf_key = test_key(seed.wrapping_add(2));
        let root = certificate(&profile.root, &root_key, &root_key);
        let intermediate = certificate(&profile.intermediate, &intermediate_key, &root_key);
        let leaf_issuer = match profile.leaf_signed_by {
            Some(pattern) => test_key(pattern),
            None => intermediate_key,
        };
        let leaf = certificate(&profile.leaf, &leaf_key, &leaf_issuer);
        Authority { root, intermediate, leaf, leaf_key, now: NOW }
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        certificate_fingerprint(&self.root)
    }

    /// A verifier pinned to this authority's root.
    pub fn verifier(&self) -> NitroVerifier {
        NitroVerifier::with_root(self.fingerprint())
    }

    /// The payload fields of a document, for a test to change.
    pub fn fields(&self, pcrs: &Pcrs, user_data: &[u8], nonce: &[u8], timestamp_ms: u64) -> Vec<(Value, Value)> {
        let text = |t: &str| Value::Text(t.into());
        vec![
            (text("module_id"), text("i-0test-enc0test")),
            (text("digest"), text("SHA384")),
            (text("timestamp"), Value::Unsigned(timestamp_ms)),
            (
                text("pcrs"),
                Value::Map(vec![
                    (Value::Unsigned(0), Value::Bytes(pcrs.pcr0.to_vec())),
                    (Value::Unsigned(1), Value::Bytes(pcrs.pcr1.to_vec())),
                    (Value::Unsigned(2), Value::Bytes(pcrs.pcr2.to_vec())),
                    (Value::Unsigned(3), Value::Bytes(vec![0; 48])),
                    (Value::Unsigned(4), Value::Bytes(vec![0x44; 48])),
                ]),
            ),
            (text("certificate"), Value::Bytes(self.leaf.clone())),
            (text("cabundle"), Value::Array(vec![Value::Bytes(self.root.clone()), Value::Bytes(self.intermediate.clone())])),
            (text("public_key"), Value::Null),
            (text("user_data"), Value::Bytes(user_data.to_vec())),
            (text("nonce"), Value::Bytes(nonce.to_vec())),
        ]
    }

    /// Signs a payload as the NSM would.
    pub fn sign_payload(&self, payload: &[u8]) -> Vec<u8> {
        let protected = es384_protected_header();
        let signature: Signature = self.leaf_key.sign(&sig_structure(&protected, payload));
        encode_cose_sign1(&protected, payload, &signature.to_bytes())
    }

    pub fn sign_fields(&self, fields: Vec<(Value, Value)>) -> Vec<u8> {
        self.sign_payload(&cbor::encode(&Value::Map(fields)))
    }

    /// A good document made now.
    pub fn document(&self, pcrs: &Pcrs, user_data: &[u8], nonce: &[u8]) -> Vec<u8> {
        self.sign_fields(self.fields(pcrs, user_data, nonce, self.now * 1000))
    }
}

/// One test enclave's NSM: documents from `authority` with this enclave's PCRs.
pub struct AuthoritySource {
    pub authority: Rc<Authority>,
    pub pcrs: Pcrs,
    /// Milliseconds added to the authority's time, moved by the test.
    pub offset_ms: Rc<Cell<u64>>,
}

impl AuthoritySource {
    pub fn new(authority: Rc<Authority>, pcrs: Pcrs) -> AuthoritySource {
        AuthoritySource { authority, pcrs, offset_ms: Rc::new(Cell::new(0)) }
    }
}

impl AttestationSource for AuthoritySource {
    fn attest(&mut self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, AttestationError> {
        let at = self.authority.now * 1000 + self.offset_ms.get();
        Ok(self.authority.sign_fields(self.authority.fields(&self.pcrs, user_data, nonce, at)))
    }
}

pub fn pcrs(a: u8, b: u8, c: u8) -> Pcrs {
    Pcrs { pcr0: [a; 48], pcr1: [b; 48], pcr2: [c; 48] }
}

/// Builds in `tests/fixtures/measurements.json`.
pub fn allowed_old() -> Pcrs {
    pcrs(0xa1, 0xb1, 0xc1)
}
pub fn allowed_new() -> Pcrs {
    pcrs(0xa2, 0xb1, 0xc2)
}
pub fn revoked() -> Pcrs {
    pcrs(0xa0, 0xb0, 0xc0)
}
pub fn unlisted() -> Pcrs {
    pcrs(0xd1, 0xb1, 0xd2)
}
