//! Real Nitro attestation documents, made by AWS Nitro hardware, through the
//! Seal's own code: the AWS verifier (signature and chain included), the
//! decoder's reasons when bytes are not CBOR, the NSM's answer as the NSM
//! writes it, and a key share carrying a real-size document end to end
//! through the giver's service and both parent proxies.
//!
//! The three documents are public test vectors, copied byte for byte (each
//! verifies under the pinned AWS root, which no copy with a changed byte
//! would):
//!
//! - `fixtures/nitro_document_sui.hex`: MystenLabs/sui,
//!   `crates/sui-types/benches/nitro_attestation_bench.rs` (a debug-mode
//!   enclave in us-east-1, 2024-11-14; PCR0 to PCR2 all zeros, `user_data`
//!   set, `public_key` and `nonce` null).
//! - `fixtures/nitro_document_base.hex`: base/base,
//!   `crates/proof/tee/nitro-verifier/src/verify.rs`, `ATTESTATION_HEX`
//!   (us-east-1, 2024-11-30; a 65-byte `public_key`, `user_data` and `nonce`
//!   null).
//! - `fixtures/nitro_document_nautilus.hex`: MystenLabs/nautilus,
//!   `move/weather-example/sources/weather.move`, `test_weather_flow`
//!   (us-east-1, 2025-04-15; a 32-byte `public_key`, `user_data` and `nonce`
//!   null).
//!
//! Each is about 4.5 KB, untagged (no COSE tag 18), with 16 PCRs of 48
//! bytes and four certificates in its bundle, where the tests' authority
//! writes about 1 KB, tagged, with five PCRs and two.

#[path = "fixtures/nitro_authority.rs"]
mod authority;
#[path = "fixtures/test_release_key.rs"]
mod release;

use std::io::Write;
use std::net::TcpListener;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use authority::{CertSpec, NOW, allowed_new, allowed_old, certificate, test_key};
use ghost_seal::attestation::cbor::{self, Value};
use ghost_seal::attestation::{
    AttestationError, AttestationRejected, AttestationSource, AttestationVerifier, AttestedDocument, NitroVerifier,
    NsmDevice, NsmSource, certificate_fingerprint, es384_protected_header, sig_structure,
};
use ghost_seal::enclave_serve::{
    ANSWER_OK, EnclaveAttestation, EnclaveService, KIND_KEY_SHARE, MemoryServiceLog, ServiceConfig, ServiceDeps,
    ServiceEvent,
};
use ghost_seal::enclave_tls::EnclaveTls;
use ghost_seal::key_share::{
    LogSide, MAX_FRAME_BYTES, Receiver, log_lines_to, package_log_line, read_frame, request_log_line, write_frame,
};
use ghost_seal::measurements::{Pcrs, TrustedList};
use ghost_seal::phone_attestation::answer_key;
use ghost_seal::primitives::sha3_256;
use ghost_seal::proxy::{
    BoundedService, DeadlineStream, MemoryLog, Proxy, ProxyLimits, ProxyLog, ServiceLimits, TcpConnector, UnixConnector,
};
use ghost_seal::{Clock, MasterKey, RelayLimits, SealError, SealRandom};
use ml_kem::{DecapsulationKey, KeyExport, MlKem768};
use p384::ecdsa::signature::Signer;
use p384::ecdsa::{Signature, SigningKey};
use release::TestOnlyReleaseKey;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// The real documents.

/// One real document and what it says.
struct RealDocument {
    name: &'static str,
    hex: &'static str,
    /// Its `timestamp`, milliseconds.
    timestamp_ms: u64,
    module_id: &'static str,
    /// The first bytes of its PCR0.
    pcr0_starts: [u8; 4],
    public_key_bytes: Option<usize>,
    user_data_bytes: Option<usize>,
}

const SUI: RealDocument = RealDocument {
    name: "sui",
    hex: include_str!("fixtures/nitro_document_sui.hex"),
    timestamp_ms: 0x0000_0193_2d12_39ca,
    module_id: "i-0f73a4b4cb74cc9f2-enc0192e4188fef781d",
    pcr0_starts: [0, 0, 0, 0],
    public_key_bytes: None,
    user_data_bytes: Some(32),
};

const BASE: RealDocument = RealDocument {
    name: "base",
    hex: include_str!("fixtures/nitro_document_base.hex"),
    timestamp_ms: 0x0000_0193_7de1_c543,
    module_id: "i-0de38b2b6853cc9e8-enc0193685e7fee7d85",
    pcr0_starts: [0xec, 0x74, 0xbf, 0xbe],
    public_key_bytes: Some(65),
    user_data_bytes: None,
};

const NAUTILUS: RealDocument = RealDocument {
    name: "nautilus",
    hex: include_str!("fixtures/nitro_document_nautilus.hex"),
    timestamp_ms: 0x0000_0196_3743_f8f0,
    module_id: "i-06e4b98c6549ff803-enc0196373b195fb723",
    pcr0_starts: [0xcb, 0xe1, 0xaf, 0xb6],
    public_key_bytes: Some(32),
    user_data_bytes: None,
};

const REAL: [&RealDocument; 3] = [&SUI, &BASE, &NAUTILUS];

fn from_hex(text: &str) -> Vec<u8> {
    let text = text.trim();
    assert!(text.len() % 2 == 0 && text.bytes().all(|c| c.is_ascii_hexdigit()), "a fixture is not hex");
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl RealDocument {
    fn bytes(&self) -> Vec<u8> {
        from_hex(self.hex)
    }

    /// A moment inside every certificate's validity, one second after the
    /// document was made.
    fn now(&self) -> u64 {
        self.timestamp_ms / 1000 + 1
    }

    fn verify(&self) -> Result<AttestedDocument, AttestationRejected> {
        NitroVerifier::aws().verify(&self.bytes(), self.now())
    }
}

/// Where the payload byte string starts in a document, and its length.
fn payload_span(document: &[u8]) -> (usize, usize) {
    // 0x84 (array of 4), 0x44 a1 01 38 22 (the protected header), 0xa0 (the
    // empty unprotected header), then the payload's head: 0x59 and a u16.
    assert_eq!(&document[..7], &[0x84, 0x44, 0xa1, 0x01, 0x38, 0x22, 0xa0], "an untagged ES384 COSE_Sign1");
    assert_eq!(document[7], 0x59, "a payload of 256 to 65535 bytes");
    let length = usize::from(u16::from_be_bytes([document[8], document[9]]));
    (10, length)
}

fn find(haystack: &[u8], needle: &[u8]) -> usize {
    haystack.windows(needle.len()).position(|w| w == needle).expect("the bytes are there")
}

#[test]
fn the_real_documents_are_real_size_and_shape() {
    for real in REAL {
        let document = real.bytes();
        assert!((4400..=4600).contains(&document.len()), "{}: {} bytes", real.name, document.len());
        // Untagged: the array head comes first.
        assert_eq!(document[0], 0x84, "{}", real.name);
        let (start, length) = payload_span(&document);
        let Ok(Value::Map(fields)) = cbor::decode(&document[start..start + length]) else {
            panic!("{}: the payload decodes to a map", real.name)
        };
        let pcrs = fields.iter().find(|(k, _)| *k == Value::Text("pcrs".into())).map(|(_, v)| v.clone());
        let Some(Value::Map(pcrs)) = pcrs else { panic!("{}: pcrs", real.name) };
        assert_eq!(pcrs.len(), 16, "{}", real.name);
        assert!(pcrs.iter().all(|(_, v)| matches!(v, Value::Bytes(b) if b.len() == 48)), "{}", real.name);
        let bundle = fields.iter().find(|(k, _)| *k == Value::Text("cabundle".into())).map(|(_, v)| v.clone());
        assert!(matches!(bundle, Some(Value::Array(certs)) if certs.len() == 4), "{}", real.name);
        // Some fields are null.
        assert!(fields.iter().any(|(_, v)| *v == Value::Null), "{}", real.name);
    }
}

#[test]
fn each_real_document_verifies_fully_under_the_aws_root() {
    for real in REAL {
        let document = real.bytes();
        let attested = real.verify().unwrap_or_else(|why| panic!("{}: {why}", real.name));
        assert_eq!(attested.timestamp_ms, real.timestamp_ms, "{}", real.name);
        assert_eq!(attested.module_id, real.module_id, "{}", real.name);
        assert_eq!(attested.pcrs.pcr0[..4], real.pcr0_starts, "{}", real.name);
        assert_eq!(attested.public_key.as_ref().map(Vec::len), real.public_key_bytes, "{}", real.name);
        assert_eq!(attested.user_data.as_ref().map(Vec::len), real.user_data_bytes, "{}", real.name);
        assert_eq!(attested.nonce, None, "{}", real.name);
        assert_eq!(attested.hash, ghost_seal::attestation::document_hash(&document), "{}", real.name);
    }
}

#[test]
fn a_real_document_with_one_byte_changed_is_refused() {
    for real in REAL {
        let document = real.bytes();
        // The last byte of the signature.
        let mut signature = document.clone();
        *signature.last_mut().unwrap() ^= 0x01;
        assert_eq!(
            NitroVerifier::aws().verify(&signature, real.now()),
            Err(AttestationRejected::BadSignature),
            "{}",
            real.name
        );
        // A byte of PCR15 (still 48 bytes of CBOR, so only the signature
        // can tell).
        let (start, length) = payload_span(&document);
        let pcr15 = start + find(&document[start..start + length], &[0x0f, 0x58, 0x30]) + 3;
        let mut payload = document.clone();
        payload[pcr15] ^= 0x80;
        assert_eq!(
            NitroVerifier::aws().verify(&payload, real.now()),
            Err(AttestationRejected::BadSignature),
            "{}",
            real.name
        );
    }
}

#[test]
fn a_real_document_is_still_checked_for_root_age_and_validity() {
    for real in REAL {
        let document = real.bytes();
        assert_eq!(
            NitroVerifier::with_root([7; 32]).verify(&document, real.now()),
            Err(AttestationRejected::WrongRoot),
            "{}",
            real.name
        );
        // Older than five minutes.
        assert_eq!(
            NitroVerifier::aws().verify(&document, real.now() + 300),
            Err(AttestationRejected::Expired),
            "{}",
            real.name
        );
        // Before its certificate was issued (and long before the document).
        assert_eq!(
            NitroVerifier::aws().verify(&document, real.now() - 86_400),
            Err(AttestationRejected::NotYetValid),
            "{}",
            real.name
        );
        // A day later its certificate has expired, whatever the allowed age.
        assert_eq!(
            NitroVerifier::aws().max_age(10 * 86_400).verify(&document, real.now() + 86_400),
            Err(AttestationRejected::Expired),
            "{}",
            real.name
        );
    }
}

#[test]
fn the_phones_port_of_the_check_takes_the_real_documents_too() {
    // The wallet core's copy of this verifier (what phones run on the Seal's
    // documents) must take what AWS writes as this one does, and say why
    // the same way when bytes are not CBOR.
    use ghost_wallet_core::seal_attestation::{AWS_NITRO_ROOT_SHA256, check_nitro_document};
    for real in REAL {
        let document = real.bytes();
        assert_eq!(check_nitro_document(&document, &AWS_NITRO_ROOT_SHA256, real.now()), Ok(()), "{}", real.name);
        let mut ten = document.clone();
        ten[10] = 0xaa;
        let seal = NitroVerifier::aws().verify(&ten, real.now()).unwrap_err().to_string();
        assert_eq!(check_nitro_document(&ten, &AWS_NITRO_ROOT_SHA256, real.now()), Err(seal.clone()), "{}", real.name);
        assert!(seal.contains("the payload is not CBOR: truncated at byte"), "{seal}");
    }
}

// ---------------------------------------------------------------------------
// The decoder's reasons.

#[test]
fn a_payload_that_is_not_cbor_says_why_and_where() {
    let document = SUI.bytes();
    let (start, length) = payload_span(&document);
    assert_eq!(length, 4385);

    // Ten fields announced, nine there: the tenth key runs off the end.
    let mut ten = document.clone();
    assert_eq!(ten[start], 0xa9);
    ten[start] = 0xaa;
    let why = NitroVerifier::aws().verify(&ten, SUI.now()).unwrap_err();
    assert!(matches!(why, AttestationRejected::Malformed(_)));
    assert_eq!(
        why.to_string(),
        "malformed attestation document: the payload is not CBOR: truncated at byte 4385 of 4385"
    );

    // `public_key: undefined` (simple value 23) instead of null.
    let mut undefined = document.clone();
    let null = find(&document[start..start + length], b"\x6apublic_key\xf6") + 11;
    undefined[start + null] = 0xf7;
    let why = NitroVerifier::aws().verify(&undefined, SUI.now()).unwrap_err();
    assert_eq!(
        why.to_string(),
        format!("malformed attestation document: the payload is not CBOR: a float or simple value at byte {null} of 4385")
    );

    // The same key twice: `user_data` renamed `timestamp` (both 9 bytes).
    let mut twice = document.clone();
    let user_data = find(&document[start..start + length], b"\x69user_data");
    twice[start + user_data + 1..start + user_data + 10].copy_from_slice(b"timestamp");
    let why = NitroVerifier::aws().verify(&twice, SUI.now()).unwrap_err();
    assert_eq!(
        why.to_string(),
        format!("malformed attestation document: the payload is not CBOR: a map key appears twice at byte {user_data} of 4385")
    );

    // A name that is not UTF-8.
    let mut not_text = document.clone();
    not_text[start + user_data + 1] = 0xff;
    let why = NitroVerifier::aws().verify(&not_text, SUI.now()).unwrap_err();
    assert_eq!(
        why.to_string(),
        format!("malformed attestation document: the payload is not CBOR: text is not UTF-8 at byte {user_data} of 4385")
    );
}

#[test]
fn a_document_that_is_not_cbor_says_why_and_where() {
    let document = SUI.bytes();
    // One byte short: the signature's 96 bytes run off the end. Its head is
    // the 98 bytes before the end.
    let short = &document[..document.len() - 1];
    let why = NitroVerifier::aws().verify(short, SUI.now()).unwrap_err();
    assert_eq!(
        why.to_string(),
        format!(
            "malformed attestation document: the document is not CBOR: a length runs past the end at byte {} of {}",
            document.len() - 98,
            short.len()
        )
    );
    // A byte after the document.
    let long = [&document[..], &[0x00]].concat();
    let why = NitroVerifier::aws().verify(&long, SUI.now()).unwrap_err();
    assert_eq!(
        why.to_string(),
        format!(
            "malformed attestation document: the document is not CBOR: data after the value at byte {} of {}",
            document.len(),
            long.len()
        )
    );
    // The reason carries a rule and a position only, never the bytes.
    assert!(!why.to_string().contains(&to_hex(&document[..8])));
}

#[test]
fn the_decoder_reports_the_byte_of_the_item_that_breaks_a_rule() {
    // [1, 2, h'00 00' with a length of 9]
    let error = cbor::decode(&[0x83, 0x01, 0x02, 0x49, 0x00, 0x00]).unwrap_err();
    assert_eq!((error.reason, error.at, error.length), ("a length runs past the end", 3, 6));
    assert_eq!(error.to_string(), "a length runs past the end at byte 3 of 6");
    // {1: 0, 1: 0}: the second key.
    let error = cbor::decode(&[0xa2, 0x01, 0x00, 0x01, 0x00]).unwrap_err();
    assert_eq!((error.reason, error.at), ("a map key appears twice", 3));
    // An indefinite-length array.
    let error = cbor::decode(&[0x82, 0x01, 0x9f, 0xff]).unwrap_err();
    assert_eq!((error.reason, error.at), ("indefinite or reserved length", 2));
    // A half float.
    let error = cbor::decode(&[0x81, 0xf9, 0x3c, 0x00]).unwrap_err();
    assert_eq!((error.reason, error.at), ("a float or simple value", 1));
    // Text that is not UTF-8.
    let error = cbor::decode(&[0x82, 0x00, 0x62, 0xc3, 0x28]).unwrap_err();
    assert_eq!((error.reason, error.at), ("text is not UTF-8", 2));
}

// ---------------------------------------------------------------------------
// The NSM's answer.

/// A stand-in NSM device: answers `response` to an attestation request.
struct CannedNsm {
    response: Vec<u8>,
}

impl NsmDevice for CannedNsm {
    fn call(&mut self, request: &[u8]) -> Result<Vec<u8>, AttestationError> {
        assert_eq!(request, NsmSource::<CannedNsm>::request(&[0x5a; 32], &[0x6e; 32]));
        Ok(self.response.clone())
    }
}

fn nsm_answer(document: Value) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![(
        Value::Text("Attestation".into()),
        Value::Map(vec![(Value::Text("document".into()), document)]),
    )]))
}

#[test]
fn a_real_size_nsm_answer_gives_the_document_byte_for_byte() {
    for real in REAL {
        let document = real.bytes();
        let response = nsm_answer(Value::Bytes(document.clone()));
        assert!(response.len() > 4500, "{}", real.name);
        assert_eq!(NsmSource::<CannedNsm>::read_response(&response).unwrap(), document, "{}", real.name);

        // Through the source, as the enclave asks for one.
        let mut source = NsmSource::new(CannedNsm { response });
        let got = source.attest(&[0x5a; 32], &[0x6e; 32]).unwrap();
        assert_eq!(got, document, "{}", real.name);
        assert_eq!(NitroVerifier::aws().verify(&got, real.now()).unwrap().module_id, real.module_id);
    }
}

#[test]
fn an_nsm_answer_with_the_document_as_an_array_of_bytes_gives_the_same_bytes() {
    let document = BASE.bytes();
    let array = Value::Array(document.iter().map(|b| Value::Unsigned(u64::from(*b))).collect());
    let response = nsm_answer(array);
    let read = NsmSource::<CannedNsm>::read_response(&response).unwrap();
    assert_eq!(read, document);
    assert!(NitroVerifier::aws().verify(&read, BASE.now()).is_ok());

    // An item that is not a byte is refused.
    let mut items: Vec<Value> = document.iter().map(|b| Value::Unsigned(u64::from(*b))).collect();
    items[100] = Value::Unsigned(256);
    assert_eq!(
        NsmSource::<CannedNsm>::read_response(&nsm_answer(Value::Array(items.clone()))),
        Err(AttestationError::bad_response("a document array holds more than bytes"))
    );
    items[100] = Value::Text("x".into());
    assert!(NsmSource::<CannedNsm>::read_response(&nsm_answer(Value::Array(items))).is_err());
    assert_eq!(
        NsmSource::<CannedNsm>::read_response(&nsm_answer(Value::Text("document".into()))),
        Err(AttestationError::bad_response("the document is not bytes"))
    );
}

#[test]
fn an_nsm_answer_that_is_not_cbor_says_why_and_where() {
    let response = nsm_answer(Value::Bytes(SUI.bytes()));
    // Cut where a buffer too small would cut it.
    let cut = &response[..4096];
    let why = NsmSource::<CannedNsm>::read_response(cut).unwrap_err();
    assert_eq!(why.to_string(), "the NSM answered: not CBOR: a length runs past the end at byte 23 of 4096");
    assert_eq!(
        NsmSource::<CannedNsm>::read_response(&cbor::encode(&Value::Map(vec![(
            Value::Text("Error".into()),
            Value::Text("InvalidArgument".into())
        )]))),
        Err(AttestationError::Device("InvalidArgument".into()))
    );
}

// ---------------------------------------------------------------------------
// A real-size document carried end to end.

/// A test authority shaped like AWS's: a root, three CAs below it (regional,
/// zonal, instance, path lengths 2, 1 and 0) and the document's certificate,
/// each with a long name and an extra non-critical extension as AWS's carry
/// (a CRL address), and documents untagged with 16 PCRs. Test keys only.
struct AwsShapedAuthority {
    bundle: Vec<Vec<u8>>,
    leaf: Vec<u8>,
    leaf_key: SigningKey,
}

const OID_CRL_DISTRIBUTION_POINTS: &[u8] = &[0x55, 0x1d, 0x1f];

impl AwsShapedAuthority {
    fn new() -> AwsShapedAuthority {
        let keys: Vec<SigningKey> = (0..5u8).map(|i| test_key(0x61 + i)).collect();
        let names = [
            "aws.nitro-enclaves.test-root".to_owned(),
            "4b8c5a6e1f2d3c40.us-east-1.aws.nitro-enclaves.test".to_owned(),
            "9a1b2c3d4e5f6071.zonal.us-east-1.aws.nitro-enclaves.test".to_owned(),
            "i-0f73a4b4cb74cc9f2.us-east-1.aws.nitro-enclaves.test".to_owned(),
            "i-0f73a4b4cb74cc9f2-enc0192e4188fef781d.us-east-1.aws.test".to_owned(),
        ];
        let year = 365 * 86_400;
        let validity = [(NOW - 5 * year, NOW + 25 * year), (NOW - 86_400, NOW + 20 * 86_400), (NOW - 3600, NOW + 5 * 86_400), (NOW - 3600, NOW + 86_400), (NOW - 3600, NOW + 3 * 3600)];
        let ca = [Some(None), Some(Some(2)), Some(Some(1)), Some(Some(0)), None];
        let mut certs = Vec::new();
        for i in 0..5 {
            let issuer = if i == 0 { 0 } else { i - 1 };
            let crl = format!("http://crl.test.aws-nitro-enclaves.example/crl/{}-{:0>200}.crl", names[i], i);
            let spec = CertSpec {
                serial: 0x10 + i as u8,
                issuer: names[issuer].clone(),
                subject: names[i].clone(),
                not_before: validity[i].0,
                not_after: validity[i].1,
                ca: ca[i],
                key_cert_sign: ca[i].is_some(),
                extra_extensions: vec![(OID_CRL_DISTRIBUTION_POINTS.to_vec(), false, authority::seq(&[authority::tlv(0x86, crl.as_bytes())]))],
            };
            certs.push(certificate(&spec, &keys[i], &keys[issuer]));
        }
        let leaf = certs.pop().unwrap();
        AwsShapedAuthority { bundle: certs, leaf, leaf_key: keys[4].clone() }
    }

    fn root_fingerprint(&self) -> [u8; 32] {
        certificate_fingerprint(&self.bundle[0])
    }

    fn verifier(&self) -> NitroVerifier {
        NitroVerifier::with_root(self.root_fingerprint())
    }

    /// A document as the NSM writes one: untagged, 16 PCRs, PCR4 the
    /// instance's, `public_key` null.
    fn document(&self, pcrs: &Pcrs, user_data: &[u8], nonce: &[u8]) -> Vec<u8> {
        let text = |t: &str| Value::Text(t.into());
        let pcr = |i: u64| match i {
            0 => pcrs.pcr0.to_vec(),
            1 => pcrs.pcr1.to_vec(),
            2 => pcrs.pcr2.to_vec(),
            3 => [0x63; 48].to_vec(),
            4 => [0x44; 48].to_vec(),
            _ => vec![0; 48],
        };
        let payload = cbor::encode(&Value::Map(vec![
            (text("module_id"), text("i-0f73a4b4cb74cc9f2-enc0192e4188fef781d")),
            (text("digest"), text("SHA384")),
            (text("timestamp"), Value::Unsigned(NOW * 1000 + 417)),
            (text("pcrs"), Value::Map((0..16).map(|i| (Value::Unsigned(i), Value::Bytes(pcr(i)))).collect())),
            (text("certificate"), Value::Bytes(self.leaf.clone())),
            (text("cabundle"), Value::Array(self.bundle.iter().map(|c| Value::Bytes(c.clone())).collect())),
            (text("public_key"), Value::Null),
            (text("user_data"), Value::Bytes(user_data.to_vec())),
            (text("nonce"), Value::Bytes(nonce.to_vec())),
        ]));
        let protected = es384_protected_header();
        let signature: Signature = self.leaf_key.sign(&sig_structure(&protected, &payload));
        cbor::encode(&Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(Vec::new()),
            Value::Bytes(payload),
            Value::Bytes(signature.to_bytes().to_vec()),
        ]))
    }
}

fn aws_shaped() -> Arc<AwsShapedAuthority> {
    static AUTHORITY: OnceLock<Arc<AwsShapedAuthority>> = OnceLock::new();
    AUTHORITY.get_or_init(|| Arc::new(AwsShapedAuthority::new())).clone()
}

/// One enclave's NSM: its documents, each kept as it was made.
struct ShapedSource {
    authority: Arc<AwsShapedAuthority>,
    pcrs: Pcrs,
    made: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl AttestationSource for ShapedSource {
    fn attest(&mut self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, AttestationError> {
        let document = self.authority.document(&self.pcrs, user_data, nonce);
        self.made.lock().unwrap().push(document.clone());
        Ok(document)
    }
}

/// The AWS-shaped root's verifier, keeping each document it is given.
struct KeepingVerifier {
    inner: NitroVerifier,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl AttestationVerifier for KeepingVerifier {
    fn verify(&self, document: &[u8], now_unix: u64) -> Result<AttestedDocument, AttestationRejected> {
        self.seen.lock().unwrap().push(document.to_vec());
        self.inner.verify(document, now_unix)
    }
}

/// The giving enclave's attestation: its NSM and the verifier it checks
/// receivers with.
struct GiverAttestation {
    pcrs: Pcrs,
    made: Arc<Mutex<Vec<Vec<u8>>>>,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl EnclaveAttestation for GiverAttestation {
    fn source(&self) -> Result<Box<dyn AttestationSource>, String> {
        Ok(Box::new(ShapedSource { authority: aws_shaped(), pcrs: self.pcrs, made: self.made.clone() }))
    }

    fn verifier(&self) -> Box<dyn AttestationVerifier> {
        Box::new(KeepingVerifier { inner: aws_shaped().verifier(), seen: self.seen.clone() })
    }
}

struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

/// Deterministic test randomness.
struct TestRandom(u64);

impl SealRandom for TestRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), SealError> {
        for chunk in out.chunks_mut(32) {
            self.0 += 1;
            let block = sha3_256(&[b"real nitro documents test random", &self.0.to_be_bytes()]);
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        Ok(())
    }
}

/// The test M (a fixed pattern: test only).
fn test_m() -> MasterKey {
    let mut bytes = [0x4d; 32];
    bytes[0] = 0x01;
    MasterKey::take(&mut bytes)
}

fn trusted() -> TrustedList {
    let release = TestOnlyReleaseKey::new();
    let mut trusted = TrustedList::compiled_in();
    trusted.install_signed(&release.sign(include_str!("fixtures/measurements.json")), &release.release_key()).unwrap();
    trusted
}

static NEXT_SOCKET: AtomicUsize = AtomicUsize::new(0);

fn socket_path(what: &str) -> PathBuf {
    let n = NEXT_SOCKET.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!("seal-real-nitro-{what}-{}-{n}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

/// The giver's lines, as the enclave program would print them.
fn giver_lines() -> &'static Mutex<Vec<String>> {
    static LINES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    LINES.get_or_init(|| Mutex::new(Vec::new()))
}

fn keep_giver_line(line: &str) {
    giver_lines().lock().unwrap().push(line.to_owned());
}

/// A giving region, as deployed but in-process: the enclave's service (the
/// real `EnclaveService` holding M, on a bounded service over a Unix socket
/// standing in for vsock 5001), its parent's inbound proxy (TCP to that
/// socket), and the joining region's parent outbound proxy (a Unix socket
/// standing in for vsock 5002, to the inbound proxy over TCP).
struct Regions {
    /// Where the joining enclave connects (its parent's port 5002).
    outbound: PathBuf,
    /// The giver's own documents, as its NSM made them.
    giver_made: Arc<Mutex<Vec<Vec<u8>>>>,
    /// The documents the giver was given to check (the receiver's first).
    giver_seen: Arc<Mutex<Vec<Vec<u8>>>>,
    service_log: Arc<MemoryServiceLog>,
    proxy_log: Arc<MemoryLog>,
}

fn start_regions() -> Regions {
    log_lines_to(keep_giver_line);
    let giver_made = Arc::new(Mutex::new(Vec::new()));
    let giver_seen = Arc::new(Mutex::new(Vec::new()));
    let attestation = GiverAttestation { pcrs: allowed_old(), made: giver_made.clone(), seen: giver_seen.clone() };
    let kem = DecapsulationKey::<MlKem768>::from_seed(ml_kem::Seed::from([0x24; 64]));
    let service_log = Arc::new(MemoryServiceLog::default());
    let service = Arc::new(EnclaveService::new(
        EnclaveTls::generate().unwrap(),
        kem.encapsulation_key().to_bytes().to_vec(),
        trusted(),
        Arc::new(attestation),
        ServiceDeps::none(),
        ServiceConfig {
            measurement: allowed_old().pcr0,
            answer_lifetime_secs: 120,
            relay_limits: RelayLimits::default(),
            clock: Arc::new(FixedClock(NOW)),
        },
        service_log.clone(),
    ));
    service.install_master(test_m());

    let enclave_path = socket_path("enclave");
    let enclave = UnixListener::bind(&enclave_path).unwrap();
    let limits = ServiceLimits { workers: 2, queue: 4, connection_time: Duration::from_secs(30) };
    thread::spawn(move || {
        let _ = BoundedService::new(enclave, limits)
            .serve(move |stream: &mut DeadlineStream<UnixStream>| service.serve_connection(stream), None);
    });

    let proxy_log = Arc::new(MemoryLog::default());
    let inbound = TcpListener::bind("127.0.0.1:0").unwrap();
    let inbound_address = inbound.local_addr().unwrap().to_string();
    let log: Arc<dyn ProxyLog> = proxy_log.clone();
    thread::spawn(move || Proxy::new(inbound, UnixConnector(enclave_path), ProxyLimits::default(), log).serve(None));

    let outbound_path = socket_path("outbound");
    let outbound = UnixListener::bind(&outbound_path).unwrap();
    let log: Arc<dyn ProxyLog> = proxy_log.clone();
    thread::spawn(move || {
        Proxy::new(outbound, TcpConnector(inbound_address), ProxyLimits::default(), log).serve(None)
    });
    Regions { outbound: outbound_path, giver_made, giver_seen, service_log, proxy_log }
}

/// How the joining enclave writes its request frame.
#[derive(Clone, Copy)]
enum Writes {
    /// One frame, as `write_frame` writes it.
    Whole,
    /// A few bytes at a time, with pauses: the stream splits it anywhere.
    Dribbled,
}

/// What the joining enclave sent and got.
struct Joined {
    sent_document: Vec<u8>,
    request: Vec<u8>,
    package: Vec<u8>,
    master: MasterKey,
    receiver_seen: Vec<Vec<u8>>,
}

/// Joins as `seal_enclave`'s `join` does: a receiver, the request through
/// the outbound proxy, the package back, opened.
fn join(regions: &Regions, writes: Writes, seed: u64) -> Joined {
    let authority = aws_shaped();
    let made = Arc::new(Mutex::new(Vec::new()));
    let mut source = ShapedSource { authority: authority.clone(), pcrs: allowed_new(), made: made.clone() };
    let receiver = Receiver::start(&mut source, &mut TestRandom(seed)).unwrap();
    let sent_document = made.lock().unwrap()[0].clone();
    let request = receiver.request();
    let frame = [&[KIND_KEY_SHARE][..], &request].concat();

    let stream = UnixStream::connect(&regions.outbound).unwrap();
    let mut peer = DeadlineStream::new(stream, Instant::now() + Duration::from_secs(30));
    match writes {
        Writes::Whole => write_frame(&mut peer, &frame).unwrap(),
        Writes::Dribbled => {
            let whole = [&(frame.len() as u32).to_be_bytes()[..], &frame].concat();
            for chunk in whole.chunks(997) {
                peer.write_all(chunk).unwrap();
                peer.flush().unwrap();
                thread::sleep(Duration::from_millis(2));
            }
        }
    }
    let answer = read_frame(&mut peer).unwrap();
    peer.close();
    let Some((&ANSWER_OK, package)) = answer.split_first() else {
        panic!("the giver refused: {}", String::from_utf8_lossy(&answer[1..]))
    };
    let seen = Arc::new(Mutex::new(Vec::new()));
    let verifier = KeepingVerifier { inner: authority.verifier(), seen: seen.clone() };
    let (master, build) = receiver.accept(package, &verifier, &trusted(), NOW).unwrap();
    assert_eq!(build, trusted().check(&allowed_old()).unwrap().clone());
    let receiver_seen = seen.lock().unwrap().clone();
    Joined { sent_document, request, package: package.to_vec(), master, receiver_seen }
}

fn same_m(a: &MasterKey, b: &MasterKey) -> bool {
    answer_key(a) == answer_key(b)
}

#[test]
fn the_aws_shaped_document_is_real_size_and_verifies() {
    let authority = aws_shaped();
    let document = authority.document(&allowed_new(), &[0x5a; 32], &[0x6e; 32]);
    assert!(document.len() >= 4500, "{} bytes", document.len());
    assert!(document.len() <= 6000, "{} bytes", document.len());
    assert_eq!(document[0], 0x84, "untagged");
    let attested = authority.verifier().verify(&document, NOW).unwrap();
    assert_eq!(attested.pcrs, allowed_new());
    assert_eq!(attested.nonce, Some(vec![0x6e; 32]));
    // Not under the AWS root.
    assert_eq!(NitroVerifier::aws().verify(&document, NOW), Err(AttestationRejected::WrongRoot));
}

#[test]
fn a_real_size_document_arrives_byte_for_byte_through_the_proxies() {
    let regions = start_regions();
    for (writes, seed) in [(Writes::Whole, 1), (Writes::Dribbled, 2)] {
        let before = regions.giver_seen.lock().unwrap().len();
        let joined = join(&regions, writes, seed);
        assert!(joined.sent_document.len() >= 4500);
        assert!(same_m(&joined.master, &test_m()));

        // The receiver's document, as the giver was given it to check.
        let giver_seen = regions.giver_seen.lock().unwrap()[before..].to_vec();
        assert_eq!(giver_seen.len(), 2, "the receiver's document, then its own");
        assert_eq!(giver_seen[0], joined.sent_document, "the receiver's document arrived changed");
        // And the giver's own, as the receiver was given it.
        let giver_document = giver_seen[1].clone();
        assert!(regions.giver_made.lock().unwrap().contains(&giver_document));
        assert_eq!(joined.receiver_seen, vec![giver_document.clone()], "the giver's document arrived changed");
        assert_eq!(&joined.package[8..8 + giver_document.len()], &giver_document[..]);

        // The giver's lines match the receiver's but for the side.
        let sent = request_log_line(LogSide::ReceiverSends, &joined.request);
        let received = request_log_line(LogSide::GiverReceived, &joined.request);
        assert_eq!(sent.replace("receiver sends", "giver received"), received);
        let lines = giver_lines().lock().unwrap().clone();
        assert!(lines.contains(&received), "the giver logged {lines:?}");
        assert!(lines.contains(&package_log_line(LogSide::GiverSends, &joined.package)));
        let sha256 = to_hex(&Sha256::digest(&joined.sent_document));
        assert!(
            sent.ends_with(&format!("; attestation document {} bytes, sha256 {sha256}", joined.sent_document.len())),
            "{sent}"
        );
        assert!(sent.starts_with(&format!("key share: receiver sends request {} bytes, sha256 ", joined.request.len())));
        // Lengths and hashes only.
        for line in &lines {
            assert!(!line.contains(&to_hex(&joined.sent_document[..16])), "{line}");
            assert!(line.len() < 300, "{line}");
        }
    }
    let events = regions.service_log.0.lock().unwrap().clone();
    assert_eq!(events.iter().filter(|e| matches!(e, ServiceEvent::HandedMaster { .. })).count(), 2, "{events:?}");
    assert!(!regions.proxy_log.0.lock().unwrap().is_empty());
}

#[test]
fn a_request_cut_on_the_way_is_logged_with_its_own_hash() {
    let authority = aws_shaped();
    let made = Arc::new(Mutex::new(Vec::new()));
    let mut source = ShapedSource { authority, pcrs: allowed_new(), made: made.clone() };
    let request = Receiver::start(&mut source, &mut TestRandom(9)).unwrap().request();
    let document = made.lock().unwrap()[0].clone();
    let whole = request_log_line(LogSide::GiverReceived, &request);
    assert!(whole.ends_with(&format!("attestation document {} bytes, sha256 {}", document.len(), to_hex(&Sha256::digest(&document)))));
    // Cut: the document cannot be read out, the request's own hash differs.
    let cut = request_log_line(LogSide::GiverReceived, &request[..request.len() - 1]);
    assert!(cut.ends_with("; no readable attestation document"), "{cut}");
    assert!(cut.starts_with(&format!("key share: giver received request {} bytes, sha256 ", request.len() - 1)));
    assert_ne!(cut.split(';').next(), whole.split(';').next());
}

#[test]
fn the_largest_request_frame_passes_through_the_proxies_whole() {
    // A frame of the largest size, of a pattern no stage could pass by
    // accident, through both proxies to a stand-in service that echoes what
    // it read.
    let enclave_path = socket_path("echo");
    let enclave = UnixListener::bind(&enclave_path).unwrap();
    let limits = ServiceLimits { workers: 1, queue: 2, connection_time: Duration::from_secs(30) };
    thread::spawn(move || {
        let _ = BoundedService::new(enclave, limits).serve(
            |stream: &mut DeadlineStream<UnixStream>| {
                if let Ok(frame) = read_frame(stream) {
                    let _ = write_frame(stream, &Sha256::digest(&frame));
                }
            },
            None,
        );
    });
    let inbound = TcpListener::bind("127.0.0.1:0").unwrap();
    let inbound_address = inbound.local_addr().unwrap().to_string();
    let log: Arc<dyn ProxyLog> = Arc::new(MemoryLog::default());
    let in_log = log.clone();
    thread::spawn(move || Proxy::new(inbound, UnixConnector(enclave_path), ProxyLimits::default(), in_log).serve(None));
    let outbound_path = socket_path("echo-outbound");
    let outbound = UnixListener::bind(&outbound_path).unwrap();
    thread::spawn(move || Proxy::new(outbound, TcpConnector(inbound_address), ProxyLimits::default(), log).serve(None));

    let frame: Vec<u8> = (0..MAX_FRAME_BYTES).map(|i| (i * 7 + i / 251) as u8).collect();
    let mut peer = DeadlineStream::new(UnixStream::connect(&outbound_path).unwrap(), Instant::now() + Duration::from_secs(30));
    write_frame(&mut peer, &frame).unwrap();
    let digest = read_frame(&mut peer).unwrap();
    assert_eq!(digest, Sha256::digest(&frame).to_vec());
}
