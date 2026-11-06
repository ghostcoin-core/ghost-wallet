//! The Nitro attestation verifier, against documents a test authority signs
//! (real X.509 and COSE, test keys), the NSM-backed source, the fake, and
//! the phones' attestation.

#[path = "fixtures/nitro_authority.rs"]
mod authority;

use std::rc::Rc;

use authority::{Authority, AuthoritySource, NOW, Profile, allowed_new, allowed_old, pcrs, revoked, unlisted};
use ghost_seal::attestation::cbor::{self, Value};
use ghost_seal::attestation::fake::{FakeSource, FakeVerifier};
use ghost_seal::attestation::{
    AWS_NITRO_ROOT_SHA256, AttestationError, AttestationRejected, AttestationSource, AttestationVerifier,
    DEFAULT_MAX_AGE_SECS, NitroVerifier, NsmDevice, NsmSource, document_hash, encode_cose_sign1,
};
use ghost_seal::measurements::{MeasurementList, MeasurementRefused};
use ghost_seal::phone_attestation::{self, ANSWER_KEY_BYTES, KEM_KEY_BYTES, PhoneAttestationRejected};
use ghost_seal::{Clock, MasterKey, PhoneSecret};

const FIXTURE: &str = include_str!("fixtures/measurements.json");

fn good(authority: &Authority) -> Vec<u8> {
    authority.document(&allowed_old(), b"user data", b"a nonce")
}

fn verify(authority: &Authority, document: &[u8]) -> Result<ghost_seal::attestation::AttestedDocument, AttestationRejected> {
    authority.verifier().verify(document, NOW)
}

/// The document with `fields` changed.
fn with_fields(authority: &Authority, change: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
    let mut fields = authority.fields(&allowed_old(), b"user data", b"a nonce", NOW * 1000);
    change(&mut fields);
    authority.sign_fields(fields)
}

fn key(name: &str) -> Value {
    Value::Text(name.into())
}

fn remove(fields: &mut Vec<(Value, Value)>, name: &str) {
    fields.retain(|(k, _)| *k != key(name));
}

fn set(fields: &mut [(Value, Value)], name: &str, value: Value) {
    for (k, v) in fields.iter_mut() {
        if *k == key(name) {
            *v = value.clone();
        }
    }
}

#[test]
fn the_pinned_aws_root_is_the_fingerprint_aws_publishes() {
    let published = "64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B";
    let bytes: Vec<u8> = published.split(':').map(|h| u8::from_str_radix(h, 16).unwrap()).collect();
    assert_eq!(bytes, AWS_NITRO_ROOT_SHA256);
}

#[test]
fn a_good_document_verifies_and_says_what_it_binds() {
    let authority = Authority::new(0x21);
    let document = good(&authority);
    let attested = verify(&authority, &document).expect("a good document verifies");
    assert_eq!(attested.pcrs, allowed_old());
    assert_eq!(attested.user_data.as_deref(), Some(&b"user data"[..]));
    assert_eq!(attested.nonce.as_deref(), Some(&b"a nonce"[..]));
    assert_eq!(attested.public_key, None);
    assert_eq!(attested.module_id, "i-0test-enc0test");
    assert_eq!(attested.timestamp_ms, NOW * 1000);
    assert_eq!(attested.hash, document_hash(&document));
}

#[test]
fn an_untagged_cose_sign1_verifies_too() {
    let authority = Authority::new(0x21);
    let Value::Tag(18, inner) = cbor::decode(&good(&authority)).unwrap() else { panic!("tagged") };
    let untagged = cbor::encode(&inner);
    assert!(verify(&authority, &untagged).is_ok());
    let other_tag = cbor::encode(&Value::Tag(98, inner));
    assert!(matches!(verify(&authority, &other_tag), Err(AttestationRejected::Malformed(_))));
}

#[test]
fn a_bad_signature_is_refused() {
    let authority = Authority::new(0x21);
    let document = good(&authority);
    // The signature is the last 96 bytes.
    let mut flipped = document.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert_eq!(verify(&authority, &flipped), Err(AttestationRejected::BadSignature));
}

#[test]
fn a_tampered_payload_is_refused() {
    let authority = Authority::new(0x21);
    let document = good(&authority);
    // Swap the signed payload for one claiming another build, keeping the signature.
    let Value::Tag(18, inner) = cbor::decode(&document).unwrap() else { panic!("tagged") };
    let Value::Array(parts) = *inner else { panic!("array") };
    let Value::Bytes(signature) = &parts[3] else { panic!("bytes") };
    let mut fields = authority.fields(&allowed_new(), b"user data", b"a nonce", NOW * 1000);
    set(&mut fields, "user_data", Value::Bytes(b"other data".to_vec()));
    let forged = encode_cose_sign1(
        &ghost_seal::attestation::es384_protected_header(),
        &cbor::encode(&Value::Map(fields)),
        signature,
    );
    assert_eq!(verify(&authority, &forged), Err(AttestationRejected::BadSignature));
}

#[test]
fn a_document_signed_by_another_key_is_refused() {
    let authority = Authority::new(0x21);
    let mut profile = Profile::standard(NOW);
    profile.leaf_signed_by = Some(0x77);
    let forged = Authority::with_profile(0x21, profile);
    // Same root, but the document's certificate is not signed by the intermediate.
    assert_eq!(forged.fingerprint(), authority.fingerprint());
    assert!(matches!(verify(&authority, &good(&forged)), Err(AttestationRejected::BadChain(_))));
}

#[test]
fn the_wrong_root_is_refused() {
    let authority = Authority::new(0x21);
    let other = Authority::new(0x51);
    assert_eq!(other.verifier().verify(&good(&authority), NOW), Err(AttestationRejected::WrongRoot));
    // The real verifier never trusts a test root.
    assert_eq!(NitroVerifier::aws().verify(&good(&authority), NOW), Err(AttestationRejected::WrongRoot));
    // A bundle that leaves out the root.
    let no_root = with_fields(&authority, |f| {
        set(f, "cabundle", Value::Array(vec![Value::Bytes(authority.intermediate.clone())]))
    });
    assert_eq!(verify(&authority, &no_root), Err(AttestationRejected::WrongRoot));
}

#[test]
fn an_issuer_that_is_not_a_ca_or_may_not_sign_is_refused() {
    let mut profile = Profile::standard(NOW);
    profile.intermediate.ca = None;
    let authority = Authority::with_profile(0x21, profile);
    assert!(matches!(verify(&authority, &good(&authority)), Err(AttestationRejected::BadChain(_))));

    let mut profile = Profile::standard(NOW);
    profile.intermediate.key_cert_sign = false;
    let authority = Authority::with_profile(0x21, profile);
    assert!(matches!(verify(&authority, &good(&authority)), Err(AttestationRejected::BadChain(_))));

    let mut profile = Profile::standard(NOW);
    profile.leaf.issuer = "test.other-region".into();
    let authority = Authority::with_profile(0x21, profile);
    assert!(matches!(verify(&authority, &good(&authority)), Err(AttestationRejected::BadChain(_))));
}

#[test]
fn an_unknown_critical_extension_is_refused_and_a_non_critical_one_is_not() {
    let unknown = vec![0x2b, 0x06, 0x01, 0x04, 0x01, 0x99, 0x01];
    let mut profile = Profile::standard(NOW);
    profile.leaf.extra_extensions.push((unknown.clone(), false, vec![0x05, 0x00]));
    let authority = Authority::with_profile(0x21, profile);
    assert!(verify(&authority, &good(&authority)).is_ok());

    let mut profile = Profile::standard(NOW);
    profile.leaf.extra_extensions.push((unknown, true, vec![0x05, 0x00]));
    let authority = Authority::with_profile(0x21, profile);
    assert!(matches!(verify(&authority, &good(&authority)), Err(AttestationRejected::BadChain(_))));
}

#[test]
fn an_expired_document_or_certificate_is_refused() {
    let authority = Authority::new(0x21);
    let document = good(&authority);
    let verifier = authority.verifier();
    assert!(verifier.verify(&document, NOW + DEFAULT_MAX_AGE_SECS).is_ok());
    assert_eq!(verifier.verify(&document, NOW + DEFAULT_MAX_AGE_SECS + 1), Err(AttestationRejected::Expired));
    // The document's certificate lasts three hours.
    let long = authority.verifier().max_age(24 * 3600);
    assert_eq!(long.verify(&document, NOW + 4 * 3600), Err(AttestationRejected::Expired));
    // An old document, signed by a certificate still valid.
    let old = with_fields(&authority, |f| set(f, "timestamp", Value::Unsigned((NOW - 3600) * 1000)));
    assert_eq!(verify(&authority, &old), Err(AttestationRejected::Expired));
    // An expired intermediate.
    let mut profile = Profile::standard(NOW);
    profile.intermediate.not_after = NOW - 1;
    let expired = Authority::with_profile(0x21, profile);
    assert_eq!(verify(&expired, &good(&expired)), Err(AttestationRejected::Expired));
}

#[test]
fn a_document_or_certificate_from_the_future_is_refused() {
    let authority = Authority::new(0x21);
    let ahead = with_fields(&authority, |f| set(f, "timestamp", Value::Unsigned((NOW + 600) * 1000)));
    assert_eq!(verify(&authority, &ahead), Err(AttestationRejected::NotYetValid));
    let mut profile = Profile::standard(NOW);
    profile.leaf.not_before = NOW + 60;
    let early = Authority::with_profile(0x21, profile);
    assert_eq!(verify(&early, &good(&early)), Err(AttestationRejected::NotYetValid));
}

#[test]
fn a_missing_field_is_refused() {
    let authority = Authority::new(0x21);
    for name in ["module_id", "digest", "timestamp", "pcrs", "certificate", "cabundle"] {
        let document = with_fields(&authority, |f| remove(f, name));
        assert_eq!(verify(&authority, &document), Err(AttestationRejected::MissingField(name)), "without {name}");
    }
    let no_pcr2 = with_fields(&authority, |f| {
        set(
            f,
            "pcrs",
            Value::Map(vec![
                (Value::Unsigned(0), Value::Bytes(vec![0xa1; 48])),
                (Value::Unsigned(1), Value::Bytes(vec![0xb1; 48])),
            ]),
        )
    });
    assert!(matches!(verify(&authority, &no_pcr2), Err(AttestationRejected::MissingField(_))));
    // The optional fields may be left out.
    let bare = with_fields(&authority, |f| {
        remove(f, "public_key");
        remove(f, "user_data");
        remove(f, "nonce");
    });
    let attested = verify(&authority, &bare).unwrap();
    assert_eq!((attested.user_data, attested.nonce), (None, None));
}

#[test]
fn an_extra_unknown_field_is_refused() {
    let authority = Authority::new(0x21);
    let extra = with_fields(&authority, |f| f.push((key("debug"), Value::Bool(true))));
    assert_eq!(verify(&authority, &extra), Err(AttestationRejected::UnknownField));
    let number_key = with_fields(&authority, |f| f.push((Value::Unsigned(7), Value::Null)));
    assert_eq!(verify(&authority, &number_key), Err(AttestationRejected::UnknownField));
}

#[test]
fn the_wrong_digest_is_refused() {
    let authority = Authority::new(0x21);
    let sha256 = with_fields(&authority, |f| set(f, "digest", key("SHA256")));
    assert_eq!(verify(&authority, &sha256), Err(AttestationRejected::WrongDigest));
    let short_pcr = with_fields(&authority, |f| {
        set(
            f,
            "pcrs",
            Value::Map(vec![
                (Value::Unsigned(0), Value::Bytes(vec![0xa1; 32])),
                (Value::Unsigned(1), Value::Bytes(vec![0xb1; 48])),
                (Value::Unsigned(2), Value::Bytes(vec![0xc1; 48])),
            ]),
        )
    });
    assert!(matches!(verify(&authority, &short_pcr), Err(AttestationRejected::Malformed(_))));
}

#[test]
fn fields_of_the_wrong_type_or_size_are_refused() {
    let authority = Authority::new(0x21);
    let cases: Vec<(&str, Value)> = vec![
        ("module_id", key("")),
        ("timestamp", Value::Unsigned(0)),
        ("timestamp", key("now")),
        ("user_data", Value::Bytes(vec![0; 1025])),
        ("nonce", key("text")),
        ("cabundle", Value::Array(Vec::new())),
        ("certificate", Value::Bytes(Vec::new())),
        ("pcrs", Value::Map(Vec::new())),
    ];
    for (name, value) in cases {
        let document = with_fields(&authority, |f| set(f, name, value.clone()));
        assert!(matches!(verify(&authority, &document), Err(AttestationRejected::Malformed(_))), "{name}: {value:?}");
    }
}

#[test]
fn not_cose_or_not_es384_is_refused() {
    let authority = Authority::new(0x21);
    for bytes in [&b""[..], b"\x84\x40", b"not cbor at all", &[0xff; 40]] {
        assert!(matches!(verify(&authority, bytes), Err(AttestationRejected::Malformed(_))));
    }
    let document = good(&authority);
    assert!(verify(&authority, &document[..document.len() - 10]).is_err());
    let Value::Tag(18, inner) = cbor::decode(&document).unwrap() else { panic!("tagged") };
    let Value::Array(mut parts) = *inner else { panic!("array") };
    // ES256 ({1: -7}) instead of ES384.
    parts[0] = Value::Bytes(cbor::encode(&Value::Map(vec![(Value::Unsigned(1), Value::Negative(6))])));
    let es256 = cbor::encode(&Value::Tag(18, Box::new(Value::Array(parts.clone()))));
    assert!(matches!(verify(&authority, &es256), Err(AttestationRejected::Malformed(_))));
    parts.pop();
    let three = cbor::encode(&Value::Array(parts));
    assert!(matches!(verify(&authority, &three), Err(AttestationRejected::Malformed(_))));
}

#[test]
fn cbor_round_trips_and_refuses_what_it_does_not_take() {
    let value = Value::Map(vec![
        (Value::Unsigned(1), Value::Negative(34)),
        (key("big"), Value::Unsigned(u64::MAX)),
        (key("bytes"), Value::Bytes(vec![7; 300])),
        (key("list"), Value::Array(vec![Value::Bool(true), Value::Null, Value::Tag(18, Box::new(Value::Bool(false)))])),
    ]);
    assert_eq!(cbor::decode(&cbor::encode(&value)).unwrap(), value);
    assert!(cbor::decode(&[0x5f, 0x40, 0xff]).is_err(), "indefinite length");
    assert!(cbor::decode(&[0xf9, 0x3c, 0x00]).is_err(), "a float");
    assert!(cbor::decode(&[0xa2, 0x01, 0x01, 0x01, 0x02]).is_err(), "a duplicate key");
    assert!(cbor::decode(&[0x5a, 0xff, 0xff, 0xff, 0xff]).is_err(), "a length past the end");
    assert!(cbor::decode(&[0x01, 0x02]).is_err(), "trailing data");
    assert!(cbor::decode(&[0x81; 40]).is_err(), "nested too deep");
}

/// An NSM stand-in: checks the request is the NSM's attestation request
/// and answers with a document from the test authority.
struct TestNsm {
    authority: Authority,
    answer_error: bool,
}

impl NsmDevice for TestNsm {
    fn call(&mut self, request: &[u8]) -> Result<Vec<u8>, AttestationError> {
        let Value::Map(outer) = cbor::decode(request).unwrap() else { panic!("a map") };
        assert_eq!(outer.len(), 1);
        assert_eq!(outer[0].0, key("Attestation"));
        let Value::Map(inner) = &outer[0].1 else { panic!("a map") };
        let get = |name: &str| inner.iter().find(|(k, _)| *k == key(name)).map(|(_, v)| v.clone()).unwrap();
        assert_eq!(get("public_key"), Value::Null);
        let (Value::Bytes(user_data), Value::Bytes(nonce)) = (get("user_data"), get("nonce")) else { panic!("bytes") };
        if self.answer_error {
            return Ok(cbor::encode(&Value::Map(vec![(key("Error"), key("InvalidArgument"))])));
        }
        let document = self.authority.document(&allowed_old(), &user_data, &nonce);
        Ok(cbor::encode(&Value::Map(vec![(
            key("Attestation"),
            Value::Map(vec![(key("document"), Value::Bytes(document))]),
        )])))
    }
}

#[test]
fn the_nsm_source_asks_for_an_attestation_and_reads_the_document() {
    let mut source = NsmSource::new(TestNsm { authority: Authority::new(0x21), answer_error: false });
    let document = source.attest(b"bound data", b"fresh nonce").unwrap();
    let attested = Authority::new(0x21).verifier().verify(&document, NOW).unwrap();
    assert_eq!(attested.user_data.as_deref(), Some(&b"bound data"[..]));
    assert_eq!(attested.nonce.as_deref(), Some(&b"fresh nonce"[..]));
    assert_eq!(source.attest(&[0; 1025], b""), Err(AttestationError::TooLong));

    let mut failing = NsmSource::new(TestNsm { authority: Authority::new(0x21), answer_error: true });
    assert_eq!(failing.attest(b"x", b"y"), Err(AttestationError::Device("InvalidArgument".into())));
    assert!(NsmSource::<TestNsm>::read_response(b"\xa0").is_err());
    assert!(NsmSource::<TestNsm>::read_response(&cbor::encode(&Value::Map(vec![(key("Other"), Value::Null)]))).is_err());
}

#[derive(Clone, Copy)]
struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

#[test]
fn the_fake_verifies_only_its_own_key_and_still_checks_the_payload() {
    let mut source = FakeSource::new([7; 32], allowed_old(), Box::new(FixedClock(NOW)));
    let document = source.attest(b"data", b"nonce").unwrap();
    let attested = FakeVerifier::new([7; 32]).verify(&document, NOW).unwrap();
    assert_eq!(attested.pcrs, allowed_old());
    assert_eq!(FakeVerifier::new([8; 32]).verify(&document, NOW), Err(AttestationRejected::BadSignature));
    assert_eq!(FakeVerifier::new([7; 32]).verify(&document, NOW + 3600), Err(AttestationRejected::Expired));
    // A fake document is never a Nitro document.
    assert!(Authority::new(0x21).verifier().verify(&document, NOW).is_err());
}

fn answer_key() -> Vec<u8> {
    let mut bytes = [0x42u8; 32];
    phone_attestation::answer_key(&MasterKey::take(&mut bytes))
}

fn kem_key() -> Vec<u8> {
    PhoneSecret::from_seed(&mut [0x24; 64]).public_key()
}

#[test]
fn a_phone_attestation_binds_both_keys_and_the_challenge() {
    let authority = Rc::new(Authority::new(0x21));
    let list = MeasurementList::parse(FIXTURE).unwrap();
    let (answer, kem) = (answer_key(), kem_key());
    assert_eq!((answer.len(), kem.len()), (ANSWER_KEY_BYTES, KEM_KEY_BYTES));
    let challenge = [0x5a; 32];
    let mut source = AuthoritySource::new(authority.clone(), allowed_new());
    let bytes = phone_attestation::make(&mut source, &answer, &kem, &challenge).unwrap();
    let seal = phone_attestation::verify(&bytes, &challenge, &authority.verifier(), &list, NOW).unwrap();
    assert_eq!(seal.answer_key, answer);
    assert_eq!(seal.kem_key, kem);
    assert_eq!(seal.build.name, "seal-2026-11-01");
    assert_eq!(seal.document.user_data.as_deref(), Some(&phone_attestation::binding(&answer, &kem, &challenge)[..]));

    // Another challenge: an old attestation replayed.
    assert_eq!(
        phone_attestation::verify(&bytes, &[0x5b; 32], &authority.verifier(), &list, NOW),
        Err(PhoneAttestationRejected::Binding)
    );
    // A key swapped after the document was made.
    let mut swapped = bytes.clone();
    let at = swapped.len() - KEM_KEY_BYTES - 1;
    swapped[at] ^= 0x01;
    assert_eq!(
        phone_attestation::verify(&swapped, &challenge, &authority.verifier(), &list, NOW),
        Err(PhoneAttestationRejected::Binding)
    );
    // The app's pinned list is empty until the first build is published: every Seal is refused.
    assert_eq!(
        phone_attestation::verify(&bytes, &challenge, &authority.verifier(), &MeasurementList::empty(), NOW),
        Err(PhoneAttestationRejected::Measurement(MeasurementRefused::NotListed))
    );
    assert!(matches!(
        phone_attestation::verify(&bytes, &challenge, &Authority::new(0x51).verifier(), &list, NOW),
        Err(PhoneAttestationRejected::Document(AttestationRejected::WrongRoot))
    ));
    assert!(matches!(
        phone_attestation::verify(&bytes[..bytes.len() - 1], &challenge, &authority.verifier(), &list, NOW),
        Err(PhoneAttestationRejected::Malformed(_))
    ));
}

#[test]
fn a_phone_attestation_from_a_revoked_or_unlisted_build_is_refused() {
    let authority = Rc::new(Authority::new(0x21));
    let list = MeasurementList::parse(FIXTURE).unwrap();
    let challenge = [0x5a; 32];
    for (measured, why) in [
        (revoked(), MeasurementRefused::Revoked { name: "seal-2026-09-01".into() }),
        (unlisted(), MeasurementRefused::NotListed),
        (pcrs(0xa1, 0xb1, 0xc2), MeasurementRefused::NotListed),
        (pcrs(0, 0, 0), MeasurementRefused::DebugMode),
    ] {
        let mut source = AuthoritySource::new(authority.clone(), measured);
        let bytes = phone_attestation::make(&mut source, &answer_key(), &kem_key(), &challenge).unwrap();
        assert_eq!(
            phone_attestation::verify(&bytes, &challenge, &authority.verifier(), &list, NOW),
            Err(PhoneAttestationRejected::Measurement(why))
        );
    }
    let mut source = AuthoritySource::new(authority, allowed_old());
    assert!(phone_attestation::make(&mut source, &[0; 10], &kem_key(), &challenge).is_err());
}
