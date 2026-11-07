//! The phone's check of the Seal's `GPA2` Nitro attestation
//! (core/src/seal_attestation.rs), against documents a test authority signs
//! (tests/support/nitro_authority.rs). No test uses the AWS root to accept a
//! document and none touches the network.

#[path = "support/nitro_authority.rs"]
mod nitro_authority;

use ghost_wallet_core::seal_attestation::{
    AWS_NITRO_ROOT_SHA256, AttestationRefusal, PinnedSealBuild, SealAttestationCheck, VerifiedSeal,
    check_nitro_document, seal_attestation_challenge, verify_seal_attestation, verify_with_root,
};
use ghost_wallet_core::seal_open::phone_key_of;
use ml_dsa::{ExpandedSigningKey, MlDsa65, Seed};
use nitro_authority::{Authority, NOW, Pcrs, Profile, Value, cbor, encode_cose_sign1, es384_protected_header, pcrs};
use sha3::{Digest, Sha3_256};

const CHALLENGE: [u8; 32] = [0x5c; 32];
const CERT_HASH: [u8; 32] = [0x7e; 32];

fn allowed() -> Pcrs {
    pcrs(0xa2, 0xb1, 0xc2)
}

fn revoked() -> Pcrs {
    pcrs(0xa0, 0xb0, 0xc0)
}

fn build(name: &str, p: Pcrs, allowed: bool) -> PinnedSealBuild {
    PinnedSealBuild { name: name.into(), pcr0: p.pcr0.to_vec(), pcr1: p.pcr1.to_vec(), pcr2: p.pcr2.to_vec(), allowed }
}

/// The app's pinned list in these tests: an old allowed build, the current one and a revoked one.
fn pinned() -> Vec<PinnedSealBuild> {
    vec![
        build("seal-test-old", pcrs(0xa1, 0xb1, 0xc1), true),
        build("seal-test-new", allowed(), true),
        build("seal-test-revoked", revoked(), false),
    ]
}

fn verifying_key(seed: u8) -> Vec<u8> {
    ExpandedSigningKey::<MlDsa65>::from_seed(&Seed::from([seed; 32])).verifying_key().encode().to_vec()
}

fn kem_key(seed: u8) -> Vec<u8> {
    phone_key_of(&[seed; 64])
}

/// SHA3-256 of the domain, both keys, the certificate hash and the challenge, written out here.
fn binding(verifying_key: &[u8], kem_key: &[u8], cert_hash: &[u8], challenge: &[u8]) -> Vec<u8> {
    let mut hash = Sha3_256::new();
    hash.update(b"ghost-seal/v2/phone-attestation");
    hash.update(verifying_key);
    hash.update(kem_key);
    hash.update(cert_hash);
    hash.update(challenge);
    hash.finalize().to_vec()
}

fn layout(magic: &[u8; 4], document: &[u8], verifying_key: &[u8], kem_key: &[u8], cert_hash: &[u8]) -> Vec<u8> {
    let mut out = magic.to_vec();
    out.extend_from_slice(&(document.len() as u32).to_be_bytes());
    out.extend_from_slice(document);
    out.extend_from_slice(verifying_key);
    out.extend_from_slice(kem_key);
    out.extend_from_slice(cert_hash);
    out
}

/// A Seal's attestation: the keys, the certificate hash and the document, each changeable.
struct Seal {
    authority: Authority,
    pcrs: Pcrs,
    verifying_key: Vec<u8>,
    kem_key: Vec<u8>,
    cert_hash: Vec<u8>,
    challenge: Vec<u8>,
}

impl Seal {
    fn new() -> Seal {
        Seal::with(Authority::new(0x10))
    }

    fn with(authority: Authority) -> Seal {
        Seal {
            authority,
            pcrs: allowed(),
            verifying_key: verifying_key(7),
            kem_key: kem_key(9),
            cert_hash: CERT_HASH.to_vec(),
            challenge: CHALLENGE.to_vec(),
        }
    }

    fn user_data(&self) -> Vec<u8> {
        binding(&self.verifying_key, &self.kem_key, &self.cert_hash, &self.challenge)
    }

    fn fields(&self) -> Vec<(Value, Value)> {
        self.authority.fields(&self.pcrs, &self.user_data(), self.authority.now * 1000)
    }

    fn document(&self) -> Vec<u8> {
        self.authority.sign_fields(self.fields())
    }

    fn attestation_of(&self, document: &[u8]) -> Vec<u8> {
        layout(b"GPA2", document, &self.verifying_key, &self.kem_key, &self.cert_hash)
    }

    fn attestation(&self) -> Vec<u8> {
        self.attestation_of(&self.document())
    }
}

fn check(attestation: Vec<u8>) -> SealAttestationCheck {
    SealAttestationCheck {
        attestation,
        challenge: CHALLENGE.to_vec(),
        tls_cert_sha256: CERT_HASH.to_vec(),
        pinned_builds: pinned(),
        now: NOW,
    }
}

fn verify(check: &SealAttestationCheck, authority: &Authority) -> Result<VerifiedSeal, AttestationRefusal> {
    verify_with_root(check, &authority.fingerprint())
}

fn refusal_of(check: &SealAttestationCheck, authority: &Authority) -> AttestationRefusal {
    verify(check, authority).expect_err("refused")
}

#[test]
fn a_good_attestation_gives_the_seals_keys_measurement_and_build() {
    let seal = Seal::new();
    let seal_found = verify(&check(seal.attestation()), &seal.authority).expect("accepted");
    assert_eq!(seal_found.verifying_key, verifying_key(7));
    assert_eq!(seal_found.kem_key, kem_key(9));
    assert_eq!(seal_found.measurement, allowed().pcr0.to_vec());
    assert_eq!(seal_found.build_name, "seal-test-new");
}

#[test]
fn an_older_allowed_build_is_accepted_too() {
    let mut seal = Seal::new();
    seal.pcrs = pcrs(0xa1, 0xb1, 0xc1);
    let found = verify(&check(seal.attestation()), &seal.authority).expect("accepted");
    assert_eq!(found.build_name, "seal-test-old");
}

#[test]
fn a_document_up_to_300_seconds_old_is_accepted() {
    let seal = Seal::new();
    let mut c = check(seal.attestation());
    c.now = NOW + 300;
    assert!(verify(&c, &seal.authority).is_ok());
}

// --- PCRs against the pinned list --------------------------------------------

#[test]
fn any_one_pcr_differing_from_the_pinned_build_is_not_pinned() {
    for (which, p) in [(0, pcrs(0xa3, 0xb1, 0xc2)), (1, pcrs(0xa2, 0xb3, 0xc2)), (2, pcrs(0xa2, 0xb1, 0xc3))] {
        let mut seal = Seal::new();
        seal.pcrs = p;
        assert_eq!(refusal_of(&check(seal.attestation()), &seal.authority), AttestationRefusal::NotPinned, "PCR{which}");
    }
}

#[test]
fn an_unlisted_build_is_not_pinned() {
    let mut seal = Seal::new();
    seal.pcrs = pcrs(0xd1, 0xd2, 0xd3);
    assert_eq!(refusal_of(&check(seal.attestation()), &seal.authority), AttestationRefusal::NotPinned);
}

#[test]
fn a_revoked_build_is_refused_even_when_also_listed_allowed() {
    let mut seal = Seal::new();
    seal.pcrs = revoked();
    let mut c = check(seal.attestation());
    assert_eq!(refusal_of(&c, &seal.authority), AttestationRefusal::Revoked);
    c.pinned_builds.push(build("seal-test-relisted", revoked(), true));
    assert_eq!(refusal_of(&c, &seal.authority), AttestationRefusal::Revoked);
}

#[test]
fn an_empty_pinned_list_refuses_every_seal() {
    let seal = Seal::new();
    let mut c = check(seal.attestation());
    c.pinned_builds.clear();
    assert_eq!(refusal_of(&c, &seal.authority), AttestationRefusal::NotPinned);
}

#[test]
fn zero_pcrs_are_a_debug_mode_enclave_even_when_listed() {
    for p in [pcrs(0, 0, 0), pcrs(0, 0xb1, 0xc2), pcrs(0xa2, 0, 0xc2), pcrs(0xa2, 0xb1, 0)] {
        let mut seal = Seal::new();
        seal.pcrs = p;
        let mut c = check(seal.attestation());
        c.pinned_builds.push(build("seal-test-debug", p, true));
        assert_eq!(refusal_of(&c, &seal.authority), AttestationRefusal::DebugMode);
    }
}

// --- the chain -------------------------------------------------------------------

#[test]
fn another_root_is_a_bad_chain() {
    let seal = Seal::new();
    let other = Authority::new(0x40);
    assert_eq!(refusal_of(&check(seal.attestation()), &other), AttestationRefusal::BadChain);
}

#[test]
fn the_built_in_aws_root_refuses_a_test_authority_document() {
    let seal = Seal::new();
    assert_ne!(seal.authority.fingerprint(), AWS_NITRO_ROOT_SHA256);
    let verdict = verify_seal_attestation(check(seal.attestation()));
    assert_eq!(verdict.refusal, "bad-chain");
    assert!(verdict.seal.is_none());
}

#[test]
fn an_intermediate_signed_by_another_key_is_a_bad_chain() {
    let mut profile = Profile::standard(NOW);
    profile.intermediate_signed_by = Some(0x77);
    let seal = Seal::with(Authority::with_profile(0x10, profile));
    assert_eq!(refusal_of(&check(seal.attestation()), &seal.authority), AttestationRefusal::BadChain);
}

#[test]
fn a_leaf_signed_by_another_key_is_a_bad_chain() {
    let mut profile = Profile::standard(NOW);
    profile.leaf_signed_by = Some(0x77);
    let seal = Seal::with(Authority::with_profile(0x10, profile));
    assert_eq!(refusal_of(&check(seal.attestation()), &seal.authority), AttestationRefusal::BadChain);
}

#[test]
fn a_ca_that_may_not_issue_is_a_bad_chain() {
    let cases: [fn(&mut Profile); 4] = [
        // The intermediate may not sign certificates.
        |p| p.intermediate.key_cert_sign = false,
        // The intermediate is no CA.
        |p| p.intermediate.ca = None,
        // The root allows no CA below it.
        |p| p.root.ca = Some(Some(0)),
        // An unknown critical extension.
        |p| p.intermediate.extra_extensions.push((vec![0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x99], true, vec![0x05, 0x00])),
    ];
    for (i, change) in cases.iter().enumerate() {
        let mut profile = Profile::standard(NOW);
        change(&mut profile);
        let seal = Seal::with(Authority::with_profile(0x10, profile));
        assert_eq!(refusal_of(&check(seal.attestation()), &seal.authority), AttestationRefusal::BadChain, "case {i}");
    }
}

#[test]
fn an_unknown_extension_that_is_not_critical_is_ignored() {
    let mut profile = Profile::standard(NOW);
    profile.intermediate.extra_extensions.push((vec![0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x99], false, vec![0x05, 0x00]));
    let seal = Seal::with(Authority::with_profile(0x10, profile));
    assert!(verify(&check(seal.attestation()), &seal.authority).is_ok());
}

#[test]
fn an_expired_or_future_certificate_is_refused() {
    let mut expired = Profile::standard(NOW);
    expired.leaf.not_before = NOW - 7200;
    expired.leaf.not_after = NOW - 1;
    let seal = Seal::with(Authority::with_profile(0x10, expired));
    assert_eq!(refusal_of(&check(seal.attestation()), &seal.authority), AttestationRefusal::Expired);

    let mut future = Profile::standard(NOW);
    future.intermediate.not_before = NOW + 10;
    let seal = Seal::with(Authority::with_profile(0x10, future));
    assert_eq!(refusal_of(&check(seal.attestation()), &seal.authority), AttestationRefusal::NotYetValid);
}

// --- the signature and the payload ------------------------------------------------

#[test]
fn a_bad_signature_is_refused() {
    let seal = Seal::new();
    let payload = cbor(&Value::Map(seal.fields()));
    let mut signature = seal.authority.signature(&payload);
    signature[10] ^= 0x01;
    let document = encode_cose_sign1(&es384_protected_header(), &payload, &signature);
    assert_eq!(refusal_of(&check(seal.attestation_of(&document)), &seal.authority), AttestationRefusal::BadSignature);
}

#[test]
fn a_tampered_payload_is_refused() {
    let seal = Seal::new();
    let payload = cbor(&Value::Map(seal.fields()));
    let signature = seal.authority.signature(&payload);
    // The same document with another PCR0 (still a pinned build), under the original signature.
    let mut other = Seal::new();
    other.pcrs = pcrs(0xa1, 0xb1, 0xc1);
    let tampered = cbor(&Value::Map(other.fields()));
    let document = encode_cose_sign1(&es384_protected_header(), &tampered, &signature);
    assert_eq!(refusal_of(&check(seal.attestation_of(&document)), &seal.authority), AttestationRefusal::BadSignature);
}

#[test]
fn a_header_other_than_es384_is_malformed() {
    let seal = Seal::new();
    let payload = cbor(&Value::Map(seal.fields()));
    let es512 = cbor(&Value::Map(vec![(Value::Unsigned(1), Value::Negative(35))]));
    let document = encode_cose_sign1(&es512, &payload, &seal.authority.signature(&payload));
    assert_eq!(refusal_of(&check(seal.attestation_of(&document)), &seal.authority), AttestationRefusal::Malformed);
}

#[test]
fn a_document_older_than_300_seconds_is_expired() {
    let seal = Seal::new();
    let mut c = check(seal.attestation());
    c.now = NOW + 301;
    assert_eq!(refusal_of(&c, &seal.authority), AttestationRefusal::Expired);
}

#[test]
fn a_document_from_the_future_is_not_yet_valid() {
    let seal = Seal::new();
    let mut fields = seal.fields();
    fields[2].1 = Value::Unsigned((NOW + 120) * 1000);
    let document = seal.authority.sign_fields(fields);
    assert_eq!(refusal_of(&check(seal.attestation_of(&document)), &seal.authority), AttestationRefusal::NotYetValid);
}

#[test]
fn an_unknown_payload_field_is_malformed() {
    let seal = Seal::new();
    let mut fields = seal.fields();
    fields.push((Value::Text("extra".into()), Value::Bytes(vec![1])));
    let document = seal.authority.sign_fields(fields);
    assert_eq!(refusal_of(&check(seal.attestation_of(&document)), &seal.authority), AttestationRefusal::Malformed);
}

#[test]
fn a_missing_payload_field_is_malformed() {
    for missing in ["module_id", "digest", "timestamp", "pcrs", "certificate", "cabundle"] {
        let seal = Seal::new();
        let fields: Vec<_> = seal.fields().into_iter().filter(|(k, _)| *k != Value::Text(missing.into())).collect();
        let document = seal.authority.sign_fields(fields);
        assert_eq!(
            refusal_of(&check(seal.attestation_of(&document)), &seal.authority),
            AttestationRefusal::Malformed,
            "{missing}"
        );
    }
}

#[test]
fn a_digest_other_than_sha384_or_a_short_pcr_is_malformed() {
    let seal = Seal::new();
    let mut fields = seal.fields();
    fields[1].1 = Value::Text("SHA256".into());
    let document = seal.authority.sign_fields(fields);
    assert_eq!(refusal_of(&check(seal.attestation_of(&document)), &seal.authority), AttestationRefusal::Malformed);

    let mut fields = seal.fields();
    fields[3].1 = Value::Map(vec![
        (Value::Unsigned(0), Value::Bytes(vec![0xa2; 32])),
        (Value::Unsigned(1), Value::Bytes(vec![0xb1; 48])),
        (Value::Unsigned(2), Value::Bytes(vec![0xc2; 48])),
    ]);
    let document = seal.authority.sign_fields(fields);
    assert_eq!(refusal_of(&check(seal.attestation_of(&document)), &seal.authority), AttestationRefusal::Malformed);
}

// --- what the document binds ----------------------------------------------------

#[test]
fn keys_the_document_does_not_bind_are_refused() {
    let seal = Seal::new();
    let document = seal.document();

    let other_key = layout(b"GPA2", &document, &verifying_key(8), &seal.kem_key, &seal.cert_hash);
    assert_eq!(refusal_of(&check(other_key), &seal.authority), AttestationRefusal::KeysNotBound);

    let other_kem = layout(b"GPA2", &document, &seal.verifying_key, &kem_key(10), &seal.cert_hash);
    assert_eq!(refusal_of(&check(other_kem), &seal.authority), AttestationRefusal::KeysNotBound);

    let other_cert = layout(b"GPA2", &document, &seal.verifying_key, &seal.kem_key, &[0x7f; 32]);
    let mut c = check(other_cert);
    c.tls_cert_sha256 = vec![0x7f; 32];
    assert_eq!(refusal_of(&c, &seal.authority), AttestationRefusal::KeysNotBound);
}

#[test]
fn a_document_for_another_challenge_is_refused() {
    let seal = Seal::new();
    let mut c = check(seal.attestation());
    c.challenge = vec![0x5d; 32];
    assert_eq!(refusal_of(&c, &seal.authority), AttestationRefusal::KeysNotBound);
}

#[test]
fn a_document_with_no_user_data_binds_nothing() {
    let seal = Seal::new();
    let mut fields = seal.fields();
    fields[7].1 = Value::Null;
    let document = seal.authority.sign_fields(fields);
    assert_eq!(refusal_of(&check(seal.attestation_of(&document)), &seal.authority), AttestationRefusal::KeysNotBound);
}

#[test]
fn a_kem_key_that_does_not_decode_is_refused_even_when_bound() {
    let mut seal = Seal::new();
    // Every coefficient 4095, above the ML-KEM modulus.
    let mut bad = seal.kem_key.clone();
    bad[..1152].fill(0xff);
    seal.kem_key = bad;
    assert_eq!(refusal_of(&check(seal.attestation()), &seal.authority), AttestationRefusal::KeysNotBound);
}

#[test]
fn another_certificate_on_the_connection_is_a_tls_mismatch() {
    let seal = Seal::new();
    let mut c = check(seal.attestation());
    c.tls_cert_sha256 = vec![0x01; 32];
    assert_eq!(refusal_of(&c, &seal.authority), AttestationRefusal::TlsMismatch);
}

// --- the layout -----------------------------------------------------------------

#[test]
fn another_magic_or_a_wrong_length_is_malformed() {
    let seal = Seal::new();
    let document = seal.document();
    let good = seal.attestation_of(&document);
    assert!(verify(&check(good.clone()), &seal.authority).is_ok());

    let gpa1 = layout(b"GPA1", &document, &seal.verifying_key, &seal.kem_key, &seal.cert_hash);
    assert_eq!(refusal_of(&check(gpa1), &seal.authority), AttestationRefusal::Malformed);

    let truncated = good[..good.len() - 1].to_vec();
    assert_eq!(refusal_of(&check(truncated), &seal.authority), AttestationRefusal::Malformed);

    let mut overlong = good.clone();
    overlong.push(0);
    assert_eq!(refusal_of(&check(overlong), &seal.authority), AttestationRefusal::Malformed);

    let mut wrong_length = good.clone();
    wrong_length[7] ^= 0x01;
    assert_eq!(refusal_of(&check(wrong_length), &seal.authority), AttestationRefusal::Malformed);

    // The layout without the certificate hash (the older shape).
    let no_cert = good[..good.len() - 32].to_vec();
    assert_eq!(refusal_of(&check(no_cert), &seal.authority), AttestationRefusal::Malformed);

    for short in [Vec::new(), b"GPA2".to_vec(), good[..8].to_vec()] {
        assert_eq!(refusal_of(&check(short), &seal.authority), AttestationRefusal::Malformed);
    }
}

#[test]
fn a_challenge_or_certificate_hash_of_the_wrong_length_is_malformed() {
    let seal = Seal::new();
    let mut c = check(seal.attestation());
    c.challenge = vec![0x5c; 31];
    assert_eq!(refusal_of(&c, &seal.authority), AttestationRefusal::Malformed);
    let mut c = check(seal.attestation());
    c.tls_cert_sha256 = vec![0x7e; 31];
    assert_eq!(refusal_of(&c, &seal.authority), AttestationRefusal::Malformed);
}

#[test]
fn every_refusal_reaches_the_app_as_its_code_with_no_seal() {
    let seal = Seal::new();
    let mut c = check(seal.attestation());
    c.attestation[0] = b'X';
    let verdict = verify_seal_attestation(c);
    assert_eq!(verdict.refusal, "malformed");
    assert!(verdict.seal.is_none());
    let codes: Vec<&str> = [
        AttestationRefusal::Malformed,
        AttestationRefusal::BadChain,
        AttestationRefusal::BadSignature,
        AttestationRefusal::Expired,
        AttestationRefusal::NotYetValid,
        AttestationRefusal::NotPinned,
        AttestationRefusal::Revoked,
        AttestationRefusal::DebugMode,
        AttestationRefusal::KeysNotBound,
        AttestationRefusal::TlsMismatch,
    ]
    .iter()
    .map(|r| r.code())
    .collect();
    assert_eq!(
        codes,
        [
            "malformed",
            "bad-chain",
            "bad-signature",
            "expired",
            "not-yet-valid",
            "not-pinned",
            "revoked",
            "debug-mode",
            "keys-not-bound",
            "tls-mismatch"
        ]
    );
}

#[test]
fn garbage_never_panics() {
    let seal = Seal::new();
    let good = seal.attestation();
    for cut in (0..good.len()).step_by(97) {
        let mut bytes = good.clone();
        bytes[cut] ^= 0xa5;
        let _ = verify(&check(bytes), &seal.authority);
        let _ = verify(&check(good[..cut].to_vec()), &seal.authority);
    }
}

// --- Indefinite-length CBOR, as the NSM's CBOR library writes it -------------

/// A string of head `initial` (0x5f bytes, 0x7f text) in three chunks: the
/// first half, an empty chunk, the rest. `piece` writes one chunk.
fn chunked(initial: u8, len: usize, mid: usize, piece: impl Fn(usize, usize) -> Value) -> Vec<u8> {
    [vec![initial], cbor(&piece(0, mid)), cbor(&piece(mid, mid)), cbor(&piece(mid, len)), vec![0xff]].concat()
}

/// `value` with every map, array, byte string and text string written
/// indefinite-length.
fn indefinite(value: &Value) -> Vec<u8> {
    match value {
        Value::Bytes(b) => chunked(0x5f, b.len(), b.len() / 2, |from, to| Value::Bytes(b[from..to].to_vec())),
        Value::Text(t) => {
            let mut mid = t.len() / 2;
            while !t.is_char_boundary(mid) {
                mid -= 1;
            }
            chunked(0x7f, t.len(), mid, |from, to| Value::Text(t[from..to].into()))
        }
        Value::Array(items) => [vec![0x9f], items.iter().flat_map(indefinite).collect(), vec![0xff]].concat(),
        Value::Map(fields) => {
            let inner: Vec<u8> = fields.iter().flat_map(|(k, v)| [indefinite(k), indefinite(v)].concat()).collect();
            [vec![0xbf], inner, vec![0xff]].concat()
        }
        Value::Tag(tag, inner) => {
            let mut head = cbor(&Value::Tag(*tag, Box::new(Value::Null)));
            head.pop();
            [head, indefinite(inner)].concat()
        }
        other => cbor(other),
    }
}

#[test]
fn core_indefinite_map_payload_decodes() {
    let seal = Seal::new();
    let definite = cbor(&Value::Map(seal.fields()));
    let payload = indefinite(&Value::Map(seal.fields()));
    assert_eq!(payload[0], 0xbf, "an indefinite map, as the NSM wrote it");
    assert_ne!(payload, definite);
    let document = seal.authority.sign_payload(&payload);

    // It verifies, and says what the definite form says.
    assert_eq!(check_nitro_document(&document, &seal.authority.fingerprint(), NOW), Ok(()));
    let found = verify(&check(seal.attestation_of(&document)), &seal.authority).expect("accepted");
    assert_eq!(Ok(found.clone()), verify(&check(seal.attestation()), &seal.authority));
    assert_eq!(found.build_name, "seal-test-new");
    assert_eq!(found.measurement, allowed().pcr0.to_vec());
    assert_eq!(found.verifying_key, verifying_key(7));

    // Its PCRs and user data are read, not passed over.
    let mut other = Seal::new();
    other.pcrs = pcrs(0xa3, 0xb1, 0xc2);
    let unpinned = other.authority.sign_payload(&indefinite(&Value::Map(other.fields())));
    assert_eq!(refusal_of(&check(other.attestation_of(&unpinned)), &other.authority), AttestationRefusal::NotPinned);
    let mut unbound = Seal::new();
    unbound.challenge = vec![0x11; 32];
    let unbound = unbound.authority.sign_payload(&indefinite(&Value::Map(unbound.fields())));
    assert_eq!(refusal_of(&check(seal.attestation_of(&unbound)), &seal.authority), AttestationRefusal::KeysNotBound);

    // The signature covers the payload's bytes as carried: signed over the
    // definite form, the indefinite one is refused, and the other way round.
    let protected = es384_protected_header();
    let swapped = encode_cose_sign1(&protected, &payload, &seal.authority.signature(&definite));
    assert_eq!(refusal_of(&check(seal.attestation_of(&swapped)), &seal.authority), AttestationRefusal::BadSignature);
    let swapped = encode_cose_sign1(&protected, &definite, &seal.authority.signature(&payload));
    assert_eq!(refusal_of(&check(seal.attestation_of(&swapped)), &seal.authority), AttestationRefusal::BadSignature);

    // The whole document indefinite too: tag 18 over an indefinite array,
    // an indefinite empty map, the payload's bytes in chunks.
    let parts = Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(Vec::new()),
        Value::Bytes(payload.clone()),
        Value::Bytes(seal.authority.signature(&payload)),
    ]);
    let whole = indefinite(&Value::Tag(18, Box::new(parts)));
    assert_eq!(&whole[..2], &[0xd2, 0x9f]);
    assert_eq!(check_nitro_document(&whole, &seal.authority.fingerprint(), NOW), Ok(()));
    assert_eq!(verify(&check(seal.attestation_of(&whole)), &seal.authority), Ok(found));
    // One byte of the payload changed inside a chunk is caught.
    let pcr0 = whole.windows(4).position(|w| w == [0xa2; 4]).expect("PCR0 is there");
    let mut changed = whole.clone();
    changed[pcr0] ^= 0x01;
    assert_eq!(
        check_nitro_document(&changed, &seal.authority.fingerprint(), NOW),
        Err("attestation document signature does not verify".to_owned())
    );
}

#[test]
fn core_indefinite_items_keep_the_rules() {
    // Bytes given as a whole document: the decoder's reason and where.
    let refusal = |bytes: &[u8]| check_nitro_document(bytes, &[0; 32], NOW).expect_err("refused");
    let not_cbor = |reason: &str, at: usize, bytes: &[u8]| {
        format!("malformed attestation document: the document is not CBOR: {reason} at byte {at} of {}", bytes.len())
    };
    const RESERVED: &str = "indefinite or reserved length";
    const STRAY: &str = "a break outside an indefinite-length item";
    const CHUNK: &str = "a chunk is not a definite-length string of its string's type";
    let cases: Vec<(Vec<u8>, &str, usize)> = vec![
        // Integers and tags have no indefinite form.
        (vec![0x1f], RESERVED, 0),
        (vec![0x81, 0x3f], RESERVED, 1),
        (vec![0x9f, 0xdf, 0x00, 0xff], RESERVED, 1),
        // A break only ends an indefinite item, a map's only where a key would start.
        (vec![0xff], STRAY, 0),
        (vec![0x81, 0xff], STRAY, 1),
        (vec![0xa1, 0x01, 0xff], STRAY, 2),
        (vec![0xbf, 0x01, 0xff], STRAY, 2),
        (vec![0xbf, 0x01, 0x02, 0x03, 0xff, 0xff], STRAY, 4),
        (vec![0xd2, 0xff], STRAY, 1),
        (vec![0x9f, 0xff, 0xff], "data after the value", 2),
        // Duplicate keys inside an indefinite map.
        (vec![0xbf, 0x61, b'a', 0x01, 0x61, b'a', 0x02, 0xff], "a map key appears twice", 4),
        (vec![0xbf, 0x61, b'a', 0x01, 0x7f, 0x61, b'a', 0xff, 0x02, 0xff], "a map key appears twice", 4),
        // A chunk is a definite-length string of its string's type.
        (vec![0x5f, 0x61, b'a', 0xff], CHUNK, 1),
        (vec![0x7f, 0x41, b'a', 0xff], CHUNK, 1),
        (vec![0x5f, 0x41, 0x00, 0x5f, 0xff, 0xff], CHUNK, 3),
        (vec![0x5f, 0x00, 0xff], CHUNK, 1),
        (vec![0x5f, 0x5c, 0xff], RESERVED, 1),
        // Text is UTF-8, each chunk whole.
        (vec![0x7f, 0x61, b'a', 0x62, 0xc3, 0x28, 0xff], "text is not UTF-8", 3),
        (vec![0x7f, 0x61, 0xc3, 0x61, 0xa9, 0xff], "text is not UTF-8", 1),
        // Floats and simple values other than false, true and null.
        (vec![0x9f, 0xf9, 0x3c, 0x00, 0xff], "a float or simple value", 1),
        (vec![0xbf, 0x01, 0xf7, 0xff], "a float or simple value", 2),
        // Truncation, and no chunk longer than what is left.
        (vec![0x9f, 0x01], "truncated", 2),
        (vec![0xbf, 0x01], "truncated", 2),
        (vec![0x5f, 0x41, 0x00], "truncated", 3),
        (vec![0x5f, 0x43, 0x00, 0xff], "a length runs past the end", 1),
        (vec![0x5f, 0x5a, 0xff, 0xff, 0xff, 0xff, 0xff], "a length runs past the end", 1),
        // Nesting: 16 levels below the top, indefinite or not, and no deeper.
        ([vec![0x9f; 17], vec![0x00], vec![0xff; 17]].concat(), "nested too deep", 17),
        ([[0xbf, 0x00].repeat(17), vec![0x00], vec![0xff; 17]].concat(), "nested too deep", 33),
    ];
    for (bytes, reason, at) in &cases {
        assert_eq!(refusal(bytes), not_cbor(reason, *at, bytes), "{bytes:02x?}");
    }
    // Reserved additional information stays reserved on every major type.
    for info in 28..=30u8 {
        for major in 0..=6u8 {
            let bytes = [0x82, 0x00, major << 5 | info, 0x00];
            assert_eq!(refusal(&bytes), not_cbor(RESERVED, 2, &bytes), "major {major}, info {info}");
        }
    }
    // As deep as allowed, it decodes (and is then not a COSE_Sign1).
    let deepest = [vec![0x9f; 16], vec![0x00], vec![0xff; 16]].concat();
    assert_eq!(refusal(&deepest), "malformed attestation document");

    // In a signed payload: a key twice in the indefinite map, a break in
    // place of a value, the break missing.
    let seal = Seal::new();
    let payload = indefinite(&Value::Map(seal.fields()));
    let end = payload.len() - 1;
    let payload_refusal = |payload: &[u8]| {
        check_nitro_document(&seal.authority.sign_payload(payload), &seal.authority.fingerprint(), NOW).unwrap_err()
    };
    let in_payload = |reason: &str, at: usize, length: usize| {
        format!("malformed attestation document: the payload is not CBOR: {reason} at byte {at} of {length}")
    };
    let twice = [&payload[..end], &cbor(&Value::Text("nonce".into())), &[0xf6, 0xff]].concat();
    assert_eq!(payload_refusal(&twice), in_payload("a map key appears twice", end, twice.len()));
    let stray = [&payload[..end], &cbor(&Value::Text("extra".into())), &[0xff]].concat();
    assert_eq!(payload_refusal(&stray), in_payload(STRAY, stray.len() - 1, stray.len()));
    assert_eq!(payload_refusal(&payload[..end]), in_payload("truncated", end, end));
}

#[test]
fn each_challenge_is_32_fresh_bytes() {
    let first = seal_attestation_challenge();
    let second = seal_attestation_challenge();
    assert_eq!(first.len(), 32);
    assert_eq!(second.len(), 32);
    assert_ne!(first, second);
}

#[test]
fn the_verifier_source_holds_no_signing_call_or_private_key_type() {
    let source = include_str!("../src/seal_attestation.rs");
    assert!(!source.contains("SigningKey"), "a private key type in the verifier");
    assert!(!source.contains("Signer"), "a signing call in the verifier");
}
