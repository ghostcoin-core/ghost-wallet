//! The phone's check of the Seal's signed answers, against answers signed the
//! way the Seal signs them (ML-DSA-65, context `ghost-seal answer`, the
//! layout of `seal/src/answer.rs`) with a test key from a fixed seed.

use ghost_wallet_core::seal_answer::{
    ANSWER_BYTES, ANSWER_CONTEXT, ANSWER_DOMAIN, SealAnswerCheck, decode_answer, sha3_256, verify_seal_answer,
    verify_seal_fill_answer,
};
use ml_dsa::{ExpandedSigningKey, MlDsa65, Seed};

const UID: [u8; 7] = [0x04, 0x51, 0x8d, 0xfa, 0xa9, 0x61, 0x80];
const MEASUREMENT: [u8; 48] = [0x5e; 48];
const NOW: u64 = 1_800_000_000;
const AMOUNT: u128 = 5_000_000_000_000_000_000;

/// A test Seal key from a fixed seed (never a real Seal's).
fn seal_key(fill: u8) -> ExpandedSigningKey<MlDsa65> {
    ExpandedSigningKey::<MlDsa65>::from_seed(&Seed::from([fill; 32]))
}

#[derive(Clone)]
struct Body {
    kind: u8,
    challenge: [u8; 32],
    uid: [u8; 7],
    generation: u32,
    coin: [u8; 32],
    measurement: [u8; 48],
    state: u8,
    amount: u128,
    expires_at: u64,
    binding: [u8; 32],
    pin: u8,
    tries: u8,
}

impl Body {
    fn check(challenge: [u8; 32]) -> Body {
        Body {
            kind: 1,
            challenge,
            uid: UID,
            generation: 0,
            coin: [0xc0; 32],
            measurement: MEASUREMENT,
            state: 1,
            amount: AMOUNT,
            expires_at: NOW + 120,
            binding: [0; 32],
            pin: 0,
            tries: 0,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ANSWER_BYTES);
        out.extend_from_slice(ANSWER_DOMAIN);
        out.push(self.kind);
        out.extend_from_slice(&self.challenge);
        out.extend_from_slice(&self.uid);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.coin);
        out.extend_from_slice(&self.measurement);
        out.push(self.state);
        out.extend_from_slice(&self.amount.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.binding);
        out.push(self.pin);
        out.push(self.tries);
        assert_eq!(out.len(), ANSWER_BYTES);
        out
    }
}

fn sign(key: &ExpandedSigningKey<MlDsa65>, bytes: &[u8]) -> Vec<u8> {
    key.sign_deterministic(bytes, ANSWER_CONTEXT).expect("signed").encode().to_vec()
}

fn verifying_key(key: &ExpandedSigningKey<MlDsa65>) -> Vec<u8> {
    key.verifying_key().encode().to_vec()
}

/// What the phone checks a Check answer against, signed by `key`.
fn check_of(key: &ExpandedSigningKey<MlDsa65>, body: &Body, challenge: [u8; 32]) -> SealAnswerCheck {
    let answer = body.encode();
    SealAnswerCheck {
        verifying_key: verifying_key(key),
        measurement: MEASUREMENT.to_vec(),
        pinned_measurements: vec![[0x11; 48].to_vec(), MEASUREMENT.to_vec()],
        signature: sign(key, &answer),
        answer,
        challenge: challenge.to_vec(),
        uid: UID.to_vec(),
        now: NOW,
        kind: "check".to_owned(),
    }
}

fn refusal(check: SealAnswerCheck) -> String {
    let verdict = verify_seal_answer(check);
    assert!(verdict.answer.is_none(), "a refused answer hands nothing back");
    verdict.refusal
}

#[test]
fn accepts_a_fresh_signed_check_and_reads_it() {
    let key = seal_key(7);
    let challenge = [0xa1; 32];
    let mut body = Body::check(challenge);
    body.pin = 1;
    body.tries = 4;
    let verdict = verify_seal_answer(check_of(&key, &body, challenge));
    assert_eq!(verdict.refusal, "");
    let answer = verdict.answer.expect("accepted");
    assert_eq!(answer.kind, "check");
    assert_eq!(answer.state, "sealed");
    assert_eq!(answer.amount_wei, AMOUNT.to_string());
    assert_eq!(answer.uid, UID.to_vec());
    assert!(answer.pin_required);
    assert_eq!(answer.pin_tries_left, 4);
    assert_eq!(answer.expires_at, NOW + 120);
}

#[test]
fn reads_every_state() {
    let key = seal_key(7);
    let challenge = [0xa2; 32];
    for (byte, state) in [(0u8, "empty"), (1, "sealed"), (2, "opening"), (3, "opened")] {
        let mut body = Body::check(challenge);
        body.state = byte;
        let answer = verify_seal_answer(check_of(&key, &body, challenge)).answer.expect("accepted");
        assert_eq!(answer.state, state);
    }
}

#[test]
fn refuses_a_bad_signature() {
    let key = seal_key(7);
    let challenge = [0xa3; 32];
    let body = Body::check(challenge);

    let mut flipped = check_of(&key, &body, challenge);
    flipped.signature[10] ^= 0x01;
    assert_eq!(refusal(flipped), "bad-signature");

    // Signed by another key than the Seal's.
    let mut other = check_of(&seal_key(8), &body, challenge);
    other.verifying_key = verifying_key(&key);
    assert_eq!(refusal(other), "bad-signature");

    // The answer's amount changed after it was signed.
    let mut tampered = check_of(&key, &body, challenge);
    tampered.answer[160] ^= 0x01;
    assert_eq!(refusal(tampered), "bad-signature");

    let mut short = check_of(&key, &body, challenge);
    short.signature.truncate(100);
    assert_eq!(refusal(short), "malformed");
}

#[test]
fn refuses_a_replayed_answer() {
    let key = seal_key(7);
    let old = [0x01; 32];
    let fresh = [0x02; 32];
    // A Sealed answer signed over an old challenge, replayed to a new Check.
    let replayed = check_of(&key, &Body::check(old), fresh);
    assert_eq!(refusal(replayed), "wrong-challenge");
}

#[test]
fn refuses_an_expired_answer() {
    let key = seal_key(7);
    let challenge = [0xa4; 32];
    let body = Body::check(challenge);
    let mut at_expiry = check_of(&key, &body, challenge);
    at_expiry.now = NOW + 120;
    assert_eq!(refusal(at_expiry), "expired");
    let mut just_before = check_of(&key, &body, challenge);
    just_before.now = NOW + 119;
    assert_eq!(verify_seal_answer(just_before).refusal, "");
}

#[test]
fn refuses_another_card() {
    let key = seal_key(7);
    let challenge = [0xa5; 32];
    let mut check = check_of(&key, &Body::check(challenge), challenge);
    check.uid = vec![0x04, 0, 0, 0, 0, 0, 1];
    assert_eq!(refusal(check), "wrong-card");
}

#[test]
fn refuses_every_seal_while_the_pinned_list_is_empty() {
    let key = seal_key(7);
    let challenge = [0xa6; 32];
    let mut check = check_of(&key, &Body::check(challenge), challenge);
    check.pinned_measurements = Vec::new();
    assert_eq!(refusal(check), "not-pinned");
}

#[test]
fn refuses_a_seal_measurement_not_pinned_and_an_answer_from_other_code() {
    let key = seal_key(7);
    let challenge = [0xa7; 32];
    let mut unpinned = check_of(&key, &Body::check(challenge), challenge);
    unpinned.pinned_measurements = vec![[0x11; 48].to_vec()];
    assert_eq!(refusal(unpinned), "not-pinned");

    let mut body = Body::check(challenge);
    body.measurement = [0x22; 48];
    assert_eq!(refusal(check_of(&key, &body, challenge)), "wrong-measurement");
}

#[test]
fn refuses_an_answer_about_another_flow() {
    let key = seal_key(7);
    let challenge = [0xa8; 32];
    let mut body = Body::check(challenge);
    body.kind = 3;
    assert_eq!(refusal(check_of(&key, &body, challenge)), "wrong-kind");
}

#[test]
fn refuses_signed_bytes_that_are_not_an_answer() {
    let key = seal_key(7);
    let challenge = [0xa9; 32];
    let mut body = Body::check(challenge);
    body.tries = 3; // tries left without a PIN
    assert_eq!(refusal(check_of(&key, &body, challenge)), "malformed");
    assert!(decode_answer(&body.encode()).is_none());
}

#[test]
fn checks_that_a_fill_answer_binds_its_commit_data() {
    let key = seal_key(7);
    let challenge = [0xaa; 32];
    let commit_data = vec![0x33; 430];
    let mut body = Body::check(challenge);
    body.kind = 2;
    body.state = 0;
    body.coin = sha3_256(&commit_data);
    body.binding = sha3_256(&commit_data);
    let mut check = check_of(&key, &body, challenge);
    check.kind = "fill".to_owned();

    let accepted = verify_seal_fill_answer(check.clone(), commit_data.clone());
    assert_eq!(accepted.refusal, "");
    assert_eq!(accepted.answer.expect("accepted").state, "empty");

    let other = verify_seal_fill_answer(check.clone(), vec![0x34; 430]);
    assert_eq!(other.refusal, "wrong-binding");
    assert!(other.answer.is_none());

    let mut as_check = check;
    as_check.kind = "check".to_owned();
    assert_eq!(verify_seal_fill_answer(as_check, commit_data).refusal, "wrong-kind");
}
