//! The enclave's service as library code: fail closed until M is held and a
//! chain status check, a card registry and a durable journal are installed
//! (with any one missing every flow is refused and no card traffic is sent),
//! then a good Check, Fill, Fill confirmation and Open with the fakes
//! installed; the attestation route with the tests' authority; and no
//! answer, log line or error text carrying M or the PIN.

#[path = "fixtures/nitro_authority.rs"]
mod authority;
#[path = "support/enclave.rs"]
mod enclave;
#[path = "fixtures/test_release_key.rs"]
mod release;
mod support;

use std::sync::Arc;

use authority::{Authority, AuthoritySource, NOW, allowed_new, allowed_old, revoked, unlisted};
use ghost_seal::attestation::AttestationRejected;
use ghost_seal::enclave_serve::{
    EnclaveService, KIND_KEY_SHARE, KIND_PHONE_ATTESTATION, MemoryServiceLog, ServiceDeps, ServiceEvent,
};
use ghost_seal::key_share::Receiver;
use ghost_seal::measurements::{MeasurementList, MeasurementRefused};
use ghost_seal::phone_attestation::{self, PhoneAttestationRejected, answer_key};
use ghost_seal::primitives::sha3_256;
use ghost_seal::relay::{from_hex, to_hex};
use ghost_seal::relay_http::NOT_READY_MESSAGE;
use ghost_seal::{AnswerBody, AnswerKind, AnswerVerifier, CardState, CardTransport, CardUid, CoinQuery, SealError, SealRandom};
use serde_json::{Value, json};
use support::{AMOUNT, MEASUREMENT, SimCard, UID};

const PIN: &str = "135792";
const WRONG_PIN: &str = "246801";
/// A card the registry does not hold.
const STRANGER: CardUid = CardUid([0x04, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);

fn post(service: &EnclaveService, path: &str, body: &Value) -> (u16, Value) {
    let reply = service.routes().answer("POST", path, body.to_string().as_bytes());
    (reply.status, serde_json::from_str(&reply.body).expect("JSON"))
}

/// The phone's relay: carries a flow from its start answer to its end.
fn carry(service: &EnclaveService, card: &mut SimCard, mut answer: (u16, Value), seen: &mut Vec<Value>) -> (u16, Value) {
    seen.push(answer.1.clone());
    while answer.0 == 200 && answer.1["status"] == "apdu" {
        let apdu = from_hex(answer.1["apdu"].as_str().unwrap()).unwrap();
        let card_answer = card.transceive(&apdu).expect("the card stays in the field");
        let session = answer.1["session"].clone();
        answer = post(service, "/v1/relay/step", &json!({ "session": session, "answer": to_hex(&card_answer) }));
        seen.push(answer.1.clone());
    }
    answer
}

/// The fields whose values are bytes as hex.
const HEX_FIELDS: [&str; 7] = ["answer", "signature", "commitData", "release", "apdu", "session", "attestation"];

/// What an answer exposes: the bytes of its hex fields, the text of the
/// others. (A PIN is digits, so it is looked for in the bytes the hex
/// stands for, not in the hex text, where it would turn up by chance.)
fn exposed(answer: &Value) -> Vec<Vec<u8>> {
    let Value::Object(fields) = answer else { return vec![answer.to_string().into_bytes()] };
    fields
        .iter()
        .map(|(name, value)| match value.as_str() {
            Some(text) if HEX_FIELDS.contains(&name.as_str()) => from_hex(text).expect("hex"),
            Some(text) => text.as_bytes().to_vec(),
            None => value.to_string().into_bytes(),
        })
        .collect()
}

fn uid_hex(uid: &CardUid) -> String {
    to_hex(&uid.0)
}

/// Every flow start (and a step and an abort) for card `uid`.
fn flow_requests(uid: &CardUid) -> Vec<(&'static str, Value)> {
    let phone_key = to_hex(&support::phone(5).public_key());
    vec![
        ("/v1/check/start", json!({ "uid": uid_hex(uid), "challenge": to_hex(&[1; 32]) })),
        ("/v1/fill/start", json!({ "uid": uid_hex(uid), "challenge": to_hex(&[2; 32]), "amountWei": AMOUNT.to_string(), "pin": PIN })),
        ("/v1/fill/confirm", json!({ "uid": uid_hex(uid), "challenge": to_hex(&[3; 32]) })),
        ("/v1/open/start", json!({ "uid": uid_hex(uid), "challenge": to_hex(&[4; 32]), "phoneKey": phone_key, "pin": PIN })),
        ("/v1/relay/step", json!({ "session": "00".repeat(16), "answer": "9100" })),
        ("/v1/relay/abort", json!({ "session": "00".repeat(16) })),
    ]
}

fn assert_unavailable(answer: &(u16, Value)) {
    assert_eq!(answer.0, 503, "{}", answer.1);
    assert_eq!(answer.1, json!({ "status": "error", "error": "unavailable", "message": NOT_READY_MESSAGE }));
}

fn verified(service_master_key: &[u8], answer: &Value, challenge: [u8; 32], uid: &CardUid) -> AnswerBody {
    assert_eq!(answer["status"], "done", "{answer}");
    let verifier = AnswerVerifier::new(service_master_key, MEASUREMENT).unwrap();
    let bytes = from_hex(answer["answer"].as_str().unwrap()).unwrap();
    let signature = from_hex(answer["signature"].as_str().unwrap()).unwrap();
    verifier.verify(&bytes, &signature, &challenge, uid, NOW).expect("the signed answer verifies")
}

fn attest(service: &EnclaveService, challenge: [u8; 32]) -> Vec<u8> {
    let (status, body) = post(service, "/v1/attestation", &json!({ "challenge": to_hex(&challenge) }));
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    from_hex(body["attestation"].as_str().unwrap()).unwrap()
}

#[test]
fn before_it_holds_m_the_service_answers_no_flow_and_attests_nothing() {
    let (deps, fakes) = enclave::deps(true, true, true);
    let service = enclave::service(deps, allowed_old(), Arc::new(MemoryServiceLog::default()));
    assert!(!service.serves_flows());
    for (path, body) in flow_requests(&UID) {
        assert_unavailable(&post(&service, path, &body));
    }
    let (status, body) = post(&service, "/v1/attestation", &json!({ "challenge": to_hex(&[7; 32]) }));
    assert_eq!((status, body["error"].as_str()), (503, Some("unavailable")));
    assert!(service.answer_frame(&[&[KIND_PHONE_ATTESTATION][..], &[7; 32]].concat()).is_err());
    assert!(service.answer_frame(&[KIND_KEY_SHARE, 1, 2, 3]).unwrap_err().contains("no M"));
    assert!(fakes.journal.sealed_entries().is_empty());
}

#[test]
fn with_any_of_the_three_missing_every_flow_is_refused_and_no_card_traffic_is_sent() {
    for (chain, registry, journal) in
        [(false, true, true), (true, false, true), (true, true, false), (false, false, false)]
    {
        let (deps, fakes) = enclave::deps(chain, registry, journal);
        assert!(!deps.ready());
        let log = Arc::new(MemoryServiceLog::default());
        let service = enclave::service(deps, allowed_old(), log.clone());
        service.install_master(support::master());
        assert!(!service.serves_flows(), "chain {chain}, registry {registry}, journal {journal}");
        assert_eq!(*log.0.lock().unwrap(), vec![ServiceEvent::MasterInstalled { serves_flows: false }]);
        for (path, body) in flow_requests(&UID) {
            let answer = post(&service, path, &body);
            // Refused before any session: no command for any card.
            assert_unavailable(&answer);
            assert!(answer.1.get("apdu").is_none() && answer.1.get("session").is_none());
        }
        assert!(fakes.journal.sealed_entries().is_empty(), "nothing was journaled");
        assert!(fakes.maker.made.lock().unwrap().is_empty(), "no key was made");
        // The attestation route still works.
        attest(&service, [8; 32]);
    }
    // ServiceDeps::none() is what the enclave program installs today.
    assert!(!ServiceDeps::none().ready());
}

#[test]
fn with_the_fakes_installed_check_fill_confirm_and_open_are_served() {
    let (deps, fakes) = enclave::deps(true, true, true);
    assert!(deps.ready());
    let log = Arc::new(MemoryServiceLog::default());
    let service = enclave::service(deps, allowed_old(), log.clone());
    service.install_master(support::master());
    assert!(service.serves_flows());
    assert_eq!(*log.0.lock().unwrap(), vec![ServiceEvent::MasterInstalled { serves_flows: true }]);
    let key = answer_key(&support::master());
    let mut seen = Vec::new();
    let mut card = SimCard::set_up(UID);

    // Check of the blank card.
    let start = post(&service, "/v1/check/start", &json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x11; 32]) }));
    let done = carry(&service, &mut card, start, &mut seen);
    let body = verified(&key, &done.1, [0x11; 32], &UID);
    assert_eq!((body.kind, body.state, body.measurement), (AnswerKind::Check, CardState::Empty, MEASUREMENT));

    // Fill with a PIN.
    let fill = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x12; 32]), "amountWei": AMOUNT.to_string(), "pin": PIN });
    let done = carry(&service, &mut card, post(&service, "/v1/fill/start", &fill), &mut seen);
    let body = verified(&key, &done.1, [0x12; 32], &UID);
    let commit_data = from_hex(done.1["commitData"].as_str().unwrap()).unwrap();
    assert_eq!((body.kind, body.state, body.coin), (AnswerKind::Fill, CardState::Empty, sha3_256(&[&commit_data])));
    assert!(!fakes.journal.sealed_entries().is_empty(), "the Fill was journaled in the durable journal");

    // The confirmation before the payment is on the chain: not paid.
    let confirm = |challenge: [u8; 32], card: &mut SimCard, seen: &mut Vec<Value>| {
        let start = post(&service, "/v1/fill/confirm", &json!({ "uid": uid_hex(&UID), "challenge": to_hex(&challenge) }));
        carry(&service, card, start, seen)
    };
    let refused = confirm([0x13; 32], &mut card, &mut seen);
    assert_eq!((refused.0, refused.1["reason"].as_str()), (422, Some("not-paid")));

    // The exact Vanish, settled on the fake chain: Sealed.
    let coin = CoinQuery { commit_data: commit_data.clone(), amount_wei: AMOUNT, spend_marker: fakes.maker.marker_for(&commit_data) };
    fakes.chain.pay(coin);
    let done = confirm([0x14; 32], &mut card, &mut seen);
    let body = verified(&key, &done.1, [0x14; 32], &UID);
    assert_eq!((body.kind, body.state, body.amount_wei), (AnswerKind::Fill, CardState::Sealed, AMOUNT));

    // Check: Sealed, its coin found exact, settled and unspent.
    let start = post(&service, "/v1/check/start", &json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x15; 32]) }));
    let done = carry(&service, &mut card, start, &mut seen);
    let body = verified(&key, &done.1, [0x15; 32], &UID);
    assert_eq!((body.kind, body.state, body.pin_required), (AnswerKind::Check, CardState::Sealed, true));

    // Open: a wrong PIN, then the PIN.
    let phone = support::phone(0x55);
    let open = |challenge: [u8; 32], pin: &str, card: &mut SimCard, seen: &mut Vec<Value>| {
        let body = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&challenge), "phoneKey": to_hex(&phone.public_key()), "pin": pin });
        carry(&service, card, post(&service, "/v1/open/start", &body), seen)
    };
    let refused = open([0x16; 32], WRONG_PIN, &mut card, &mut seen);
    assert_eq!((refused.0, refused.1["reason"].as_str()), (422, Some("wrong-pin")));
    let done = open([0x17; 32], PIN, &mut card, &mut seen);
    let body = verified(&key, &done.1, [0x17; 32], &UID);
    let release = from_hex(done.1["release"].as_str().unwrap()).unwrap();
    assert_eq!((body.kind, body.state, body.binding), (AnswerKind::Open, CardState::Opened, sha3_256(&[&release])));
    assert_eq!(phone.open(&release, &UID, 1).unwrap().expose_secret(), &fakes.maker.key_for(&commit_data)[..]);
    assert!(fakes.journal.has_open(&UID));

    // A card the registry does not hold is refused before any card traffic.
    let answer = post(&service, "/v1/check/start", &json!({ "uid": uid_hex(&STRANGER), "challenge": to_hex(&[0x18; 32]) }));
    assert_eq!((answer.0, answer.1["reason"].as_str()), (422, Some("not-a-ghost-card")));
    assert!(answer.1.get("apdu").is_none());

    for answer in &seen {
        for bytes in exposed(answer) {
            for pin in [PIN, WRONG_PIN] {
                assert!(!support::contains(&bytes, pin.as_bytes()), "an answer carries the PIN: {answer}");
            }
        }
    }
}

fn verify_attestation(
    attestation: &[u8],
    challenge: [u8; 32],
    hash: [u8; 32],
    authority: &Authority,
) -> Result<phone_attestation::VerifiedSeal, PhoneAttestationRejected> {
    let list = MeasurementList::parse(enclave::FIXTURE).unwrap();
    phone_attestation::verify(attestation, &challenge, &hash, &authority.verifier(), &list, NOW)
}

#[test]
fn the_attestation_route_gives_gpa2_binding_the_challenge_and_the_certificate() {
    let authority = Authority::new(enclave::AUTHORITY_SEED);
    let service = enclave::service(ServiceDeps::none(), allowed_old(), Arc::new(MemoryServiceLog::default()));
    service.install_master(support::master());
    let hash = service.certificate_hash();
    let challenge = [0x41; 32];
    let attestation = attest(&service, challenge);
    assert_eq!(&attestation[..4], b"GPA2");

    let seal = verify_attestation(&attestation, challenge, hash, &authority).expect("GPA2 verifies");
    assert_eq!(seal.certificate_hash, hash);
    assert_eq!(seal.answer_key, answer_key(&support::master()));
    assert_eq!(seal.kem_key, enclave::kem_key());
    assert_eq!(seal.build.name, "seal-2026-10-01");

    // Another challenge, another certificate, another root.
    assert_eq!(verify_attestation(&attestation, [0x42; 32], hash, &authority), Err(PhoneAttestationRejected::Binding));
    let mut other_hash = hash;
    other_hash[31] ^= 0x80;
    assert_eq!(verify_attestation(&attestation, challenge, other_hash, &authority), Err(PhoneAttestationRejected::Certificate));
    assert_eq!(
        verify_attestation(&attestation, challenge, hash, &Authority::new(0x51)).map(|_| ()),
        Err(PhoneAttestationRejected::Document(AttestationRejected::WrongRoot))
    );
    // The framed request gives the same layout for the same certificate.
    let framed = service.answer_frame(&[&[KIND_PHONE_ATTESTATION][..], &challenge].concat()).unwrap();
    verify_attestation(&framed, challenge, hash, &authority).expect("the framed attestation verifies");

    // An enclave whose PCRs are not on the list, or are revoked, is refused.
    for (pcrs, why) in [
        (unlisted(), MeasurementRefused::NotListed),
        (revoked(), MeasurementRefused::Revoked { name: "seal-2026-09-01".into() }),
    ] {
        let other = enclave::service(ServiceDeps::none(), pcrs, Arc::new(MemoryServiceLog::default()));
        other.install_master(support::master());
        let attestation = attest(&other, challenge);
        assert_eq!(
            verify_attestation(&attestation, challenge, other.certificate_hash(), &authority).map(|_| ()),
            Err(PhoneAttestationRejected::Measurement(why))
        );
    }
}

/// M's bytes (the tests' fixed pattern) in every form a leak could take.
fn master_forms() -> Vec<Vec<u8>> {
    let bytes: Vec<u8> = (0..32u8).map(|i| 0x40 + i).collect();
    let hex = to_hex(&bytes);
    vec![bytes, hex.clone().into_bytes(), hex.to_uppercase().into_bytes(), format!("{bytes:?}", bytes = (0..32u8).map(|i| 0x40 + i).collect::<Vec<u8>>()).into_bytes()]
}

#[test]
fn no_answer_log_line_or_error_text_carries_m_or_the_pin() {
    let (deps, fakes) = enclave::deps(true, true, true);
    let log = Arc::new(MemoryServiceLog::default());
    let service = enclave::service(deps, allowed_old(), log.clone());
    let mut texts: Vec<Vec<u8>> = Vec::new();

    // Before M.
    for (path, body) in flow_requests(&UID) {
        texts.push(post(&service, path, &body).1.to_string().into_bytes());
    }
    service.install_master(support::master());

    // Every flow with the PIN, a wrong PIN and malformed PINs.
    let mut seen = Vec::new();
    let mut card = SimCard::set_up(UID);
    let fill = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x21; 32]), "amountWei": AMOUNT.to_string(), "pin": PIN });
    let done = carry(&service, &mut card, post(&service, "/v1/fill/start", &fill), &mut seen);
    let commit_data = from_hex(done.1["commitData"].as_str().unwrap()).unwrap();
    fakes.chain.pay(CoinQuery { commit_data: commit_data.clone(), amount_wei: AMOUNT, spend_marker: fakes.maker.marker_for(&commit_data) });
    let confirm = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x22; 32]) });
    carry(&service, &mut card, post(&service, "/v1/fill/confirm", &confirm), &mut seen);
    let phone_key = to_hex(&support::phone(9).public_key());
    for (pin, challenge) in [(WRONG_PIN, 0x23), ("12", 0x24), ("123456789012345", 0x25), (PIN, 0x26)] {
        let open = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[challenge; 32]), "phoneKey": phone_key, "pin": pin });
        carry(&service, &mut card, post(&service, "/v1/open/start", &open), &mut seen);
    }
    texts.extend(seen.iter().flat_map(exposed));

    // Framed requests, good and bad, and their error texts.
    let authority = std::rc::Rc::new(Authority::new(enclave::AUTHORITY_SEED));
    let receiver = Receiver::start(&mut AuthoritySource::new(authority.clone(), allowed_new()), &mut Random(3)).unwrap();
    let frames: Vec<Vec<u8>> = vec![
        [&[KIND_KEY_SHARE][..], &receiver.request()].concat(),
        vec![KIND_KEY_SHARE, 0x47, 0x4b],
        vec![KIND_PHONE_ATTESTATION, 1],
        [&[KIND_PHONE_ATTESTATION][..], &[0x27; 32]].concat(),
        vec![0x09],
        vec![],
    ];
    for frame in &frames {
        match service.answer_frame(frame) {
            Ok(body) => texts.push(body),
            Err(why) => texts.push(why.into_bytes()),
        }
    }
    // A request from a build not on the list is refused, and logged as such.
    let stranger = Receiver::start(&mut AuthoritySource::new(authority, unlisted()), &mut Random(4)).unwrap();
    let refused = service.answer_frame(&[&[KIND_KEY_SHARE][..], &stranger.request()].concat()).unwrap_err();
    texts.push(refused.into_bytes());

    // The log.
    let events = log.0.lock().unwrap().clone();
    assert!(events.contains(&ServiceEvent::KeyShareRefused));
    assert!(events.iter().any(|e| matches!(e, ServiceEvent::HandedMaster { .. })));
    for event in &events {
        texts.push(event.to_string().into_bytes());
        texts.push(format!("{event:?}").into_bytes());
    }

    for text in &texts {
        for form in master_forms() {
            assert!(!support::contains(text, &form), "M leaked into {}", String::from_utf8_lossy(text));
        }
        for pin in [PIN, WRONG_PIN, "123456789012345"] {
            assert!(!support::contains(text, pin.as_bytes()), "a PIN leaked into {}", String::from_utf8_lossy(text));
        }
    }
    // Nor did the durable journal get the PIN.
    for entry in fakes.journal.sealed_entries() {
        assert!(!support::contains(&entry, PIN.as_bytes()));
    }
}

/// A deterministic random source (test only).
struct Random(u64);

impl SealRandom for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), SealError> {
        for chunk in out.chunks_mut(32) {
            self.0 += 1;
            chunk.copy_from_slice(&sha3_256(&[b"serve test random", &self.0.to_be_bytes()])[..chunk.len()]);
        }
        Ok(())
    }
}
