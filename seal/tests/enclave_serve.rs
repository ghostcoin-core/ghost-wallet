//! The enclave's service as library code: fail closed until M is held and a
//! chain status check, a card registry (loaded) and a durable journal are
//! installed (with any one missing every flow is refused and no card
//! traffic is sent), then a good Check, Fill, Fill confirmation and Open
//! with the fakes installed through the `ChainStatus` and `RegistrySource`
//! traits; the same with the sealed log (`journal_log`) installed as the
//! durable journal through `DurableJournal::journal(&master)`, a log that
//! fails to verify leaving every flow 503, an enclave built from a reopened
//! log finishing the Open the first began, and a rollback while it runs
//! refused; the real chain status check over `RpcNode`s needs two nodes and
//! never seals without them; the attestation route with the tests'
//! authority; and no answer, log line or error text carrying M or the PIN.

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
    ChainStatus, DurableJournal, EnclaveService, KIND_KEY_SHARE, KIND_PHONE_ATTESTATION, MemoryServiceLog,
    NodeChainStatus, ServiceDeps, ServiceEvent,
};
use ghost_seal::journal_log::{JournalLog, MemoryLogStore, SharedLog};
use ghost_seal::{EntryKind, Journal};
use ghost_seal::key_share::Receiver;
use ghost_seal::measurements::{MeasurementList, MeasurementRefused};
use ghost_seal::node_rpc::{NodeAddress, RpcNode, TcpTransport, VsockTransport};
use ghost_seal::{CoinStatus, LoadedRegistry, NodeList, NodeListError};
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
    assert!(!ServiceDeps::none().ready());
}

#[test]
fn a_registry_installed_but_not_loaded_is_not_ready() {
    // What the enclave program installs: a chain check, a durable journal
    // and a registry the host has not loaded yet.
    let registry = LoadedRegistry::new();
    let (deps, fakes) = enclave::deps_with_loaded(&registry);
    assert!(!deps.ready());
    let service = enclave::service(deps.clone(), allowed_old(), Arc::new(MemoryServiceLog::default()));
    service.install_master(support::master());
    assert!(!service.serves_flows());
    for (path, body) in flow_requests(&UID) {
        assert_unavailable(&post(&service, path, &body));
    }
    let without_journal = ServiceDeps { journal: None, ..deps.clone() };
    registry.load(&enclave::registry_text(&[UID])).unwrap();
    assert!(deps.ready());
    assert!(!without_journal.ready(), "a loaded registry without a durable journal is still not ready");
    assert!(service.refresh_flows());
    let answer = post(&service, "/v1/check/start", &json!({ "uid": uid_hex(&STRANGER), "challenge": to_hex(&[9; 32]) }));
    assert_eq!((answer.0, answer.1["reason"].as_str()), (422, Some("not-a-ghost-card")));
    assert!(fakes.journal.sealed_entries().is_empty());
}

/// A node that cannot be reached: plain HTTP to a loopback port nothing
/// listens on.
fn unreachable_node(name: &str) -> RpcNode {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let address = NodeAddress { name: name.into(), host: "127.0.0.1".into(), port, path: "/".into(), tls: false };
    RpcNode::new(address, Arc::new(TcpTransport)).unwrap()
}

#[test]
fn the_node_chain_status_needs_two_nodes_and_never_seals_without_them() {
    // The release node list, as the enclave program builds it.
    let list = NodeList::release();
    let nodes: Vec<RpcNode> = list
        .nodes
        .iter()
        .map(|entry| {
            RpcNode::new(NodeAddress::from_entry(entry), Arc::new(VsockTransport { cid: 3, port: entry.vsock_port }))
                .unwrap()
        })
        .collect();
    assert!(NodeChainStatus::new(list.network, nodes).is_ok());
    let network = list.network;
    assert_eq!(NodeChainStatus::new(network, vec![unreachable_node("a")]).err(), Some(NodeListError::TooFewNodes));
    assert_eq!(
        NodeChainStatus::new(network, vec![unreachable_node("a"), unreachable_node("a")]).err(),
        Some(NodeListError::SameNodeTwice)
    );

    // Installed with nodes that cannot be reached: a filled card is never
    // sealed, however the payment check answers.
    let status = NodeChainStatus::new(network, vec![unreachable_node("a"), unreachable_node("b")]).unwrap();
    let coin = support::nodes::test_coin(9, AMOUNT);
    assert_eq!(status.status_check().coin_status(&coin), CoinStatus::CantCheckNow);
    let (mut deps, fakes) = enclave::deps(true, true, true);
    deps.chain = Some(Arc::new(status) as Arc<dyn ChainStatus>);
    let service = enclave::service(deps, allowed_old(), Arc::new(MemoryServiceLog::default()));
    service.install_master(support::master());
    let mut card = SimCard::set_up(UID);
    let mut seen = Vec::new();
    let fill = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x31; 32]), "amountWei": AMOUNT.to_string() });
    let done = carry(&service, &mut card, post(&service, "/v1/fill/start", &fill), &mut seen);
    assert_eq!(done.1["status"], "done", "{}", done.1);
    let confirm = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x32; 32]) });
    let refused = carry(&service, &mut card, post(&service, "/v1/fill/confirm", &confirm), &mut seen);
    assert_eq!((refused.0, refused.1["reason"].as_str()), (422, Some("cant-check-now")), "{}", refused.1);
    let check = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x33; 32]) });
    let checked = carry(&service, &mut card, post(&service, "/v1/check/start", &check), &mut seen);
    let body = verified(&answer_key(&support::master()), &checked.1, [0x33; 32], &UID);
    assert_eq!(body.state, CardState::Empty, "never Sealed");
    assert!(!fakes.journal.sealed_entries().is_empty(), "the Fill was journaled");
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

/// A service whose durable journal is the sealed log over `store` (the
/// host's store, here in memory), with the fakes for the rest, holding M.
fn log_service(store: &MemoryLogStore) -> (EnclaveService, enclave::Fakes, Arc<MemoryServiceLog>) {
    let journal = SharedLog::new(Box::new(store.clone()));
    let (deps, fakes) = enclave::deps_with_journal(Arc::new(journal) as Arc<dyn DurableJournal>);
    assert!(deps.ready());
    let log = Arc::new(MemoryServiceLog::default());
    let service = enclave::service(deps, allowed_old(), log.clone());
    service.install_master(support::master());
    (service, fakes, log)
}

/// The log as a restarted enclave reads it from `store`.
fn reread(store: &MemoryLogStore) -> JournalLog {
    JournalLog::open(&support::master(), Box::new(store.clone())).expect("the log verifies")
}

/// Fills card `card` through `service` and has the fake chain pay and the
/// confirmation seal it; the commit data.
fn fill_and_seal(service: &EnclaveService, fakes: &enclave::Fakes, card: &mut SimCard, seen: &mut Vec<Value>) -> Vec<u8> {
    let key = answer_key(&support::master());
    let fill = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x52; 32]), "amountWei": AMOUNT.to_string() });
    let done = carry(service, card, post(service, "/v1/fill/start", &fill), seen);
    verified(&key, &done.1, [0x52; 32], &UID);
    let commit_data = from_hex(done.1["commitData"].as_str().unwrap()).unwrap();
    fakes.chain.pay(CoinQuery { commit_data: commit_data.clone(), amount_wei: AMOUNT, spend_marker: fakes.maker.marker_for(&commit_data) });
    let confirm = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x53; 32]) });
    let done = carry(service, card, post(service, "/v1/fill/confirm", &confirm), seen);
    assert_eq!(verified(&key, &done.1, [0x53; 32], &UID).state, CardState::Sealed);
    commit_data
}

#[test]
fn with_the_sealed_log_installed_check_fill_confirm_and_open_are_served() {
    let store = MemoryLogStore::new();
    let (service, fakes, log) = log_service(&store);
    assert!(service.serves_flows());
    assert_eq!(*log.0.lock().unwrap(), vec![ServiceEvent::MasterInstalled { serves_flows: true }]);
    let key = answer_key(&support::master());
    let mut seen = Vec::new();
    let mut card = SimCard::set_up(UID);

    let check = |challenge: [u8; 32], card: &mut SimCard, seen: &mut Vec<Value>| {
        let start = post(&service, "/v1/check/start", &json!({ "uid": uid_hex(&UID), "challenge": to_hex(&challenge) }));
        let done = carry(&service, card, start, seen);
        verified(&key, &done.1, challenge, &UID)
    };
    assert_eq!(check([0x51; 32], &mut card, &mut seen).state, CardState::Empty);
    let commit_data = fill_and_seal(&service, &fakes, &mut card, &mut seen);
    assert!(store.records().len() >= 1, "the Fill went to the host's store");
    assert!(reread(&store).load(&UID, EntryKind::Fill).is_some());
    assert_eq!(check([0x54; 32], &mut card, &mut seen).state, CardState::Sealed);

    let phone = support::phone(0x56);
    let open = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x55; 32]), "phoneKey": to_hex(&phone.public_key()) });
    let done = carry(&service, &mut card, post(&service, "/v1/open/start", &open), &mut seen);
    let body = verified(&key, &done.1, [0x55; 32], &UID);
    assert_eq!(body.state, CardState::Opened);
    let release = from_hex(done.1["release"].as_str().unwrap()).unwrap();
    assert_eq!(phone.open(&release, &UID, 1).unwrap().expose_secret(), &fakes.maker.key_for(&commit_data)[..]);
    assert!(reread(&store).load(&UID, EntryKind::Open).is_some());
    // The host holds counters and ciphertext: no UID, no commit data.
    let bytes = store.bytes();
    assert!(!support::contains(&bytes, &UID.0));
    assert!(!support::contains(&bytes, &commit_data[..32]));
    // Nor does the in-memory test journal get anything: the log is the
    // journal.
    assert!(fakes.journal.sealed_entries().is_empty());
}

#[test]
fn a_log_that_fails_to_verify_leaves_every_flow_503() {
    // A good log of a few records, then one record changed by the host.
    let store = MemoryLogStore::new();
    {
        let (service, fakes, _) = log_service(&store);
        fill_and_seal(&service, &fakes, &mut SimCard::set_up(UID), &mut Vec::new());
    }
    // Two more records, written by the log as the enclave writes them.
    let mut more = reread(&store);
    more.save(&STRANGER, EntryKind::Fill, b"a second entry".to_vec()).unwrap();
    more.save(&STRANGER, EntryKind::Open, b"a third entry".to_vec()).unwrap();
    let good = store.records();
    assert_eq!(good.len(), 3);
    let mut tampered = good.clone();
    tampered[0].1[18] ^= 0x01;
    let mut swapped = good.clone();
    swapped.swap(0, 1);
    let mut cut = good.clone();
    cut.remove(0);
    for (what, records) in [("a changed record", tampered), ("a reorder", swapped), ("a gap", cut)] {
        store.set_records(records);
        let (service, fakes, log) = log_service(&store);
        assert!(!service.serves_flows(), "{what}");
        assert_eq!(
            *log.0.lock().unwrap(),
            vec![ServiceEvent::JournalRefused, ServiceEvent::MasterInstalled { serves_flows: false }],
            "{what}"
        );
        for (path, body) in flow_requests(&UID) {
            let answer = post(&service, path, &body);
            assert_unavailable(&answer);
            assert!(answer.1.get("apdu").is_none(), "{what}: no card traffic");
        }
        assert!(fakes.maker.made.lock().unwrap().is_empty());
        // The attestation route still works.
        attest(&service, [0x57; 32]);
        // Once the host's log is sound again, the next refresh serves.
        store.set_records(good.clone());
        assert!(service.refresh_flows(), "{what}");
        assert!(service.serves_flows());
    }

    // A log sealed under another M is refused the same way.
    store.set_records(good);
    let (deps, _) = enclave::deps_with_journal(Arc::new(SharedLog::new(Box::new(store.clone()))) as Arc<dyn DurableJournal>);
    let log = Arc::new(MemoryServiceLog::default());
    let service = enclave::service(deps, allowed_old(), log.clone());
    let mut other = [0x5au8; 32];
    service.install_master(ghost_seal::MasterKey::take(&mut other));
    assert!(!service.serves_flows());
    assert!(log.0.lock().unwrap().contains(&ServiceEvent::JournalRefused));
    for (path, body) in flow_requests(&UID) {
        assert_unavailable(&post(&service, path, &body));
    }
}

/// Carries a flow until it ends or the card leaves the field (then the
/// phone aborts the session).
fn carry_or_drop(service: &EnclaveService, card: &mut SimCard, mut answer: (u16, Value)) -> Option<(u16, Value)> {
    while answer.0 == 200 && answer.1["status"] == "apdu" {
        let apdu = from_hex(answer.1["apdu"].as_str().unwrap()).unwrap();
        let session = answer.1["session"].clone();
        let Ok(card_answer) = card.transceive(&apdu) else {
            post(service, "/v1/relay/abort", &json!({ "session": session }));
            return None;
        };
        answer = post(service, "/v1/relay/step", &json!({ "session": session, "answer": to_hex(&card_answer) }));
    }
    Some(answer)
}

#[test]
fn the_enclave_built_from_a_reopened_log_serves_an_open_the_first_one_began() {
    let store = MemoryLogStore::new();
    let mut card = SimCard::set_up(UID);
    let phone = support::phone(0x58);
    let open = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x59; 32]), "phoneKey": to_hex(&phone.public_key()) });
    let (commit_data, first_fakes) = {
        let (service, fakes, _) = log_service(&store);
        let commit_data = fill_and_seal(&service, &fakes, &mut card, &mut Vec::new());
        // The Open is cut off at the first command after it was journaled.
        let mut step = 0;
        loop {
            card.drop_from(step, support::DropStyle::AfterCard);
            let ended = carry_or_drop(&service, &mut card, post(&service, "/v1/open/start", &open));
            card.reconnect();
            assert!(ended.is_none() || ended.as_ref().is_some_and(|a| a.0 != 200), "step {step}: cut off");
            if reread(&store).load(&UID, EntryKind::Open).is_some() {
                break;
            }
            step += 1;
            assert!(step < 64, "the Open was never journaled");
        }
        (commit_data, fakes)
        // The enclave stops here.
    };

    // A new enclave on the same host's log.
    let (service, _, log) = log_service(&store);
    assert!(service.serves_flows());
    assert_eq!(*log.0.lock().unwrap(), vec![ServiceEvent::MasterInstalled { serves_flows: true }]);
    let key = answer_key(&support::master());
    let done = carry(&service, &mut card, post(&service, "/v1/open/start", &open), &mut Vec::new());
    let body = verified(&key, &done.1, [0x59; 32], &UID);
    assert_eq!(body.state, CardState::Opened);
    let release = from_hex(done.1["release"].as_str().unwrap()).unwrap();
    assert_eq!(phone.open(&release, &UID, 1).unwrap().expose_secret(), &first_fakes.maker.key_for(&commit_data)[..]);
    // Another phone cannot take it over.
    let other = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x5a; 32]), "phoneKey": to_hex(&support::phone(0x5b).public_key()) });
    let refused = carry(&service, &mut card, post(&service, "/v1/open/start", &other), &mut Vec::new());
    assert_eq!(refused.0, 422, "{}", refused.1);
}

#[test]
fn a_host_that_rolls_the_log_back_while_the_enclave_runs_is_refused() {
    let store = MemoryLogStore::new();
    let (service, fakes, log) = log_service(&store);
    let mut card = SimCard::set_up(UID);
    fill_and_seal(&service, &fakes, &mut card, &mut Vec::new());
    let records = store.records();
    // The host drops the last record.
    store.set_records(records[..records.len() - 1].to_vec());
    let (file, keys) = (card.file.clone(), card.keys);
    let phone = support::phone(0x5c);
    let open = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x5d; 32]), "phoneKey": to_hex(&phone.public_key()) });
    let answer = carry(&service, &mut card, post(&service, "/v1/open/start", &open), &mut Vec::new());
    assert_eq!(answer.0, 422, "{}", answer.1);
    assert!(answer.1.get("release").is_none());
    assert_eq!((card.file.clone(), card.keys), (file, keys), "the card is unchanged");
    assert!(log.0.lock().unwrap().contains(&ServiceEvent::JournalRefused));
    // Refused for good: the host putting the record back changes nothing.
    store.set_records(records.clone());
    let again = carry(&service, &mut card, post(&service, "/v1/open/start", &open), &mut Vec::new());
    assert_eq!(again.0, 422, "{}", again.1);
    assert_eq!(store.records(), records, "nothing more was appended");
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
