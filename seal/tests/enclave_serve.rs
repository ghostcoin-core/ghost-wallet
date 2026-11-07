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
//! authority; no answer, log line or error text carrying M or the PIN; and,
//! over TLS ended in the enclave, a Fill answered `unavailable` without a
//! key maker and served with the enclave's own (`CoreKeyMakerSource`), its
//! key the wallet core's, found by the core's lookup, and in no answer or
//! log line. With the region list installed: a card is served by its home
//! region only; another region refuses its Check, Fill, Fill confirmation
//! and Open `wrong-region`, naming the home, with no change to either
//! region's log, the card or the service log (an Open begun at home
//! included), over TLS too; and the journal anchored in peer enclaves over
//! the service port (kind 3): every record reaches both peers' host stores,
//! ciphertext only, a replaced host restores from them, and with a peer not
//! answering, or an approved enclave on the asker's own host (its PCR4) or
//! of another region answering on a peer's port, every flow is 503 with a
//! fixed event; each answer carries the responder's fresh attestation with
//! the asker's nonce and its PCR4.

#[path = "fixtures/nitro_authority.rs"]
mod authority;
#[path = "support/enclave.rs"]
mod enclave;
#[path = "fixtures/test_release_key.rs"]
mod release;
mod support;
#[path = "support/tls_client.rs"]
mod tls_client;

use std::sync::Arc;
use std::time::Duration;

use authority::{Authority, AuthoritySource, NOW, allowed_new, allowed_old, revoked, unlisted};
use ghost_seal::attestation::{AttestationRejected, AttestationVerifier};
use ghost_seal::enclave_serve::{
    ChainStatus, DurableJournal, EnclaveService, KIND_JOURNAL_HEAD, KIND_KEY_SHARE, KIND_PHONE_ATTESTATION,
    MemoryServiceLog, NodeChainStatus, PINNED_PATHS, ServiceDeps, ServiceEvent, ServicePeer,
};
use ghost_seal::journal_anchor::{
    Anchor, PEER_PORTS, Peer, PeerLink, PeerLogs, Peers, RELEASE_REGIONS, Regions, WRONG_REGION_MESSAGE, home_region,
};
use ghost_seal::MasterKey;
use ghost_seal::journal_log::{HeadAnchor, LogStore};
use ghost_seal::proxy::TcpConnector;
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

/// One request as the service answers it over TLS: the home region's check,
/// then the routes (with no region list installed, the routes alone).
fn post(service: &EnclaveService, path: &str, body: &Value) -> (u16, Value) {
    let reply = service.answer("POST", path, body.to_string().as_bytes());
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

/// An anchor that asks no peer (test only): reads a region's log as its own
/// enclave does, every tag bound to that region.
struct ReadOnly(&'static str);

impl HeadAnchor for ReadOnly {
    fn origin(&self) -> &str {
        self.0
    }

    fn restore(&mut self, _: &MasterKey, _: &[(u64, Vec<u8>)]) -> Result<Vec<(u64, Vec<u8>)>, SealError> {
        Ok(Vec::new())
    }

    fn anchor(&mut self, _: u64, _: &[u8], _: &mut dyn LogStore) -> Result<(), SealError> {
        Err(SealError::Journal("a read-only log takes no save"))
    }
}

/// Region `origin`'s anchored log as its enclave reads it from `store`.
fn reread_in(store: &MemoryLogStore, origin: &'static str) -> JournalLog {
    let anchor = Box::new(ReadOnly(origin));
    JournalLog::open_anchored(&support::master(), Box::new(store.clone()), Box::new(Random(0)), anchor)
        .expect("the log verifies")
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

/// The phone's relay over TLS: carries a flow from its start answer to its
/// end on `tls`, each command to the card and each answer back.
fn carry_tls(
    tls: &mut (impl std::io::Read + std::io::Write),
    card: &mut SimCard,
    mut answer: (u16, Value),
    seen: &mut Vec<Value>,
) -> (u16, Value) {
    seen.push(answer.1.clone());
    while answer.0 == 200 && answer.1["status"] == "apdu" {
        let apdu = from_hex(answer.1["apdu"].as_str().unwrap()).unwrap();
        let card_answer = card.transceive(&apdu).expect("the card stays in the field");
        let step = json!({ "session": answer.1["session"].clone(), "answer": to_hex(&card_answer) });
        answer = tls_client::post(tls, "/v1/relay/step", &step);
        seen.push(answer.1.clone());
    }
    answer
}

/// A service with `deps` holding the test M, served on a local port as the
/// enclave serves its service port.
fn served(deps: ServiceDeps) -> (Arc<EnclaveService>, std::net::SocketAddr, Arc<MemoryServiceLog>) {
    let log = Arc::new(MemoryServiceLog::default());
    let service = Arc::new(enclave::service(deps, allowed_old(), log.clone()));
    service.install_master(support::master());
    assert!(service.serves_flows());
    let addr = enclave::serve(service.clone(), Duration::from_secs(60));
    (service, addr, log)
}

#[test]
fn with_the_core_key_maker_installed_a_fill_over_tls_is_served_and_its_key_is_in_no_answer_or_log_line() {
    let fill = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x61; 32]), "amountWei": AMOUNT.to_string(), "pin": PIN });

    // Without a key maker, the flows are served and a Fill is not.
    let (service, addr, _) = served(enclave::deps_with_maker(None).0);
    let mut tls = tls_client::connect(addr, service.certificate_hash());
    assert_unavailable(&tls_client::post(&mut tls, "/v1/fill/start", &fill));
    let check = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x60; 32]) });
    let started = tls_client::post(&mut tls, "/v1/check/start", &check);
    assert_eq!((started.0, started.1["status"].as_str()), (200, Some("apdu")), "{}", started.1);
    tls_client::post(&mut tls, "/v1/relay/abort", &json!({ "session": started.1["session"].clone() }));

    // With the enclave's own key maker: the same Fill over TLS is served.
    let (deps, fakes) = enclave::deps_with_maker(Some(enclave::core_key_maker()));
    let (service, addr, log) = served(deps);
    let hash = service.certificate_hash();
    let key = answer_key(&support::master());
    let mut seen = Vec::new();
    let mut card = SimCard::set_up(UID);
    let mut tls = tls_client::connect(addr, hash);
    let start = tls_client::post(&mut tls, "/v1/fill/start", &fill);
    let done = carry_tls(&mut tls, &mut card, start, &mut seen);
    let body = verified(&key, &done.1, [0x61; 32], &UID);
    let commit_data = from_hex(done.1["commitData"].as_str().unwrap()).unwrap();
    assert_eq!((body.kind, body.state, body.coin), (AnswerKind::Fill, CardState::Empty, sha3_256(&[&commit_data])));
    assert_eq!(commit_data.len(), ghost_wallet_core::COMMIT_DATA_BYTES);

    // Paid on the fake chain (its payment check needs only the coin; the
    // Seal's own status check asks with its journal's spend marker), then
    // confirmed over TLS: Sealed.
    assert!(fakes.maker.made.lock().unwrap().is_empty(), "the enclave's own maker made the key");
    fakes.chain.pay(CoinQuery { commit_data: commit_data.clone(), amount_wei: AMOUNT, spend_marker: [0u8; 32] });
    let mut tls = tls_client::connect(addr, hash);
    let confirm = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x62; 32]) });
    let start = tls_client::post(&mut tls, "/v1/fill/confirm", &confirm);
    let done = carry_tls(&mut tls, &mut card, start, &mut seen);
    assert_eq!(verified(&key, &done.1, [0x62; 32], &UID).state, CardState::Sealed);

    // Opened over TLS: the phone gets the core's key bytes, and the wallet
    // core finds exactly the filled amount with them.
    let phone = support::phone(0x63);
    let mut tls = tls_client::connect(addr, hash);
    let open = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x64; 32]), "phoneKey": to_hex(&phone.public_key()), "pin": PIN });
    let start = tls_client::post(&mut tls, "/v1/open/start", &open);
    let done = carry_tls(&mut tls, &mut card, start, &mut seen);
    let body = verified(&key, &done.1, [0x64; 32], &UID);
    assert_eq!(body.state, CardState::Opened);
    let release = from_hex(done.1["release"].as_str().unwrap()).unwrap();
    let phantom = phone.open(&release, &UID, body.generation).expect("the release opens");
    let bytes = phantom.expose_secret().to_vec();
    assert_eq!((bytes.len(), bytes[0]), (33, 0x20), "the core's key bytes");
    let core_key = ghost_wallet_core::seal_open::phantom_key_from_bytes(&bytes).expect("the core takes them");
    let leaf = ghost_wallet_core::commit_leaf(commit_data.clone(), AMOUNT.to_string()).unwrap();
    let found = ghost_wallet_core::find_coins(&core_key, support::nodes::NETWORK.chain_id, &[leaf], &[]).unwrap();
    assert_eq!((found.status.as_str(), found.amount_wei), ("found", AMOUNT.to_string()));

    // The key's bytes, in every form, are in no answer and no log line.
    let secret = &bytes[1..];
    let forms = [secret.to_vec(), to_hex(secret).into_bytes(), to_hex(secret).to_uppercase().into_bytes(), format!("{secret:?}").into_bytes()];
    let mut texts: Vec<Vec<u8>> = seen.iter().flat_map(exposed).collect();
    texts.extend(seen.iter().map(|answer| answer.to_string().into_bytes()));
    texts.extend(card.transcript.iter().cloned());
    let events = log.0.lock().unwrap().clone();
    assert!(!events.is_empty());
    for event in &events {
        texts.push(event.to_string().into_bytes());
        texts.push(format!("{event:?}").into_bytes());
    }
    for text in &texts {
        for form in &forms {
            assert!(!support::contains(text, form), "the key leaked into {}", String::from_utf8_lossy(text));
        }
    }
}

/// The home region of the tests' card ([`UID`]), as
/// `tests/vectors/home-region.json` has it.
const HOME: &str = "eu-central-1";
/// A region that is not its home.
const AWAY: &str = "us-east-1";
/// A card whose home is [`AWAY`] (from the same vectors).
const AWAY_CARD: CardUid = CardUid([0x04, 0x10, 0x22, 0x33, 0x44, 0x55, 0x66]);

/// A service of region `own` whose journal is the sealed log over `store`,
/// with the fakes for the rest, holding M.
fn region_service(own: &str, store: &MemoryLogStore) -> (EnclaveService, enclave::Fakes, Arc<MemoryServiceLog>) {
    let journal = SharedLog::new(Box::new(store.clone()));
    let (mut deps, fakes) = enclave::deps_with_journal(Arc::new(journal) as Arc<dyn DurableJournal>);
    deps.regions = Some(Regions::release(own).unwrap());
    let log = Arc::new(MemoryServiceLog::default());
    let service = enclave::service(deps, allowed_old(), log.clone());
    service.install_master(support::master());
    assert!(service.serves_flows());
    (service, fakes, log)
}

fn assert_wrong_region(answer: &(u16, Value), home: &str) {
    assert_eq!(answer.0, 422, "{}", answer.1);
    assert_eq!(
        answer.1,
        json!({
            "status": "error",
            "error": "refused",
            "reason": "wrong-region",
            "homeRegion": home,
            "message": WRONG_REGION_MESSAGE,
        })
    );
}

/// Begins an Open of `card` on `service` and cuts it off at the first card
/// command after it was journaled in `store`, the log of region `origin`
/// (`None`: a log anchored nowhere).
fn begin_open_cut_off(
    service: &EnclaveService,
    store: &MemoryLogStore,
    origin: Option<&'static str>,
    card: &mut SimCard,
    open: &Value,
) {
    let mut step = 0;
    loop {
        card.drop_from(step, support::DropStyle::AfterCard);
        let ended = carry_or_drop(service, card, post(service, "/v1/open/start", open));
        card.reconnect();
        assert!(ended.is_none() || ended.as_ref().is_some_and(|a| a.0 != 200), "step {step}: cut off");
        let log = match origin {
            Some(origin) => reread_in(store, origin),
            None => reread(store),
        };
        if log.load(&UID, EntryKind::Open).is_some() {
            return;
        }
        step += 1;
        assert!(step < 64, "the Open was never journaled");
    }
}

#[test]
fn an_open_begun_at_home_is_refused_wrong_region_elsewhere_touching_nothing_and_finished_at_home() {
    assert_eq!(home_region(&RELEASE_REGIONS, &UID), Some(HOME));
    assert_eq!(home_region(&RELEASE_REGIONS, &AWAY_CARD), Some(AWAY));
    let (home_store, away_store) = (MemoryLogStore::new(), MemoryLogStore::new());
    let (home, home_fakes, _) = region_service(HOME, &home_store);
    let (away, away_fakes, away_log) = region_service(AWAY, &away_store);
    let key = answer_key(&support::master());

    // Filled, sealed, and an Open begun at home.
    let mut card = SimCard::set_up(UID);
    let commit_data = fill_and_seal(&home, &home_fakes, &mut card, &mut Vec::new());
    let phone = support::phone(0x71);
    let open = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x72; 32]), "phoneKey": to_hex(&phone.public_key()) });
    begin_open_cut_off(&home, &home_store, None, &mut card, &open);

    // The phone tries the other region: its Open, and a Check, a Fill and a
    // Fill confirmation of the same card, are refused, naming the home.
    let home_records = home_store.records();
    let (file, keys, transcript) = (card.file.clone(), card.keys, card.transcript.len());
    let events = away_log.0.lock().unwrap().clone();
    assert_wrong_region(&post(&away, "/v1/open/start", &open), HOME);
    let pinned: Vec<(&str, Value)> =
        flow_requests(&UID).into_iter().filter(|(path, _)| PINNED_PATHS.contains(path)).collect();
    assert_eq!(pinned.len(), 4, "Check, Fill, Fill confirmation and Open");
    for (path, body) in &pinned {
        let answer = post(&away, path, body);
        assert_wrong_region(&answer, HOME);
        assert!(!support::contains(answer.1.to_string().as_bytes(), PIN.as_bytes()));
    }
    // Nothing changed: neither region's log, nor the card, nor the other
    // region's service log; no key was made and no card command sent.
    assert!(away_store.records().is_empty(), "the other region's log is untouched");
    assert_eq!(home_store.records(), home_records, "the home region's log is untouched");
    assert_eq!((card.file.clone(), card.keys, card.transcript.len()), (file, keys, transcript), "the card is untouched");
    assert_eq!(*away_log.0.lock().unwrap(), events, "no log line");
    assert!(away_fakes.maker.made.lock().unwrap().is_empty());
    assert!(away_fakes.journal.sealed_entries().is_empty());

    // The home region finishes the Open with the key of the Fill.
    let done = carry(&home, &mut card, post(&home, "/v1/open/start", &open), &mut Vec::new());
    let body = verified(&key, &done.1, [0x72; 32], &UID);
    assert_eq!(body.state, CardState::Opened);
    let release = from_hex(done.1["release"].as_str().unwrap()).unwrap();
    assert_eq!(phone.open(&release, &UID, 1).unwrap().expose_secret(), &home_fakes.maker.key_for(&commit_data)[..]);
    // And the other region, asked again, still refuses and still holds
    // nothing; it would certify nothing about the card.
    let check = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x73; 32]) });
    assert_wrong_region(&post(&away, "/v1/check/start", &check), HOME);
    assert!(away_store.records().is_empty());

    // The rule is the same the other way round: a card homed in us-east-1
    // is refused by eu-central-1 and served (here: not registered) by its
    // home.
    let other = json!({ "uid": uid_hex(&AWAY_CARD), "challenge": to_hex(&[0x74; 32]) });
    assert_wrong_region(&post(&home, "/v1/check/start", &other), AWAY);
    let served = post(&away, "/v1/check/start", &other);
    assert_eq!((served.0, served.1["reason"].as_str()), (422, Some("not-a-ghost-card")));
    // A malformed start is the routes' to refuse, as before.
    let malformed = post(&away, "/v1/check/start", &json!({ "uid": "04", "challenge": to_hex(&[1; 32]) }));
    assert_eq!(malformed.0, 400, "{}", malformed.1);
}

#[test]
fn over_tls_a_card_of_another_region_is_refused_before_the_relay_routes() {
    let (mut deps, fakes) = enclave::deps(true, true, true);
    deps.regions = Some(Regions::release(AWAY).unwrap());
    let (service, addr, log) = served(deps);
    let mut tls = tls_client::connect(addr, service.certificate_hash());
    for (path, body) in flow_requests(&UID).into_iter().filter(|(path, _)| PINNED_PATHS.contains(path)) {
        assert_wrong_region(&tls_client::post(&mut tls, path, &body), HOME);
    }
    // Every other request on the same connection is the routes'.
    let malformed = tls_client::post(&mut tls, "/v1/check/start", &json!({ "uid": "zz" }));
    assert_eq!(malformed.0, 400, "{}", malformed.1);
    assert_eq!(tls_client::post(&mut tls, "/v1/nowhere", &json!({})).0, 404);
    let step = tls_client::post(&mut tls, "/v1/relay/step", &json!({ "session": "00".repeat(16), "answer": "9100" }));
    assert_eq!((step.0, step.1["error"].as_str()), (404, Some("unknown-session")));
    let attested = tls_client::post(&mut tls, "/v1/attestation", &json!({ "challenge": to_hex(&[0x75; 32]) }));
    assert_eq!(attested.0, 200, "{}", attested.1);
    // Its own card over TLS starts a Check at once.
    let own = json!({ "uid": uid_hex(&AWAY_CARD), "challenge": to_hex(&[0x76; 32]) });
    let refused = tls_client::post(&mut tls, "/v1/check/start", &own);
    assert_eq!(refused.1["reason"].as_str(), Some("not-a-ghost-card"), "the routes answered it: {}", refused.1);
    assert!(fakes.journal.sealed_entries().is_empty());
    assert_eq!(*log.0.lock().unwrap(), vec![ServiceEvent::MasterInstalled { serves_flows: true }]);

    // The card's home region over TLS starts its Check.
    let (mut deps, _) = enclave::deps(true, true, true);
    deps.regions = Some(Regions::release(HOME).unwrap());
    let (service, addr, _) = served(deps);
    let mut tls = tls_client::connect(addr, service.certificate_hash());
    let check = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x77; 32]) });
    let started = tls_client::post(&mut tls, "/v1/check/start", &check);
    assert_eq!((started.0, started.1["status"].as_str()), (200, Some("apdu")), "{}", started.1);
    tls_client::post(&mut tls, "/v1/relay/abort", &json!({ "session": started.1["session"].clone() }));
}

/// The parent instance (PCR4) of each test enclave's host.
const HOME_HOST: [u8; 48] = [0x51; 48];
const US_HOST: [u8; 48] = [0x52; 48];
const AP_HOST: [u8; 48] = [0x53; 48];
const NEW_HOME_HOST: [u8; 48] = [0x54; 48];

/// A peer region's enclave on the instance `pcr4`: it holds M, keeps the
/// logs of the other regions in `stores` (restored at its start, with no
/// other holder to ask, as they are) and serves its service port on a local
/// socket.
fn peer_enclave(own: &str, stores: &[(&str, &MemoryLogStore)], pcr4: [u8; 48]) -> (Arc<EnclaveService>, std::net::SocketAddr) {
    let (mut deps, _) = enclave::deps(true, true, true);
    deps.regions = Some(Regions::release(own).unwrap());
    let stores = stores.iter().map(|(region, store)| (region.to_string(), Box::new((*store).clone()) as Box<dyn LogStore>));
    deps.peer_logs = Some(Arc::new(PeerLogs::new(Arc::new(Peers::new(own, Vec::new())), stores.collect())));
    let log = Arc::new(MemoryServiceLog::default());
    let service = Arc::new(enclave::service_on_instance(deps, allowed_old(), pcr4, log));
    service.install_master(support::master());
    assert!(service.serves_flows());
    let addr = enclave::serve(service.clone(), Duration::from_secs(60));
    (service, addr)
}

/// The home region's service on the instance `pcr4`, its journal the sealed
/// log over `store` anchored in the enclaves at `peers` over their service
/// ports, every answer checked with its own attestation and trusted list.
fn anchored_service(
    store: &MemoryLogStore,
    peers: &[(&str, std::net::SocketAddr)],
    pcr4: [u8; 48],
) -> (EnclaveService, enclave::Fakes, Arc<MemoryServiceLog>) {
    let links = peers
        .iter()
        .map(|(region, addr)| Peer {
            region: region.to_string(),
            link: Arc::new(ServicePeer::new(TcpConnector(addr.to_string()), Duration::from_secs(5))) as Arc<dyn PeerLink>,
        })
        .collect();
    let peers = Arc::new(Peers::new(HOME, links));
    let journal = SharedLog::anchored(Box::new(store.clone()), Box::new(Anchor::new(Arc::clone(&peers))));
    let (mut deps, fakes) = enclave::deps_with_journal(Arc::new(journal) as Arc<dyn DurableJournal>);
    deps.regions = Some(Regions::release(HOME).unwrap());
    // Its own copies of the other regions' logs are not under test here.
    deps.peer_logs = Some(Arc::new(PeerLogs::new(peers, Vec::new())));
    let log = Arc::new(MemoryServiceLog::default());
    let service = enclave::service_on_instance(deps, allowed_old(), pcr4, log.clone());
    service.install_master(support::master());
    (service, fakes, log)
}

#[test]
fn the_journal_is_anchored_in_the_peer_enclaves_over_the_service_port() {
    assert_eq!((PEER_PORTS, KIND_JOURNAL_HEAD), ([5006, 5007], 3));
    // us-east-1 and ap-southeast-1 keep eu-central-1's log, each on its host.
    let (us_copy, ap_copy) = (MemoryLogStore::new(), MemoryLogStore::new());
    let (_us, us_addr) = peer_enclave("us-east-1", &[(HOME, &us_copy), ("ap-southeast-1", &MemoryLogStore::new())], US_HOST);
    let (_ap, ap_addr) = peer_enclave("ap-southeast-1", &[("us-east-1", &MemoryLogStore::new()), (HOME, &ap_copy)], AP_HOST);
    let peers = [("us-east-1", us_addr), ("ap-southeast-1", ap_addr)];

    // The home region fills and seals the card and begins an Open; every
    // record reached both peers before its save was taken.
    let store = MemoryLogStore::new();
    let mut card = SimCard::set_up(UID);
    let phone = support::phone(0x78);
    let open = json!({ "uid": uid_hex(&UID), "challenge": to_hex(&[0x79; 32]), "phoneKey": to_hex(&phone.public_key()) });
    let (commit_data, first_fakes) = {
        let (service, fakes, log) = anchored_service(&store, &peers, HOME_HOST);
        assert!(service.serves_flows());
        assert_eq!(*log.0.lock().unwrap(), vec![ServiceEvent::MasterInstalled { serves_flows: true }]);
        let commit_data = fill_and_seal(&service, &fakes, &mut card, &mut Vec::new());
        begin_open_cut_off(&service, &store, Some(HOME), &mut card, &open);
        (commit_data, fakes)
        // The host instance is lost here, with its store.
    };
    assert!(!store.records().is_empty());
    assert_eq!(us_copy.records(), store.records());
    assert_eq!(ap_copy.records(), store.records());
    // The peers' hosts hold ciphertext only.
    for copy in [&us_copy, &ap_copy] {
        let bytes = copy.bytes();
        assert!(!support::contains(&bytes, &UID.0), "a UID on a peer's host");
        assert!(!support::contains(&bytes, &commit_data[..32]), "commit data on a peer's host");
    }

    // A replaced host: its store is empty. The enclave restores the whole
    // log from its peers before it serves, and finishes the Open it never
    // saw with the key of the Fill.
    let replaced = MemoryLogStore::new();
    let (service, _, log) = anchored_service(&replaced, &peers, NEW_HOME_HOST);
    assert!(service.serves_flows());
    assert_eq!(*log.0.lock().unwrap(), vec![ServiceEvent::MasterInstalled { serves_flows: true }]);
    assert_eq!(replaced.records(), store.records(), "restored, ciphertext as it was");
    let done = carry(&service, &mut card, post(&service, "/v1/open/start", &open), &mut Vec::new());
    let body = verified(&answer_key(&support::master()), &done.1, [0x79; 32], &UID);
    assert_eq!(body.state, CardState::Opened);
    let release = from_hex(done.1["release"].as_str().unwrap()).unwrap();
    assert_eq!(phone.open(&release, &UID, 1).unwrap().expose_secret(), &first_fakes.maker.key_for(&commit_data)[..]);
    assert_eq!(us_copy.records(), replaced.records(), "the new host's records reached the peers too");
    assert_eq!(ap_copy.records(), replaced.records());

    // A tail the host cut while the enclave was stopped, with no peer
    // reachable, or one: every flow 503, a fixed event, nothing appended.
    let gone = |region| (region, std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap());
    let cut = MemoryLogStore::new();
    cut.set_records(store.records()[..1].to_vec());
    for down in [vec![gone("us-east-1"), gone("ap-southeast-1")], vec![peers[0], gone("ap-southeast-1")]] {
        let (service, fakes, log) = anchored_service(&cut, &down, NEW_HOME_HOST);
        assert!(!service.serves_flows());
        assert_eq!(
            *log.0.lock().unwrap(),
            vec![ServiceEvent::JournalUnanchored, ServiceEvent::MasterInstalled { serves_flows: false }]
        );
        for (path, body) in flow_requests(&UID) {
            assert_unavailable(&post(&service, path, &body));
        }
        assert_eq!(cut.records(), store.records()[..1].to_vec());
        assert!(fakes.maker.made.lock().unwrap().is_empty());
    }

    // An approved us-east-1 enclave started on the home's own host (its
    // PCR4), holding M and the cut copy, on us-east-1's port: its attested
    // answers are refused, and nothing is restored or served.
    let impostor_copy = MemoryLogStore::new();
    impostor_copy.set_records(cut.records());
    let (_impostor, impostor_addr) =
        peer_enclave("us-east-1", &[(HOME, &impostor_copy), ("ap-southeast-1", &MemoryLogStore::new())], NEW_HOME_HOST);
    let (service, _, log) = anchored_service(&cut, &[("us-east-1", impostor_addr), peers[1]], NEW_HOME_HOST);
    assert!(!service.serves_flows());
    assert_eq!(log.0.lock().unwrap()[0], ServiceEvent::JournalUnanchored);
    assert_eq!(cut.records(), store.records()[..1].to_vec());
    // ap-southeast-1's enclave answering on us-east-1's port: refused too.
    let (service, _, _) = anchored_service(&cut, &[("us-east-1", ap_addr), peers[1]], NEW_HOME_HOST);
    assert!(!service.serves_flows());
    // The same cut with the established peers reachable is restored and
    // served.
    let (service, _, _) = anchored_service(&cut, &peers, NEW_HOME_HOST);
    assert!(service.serves_flows());
    assert_eq!(cut.records(), us_copy.records());

    // A kind 3 request to an enclave that keeps no peer logs, or holds no
    // M yet, is refused.
    let bare = enclave::service(ServiceDeps::none(), allowed_old(), Arc::new(MemoryServiceLog::default()));
    bare.install_master(support::master());
    assert!(bare.answer_frame(&[KIND_JOURNAL_HEAD, 2, 0]).unwrap_err().contains("no peer logs"));
    let (mut deps, _) = enclave::deps(true, true, true);
    deps.peer_logs = Some(Arc::new(PeerLogs::new(Arc::new(Peers::new("us-east-1", Vec::new())), Vec::new())));
    let early = enclave::service(deps, allowed_old(), Arc::new(MemoryServiceLog::default()));
    assert!(early.answer_frame(&[KIND_JOURNAL_HEAD, 2, 0]).unwrap_err().contains("no M"));
}

#[test]
fn a_peer_answer_carries_a_fresh_attestation_with_the_askers_nonce_and_the_responders_pcr4() {
    let copy = MemoryLogStore::new();
    let (peer, _) = peer_enclave("us-east-1", &[(HOME, &copy), ("ap-southeast-1", &MemoryLogStore::new())], US_HOST);
    let mut request = vec![KIND_JOURNAL_HEAD, 2, HOME.len() as u8];
    request.extend_from_slice(HOME.as_bytes());
    request.extend_from_slice(&[0x5a; 32]);
    let answer = peer.answer_frame(&request).expect("a head of an empty copy: no copy");
    let responder = usize::from(answer[0]);
    assert_eq!(&answer[1..1 + responder], b"us-east-1");
    let length = usize::from(u16::from_be_bytes([answer[1 + responder], answer[2 + responder]]));
    let document = &answer[3 + responder..3 + responder + length];
    let checked = Authority::new(enclave::AUTHORITY_SEED).verifier().verify(document, NOW).expect("the AWS-format document");
    assert_eq!(checked.nonce, Some(vec![0x5a; 32]), "the asker's nonce");
    assert_eq!(checked.pcrs, allowed_old());
    assert_eq!(ghost_seal::enclave_serve::document_pcr4(document), Some(US_HOST));
    assert_eq!(&answer[3 + responder + length + 32..], [0, 1], "no copy of an empty log, never a zero head");
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
