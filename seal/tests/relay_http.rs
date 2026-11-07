//! The relay's HTTP routes as the enclave serves them (`docs/seal-relay.md`):
//! every route and the error table, the 4096-byte body limit, a wrong method,
//! an unknown path, malformed request heads, the not-ready Seal, and that no
//! answer or log carries the PIN.

mod support;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ghost_seal::primitives::sha3_256;
use ghost_seal::relay::{from_hex, to_hex};
use ghost_seal::relay_http::{
    AttestRefused, Flows, MAX_BODY_BYTES, NOT_READY_MESSAGE, PhoneAttester, Reply, Routes, refusal, serve_http,
};
use ghost_seal::{
    AnswerKind, AnswerVerifier, CardState, CardTransport, MemoryJournal, Relay, RelayError, RelayLimits, SealError,
};
use serde_json::{Value, json};
use support::{AMOUNT, MEASUREMENT, START_TIME, SharedJournal, SimCard, SyncChain, SyncMaker, TestClock, UID};

const PIN: &str = "86420";
const WRONG_PIN: &str = "97531";

struct World {
    routes: Routes,
    maker: SyncMaker,
    chain: SyncChain,
    journal: SharedJournal,
}

fn world(limits: RelayLimits) -> World {
    let (maker, chain, journal) = (SyncMaker::default(), SyncChain::default(), SharedJournal::default());
    let seal_journal = journal.clone();
    let relay = Relay::new(Arc::new(move || support::thread_seal(&seal_journal)), limits);
    let (made_by, paid_by) = (maker.clone(), chain.clone());
    let flows = Flows {
        relay: Arc::new(relay),
        key_maker: Some(Arc::new(move || Box::new(made_by.clone()))),
        payment: Arc::new(move || Box::new(paid_by.clone())),
    };
    World { routes: Routes::new(Some(flows), Some(Arc::new(FixedAttester))), maker, chain, journal }
}

/// Answers every challenge with its own hash: the routes only carry it.
struct FixedAttester;

impl PhoneAttester for FixedAttester {
    fn attest(&self, challenge: &[u8; 32]) -> Result<Vec<u8>, AttestRefused> {
        Ok(sha3_256(&[b"attested", challenge]).to_vec())
    }
}

fn json_of(reply: &Reply) -> Value {
    serde_json::from_str(&reply.body).expect("every answer is JSON")
}

fn post(routes: &Routes, path: &str, body: &Value) -> (u16, Value) {
    let reply = routes.answer("POST", path, body.to_string().as_bytes());
    let value = json_of(&reply);
    (reply.status, value)
}

fn assert_error(answer: &(u16, Value), status: u16, code: &str) {
    assert_eq!(answer.0, status, "{}", answer.1);
    assert_eq!(answer.1["status"], "error", "{}", answer.1);
    assert_eq!(answer.1["error"], code, "{}", answer.1);
    assert!(answer.1["message"].as_str().is_some_and(|m| !m.is_empty()));
}

fn uid_hex() -> String {
    to_hex(&UID.0)
}

/// Carries a flow from its start answer to its end over the routes, as the
/// phone's relay does. Returns the last answer.
fn carry(routes: &Routes, card: &mut SimCard, mut answer: (u16, Value)) -> (u16, Value) {
    while answer.0 == 200 && answer.1["status"] == "apdu" {
        let session = answer.1["session"].as_str().unwrap().to_owned();
        assert_eq!(session.len(), 32);
        let apdu = from_hex(answer.1["apdu"].as_str().unwrap()).unwrap();
        let card_answer = card.transceive(&apdu).expect("the card stays in the field");
        answer = post(routes, "/v1/relay/step", &json!({ "session": session, "answer": to_hex(&card_answer) }));
    }
    answer
}

/// The fields whose values are bytes as hex.
const HEX_FIELDS: [&str; 6] = ["answer", "signature", "commitData", "release", "apdu", "session"];

/// What an answer exposes: the bytes of its hex fields, the text of the
/// others.
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

fn verifier() -> AnswerVerifier {
    let key = support::seal(&MemoryJournal::new(), &TestClock::new(), 0).answer_verifying_key();
    AnswerVerifier::new(&key, MEASUREMENT).unwrap()
}

fn verified(answer: &Value, challenge: [u8; 32]) -> ghost_seal::AnswerBody {
    assert_eq!(answer["status"], "done", "{answer}");
    let bytes = from_hex(answer["answer"].as_str().unwrap()).unwrap();
    assert_eq!(bytes.len(), 203);
    let signature = from_hex(answer["signature"].as_str().unwrap()).unwrap();
    verifier().verify(&bytes, &signature, &challenge, &UID, START_TIME).expect("the signed answer verifies")
}

#[test]
fn every_flow_runs_over_the_routes_with_the_answers_of_the_wire_format() {
    let w = world(RelayLimits::default());
    let mut card = SimCard::set_up(UID);

    // Check of a blank card: about eight round trips, a signed answer.
    let challenge = [0x61; 32];
    let start = post(&w.routes, "/v1/check/start", &json!({ "uid": uid_hex(), "challenge": to_hex(&challenge) }));
    assert_eq!(start.0, 200);
    assert_eq!(start.1["status"], "apdu");
    let done = carry(&w.routes, &mut card, start);
    let body = verified(&done.1, challenge);
    assert_eq!((body.kind, body.state), (AnswerKind::Check, CardState::Empty));
    assert!(done.1.get("commitData").is_none() && done.1.get("release").is_none());

    // Fill with a PIN (upper-case hex is taken too): done carries the commit data.
    let challenge = [0x62; 32];
    let start = post(
        &w.routes,
        "/v1/fill/start",
        &json!({ "uid": uid_hex().to_uppercase(), "challenge": to_hex(&challenge), "amountWei": AMOUNT.to_string(), "pin": PIN }),
    );
    let done = carry(&w.routes, &mut card, start);
    let body = verified(&done.1, challenge);
    let commit_data = from_hex(done.1["commitData"].as_str().expect("a Fill's done carries commitData")).unwrap();
    assert_eq!(commit_data.len(), 430);
    assert_eq!(
        (body.kind, body.state, body.amount_wei, body.coin, body.binding, body.pin_required),
        (AnswerKind::Fill, CardState::Empty, AMOUNT, sha3_256(&[&commit_data]), sha3_256(&[&commit_data]), true)
    );

    // Its confirmation before the payment: refused with the reason not-paid.
    let confirm = |challenge: [u8; 32], card: &mut SimCard| {
        let start = post(&w.routes, "/v1/fill/confirm", &json!({ "uid": uid_hex(), "challenge": to_hex(&challenge) }));
        carry(&w.routes, card, start)
    };
    let refused = confirm([0x63; 32], &mut card);
    assert_error(&refused, 422, "refused");
    assert_eq!(refused.1["reason"], "not-paid");

    // Paid: Sealed.
    w.chain.pay(&commit_data, AMOUNT);
    let done = confirm([0x64; 32], &mut card);
    let body = verified(&done.1, [0x64; 32]);
    assert_eq!((body.kind, body.state), (AnswerKind::Fill, CardState::Sealed));

    // Open: no PIN, a wrong PIN, then the PIN.
    let phone = support::phone(0x29);
    let open = |challenge: [u8; 32], pin: Option<&str>, card: &mut SimCard| {
        let mut fields = json!({ "uid": uid_hex(), "challenge": to_hex(&challenge), "phoneKey": to_hex(&phone.public_key()) });
        if let Some(pin) = pin {
            fields["pin"] = pin.into();
        }
        let start = post(&w.routes, "/v1/open/start", &fields);
        carry(&w.routes, card, start)
    };
    let refused = open([0x65; 32], None, &mut card);
    assert_error(&refused, 422, "refused");
    assert_eq!(refused.1["reason"], "pin-required");
    let refused = open([0x66; 32], Some(WRONG_PIN), &mut card);
    assert_error(&refused, 422, "refused");
    assert_eq!(refused.1["reason"], "wrong-pin");
    let done = open([0x67; 32], Some(PIN), &mut card);
    let body = verified(&done.1, [0x67; 32]);
    let release = from_hex(done.1["release"].as_str().expect("an Open's done carries release")).unwrap();
    assert_eq!((body.kind, body.state, body.binding), (AnswerKind::Open, CardState::Opened, sha3_256(&[&release])));
    assert_eq!(phone.open(&release, &UID, 1).unwrap().expose_secret(), &w.maker.key_for(&commit_data)[..]);
    assert!(w.journal.has_open(&UID));

    // A Fill of an opened card: refused, reason wrong-state.
    let start = post(
        &w.routes,
        "/v1/fill/start",
        &json!({ "uid": uid_hex(), "challenge": to_hex(&[0x68; 32]), "amountWei": "5" }),
    );
    let refused = carry(&w.routes, &mut card, start);
    assert_error(&refused, 422, "refused");
    assert_eq!(refused.1["reason"], "wrong-state");

    // Abort ends a session: aborted, then unknown.
    let start = post(&w.routes, "/v1/check/start", &json!({ "uid": uid_hex(), "challenge": to_hex(&[0x69; 32]) }));
    let session = start.1["session"].as_str().unwrap().to_owned();
    assert_eq!(post(&w.routes, "/v1/relay/abort", &json!({ "session": session })), (200, json!({ "status": "aborted" })));
    assert_error(&post(&w.routes, "/v1/relay/step", &json!({ "session": session, "answer": "9100" })), 404, "unknown-session");
}

#[test]
fn the_error_table_paths_methods_and_sizes() {
    let w = world(RelayLimits { idle_timeout: Duration::from_millis(250), total_limit: Duration::from_secs(5), max_sessions: 1 });
    let start = json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 32]) });

    // No such path, with or without a query; a path is matched exactly.
    for path in ["/", "/v1/check", "/v1/check/start/", "/v2/check/start", "/V1/CHECK/START"] {
        assert_error(&post(&w.routes, path, &start), 404, "not-found");
    }
    assert_eq!(post(&w.routes, "/v1/relay/abort?x=1", &json!({ "session": "00".repeat(16) })).0, 404, "unknown session, not path");
    // Not a POST.
    for method in ["GET", "PUT", "DELETE", "post"] {
        let reply = w.routes.answer(method, "/v1/check/start", start.to_string().as_bytes());
        assert_error(&(reply.status, json_of(&reply)), 405, "method");
    }
    // Bodies over 4096 bytes, on every route; exactly 4096 is read.
    let padded = |extra: usize| {
        let mut text = start.to_string();
        text.insert_str(1, &format!("\"pad\":\"{}\",", "x".repeat(extra)));
        text
    };
    let big = padded(MAX_BODY_BYTES);
    assert!(big.len() > MAX_BODY_BYTES);
    for path in
        ["/v1/check/start", "/v1/fill/start", "/v1/fill/confirm", "/v1/open/start", "/v1/relay/step", "/v1/relay/abort", "/v1/attestation"]
    {
        let reply = w.routes.answer("POST", path, big.as_bytes());
        assert_error(&(reply.status, json_of(&reply)), 413, "too-large");
    }
    let exact = padded(MAX_BODY_BYTES - start.to_string().len() - 9);
    assert_eq!(exact.len(), MAX_BODY_BYTES);
    // (No session field: refused as a bad request, so read, and no session is started.)
    assert_eq!(w.routes.answer("POST", "/v1/relay/abort", exact.as_bytes()).status, 400);

    // A field missing or malformed, or no JSON object.
    let bad_bodies: Vec<(&str, Vec<u8>)> = vec![
        ("/v1/check/start", b"not json".to_vec()),
        ("/v1/check/start", b"[1, 2]".to_vec()),
        ("/v1/check/start", br#"{"uid": "04518dfaa96180"}"#.to_vec()),
        ("/v1/check/start", json!({ "uid": "04518dfaa961", "challenge": to_hex(&[1; 32]) }).to_string().into_bytes()),
        ("/v1/check/start", json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 31]) }).to_string().into_bytes()),
        ("/v1/check/start", json!({ "uid": uid_hex(), "challenge": "zz".repeat(32) }).to_string().into_bytes()),
        ("/v1/fill/start", json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 32]) }).to_string().into_bytes()),
        ("/v1/fill/start", json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 32]), "amountWei": 5 }).to_string().into_bytes()),
        ("/v1/fill/start", json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 32]), "amountWei": "-5" }).to_string().into_bytes()),
        ("/v1/fill/start", json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 32]), "amountWei": "1e18" }).to_string().into_bytes()),
        ("/v1/fill/start", json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 32]), "amountWei": "9".repeat(40) }).to_string().into_bytes()),
        ("/v1/fill/start", json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 32]), "amountWei": "5", "pin": "123" }).to_string().into_bytes()),
        ("/v1/fill/start", json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 32]), "amountWei": "5", "pin": "123456789" }).to_string().into_bytes()),
        ("/v1/fill/start", json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 32]), "amountWei": "5", "pin": "12a4" }).to_string().into_bytes()),
        ("/v1/fill/start", json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 32]), "amountWei": "5", "pin": 1234 }).to_string().into_bytes()),
        ("/v1/fill/confirm", json!({ "challenge": to_hex(&[1; 32]) }).to_string().into_bytes()),
        ("/v1/open/start", json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 32]) }).to_string().into_bytes()),
        ("/v1/open/start", json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 32]), "phoneKey": "00".repeat(1183) }).to_string().into_bytes()),
        ("/v1/relay/step", json!({ "session": "00".repeat(15), "answer": "9100" }).to_string().into_bytes()),
        ("/v1/relay/step", json!({ "session": "00".repeat(16) }).to_string().into_bytes()),
        ("/v1/relay/abort", json!({}).to_string().into_bytes()),
        ("/v1/attestation", json!({ "challenge": to_hex(&[1; 16]) }).to_string().into_bytes()),
        ("/v1/attestation", b"nope".to_vec()),
    ];
    for (path, body) in &bad_bodies {
        let reply = w.routes.answer("POST", path, body);
        assert_error(&(reply.status, json_of(&reply)), 400, "bad-request");
    }
    assert_eq!(w.routes.answer("POST", "/v1/check/start", &[]).status, 400);

    // Unknown sessions.
    let unknown = json!({ "session": "ab".repeat(16), "answer": "9100" });
    assert_error(&post(&w.routes, "/v1/relay/step", &unknown), 404, "unknown-session");
    assert_error(&post(&w.routes, "/v1/relay/abort", &json!({ "session": "ab".repeat(16) })), 404, "unknown-session");

    // Busy: one session at a time here.
    let held = post(&w.routes, "/v1/check/start", &start);
    assert_eq!(held.1["status"], "apdu");
    assert_error(&post(&w.routes, "/v1/check/start", &json!({ "uid": uid_hex(), "challenge": to_hex(&[2; 32]) })), 503, "busy");
    // A card answer that is too short.
    let session = held.1["session"].as_str().unwrap().to_owned();
    assert_error(&post(&w.routes, "/v1/relay/step", &json!({ "session": session, "answer": "91" })), 400, "bad-request");
    // Expired: the card's answer comes after the idle timeout; then unknown.
    thread::sleep(Duration::from_millis(400));
    let late = json!({ "session": session, "answer": "9000" });
    assert_error(&post(&w.routes, "/v1/relay/step", &late), 410, "expired");
    assert_error(&post(&w.routes, "/v1/relay/step", &late), 404, "unknown-session");

    // A card the Seal does not hold keys for: refused, reason not-a-ghost-card.
    let mut stranger = SimCard::set_up(UID);
    stranger.keys = [[0x11; 16]; 5];
    let refused = carry(&w.routes, &mut stranger, post(&w.routes, "/v1/check/start", &json!({ "uid": uid_hex(), "challenge": to_hex(&[3; 32]) })));
    assert_error(&refused, 422, "refused");
    assert_eq!(refused.1["reason"], "not-a-ghost-card");

    // The attestation route.
    let challenge = [0x7a; 32];
    let attested = post(&w.routes, "/v1/attestation", &json!({ "challenge": to_hex(&challenge) }));
    assert_eq!(attested, (200, json!({ "status": "ok", "attestation": to_hex(&sha3_256(&[b"attested", &challenge])) })));
}

#[test]
fn the_rest_of_the_error_table_and_every_refusal_reason() {
    let table: Vec<(RelayError, u16, &str, Option<&str>)> = vec![
        (RelayError::BadRequest("uid"), 400, "bad-request", None),
        (RelayError::UnknownSession, 404, "unknown-session", None),
        (RelayError::Expired, 410, "expired", None),
        (RelayError::Seal(SealError::Dropped), 422, "card-dropped", None),
        (RelayError::Busy, 503, "busy", None),
        (RelayError::Seal(SealError::NotAGhostCard), 422, "refused", Some("not-a-ghost-card")),
        (RelayError::Seal(SealError::UnknownKeys), 422, "refused", Some("not-a-ghost-card")),
        (RelayError::Seal(SealError::NotSettled), 422, "refused", Some("filling")),
        (RelayError::Seal(SealError::NotPaid), 422, "refused", Some("not-paid")),
        (RelayError::Seal(SealError::CantCheckNow), 422, "refused", Some("cant-check-now")),
        (RelayError::Seal(SealError::CoinSpent), 422, "refused", Some("spent")),
        (RelayError::Seal(SealError::PinRequired), 422, "refused", Some("pin-required")),
        (RelayError::Seal(SealError::WrongPin { tries_left: 2 }), 422, "refused", Some("wrong-pin")),
        (RelayError::Seal(SealError::PinLocked), 422, "refused", Some("pin-locked")),
        (RelayError::Seal(SealError::WrongState(CardState::Sealed)), 422, "refused", Some("wrong-state")),
        (RelayError::Seal(SealError::FillPending), 422, "refused", Some("fill-pending")),
        (RelayError::Seal(SealError::TornRecord), 422, "refused", None),
        (RelayError::Seal(SealError::BadAmount), 422, "refused", None),
    ];
    for (error, status, code, reason) in table {
        let reply = refusal(&error);
        let body = json_of(&reply);
        assert_error(&(reply.status, body.clone()), status, code);
        assert_eq!(body.get("reason").and_then(Value::as_str), reason, "{error:?}");
    }
}

#[test]
fn a_seal_that_is_not_ready_refuses_every_flow_and_still_attests() {
    let routes = Routes::new(None, Some(Arc::new(FixedAttester)));
    assert!(!routes.serves_flows());
    let bodies = [
        ("/v1/check/start", json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 32]) })),
        ("/v1/fill/start", json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 32]), "amountWei": "5", "pin": PIN })),
        ("/v1/fill/confirm", json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 32]) })),
        ("/v1/open/start", json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 32]), "phoneKey": "00".repeat(1184) })),
        ("/v1/relay/step", json!({ "session": "00".repeat(16), "answer": "9100" })),
        ("/v1/relay/abort", json!({ "session": "00".repeat(16) })),
        ("/v1/check/start", json!("not even a request")),
    ];
    for (path, body) in &bodies {
        let answer = post(&routes, path, body);
        assert_error(&answer, 503, "unavailable");
        assert_eq!(answer.1["message"], NOT_READY_MESSAGE);
        assert!(!answer.1.to_string().contains(PIN));
    }
    // Paths, methods and sizes are still checked first.
    assert_error(&post(&routes, "/v1/nothing", &json!({})), 404, "not-found");
    let reply = routes.answer("GET", "/v1/check/start", b"{}");
    assert_eq!(reply.status, 405);
    let attested = post(&routes, "/v1/attestation", &json!({ "challenge": to_hex(&[5; 32]) }));
    assert_eq!(attested.0, 200);
    assert_eq!(attested.1["status"], "ok");

    // A Fill without a key maker is refused the same way, while Check runs.
    let w = world(RelayLimits::default());
    drop(w.routes);
    let journal = SharedJournal::default();
    let relay = Relay::new(Arc::new(move || support::thread_seal(&journal)), RelayLimits::default());
    let chain = w.chain.clone();
    let routes = Routes::new(
        Some(Flows { relay: Arc::new(relay), key_maker: None, payment: Arc::new(move || Box::new(chain.clone())) }),
        None,
    );
    let fill = post(&routes, "/v1/fill/start", &json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 32]), "amountWei": "5" }));
    assert_error(&fill, 503, "unavailable");
    assert_eq!(post(&routes, "/v1/check/start", &json!({ "uid": uid_hex(), "challenge": to_hex(&[1; 32]) })).1["status"], "apdu");
    // And no attester: the attestation route is unavailable.
    assert_error(&post(&routes, "/v1/attestation", &json!({ "challenge": to_hex(&[5; 32]) })), 503, "unavailable");
}

/// Serves `routes` on one end of a socket pair, on its own thread.
fn served(routes: Routes) -> (UnixStream, thread::JoinHandle<()>) {
    let (client, mut server) = UnixStream::pair().unwrap();
    client.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let handle = thread::spawn(move || {
        serve_http(&mut server, &routes);
    });
    (client, handle)
}

/// Reads one HTTP answer: status, the lower-cased head, the body.
fn read_answer(stream: &mut UnixStream) -> (u16, String, Value) {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        assert_eq!(stream.read(&mut byte).unwrap(), 1, "the answer's head is cut short");
        bytes.push(byte[0]);
    }
    let head = String::from_utf8(bytes).unwrap().to_lowercase();
    let status = head[9..12].parse().unwrap();
    let length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .expect("a content length")
        .trim()
        .parse()
        .unwrap();
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).unwrap();
    (status, head, serde_json::from_slice(&body).unwrap())
}

fn request(path: &str, body: &str, extra_headers: &str) -> String {
    format!("POST {path} HTTP/1.1\r\nHost: ghost-seal\r\nContent-Type: application/json\r\n{extra_headers}Content-Length: {}\r\n\r\n{body}", body.len())
}

fn closed(stream: &mut UnixStream) -> bool {
    let mut rest = Vec::new();
    matches!(stream.read_to_end(&mut rest), Ok(0))
}

#[test]
fn http_requests_on_one_connection_and_malformed_heads() {
    // Two requests on one connection, the second sent in two pieces; every answer is no-store.
    let w = world(RelayLimits::default());
    let (mut client, handle) = served(w.routes);
    let check = json!({ "uid": uid_hex(), "challenge": to_hex(&[9; 32]) }).to_string();
    client.write_all(request("/v1/check/start", &check, "").as_bytes()).unwrap();
    let (status, head, body) = read_answer(&mut client);
    assert_eq!((status, body["status"].as_str()), (200, Some("apdu")));
    assert!(head.contains("\r\ncache-control: no-store\r\n"));
    assert!(head.contains("\r\ncontent-type: application/json\r\n"));
    assert!(head.contains("\r\nconnection: keep-alive\r\n"));
    let abort = json!({ "session": body["session"] }).to_string();
    let second = request("/v1/relay/abort", &abort, "Connection: close\r\n");
    let (a, b) = second.as_bytes().split_at(second.len() / 2);
    client.write_all(a).unwrap();
    thread::sleep(Duration::from_millis(50));
    client.write_all(b).unwrap();
    let (status, head, body) = read_answer(&mut client);
    assert_eq!((status, body), (200, json!({ "status": "aborted" })));
    assert!(head.contains("\r\nconnection: close\r\n"));
    assert!(closed(&mut client));
    handle.join().unwrap();

    // A body over 4096 bytes is refused unread and the connection closed.
    let (mut client, handle) = served(world(RelayLimits::default()).routes);
    client.write_all(b"POST /v1/check/start HTTP/1.1\r\nContent-Length: 4097\r\n\r\n").unwrap();
    let (status, _, body) = read_answer(&mut client);
    assert_eq!((status, body["error"].as_str()), (413, Some("too-large")));
    assert!(closed(&mut client));
    handle.join().unwrap();

    // Wrong method and unknown path over the wire too, on one connection.
    let (mut client, handle) = served(world(RelayLimits::default()).routes);
    client.write_all(b"GET /v1/check/start HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    assert_eq!(read_answer(&mut client).0, 405);
    client.write_all(request("/v1/elsewhere", "{}", "").as_bytes()).unwrap();
    assert_eq!(read_answer(&mut client).0, 404);
    drop(client);
    handle.join().unwrap();

    // Malformed heads: answered 400 and closed.
    let malformed: [&[u8]; 7] = [
        b"POST /v1/check/start\r\n\r\n",
        b"POST /v1/check/start HTTP/1.1\r\nContent-Length: twelve\r\n\r\n",
        b"POST /v1/check/start HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}",
        b"POST /v1/check/start HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
        b"POST /v1/check/start HTTP/1.1\r\nBad Header\r\n\r\n",
        b"\x01\x02\x03 nonsense\r\n\r\n",
        b"POST /v1/check/start HTTP/9.9\r\n\r\n",
    ];
    for head in malformed {
        let (mut client, handle) = served(world(RelayLimits::default()).routes);
        client.write_all(head).unwrap();
        let (status, _, body) = read_answer(&mut client);
        assert_eq!((status, body["error"].as_str()), (400, Some("bad-request")), "{}", String::from_utf8_lossy(head));
        assert!(closed(&mut client));
        handle.join().unwrap();
    }

    // A head that never ends is cut off at its limit.
    let (mut client, handle) = served(world(RelayLimits::default()).routes);
    let endless = format!("POST /v1/check/start HTTP/1.1\r\nX-Long: {}", "a".repeat(9000));
    let _ = client.write_all(endless.as_bytes());
    assert_eq!(read_answer(&mut client).0, 400);
    handle.join().unwrap();

    // A connection closed mid-body ends the server's side without an answer.
    let (mut client, handle) = served(world(RelayLimits::default()).routes);
    client.write_all(b"POST /v1/check/start HTTP/1.1\r\nContent-Length: 50\r\n\r\n{\"uid\"").unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    handle.join().unwrap();
    assert!(closed(&mut client));
}

#[test]
fn nothing_logs_or_echoes_the_pin() {
    let w = world(RelayLimits::default());
    let mut card = SimCard::set_up(UID);
    let mut answers = Vec::new();

    let fill = json!({ "uid": uid_hex(), "challenge": to_hex(&[0x71; 32]), "amountWei": AMOUNT.to_string(), "pin": PIN });
    let start = post(&w.routes, "/v1/fill/start", &fill);
    answers.push(start.1.clone());
    let done = carry(&w.routes, &mut card, start);
    answers.push(done.1.clone());
    let commit_data = from_hex(done.1["commitData"].as_str().unwrap()).unwrap();
    w.chain.pay(&commit_data, AMOUNT);
    let start = post(&w.routes, "/v1/fill/confirm", &json!({ "uid": uid_hex(), "challenge": to_hex(&[0x72; 32]) }));
    answers.push(carry(&w.routes, &mut card, start).1);
    let phone_key = to_hex(&support::phone(3).public_key());
    for (pin, challenge) in [(WRONG_PIN, [0x73; 32]), (PIN, [0x74; 32])] {
        let open = json!({ "uid": uid_hex(), "challenge": to_hex(&challenge), "phoneKey": phone_key, "pin": pin });
        let start = post(&w.routes, "/v1/open/start", &open);
        answers.push(start.1.clone());
        answers.push(carry(&w.routes, &mut card, start).1);
    }
    // Malformed PINs are refused by the field's name only.
    for pin in ["8642097531864209", "86 42", "864x"] {
        let open = json!({ "uid": uid_hex(), "challenge": to_hex(&[0x75; 32]), "phoneKey": phone_key, "pin": pin });
        let answer = post(&w.routes, "/v1/open/start", &open);
        assert_error(&answer, 400, "bad-request");
        assert!(!answer.1.to_string().contains(pin));
        answers.push(answer.1);
    }
    // A PIN is digits, so it is looked for in the bytes a hex field stands
    // for, not in its hex text, where it could turn up by chance.
    for answer in &answers {
        for bytes in exposed(answer) {
            for pin in [PIN, WRONG_PIN] {
                assert!(!support::contains(&bytes, pin.as_bytes()), "an answer carries the PIN: {answer}");
            }
        }
    }
    // Nor did any of it reach the card in the clear, or the journal.
    for bytes in card.transcript.iter().chain(w.journal.sealed_entries().iter()) {
        assert!(!support::contains(bytes, PIN.as_bytes()) && !support::contains(bytes, WRONG_PIN.as_bytes()));
    }

    // The routes write nothing anywhere but the answer: no print or log call in the module.
    let source = include_str!("../src/relay_http.rs");
    for call in ["println!", "eprintln!", "print!(", "eprint!(", "dbg!", "log::", "tracing::", "std::fs", "File::"] {
        assert!(!source.contains(call), "relay_http.rs calls {call}");
    }
}
