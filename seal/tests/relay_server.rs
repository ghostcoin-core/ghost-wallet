//! The development test Seal server, run in-process on loopback, with the
//! simulated NTAG 424 DNA playing the phone's relay: each command the Seal
//! hands out goes to the card and the card's raw answer goes back, round
//! trip by round trip, until the Seal's signed answer.

mod support;

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ghost_seal::answer::{AnswerKind, AnswerVerifier};
use ghost_seal::card_keys::{card_keys, key_version};
use ghost_seal::flows::record_file_settings;
use ghost_seal::primitives::sha3_256;
use ghost_seal::relay::{RelayLimits, to_hex};
use ghost_seal::test_server::{
    DEFAULT_BODY_DEADLINE, DEV_MEASUREMENT, DEV_TEST_MASTER_LABEL, Options, StartError, TestSealServer, WARNING,
    dev_test_master, dev_test_master_bytes, dev_test_seal,
};
use ghost_seal::{
    CardState, CardTransport, CardUid, CheckRequest, FillRequest, MemoryJournal, Seal, SealConfig,
};
use serde_json::{Value, json};
use support::{AMOUNT, DropStyle, SimCard, StubChain, StubMaker, TestClock, TestRandom, UID, contains, hex};

/// The test M, as card setup also uses it.
const DEV_TEST_MASTER_HEX: &str = "d7c19145c84d99edf3c8fbe63d29dfe4e7a89e39e5454e3903a123e4cf7b6040";

fn args(extra: &[&str]) -> Vec<String> {
    ["--dev-test-seal", "--listen", "127.0.0.1:0"].iter().chain(extra).map(|s| s.to_string()).collect()
}

fn server(extra: &[&str]) -> TestSealServer {
    let options = Options::from_args(&args(extra), Some("1")).expect("options");
    TestSealServer::start(&options).expect("server")
}

/// One HTTP/1.1 request on its own connection; the status and JSON body.
fn post(addr: SocketAddr, path: &str, body: &Value) -> (u16, Value) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let body = body.to_string();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("an answer");
    let text = String::from_utf8(raw).expect("text");
    let (head, body) = text.split_once("\r\n\r\n").expect("a head and a body");
    let status = head.split(' ').nth(1).expect("a status").parse().expect("a number");
    (status, serde_json::from_str(body).expect("a JSON body"))
}

fn unhex(text: &Value) -> Vec<u8> {
    support::unhex(text.as_str().expect("a hex string"))
}

/// A card as card setup leaves it under the test M: its five keys of
/// generation 0, the record file set up for the Seal and blank.
fn dev_card(uid: CardUid) -> SimCard {
    let mut card = SimCard::factory(uid.0);
    let keys = card_keys(&dev_test_master(), &uid);
    for key_no in 0..5u8 {
        card.keys[usize::from(key_no)] = *keys.key(key_no);
        card.versions[usize::from(key_no)] = key_version(0);
    }
    card.settings = record_file_settings();
    card
}

/// A card under the test M, filled with a coin of [`AMOUNT`] and Sealed.
fn sealed_dev_card() -> SimCard {
    let clock = TestClock::new();
    let journal = MemoryJournal::new();
    let mut seal = Seal::new(
        dev_test_master(),
        SealConfig { measurement: DEV_MEASUREMENT, answer_lifetime_secs: 120 },
        Box::new(TestRandom::new(7)),
        Box::new(clock),
        Box::new(journal),
    );
    let mut card = dev_card(UID);
    let mut maker = StubMaker::default();
    let filled = seal
        .fill(&mut card, &FillRequest { uid: UID, challenge: [1u8; 32], amount_wei: AMOUNT, pin: None }, &mut maker)
        .expect("fill");
    let chain = StubChain::default();
    chain.pay(&filled.commit_data, AMOUNT);
    seal.confirm_fill(&mut card, &CheckRequest { uid: UID, challenge: [2u8; 32] }, &chain).expect("confirm");
    card.transcript.clear();
    card
}

/// How a relayed Check ended.
#[derive(Debug)]
enum Relayed {
    /// The signed answer, its signature and the session id used.
    Done { answer: Vec<u8>, signature: Vec<u8>, session: String, round_trips: usize },
    /// The Seal refused a request.
    Refused { status: u16, body: Value },
    /// The card left the field; the phone ended the session.
    CardLost { session: String, abort: (u16, Value) },
}

/// The phone's relay: starts a Check, then carries each command to the card
/// and each answer back, as opaque bytes.
fn relay_check(addr: SocketAddr, card: &mut SimCard, uid: CardUid, challenge: [u8; 32]) -> Relayed {
    let (mut status, mut body) =
        post(addr, "/v1/check/start", &json!({ "uid": to_hex(&uid.0), "challenge": to_hex(&challenge) }));
    let mut session = String::new();
    let mut round_trips = 1;
    loop {
        if status != 200 {
            return Relayed::Refused { status, body };
        }
        match body["status"].as_str() {
            Some("apdu") => {
                session = body["session"].as_str().expect("a session").to_owned();
                let Ok(answer) = card.transceive(&unhex(&body["apdu"])) else {
                    let abort = post(addr, "/v1/relay/abort", &json!({ "session": session }));
                    return Relayed::CardLost { session, abort };
                };
                (status, body) =
                    post(addr, "/v1/relay/step", &json!({ "session": session, "answer": to_hex(&answer) }));
                round_trips += 1;
            }
            Some("done") => {
                return Relayed::Done {
                    answer: unhex(&body["answer"]),
                    signature: unhex(&body["signature"]),
                    session,
                    round_trips,
                };
            }
            other => panic!("unexpected answer {other:?}: {body}"),
        }
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn verifier() -> AnswerVerifier {
    AnswerVerifier::new(&dev_test_seal().answer_verifying_key(), DEV_MEASUREMENT).expect("verifier")
}

#[test]
fn the_test_master_is_the_published_value() {
    assert_eq!(hex(&dev_test_master_bytes()).to_lowercase(), DEV_TEST_MASTER_HEX);
    assert_eq!(dev_test_master_bytes(), sha3_256(&[b"ghost-seal/dev-test-master/v1"]));
    assert_eq!(DEV_TEST_MASTER_LABEL, b"ghost-seal/dev-test-master/v1");
    // The server's Seal holds it: the card keys it derives are the test M's.
    let keys = card_keys(&dev_test_master(), &UID);
    let mut bytes = support::unhex(DEV_TEST_MASTER_HEX).try_into().unwrap();
    let published = ghost_seal::MasterKey::take(&mut bytes);
    assert_eq!(keys.key(1), card_keys(&published, &UID).key(1));
}

#[test]
fn a_check_relayed_round_trip_by_round_trip_verifies() {
    let server = server(&[]);
    let mut card = sealed_dev_card();
    let challenge = [0x5au8; 32];
    let Relayed::Done { answer, signature, session, round_trips } =
        relay_check(server.addr(), &mut card, UID, challenge)
    else {
        panic!("the Check did not finish");
    };
    let body = verifier().verify(&answer, &signature, &challenge, &UID, now()).expect("a verified answer");
    assert_eq!(body.kind, AnswerKind::Check);
    assert_eq!(body.state, CardState::Sealed);
    assert_eq!(body.amount_wei, AMOUNT);
    assert_eq!(body.uid, UID);

    // Every command reached the card and every answer came back: one Seal
    // round trip per card round trip, and the start.
    let card_round_trips = card.transcript.len() / 2;
    assert!(card_round_trips >= 5, "a Check selects, authenticates and reads: {card_round_trips}");
    assert_eq!(round_trips, card_round_trips + 1);

    // The relayed bytes never carry a card key: the phone holds none.
    let keys = card_keys(&dev_test_master(), &UID);
    for key_no in 0..5u8 {
        for bytes in &card.transcript {
            assert!(!contains(bytes, keys.key(key_no)));
        }
    }

    // The session is finished: its id is refused from now on.
    assert_eq!(server.session_count(), 0);
    let (status, refused) =
        post(server.addr(), "/v1/relay/step", &json!({ "session": session, "answer": "9100" }));
    assert_eq!(status, 404);
    assert_eq!(refused["error"], "unknown-session");
}

#[test]
fn a_blank_card_is_answered_empty() {
    let server = server(&[]);
    let mut card = dev_card(UID);
    let challenge = [0x11u8; 32];
    let Relayed::Done { answer, signature, .. } = relay_check(server.addr(), &mut card, UID, challenge) else {
        panic!("the Check did not finish");
    };
    let body = verifier().verify(&answer, &signature, &challenge, &UID, now()).expect("a verified answer");
    assert_eq!(body.state, CardState::Empty);
    assert_eq!(body.amount_wei, 0);
}

#[test]
fn a_card_not_set_up_with_the_test_master_is_refused() {
    let server = server(&[]);
    let mut card = SimCard::set_up(UID);
    let Relayed::Refused { status, body } = relay_check(server.addr(), &mut card, UID, [3u8; 32]) else {
        panic!("a card of another M was answered");
    };
    assert_eq!(status, 422);
    assert_eq!(body["error"], "refused");
    assert_eq!(server.session_count(), 0);
}

#[test]
fn a_card_dropped_mid_check_ends_the_session_and_a_new_check_succeeds() {
    let server = server(&[]);
    let mut card = sealed_dev_card();
    card.drop_from(3, DropStyle::BeforeCard);
    let Relayed::CardLost { session, abort } = relay_check(server.addr(), &mut card, UID, [4u8; 32]) else {
        panic!("the dropped card was not noticed");
    };
    assert_eq!(abort.0, 200);
    assert_eq!(abort.1["status"], "aborted");
    assert_eq!(server.session_count(), 0);
    let (status, body) = post(server.addr(), "/v1/relay/step", &json!({ "session": session, "answer": "9100" }));
    assert_eq!((status, body["error"].as_str()), (404, Some("unknown-session")));

    card.reconnect();
    let challenge = [5u8; 32];
    let Relayed::Done { answer, signature, .. } = relay_check(server.addr(), &mut card, UID, challenge) else {
        panic!("the Check run again did not finish");
    };
    assert_eq!(verifier().verify(&answer, &signature, &challenge, &UID, now()).unwrap().state, CardState::Sealed);
}

#[test]
fn a_connection_dropped_mid_check_leaves_the_server_serving_and_the_session_times_out() {
    let server = server(&["--idle-ms", "300", "--total-ms", "5000"]);
    let mut card = sealed_dev_card();
    let (status, started) = post(
        server.addr(),
        "/v1/check/start",
        &json!({ "uid": to_hex(&UID.0), "challenge": to_hex(&[6u8; 32]) }),
    );
    assert_eq!(status, 200);
    let session = started["session"].as_str().unwrap().to_owned();
    let answer = card.transceive(&unhex(&started["apdu"])).unwrap();

    // The phone's connection breaks halfway through sending the card's answer.
    let mut stream = TcpStream::connect(server.addr()).unwrap();
    let partial = format!("{{\"session\":\"{session}\",\"answer\":\"{}", to_hex(&answer));
    write!(stream, "POST /v1/relay/step HTTP/1.1\r\nHost: x\r\nContent-Length: 400\r\n\r\n{partial}").unwrap();
    drop(stream);

    // The Seal gave up waiting for the card: the session is refused.
    std::thread::sleep(Duration::from_millis(500));
    let (status, body) =
        post(server.addr(), "/v1/relay/step", &json!({ "session": session, "answer": to_hex(&answer) }));
    assert_eq!((status, body["error"].as_str()), (410, Some("expired")));

    // The server still serves: a fresh Check from the start succeeds.
    let challenge = [7u8; 32];
    let Relayed::Done { answer, signature, .. } = relay_check(server.addr(), &mut card, UID, challenge) else {
        panic!("the Check run again did not finish");
    };
    assert_eq!(verifier().verify(&answer, &signature, &challenge, &UID, now()).unwrap().state, CardState::Sealed);
}

#[test]
fn an_unknown_or_malformed_session_id_is_refused() {
    let server = server(&[]);
    let unknown = to_hex(&[0x42u8; 16]);
    let (status, body) = post(server.addr(), "/v1/relay/step", &json!({ "session": unknown, "answer": "9100" }));
    assert_eq!((status, body["error"].as_str()), (404, Some("unknown-session")));
    let (status, body) = post(server.addr(), "/v1/relay/abort", &json!({ "session": unknown }));
    assert_eq!((status, body["error"].as_str()), (404, Some("unknown-session")));
    let (status, body) = post(server.addr(), "/v1/relay/step", &json!({ "session": "zz", "answer": "9100" }));
    assert_eq!((status, body["error"].as_str()), (400, Some("bad-request")));
    let (status, body) = post(server.addr(), "/v1/check/start", &json!({ "uid": "0451", "challenge": "00" }));
    assert_eq!((status, body["error"].as_str()), (400, Some("bad-request")));
}

#[test]
fn an_idle_session_expires() {
    let server = server(&["--idle-ms", "200", "--total-ms", "5000"]);
    let mut card = sealed_dev_card();
    let (status, started) = post(
        server.addr(),
        "/v1/check/start",
        &json!({ "uid": to_hex(&UID.0), "challenge": to_hex(&[8u8; 32]) }),
    );
    assert_eq!(status, 200);
    let session = started["session"].as_str().unwrap().to_owned();
    let answer = card.transceive(&unhex(&started["apdu"])).unwrap();
    std::thread::sleep(Duration::from_millis(400));
    let step = json!({ "session": session, "answer": to_hex(&answer) });
    let (status, body) = post(server.addr(), "/v1/relay/step", &step);
    assert_eq!((status, body["error"].as_str()), (410, Some("expired")));
    // Once refused, it is gone.
    let (status, body) = post(server.addr(), "/v1/relay/step", &step);
    assert_eq!((status, body["error"].as_str()), (404, Some("unknown-session")));
}

#[test]
fn a_session_past_its_total_limit_expires_even_when_each_step_is_in_time() {
    let server = server(&["--idle-ms", "400", "--total-ms", "700"]);
    let mut card = sealed_dev_card();
    let (mut status, mut body) = post(
        server.addr(),
        "/v1/check/start",
        &json!({ "uid": to_hex(&UID.0), "challenge": to_hex(&[9u8; 32]) }),
    );
    while status == 200 && body["status"] == "apdu" {
        let answer = card.transceive(&unhex(&body["apdu"])).unwrap();
        std::thread::sleep(Duration::from_millis(250));
        (status, body) = post(
            server.addr(),
            "/v1/relay/step",
            &json!({ "session": body["session"], "answer": to_hex(&answer) }),
        );
    }
    assert_eq!((status, body["error"].as_str()), (410, Some("expired")), "{body}");
}

#[test]
fn the_dev_flags_are_required() {
    let refused = |args: &[&str], env: Option<&str>| {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        matches!(Options::from_args(&args, env), Err(StartError::NotDevelopment(_)))
    };
    assert!(refused(&["--listen", "127.0.0.1:0"], Some("1")));
    assert!(refused(&["--dev-test-seal", "--listen", "127.0.0.1:0"], None));
    assert!(refused(&["--dev-test-seal", "--listen", "127.0.0.1:0"], Some("0")));
    assert!(refused(&["--dev-test-seal", "--listen", "127.0.0.1:0"], Some("true")));
    assert!(Options::from_args(&args(&[]), Some("1")).is_ok());

    let binary = env!("CARGO_BIN_EXE_test_seal_server");
    let without_flag = Command::new(binary)
        .args(["--listen", "127.0.0.1:0"])
        .env("GHOST_DEV_TEST_SEAL", "1")
        .output()
        .unwrap();
    assert_eq!(without_flag.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&without_flag.stderr).contains("--dev-test-seal is missing"));

    let without_env = Command::new(binary)
        .args(["--dev-test-seal", "--listen", "127.0.0.1:0"])
        .env_remove("GHOST_DEV_TEST_SEAL")
        .output()
        .unwrap();
    assert_eq!(without_env.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&without_env.stderr).contains("GHOST_DEV_TEST_SEAL=1 is not set"));

    // With both it starts, and its first word is the warning.
    let mut running = Command::new(binary)
        .args(["--dev-test-seal", "--listen", "127.0.0.1:0"])
        .env("GHOST_DEV_TEST_SEAL", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first = String::new();
    BufReader::new(running.stderr.take().unwrap()).read_line(&mut first).unwrap();
    running.kill().unwrap();
    let _ = running.wait();
    assert_eq!(first.trim_end(), WARNING);
    assert!(WARNING.contains("never for real money"));
}

#[test]
fn plain_http_off_loopback_is_refused() {
    for listen in ["0.0.0.0:8787", "192.0.2.10:8787", "[::]:8787"] {
        let args: Vec<String> = ["--dev-test-seal", "--listen", listen].iter().map(|s| s.to_string()).collect();
        assert!(
            matches!(Options::from_args(&args, Some("1")), Err(StartError::PlainNotLoopback(_))),
            "{listen} was let through"
        );
    }
    // HTTPS may listen anywhere.
    let https: Vec<String> =
        ["--dev-test-seal", "--listen", "0.0.0.0:8787", "--tls-cert", "cert.pem", "--tls-key", "key.pem"]
            .iter()
            .map(|s| s.to_string())
            .collect();
    assert!(Options::from_args(&https, Some("1")).is_ok());
    // A certificate without its key is refused.
    let half: Vec<String> =
        ["--dev-test-seal", "--tls-cert", "cert.pem"].iter().map(|s| s.to_string()).collect();
    assert!(matches!(Options::from_args(&half, Some("1")), Err(StartError::Usage(_))));

    let output = Command::new(env!("CARGO_BIN_EXE_test_seal_server"))
        .args(["--dev-test-seal", "--listen", "0.0.0.0:0"])
        .env("GHOST_DEV_TEST_SEAL", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing plain HTTP"));
}

/// Opens a connection and sends a request head promising a 4096-byte body,
/// then only `partial` of it.
fn unfinished(addr: SocketAddr, partial: &str) -> TcpStream {
    let mut stream = TcpStream::connect(addr).expect("connect");
    write!(
        stream,
        "POST /v1/check/start HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n{partial}"
    )
    .unwrap();
    stream.flush().unwrap();
    stream
}

/// Waits for the server to close `stream`; how long that took, or `None` if
/// it was still open after `limit`.
fn closed_within(stream: &mut TcpStream, limit: Duration) -> Option<Duration> {
    let started = Instant::now();
    stream.set_read_timeout(Some(limit)).unwrap();
    let mut raw = Vec::new();
    match stream.read_to_end(&mut raw) {
        Ok(_) => Some(started.elapsed()),
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => None,
        // Reset: closed too.
        Err(_) => Some(started.elapsed()),
    }
}

fn wait_for_no_connections(server: &TestSealServer) {
    let started = Instant::now();
    while server.connection_count() > 0 && started.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(server.connection_count(), 0, "connections left open");
}

#[test]
fn unfinished_bodies_never_hold_up_a_check_and_are_closed_at_their_deadline() {
    let server = server(&["--body-ms", "3000"]);
    let mut card = sealed_dev_card();
    // More unfinished bodies than the server ever had handlers, every one
    // with its head in and its body withheld.
    let mut stalled: Vec<TcpStream> =
        (0..16).map(|at| unfinished(server.addr(), if at % 2 == 0 { "" } else { "{\"uid\":" })).collect();
    std::thread::sleep(Duration::from_millis(200));
    let opened = Instant::now();

    // A legitimate Check meanwhile goes straight through, well before any of
    // their deadlines.
    let challenge = [0x33u8; 32];
    let Relayed::Done { answer, signature, .. } = relay_check(server.addr(), &mut card, UID, challenge) else {
        panic!("the Check did not finish");
    };
    assert!(opened.elapsed() < Duration::from_millis(2500), "the Check waited: {:?}", opened.elapsed());
    assert_eq!(verifier().verify(&answer, &signature, &challenge, &UID, now()).unwrap().state, CardState::Sealed);

    // Each unfinished body has its connection closed at its deadline.
    for stream in &mut stalled {
        assert!(closed_within(stream, Duration::from_secs(10)).is_some(), "an unfinished body was left open");
    }
    assert!(opened.elapsed() < Duration::from_secs(8), "closed late: {:?}", opened.elapsed());
    wait_for_no_connections(&server);

    // And the server still serves.
    let challenge = [0x34u8; 32];
    assert!(matches!(relay_check(server.addr(), &mut card, UID, challenge), Relayed::Done { .. }));
}

#[test]
fn a_trickled_body_is_cut_off_at_its_deadline_however_steadily_it_comes() {
    let server = server(&["--body-ms", "800"]);
    let mut stream = unfinished(server.addr(), "");
    let mut writer = stream.try_clone().unwrap();
    // One byte every 100 ms: never idle, never finished.
    let trickle = std::thread::spawn(move || {
        for _ in 0..60 {
            if writer.write_all(b" ").is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    let took = closed_within(&mut stream, Duration::from_secs(5)).expect("the trickled body was left open");
    assert!(took < Duration::from_millis(2500), "closed late: {took:?}");
    drop(stream);
    trickle.join().unwrap();
    wait_for_no_connections(&server);
}

#[test]
fn a_connection_that_never_sends_a_whole_request_is_not_served() {
    let server = server(&["--body-ms", "500"]);
    let mut stream = unfinished(server.addr(), "{\"uid\":\"04518dfaa96180\"");
    // Closed with no answer for it, and no session started.
    let started = Instant::now();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(!String::from_utf8_lossy(&raw).contains("\"apdu\""));
    assert_eq!(server.session_count(), 0);
}

#[test]
fn the_body_deadline_is_bounded() {
    for extra in [["--body-ms", "0"], ["--body-ms", "30001"]] {
        assert!(matches!(Options::from_args(&args(&extra), Some("1")), Err(StartError::Usage(_))), "{extra:?}");
    }
    let options = Options::from_args(&args(&["--body-ms", "1200"]), Some("1")).unwrap();
    assert_eq!(options.body_deadline(), Duration::from_millis(1200));
    assert_eq!(Options::from_args(&args(&[]), Some("1")).unwrap().body_deadline(), DEFAULT_BODY_DEADLINE);
}

#[test]
fn limits_stay_well_inside_the_ios_nfc_session() {
    let defaults = RelayLimits::default();
    assert!(defaults.valid());
    assert!(defaults.total_limit <= Duration::from_secs(45));
    for extra in [["--total-ms", "60000"], ["--idle-ms", "0"]] {
        assert!(matches!(Options::from_args(&args(&extra), Some("1")), Err(StartError::Usage(_))), "{extra:?}");
    }
    let too_idle = args(&["--idle-ms", "20000", "--total-ms", "10000"]);
    assert!(matches!(Options::from_args(&too_idle, Some("1")), Err(StartError::Usage(_))));
}
