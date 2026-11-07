//! The development test Seal server, run in-process on loopback, with the
//! simulated NTAG 424 DNA playing the phone's relay: each command the Seal
//! hands out goes to the card and the card's raw answer goes back, round
//! trip by round trip, until the Seal's signed answer. Its Seal is built
//! with the chain check over two fake nodes and a registry, handed in
//! through `TestSealServer::start_with`, so no test needs the network. It
//! refuses an unregistered card, and refuses to start without a registry,
//! with fewer than two nodes or without a journal file; its journal file
//! (mode 0600) keeps a Fill cut off before a restart, which it finishes
//! after one. Its Fill factory is the enclave's maker (`CoreKeyMaker` on the
//! chain check's network): a Fill makes the wallet core's key and coin, its
//! confirmation seals the card once the coin is paid, and its Check stops
//! answering Sealed once the coin's own spend marker is spent. Run as one
//! region of several (`--region`, `--regions`, `--peer-listen` and a
//! `--peer` per other region), it refuses a card whose home is another
//! region `wrong-region` before any card traffic, serves its own, and its
//! Fill reaches the other regions' peer logs.

mod support;

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ghost_seal::answer::{AnswerKind, AnswerVerifier};
use ghost_seal::card_keys::{card_keys, key_version};
use ghost_seal::chain_check::safe_depth;
use ghost_seal::host_journal::HostStore;
use ghost_seal::journal_anchor::WRONG_REGION_MESSAGE;
use ghost_seal::{CoinQuery, SealError};
use ghost_seal::flows::record_file_settings;
use ghost_seal::primitives::sha3_256;
use ghost_seal::relay::{RelayLimits, to_hex};
use ghost_seal::test_server::{
    DEFAULT_BODY_DEADLINE, DEV_MEASUREMENT, DEV_TEST_MASTER_LABEL, Installed, Options, StartError, TestSealServer,
    WARNING, dev_test_master, dev_test_master_bytes, dev_test_seal,
};
use ghost_seal::{CardRegistry, CardState, CardTransport, CardUid, ChainNode, CheckRequest, FillRequest, RegistryEntry};
use ghost_wallet_core::seal_open::phantom_key_from_bytes;
use ghost_wallet_core::vanish::{tree_leaves, unspent_coin};
use ghost_wallet_core::{COMMIT_DATA_BYTES, commit_leaf, find_coins};
use serde_json::{Value, json};
use support::nodes::{FakeChain, NETWORK, two_nodes};
use support::{AMOUNT, DropStyle, SettledCheck, SimCard, StubChain, StubMaker, UID, contains, hex, registered};

/// The test M, as card setup also uses it.
const DEV_TEST_MASTER_HEX: &str = "d7c19145c84d99edf3c8fbe63d29dfe4e7a89e39e5454e3903a123e4cf7b6040";

/// A card set up with the test M that the registry does not hold.
const STRANGER: CardUid = CardUid([0x04, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76]);

/// Two loopback nodes: never reached, the tests hand in their fakes.
const NODE_ARGS: [&str; 4] = ["--node", "http://127.0.0.1:9/node-a", "--node", "http://127.0.0.1:9/node-b"];

/// A registry file holding `uids`, in the temporary directory.
fn registry_file(name: &str, uids: &[CardUid]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("ghost-seal-relay-server-{}-{name}.registry", std::process::id()));
    let text: String =
        uids.iter().map(|uid| RegistryEntry::new(*uid, "2026-11-06", "dev-batch").unwrap().to_line()).collect();
    std::fs::write(&path, text).unwrap();
    path
}

/// A journal file of its own, not there yet, in the temporary directory:
/// each server that runs at the same time as others gets its own.
fn journal_file(name: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!("ghost-seal-relay-server-{}-{name}-{n}.journal", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

/// The command line with the development flag, a loopback address, a
/// registry, two nodes and a fresh journal file, then `extra`.
fn args(extra: &[&str]) -> Vec<String> {
    args_with_journal(&journal_file("args"), extra)
}

/// [`args`] with the journal file `journal`.
fn args_with_journal(journal: &std::path::Path, extra: &[&str]) -> Vec<String> {
    let registry = registry_file("args", &[UID]);
    let mut args: Vec<String> = ["--dev-test-seal", "--listen", "127.0.0.1:0", "--registry"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    args.push(registry.display().to_string());
    args.extend(NODE_ARGS.iter().map(|s| s.to_string()));
    args.push("--journal".to_owned());
    args.push(journal.display().to_string());
    args.extend(extra.iter().map(|s| s.to_string()));
    args
}

/// The fakes the server's Seals are built with: two nodes over a fake chain
/// that agree, and a registry holding `uids`.
fn installed(uids: &[CardUid]) -> Installed {
    installed_on(&Arc::new(Mutex::new(FakeChain::new())), uids)
}

/// [`installed`] over `chain`, which the test can pay into.
fn installed_on(chain: &Arc<Mutex<FakeChain>>, uids: &[CardUid]) -> Installed {
    let chain = Arc::clone(chain);
    let uids = uids.to_vec();
    Installed {
        network: NETWORK,
        nodes: Arc::new(move || {
            let shared = chain.lock().unwrap().clone().shared();
            let (a, b) = two_nodes(&shared);
            vec![Box::new(a) as Box<dyn ChainNode>, Box::new(b)]
        }),
        registry: Arc::new(move || Box::new(registered(&uids)) as Box<dyn CardRegistry>),
    }
}

fn server(extra: &[&str]) -> TestSealServer {
    let options = Options::from_args(&args(extra), Some("1")).expect("options");
    TestSealServer::start_with(&options, installed(&[UID])).expect("server")
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

/// A card under the test M, filled with a coin of [`AMOUNT`] and Sealed by
/// another Seal (whose Fill journal entry the test server never sees).
fn sealed_dev_card() -> SimCard {
    let mut seal = dev_test_seal(Box::new(SettledCheck), Box::new(registered(&[UID])));
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
    let seal = dev_test_seal(Box::new(SettledCheck), Box::new(registered(&[])));
    AnswerVerifier::new(&seal.answer_verifying_key(), DEV_MEASUREMENT).expect("verifier")
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
    let mut card = dev_card(UID);
    let challenge = [0x5au8; 32];
    let Relayed::Done { answer, signature, session, round_trips } =
        relay_check(server.addr(), &mut card, UID, challenge)
    else {
        panic!("the Check did not finish");
    };
    let body = verifier().verify(&answer, &signature, &challenge, &UID, now()).expect("a verified answer");
    assert_eq!(body.kind, AnswerKind::Check);
    assert_eq!(body.state, CardState::Empty);
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
fn an_unregistered_card_is_refused_not_a_ghost_card_before_any_card_traffic() {
    let server = server(&[]);
    // Set up with the test M, but not in the registry.
    let mut card = dev_card(STRANGER);
    let Relayed::Refused { status, body } = relay_check(server.addr(), &mut card, STRANGER, [0x21u8; 32]) else {
        panic!("an unregistered card was answered");
    };
    assert_eq!(status, 422);
    assert_eq!(body["error"], "refused");
    assert_eq!(body["reason"], "not-a-ghost-card");
    assert!(body["message"].as_str().unwrap().contains("Not a Ghost card"));
    assert!(body.get("apdu").is_none() && body.get("session").is_none());
    assert_eq!(card.sent, 0, "no command reached the card");
    assert_eq!(server.session_count(), 0);

    // The registered card next to it is served.
    let mut registered_card = dev_card(UID);
    assert!(matches!(relay_check(server.addr(), &mut registered_card, UID, [0x22u8; 32]), Relayed::Done { .. }));
}

#[test]
fn a_registry_file_is_read_again_so_a_card_set_up_later_is_served() {
    let path = registry_file("later", &[UID]);
    let options = Options::from_args(&args(&[]), Some("1")).unwrap();
    let file = path.clone();
    let mut fakes = installed(&[]);
    fakes.registry = Arc::new(move || Box::new(ghost_seal::FileRegistry::open(&file).unwrap()) as Box<dyn CardRegistry>);
    let server = TestSealServer::start_with(&options, fakes).unwrap();

    let mut card = dev_card(STRANGER);
    assert!(matches!(relay_check(server.addr(), &mut card, STRANGER, [0x23u8; 32]), Relayed::Refused { .. }));
    let mut registry = ghost_seal::FileRegistry::open(&path).unwrap();
    registry.record(&RegistryEntry::new(STRANGER, "2026-11-07", "dev-batch").unwrap()).unwrap();
    assert!(matches!(relay_check(server.addr(), &mut card, STRANGER, [0x24u8; 32]), Relayed::Done { .. }));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_sealed_card_is_never_answered_sealed_without_its_chain_check() {
    // Sealed elsewhere: this server's journal holds no Fill entry for its
    // coin, so its chain status check cannot be asked, and it refuses.
    let server = server(&[]);
    let mut card = sealed_dev_card();
    let Relayed::Refused { status, body } = relay_check(server.addr(), &mut card, UID, [0x25u8; 32]) else {
        panic!("a Sealed card was answered without its chain check");
    };
    assert_eq!((status, body["error"].as_str()), (422, Some("refused")));
}

#[test]
fn the_server_refuses_to_start_without_a_registry_or_two_nodes() {
    let registry_path = registry_file("refusals", &[UID]).display().to_string();
    let registry = registry_path.as_str();
    let with = |rest: &[&str]| -> Result<Options, StartError> {
        let args: Vec<String> =
            ["--dev-test-seal", "--listen", "127.0.0.1:0"].iter().chain(rest).map(|s| s.to_string()).collect();
        Options::from_args(&args, Some("1"))
    };
    let missing = |result: Result<Options, StartError>| matches!(result, Err(StartError::Missing(_)));

    assert!(missing(with(&NODE_ARGS)), "no registry");
    assert!(missing(with(&["--registry", registry])), "no node");
    assert!(missing(with(&["--registry", registry, "--node", "http://127.0.0.1:9/a"])), "one node");
    let twice = ["--registry", registry, "--node", "http://127.0.0.1:9/a", "--node", "http://127.0.0.1:9/a"];
    assert!(missing(with(&twice)), "the same node twice");
    // Plain HTTP to a node only on loopback.
    let remote = ["--registry", registry, "--node", "http://192.0.2.1:8545/", "--node", "http://127.0.0.1:9/a"];
    assert!(matches!(with(&remote), Err(StartError::Usage(_))));
    let journal_path = journal_file("refusals").display().to_string();
    let mut both = vec!["--registry", registry];
    both.extend(NODE_ARGS);
    both.extend(["--journal", journal_path.as_str()]);
    let options = with(&both).expect("a registry, two nodes and a journal");
    assert_eq!(options.nodes().len(), 2);
    assert_eq!(options.network(), ghost_seal::NodeList::release().network);

    // The library start refuses fewer than two nodes handed in, too.
    let mut one = installed(&[UID]);
    one.nodes = Arc::new(|| {
        let (a, _) = two_nodes(&FakeChain::new().shared());
        vec![Box::new(a) as Box<dyn ChainNode>]
    });
    assert!(matches!(TestSealServer::start_with(&options, one), Err(StartError::Missing(_))));
    // And a registry file that is not there.
    let mut gone = vec!["--registry", "/nonexistent/ghost-seal/registry"];
    gone.extend(NODE_ARGS);
    gone.extend(["--journal", journal_path.as_str()]);
    assert!(matches!(TestSealServer::start(&with(&gone).unwrap()), Err(StartError::Missing(_))));

    // The binary says so in one plain line and exits 2.
    let binary = env!("CARGO_BIN_EXE_test_seal_server");
    for rest in [&NODE_ARGS[..], &["--registry", registry, "--node", "http://127.0.0.1:9/a"][..]] {
        let output = Command::new(binary)
            .args(["--dev-test-seal", "--listen", "127.0.0.1:0"])
            .args(rest)
            .env("GHOST_DEV_TEST_SEAL", "1")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(stderr.trim_end().lines().count(), 1, "{stderr}");
        assert!(stderr.starts_with("test_seal_server: refusing to start:"), "{stderr}");
    }
}

#[test]
fn the_test_server_refuses_to_start_without_a_journal() {
    let registry = registry_file("no-journal", &[UID]).display().to_string();
    let mut no_journal: Vec<String> =
        ["--dev-test-seal", "--listen", "127.0.0.1:0", "--registry", registry.as_str()].iter().map(|s| s.to_string()).collect();
    no_journal.extend(NODE_ARGS.iter().map(|s| s.to_string()));
    match Options::from_args(&no_journal, Some("1")) {
        Err(StartError::Missing(why)) => assert!(why.contains("--journal"), "{why}"),
        other => panic!("started without a journal: {other:?}"),
    }
    // The binary says so in one plain line and exits 2.
    let output = Command::new(env!("CARGO_BIN_EXE_test_seal_server"))
        .args(&no_journal)
        .env("GHOST_DEV_TEST_SEAL", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr.trim_end().lines().count(), 1, "{stderr}");
    assert!(stderr.starts_with("test_seal_server: refusing to start: --journal FILE is missing"), "{stderr}");
}

#[test]
fn the_journal_file_is_made_mode_0600_and_one_that_fails_its_checks_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let journal = journal_file("mode");
    let options = Options::from_args(&args_with_journal(&journal, &[]), Some("1")).unwrap();
    assert_eq!(options.journal(), journal.as_path());
    let server = TestSealServer::start_with(&options, installed(&[UID])).expect("server");
    assert_eq!(std::fs::metadata(&journal).unwrap().permissions().mode() & 0o777, 0o600);
    server.stop();

    // A file whose records are sound on disk but were not sealed by the
    // test Seal (a record of noise): refused, in one line from the binary.
    let forged = journal_file("forged");
    HostStore::open(&forged).unwrap().append(1, &[0x55; 64]).unwrap();
    let options = Options::from_args(&args_with_journal(&forged, &[]), Some("1")).unwrap();
    assert!(matches!(TestSealServer::start_with(&options, installed(&[UID])), Err(StartError::Journal(_))));
    let output = Command::new(env!("CARGO_BIN_EXE_test_seal_server"))
        .args(args_with_journal(&forged, &[]))
        .env("GHOST_DEV_TEST_SEAL", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.lines().any(|line| line.starts_with("test_seal_server: refusing to start: the journal file")), "{stderr}");
    let _ = std::fs::remove_file(&journal);
    let _ = std::fs::remove_file(&forged);
}

fn fill_request() -> FillRequest {
    FillRequest { uid: UID, challenge: [0x41; 32], amount_wei: AMOUNT, pin: None }
}

#[test]
fn after_a_restart_on_the_same_file_a_fill_that_was_cut_off_is_finished() {
    let chain = Arc::new(Mutex::new(FakeChain::new()));
    // How many commands a whole Fill takes (on a card and a journal of its
    // own).
    let commands = {
        let options = Options::from_args(&args(&[]), Some("1")).unwrap();
        let server = TestSealServer::start_with(&options, installed_on(&chain, &[UID])).unwrap();
        let mut card = dev_card(UID);
        server.seal().fill(&mut card, &fill_request(), &mut StubMaker::default()).expect("a whole Fill");
        card.sent
    };

    let journal = journal_file("restart");
    let options = Options::from_args(&args_with_journal(&journal, &[]), Some("1")).unwrap();
    let mut card = dev_card(UID);
    let mut maker = StubMaker::default();
    {
        let server = TestSealServer::start_with(&options, installed_on(&chain, &[UID])).unwrap();
        // The Fill's last command runs on the card; its answer is lost, and
        // the server stops.
        card.drop_from(commands - 1, DropStyle::AfterCard);
        assert_eq!(server.seal().fill(&mut card, &fill_request(), &mut maker).err(), Some(SealError::Dropped));
        card.reconnect();
        server.stop();
    }
    assert_eq!(maker.made.borrow().len(), 1);

    // Started again on the same file: the Fill hands back the same coin.
    let server = TestSealServer::start_with(&options, installed_on(&chain, &[UID])).unwrap();
    let filled = server.seal().fill(&mut card, &fill_request(), &mut maker).expect("finished after the restart");
    assert_eq!(maker.made.borrow().len(), 1, "no new key");
    assert_eq!(filled.commit_data, maker.made.borrow()[0].1, "the same coin");

    // Paid and confirmed, the server's own Check answers Sealed, after one
    // more restart too: its chain check finds the coin from the journal.
    let key = maker.key_for(&filled.commit_data);
    let coin = CoinQuery { commit_data: filled.commit_data.clone(), amount_wei: AMOUNT, spend_marker: support::stub_spend_marker(&key) };
    chain.lock().unwrap().pay(&coin, safe_depth(AMOUNT));
    let paid = StubChain::default();
    paid.pay(&filled.commit_data, AMOUNT);
    let sealed = server.seal().confirm_fill(&mut card, &CheckRequest { uid: UID, challenge: [0x42; 32] }, &paid).unwrap();
    assert_eq!(sealed.body.state, CardState::Sealed);
    server.stop();
    let server = TestSealServer::start_with(&options, installed_on(&chain, &[UID])).unwrap();
    let challenge = [0x43u8; 32];
    let Relayed::Done { answer, signature, .. } = relay_check(server.addr(), &mut card, UID, challenge) else {
        panic!("the Check of the card filled across a restart did not finish");
    };
    let body = verifier().verify(&answer, &signature, &challenge, &UID, now()).expect("a verified answer");
    assert_eq!((body.state, body.amount_wei), (CardState::Sealed, AMOUNT));
    server.stop();
    let _ = std::fs::remove_file(&journal);
}

#[test]
fn the_servers_fill_makes_a_real_coin_that_its_confirmation_seals_and_its_check_follows() {
    let chain = Arc::new(Mutex::new(FakeChain::new()));
    let journal = journal_file("core-maker");
    let options = Options::from_args(&args_with_journal(&journal, &[]), Some("1")).unwrap();
    let server = TestSealServer::start_with(&options, installed_on(&chain, &[UID])).unwrap();
    let mut card = dev_card(UID);

    // The Fill, with the server's own maker: the wallet core's coin.
    let filled = server.fill(&mut card, &fill_request()).expect("a Fill with the core's maker");
    assert_eq!(filled.commit_data.len(), COMMIT_DATA_BYTES);
    assert_eq!(filled.commit_data[..2], [0x00, 0x03]);
    // The card's key slot (offset 128: length at 40, key at 41) holds the
    // core's key bytes, which find the coin on the server's network only.
    let length = usize::from(card.file[128 + 40]);
    let key_bytes = card.file[128 + 41..128 + 41 + length].to_vec();
    assert_eq!((key_bytes.len(), key_bytes[0]), (33, 0x20));
    let key = phantom_key_from_bytes(&key_bytes).expect("the core's key bytes");
    let leaf = commit_leaf(filled.commit_data.clone(), AMOUNT.to_string()).unwrap();
    let found = find_coins(&key, NETWORK.chain_id, &[leaf.clone()], &[]).unwrap();
    assert_eq!((found.status.as_str(), found.amount_wei), ("found", AMOUNT.to_string()));
    assert_eq!(find_coins(&key, NETWORK.chain_id + 1, &[leaf.clone()], &[]).unwrap().status, "not-found");
    // The key never crossed the relay: the card traffic is EV2 secured.
    for bytes in &card.transcript {
        assert!(!contains(bytes, &key_bytes[1..]));
    }

    // Paid exactly on the fake chain and confirmed: Sealed, and the server's
    // relayed Check answers Sealed.
    let marker = *unspent_coin(&key, NETWORK.chain_id, &tree_leaves(&[leaf]).unwrap(), &[]).unwrap().marker.as_bytes();
    let coin = CoinQuery { commit_data: filled.commit_data.clone(), amount_wei: AMOUNT, spend_marker: marker };
    chain.lock().unwrap().pay(&coin, safe_depth(AMOUNT));
    let paid = StubChain::default();
    paid.pay(&filled.commit_data, AMOUNT);
    let sealed = server.seal().confirm_fill(&mut card, &CheckRequest { uid: UID, challenge: [0x44; 32] }, &paid).unwrap();
    assert_eq!(sealed.body.state, CardState::Sealed);
    let challenge = [0x45u8; 32];
    let Relayed::Done { answer, signature, .. } = relay_check(server.addr(), &mut card, UID, challenge) else {
        panic!("the Check of the filled card did not finish");
    };
    let body = verifier().verify(&answer, &signature, &challenge, &UID, now()).expect("a verified answer");
    assert_eq!((body.state, body.amount_wei), (CardState::Sealed, AMOUNT));

    // The journaled spend marker is the coin's own: once it is spent on the
    // chain, the Check no longer answers Sealed.
    chain.lock().unwrap().spend(marker);
    assert!(matches!(relay_check(server.addr(), &mut card, UID, [0x46u8; 32]), Relayed::Refused { status: 422, .. }));
    server.stop();
    let _ = std::fs::remove_file(&journal);
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
    let mut card = dev_card(UID);
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
    assert_eq!(verifier().verify(&answer, &signature, &challenge, &UID, now()).unwrap().state, CardState::Empty);
}

#[test]
fn a_connection_dropped_mid_check_leaves_the_server_serving_and_the_session_times_out() {
    let server = server(&["--idle-ms", "300", "--total-ms", "5000"]);
    let mut card = dev_card(UID);
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
    assert_eq!(verifier().verify(&answer, &signature, &challenge, &UID, now()).unwrap().state, CardState::Empty);
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
    let mut card = dev_card(UID);
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
    let mut card = dev_card(UID);
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

    // With both (and a registry and two nodes) it starts, and its first word
    // is the warning.
    let mut running = Command::new(binary)
        .args(["--dev-test-seal", "--listen", "127.0.0.1:0"])
        .args(required("binary"))
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

/// `--registry` (a registry file holding [`UID`]), two `--node`s and a
/// fresh `--journal` file.
fn required(name: &str) -> Vec<String> {
    let mut args = vec!["--registry".to_owned(), registry_file(name, &[UID]).display().to_string()];
    args.extend(NODE_ARGS.iter().map(|s| s.to_string()));
    args.push("--journal".to_owned());
    args.push(journal_file(name).display().to_string());
    args
}

#[test]
fn plain_http_off_loopback_is_refused() {
    let with = |rest: &[&str]| -> Vec<String> {
        let mut args: Vec<String> = rest.iter().map(|s| s.to_string()).collect();
        args.extend(required("plain"));
        args
    };
    for listen in ["0.0.0.0:8787", "192.0.2.10:8787", "[::]:8787"] {
        let args = with(&["--dev-test-seal", "--listen", listen]);
        assert!(
            matches!(Options::from_args(&args, Some("1")), Err(StartError::PlainNotLoopback(_))),
            "{listen} was let through"
        );
    }
    // HTTPS may listen anywhere.
    let https = with(&["--dev-test-seal", "--listen", "0.0.0.0:8787", "--tls-cert", "cert.pem", "--tls-key", "key.pem"]);
    assert!(Options::from_args(&https, Some("1")).is_ok());
    // A certificate without its key is refused.
    let half = with(&["--dev-test-seal", "--tls-cert", "cert.pem"]);
    assert!(matches!(Options::from_args(&half, Some("1")), Err(StartError::Usage(_))));

    let output = Command::new(env!("CARGO_BIN_EXE_test_seal_server"))
        .args(["--dev-test-seal", "--listen", "0.0.0.0:0"])
        .args(required("plain-binary"))
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
    let mut card = dev_card(UID);
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
    assert_eq!(verifier().verify(&answer, &signature, &challenge, &UID, now()).unwrap().state, CardState::Empty);

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

/// The release's ordered region list.
const REGIONS: &str = "us-east-1,eu-central-1,ap-southeast-1";
/// The home region of the tests' card ([`UID`]), as
/// `tests/vectors/home-region.json` has it.
const UID_HOME: &str = "eu-central-1";

/// A directory of its own for one region's journal and peer logs.
fn region_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ghost-seal-relay-server-{}-region-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The region flags of region `own` of [`REGIONS`], its peer port at
/// `addrs[own's index]` and each other region's at its index.
fn region_flags(own: usize, addrs: &[String]) -> Vec<String> {
    let names: Vec<&str> = REGIONS.split(',').collect();
    let mut flags = vec!["--region".to_owned(), names[own].to_owned(), "--regions".to_owned(), REGIONS.to_owned()];
    flags.extend(["--peer-listen".to_owned(), addrs[own].clone()]);
    for (index, other) in names.iter().enumerate().filter(|(index, _)| *index != own) {
        flags.extend(["--peer".to_owned(), format!("{other}={}", addrs[index])]);
    }
    flags
}

/// Three test servers, one per region, each anchoring its journal in the
/// other two: (region, its directory, the server).
fn three_regions() -> Vec<(String, PathBuf, TestSealServer)> {
    let held: Vec<std::net::TcpListener> = (0..3).map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap()).collect();
    let addrs: Vec<String> = held.iter().map(|listener| listener.local_addr().unwrap().to_string()).collect();
    drop(held);
    REGIONS
        .split(',')
        .enumerate()
        .map(|(index, own)| {
            let dir = region_dir(own);
            let flags = region_flags(index, &addrs);
            let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
            let options = Options::from_args(&args_with_journal(&dir.join("journal.log"), &flags), Some("1")).unwrap();
            let server = TestSealServer::start_with(&options, installed(&[UID])).expect("a region's server");
            assert_eq!(server.peer_addr().map(|addr| addr.to_string()), Some(addrs[index].clone()));
            assert_eq!(server.regions().map(|regions| regions.own().to_owned()), Some(own.to_owned()));
            (own.to_owned(), dir, server)
        })
        .collect()
}

#[test]
fn as_one_region_of_several_the_test_server_refuses_a_card_that_is_not_its_own() {
    let regions = three_regions();
    let (home, away): (Vec<_>, Vec<_>) = regions.iter().partition(|(name, _, _)| name == UID_HOME);
    let (_, home_dir, home) = home[0];
    assert_eq!(away.len(), 2);

    // Each other region refuses the card's Check before any session or card
    // traffic, naming its home, and its Fill before any card command.
    for (name, dir, server) in &away {
        let mut card = dev_card(UID);
        let Relayed::Refused { status, body } = relay_check(server.addr(), &mut card, UID, [0x51; 32]) else {
            panic!("{name} served a card whose home is {UID_HOME}");
        };
        assert_eq!(status, 422, "{name}");
        assert_eq!(
            body,
            json!({
                "status": "error",
                "error": "refused",
                "reason": "wrong-region",
                "homeRegion": UID_HOME,
                "message": WRONG_REGION_MESSAGE,
            })
        );
        assert_eq!(server.session_count(), 0, "{name}: no session");
        assert!(server.fill(&mut card, &fill_request()).is_err(), "{name}");
        assert!(card.transcript.is_empty(), "{name}: no card command");
        assert!(HostStore::open(&dir.join("journal.log")).unwrap().records().is_empty(), "{name}: nothing journaled");
    }

    // Its home serves it: a Check round trip, and a Fill on its journal,
    // which reaches the other two regions' peer logs (ciphertext only).
    let mut card = dev_card(UID);
    let challenge = [0x52u8; 32];
    let Relayed::Done { answer, signature, .. } = relay_check(home.addr(), &mut card, UID, challenge) else {
        panic!("the home region did not serve its card");
    };
    assert_eq!(verifier().verify(&answer, &signature, &challenge, &UID, now()).unwrap().state, CardState::Empty);
    home.fill(&mut card, &fill_request()).expect("the home region fills its card");
    let written = HostStore::open(&home_dir.join("journal.log")).unwrap().records().to_vec();
    assert!(!written.is_empty());
    for (name, dir, _) in &away {
        let copy = dir.join(format!("peer-{UID_HOME}.log"));
        assert_eq!(HostStore::open(&copy).unwrap().records(), written.as_slice(), "{name} holds the home's log");
        assert!(!contains(&std::fs::read(&copy).unwrap(), &UID.0), "{name}: ciphertext only");
    }
    drop(regions);
}

#[test]
fn the_region_flags_must_name_this_region_and_one_peer_for_each_other() {
    let addrs: Vec<String> = ["127.0.0.1:7101", "127.0.0.1:7102", "127.0.0.1:7103"].map(String::from).to_vec();
    let good = region_flags(0, &addrs);
    let parse = |flags: &[String]| {
        let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
        Options::from_args(&args(&flags), Some("1"))
    };
    let options = parse(&good).expect("the region flags");
    let regions = options.regions().expect("one region of several");
    assert_eq!((regions.regions.own(), regions.peers.len()), ("us-east-1", 2));
    // --region without --regions, and the other way round.
    assert!(matches!(parse(&good[..2]), Err(StartError::Usage(_))));
    assert!(matches!(parse(&good[2..4]), Err(StartError::Usage(_))));
    // A list that does not name this region, or names one twice.
    let mut flags = good.clone();
    flags[3] = "eu-central-1,ap-southeast-1".into();
    assert!(matches!(parse(&flags), Err(StartError::Usage(_))));
    flags[3] = "us-east-1,us-east-1".into();
    assert!(matches!(parse(&flags), Err(StartError::Usage(_))));
    // A peer left out, a peer given twice, a peer of no listed region, a
    // peer port that is not loopback.
    assert!(matches!(parse(&good[..good.len() - 2]), Err(StartError::Missing(_))));
    let mut twice = good.clone();
    twice.extend(good[good.len() - 2..].to_vec());
    assert!(parse(&twice).is_err());
    let mut stranger = good.clone();
    stranger.extend(["--peer".to_owned(), "sa-east-1=127.0.0.1:7104".to_owned()]);
    assert!(matches!(parse(&stranger), Err(StartError::Usage(_))));
    let mut remote = good.clone();
    remote[5] = "192.0.2.10:7101".into();
    assert!(matches!(parse(&remote), Err(StartError::Usage(_))));
    // Without the flags it runs as the one region it always was.
    assert!(parse(&[]).unwrap().regions().is_none());
}
