//! The development test Seal server: the relay protocol
//! (`docs/seal-relay.md`) over HTTP, for development and the phone's speed
//! test only. **Never for real money.**
//!
//! It runs the Seal's Check against the public test M, the 32 bytes
//! SHA3-256(`ghost-seal/dev-test-master/v1`), which anyone can derive: a
//! card set up with it protects nothing. Its answers carry an all-zero code
//! measurement, so a phone that pins a real Seal's measurement never takes
//! one. There is no enclave, no journal on disk and no card registry: it
//! answers a Check for any card set up with the test M.
//!
//! It refuses to start unless it is given `--dev-test-seal` and the
//! environment variable `GHOST_DEV_TEST_SEAL=1`. It serves HTTPS when given
//! `--tls-cert` and `--tls-key` (PEM files); without them it serves plain
//! HTTP, and only on a loopback address.

use std::fmt;
use std::io::Read;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{Value, json};
use tiny_http::{Header, Method, Request, Response, Server, SslConfig};

use crate::card_keys::CardUid;
use crate::error::SealError;
use crate::flows::{Seal, SealConfig};
use crate::journal::MemoryJournal;
use crate::primitives::sha3_256;
use crate::relay::{Relay, RelayError, RelayLimits, SessionId, Step, from_hex, to_hex};
use crate::secrets::MasterKey;
use crate::traits::{SystemClock, SystemRandom};

/// The text whose SHA3-256 is the test M. Public: the test M protects nothing.
pub const DEV_TEST_MASTER_LABEL: &[u8] = b"ghost-seal/dev-test-master/v1";
/// The flag the server needs to start.
pub const DEV_FLAG: &str = "--dev-test-seal";
/// The environment variable the server needs, set to `1`, to start.
pub const DEV_ENV: &str = "GHOST_DEV_TEST_SEAL";
/// The one-line warning the server prints when it starts.
pub const WARNING: &str =
    "test_seal_server: WARNING: development test Seal with the public test M, for development and speed tests only, never for real money";
/// The code measurement in the test server's answers: all zeros, which no
/// real Seal build has.
pub const DEV_MEASUREMENT: [u8; 48] = [0u8; 48];
/// How long the test server's answers are good for, in seconds.
pub const DEV_ANSWER_LIFETIME_SECS: u64 = 120;
/// The address the server listens on without `--listen`.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8787";
/// The largest request body the server reads.
pub const MAX_BODY_BYTES: usize = 4096;
/// How many requests the server handles at once.
const HANDLERS: usize = 8;

/// The usage line.
pub const USAGE: &str = "usage: GHOST_DEV_TEST_SEAL=1 test_seal_server --dev-test-seal [--listen ADDR:PORT] \
[--tls-cert CERT.pem --tls-key KEY.pem] [--idle-ms N] [--total-ms N] [--max-sessions N]";

/// The test M's bytes. Public by design: SHA3-256 of
/// [`DEV_TEST_MASTER_LABEL`]. Card setup uses the same value for test cards.
pub fn dev_test_master_bytes() -> [u8; 32] {
    sha3_256(&[DEV_TEST_MASTER_LABEL])
}

/// The test M.
pub fn dev_test_master() -> MasterKey {
    let mut bytes = dev_test_master_bytes();
    MasterKey::take(&mut bytes)
}

/// A Seal holding the test M, with the system's random source and clock and
/// a journal in memory only.
pub fn dev_test_seal() -> Seal {
    Seal::new(
        dev_test_master(),
        SealConfig { measurement: DEV_MEASUREMENT, answer_lifetime_secs: DEV_ANSWER_LIFETIME_SECS },
        Box::new(SystemRandom),
        Box::new(SystemClock),
        Box::new(MemoryJournal::new()),
    )
}

/// Why the server would not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    /// `--dev-test-seal` or `GHOST_DEV_TEST_SEAL=1` is missing.
    NotDevelopment(&'static str),
    /// The arguments are wrong.
    Usage(String),
    /// Plain HTTP was asked for on an address that is not loopback.
    PlainNotLoopback(SocketAddr),
    /// The TLS certificate or key could not be read or used.
    Tls(String),
    /// The address could not be listened on.
    Listen(String),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartError::NotDevelopment(what) => {
                write!(f, "refusing to start: {what} (this server is for development only)")
            }
            StartError::Usage(what) => write!(f, "{what}"),
            StartError::PlainNotLoopback(addr) => write!(
                f,
                "refusing plain HTTP on {addr}: without --tls-cert and --tls-key it listens on a loopback address only"
            ),
            StartError::Tls(what) => write!(f, "TLS: {what}"),
            StartError::Listen(what) => write!(f, "cannot listen: {what}"),
        }
    }
}

impl std::error::Error for StartError {}

/// The certificate and key files of an HTTPS server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFiles {
    /// PEM certificate chain.
    pub cert: PathBuf,
    /// PEM private key (PKCS#8 or RSA).
    pub key: PathBuf,
}

/// What the server runs with. Made only by [`Options::from_args`], which
/// checks the development flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    listen: SocketAddr,
    tls: Option<TlsFiles>,
    limits: RelayLimits,
}

impl Options {
    /// Reads the command line (`args`, without the program name) and the
    /// value of `GHOST_DEV_TEST_SEAL` (`dev_env`). Refuses unless both
    /// development flags are given, and refuses plain HTTP on any address
    /// that is not loopback.
    pub fn from_args(args: &[String], dev_env: Option<&str>) -> Result<Options, StartError> {
        if !args.iter().any(|a| a == DEV_FLAG) {
            return Err(StartError::NotDevelopment("--dev-test-seal is missing"));
        }
        if dev_env != Some("1") {
            return Err(StartError::NotDevelopment("GHOST_DEV_TEST_SEAL=1 is not set"));
        }
        let mut listen = DEFAULT_LISTEN.to_owned();
        let mut cert = None;
        let mut key = None;
        let mut limits = RelayLimits::default();
        let mut at = 0;
        while at < args.len() {
            let flag = args[at].as_str();
            if flag == DEV_FLAG {
                at += 1;
                continue;
            }
            let value = args.get(at + 1).ok_or_else(|| StartError::Usage(format!("{flag} needs a value")))?;
            match flag {
                "--listen" => listen = value.clone(),
                "--tls-cert" => cert = Some(PathBuf::from(value)),
                "--tls-key" => key = Some(PathBuf::from(value)),
                "--idle-ms" => limits.idle_timeout = Duration::from_millis(number(flag, value)?),
                "--total-ms" => limits.total_limit = Duration::from_millis(number(flag, value)?),
                "--max-sessions" => limits.max_sessions = number(flag, value)? as usize,
                _ => return Err(StartError::Usage(format!("unknown argument {flag}"))),
            }
            at += 2;
        }
        if !limits.valid() {
            return Err(StartError::Usage(
                "limits must be more than zero, the idle timeout within the total, and the total at most 45 seconds"
                    .into(),
            ));
        }
        let listen = listen
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .ok_or_else(|| StartError::Usage(format!("{listen} is not an address")))?;
        let tls = match (cert, key) {
            (Some(cert), Some(key)) => Some(TlsFiles { cert, key }),
            (None, None) => None,
            _ => return Err(StartError::Usage("--tls-cert and --tls-key go together".into())),
        };
        if tls.is_none() && !listen.ip().is_loopback() {
            return Err(StartError::PlainNotLoopback(listen));
        }
        Ok(Options { listen, tls, limits })
    }

    /// The address to listen on.
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// The TLS files, for HTTPS.
    pub fn tls(&self) -> Option<&TlsFiles> {
        self.tls.as_ref()
    }

    /// The relay's limits.
    pub fn limits(&self) -> RelayLimits {
        self.limits
    }
}

fn number(flag: &str, value: &str) -> Result<u64, StartError> {
    value.parse().map_err(|_| StartError::Usage(format!("{flag} is not a number")))
}

/// A running test server. Stops when dropped.
pub struct TestSealServer {
    server: Arc<Server>,
    addr: SocketAddr,
    https: bool,
    relay: Arc<Relay>,
    stop: Arc<AtomicBool>,
    handlers: Vec<JoinHandle<()>>,
}

impl TestSealServer {
    /// Starts serving the relay protocol on `options`' address.
    pub fn start(options: &Options) -> Result<TestSealServer, StartError> {
        let server = match &options.tls {
            Some(files) => {
                let certificate = std::fs::read(&files.cert)
                    .map_err(|e| StartError::Tls(format!("cannot read {}: {e}", files.cert.display())))?;
                let private_key = std::fs::read(&files.key)
                    .map_err(|e| StartError::Tls(format!("cannot read {}: {e}", files.key.display())))?;
                Server::https(options.listen, SslConfig { certificate, private_key })
                    .map_err(|e| StartError::Tls(e.to_string()))?
            }
            None => {
                // Checked again here: plain HTTP never leaves the machine.
                if !options.listen.ip().is_loopback() {
                    return Err(StartError::PlainNotLoopback(options.listen));
                }
                Server::http(options.listen).map_err(|e| StartError::Listen(e.to_string()))?
            }
        };
        let addr = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| StartError::Listen("not an IP address".into()))?;
        let server = Arc::new(server);
        let relay = Arc::new(Relay::new(Arc::new(dev_test_seal), options.limits));
        let stop = Arc::new(AtomicBool::new(false));
        let handlers = (0..HANDLERS)
            .map(|_| {
                let server = Arc::clone(&server);
                let relay = Arc::clone(&relay);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        match server.recv_timeout(Duration::from_millis(100)) {
                            Ok(Some(request)) => handle(&relay, request),
                            Ok(None) => {}
                            Err(_) => break,
                        }
                    }
                })
            })
            .collect();
        Ok(TestSealServer { server, addr, https: options.tls.is_some(), relay, stop, handlers })
    }

    /// The address it listens on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Its base URL.
    pub fn url(&self) -> String {
        format!("{}://{}", if self.https { "https" } else { "http" }, self.addr)
    }

    /// How many relay sessions it holds.
    pub fn session_count(&self) -> usize {
        self.relay.session_count()
    }

    /// Serves until the process ends.
    pub fn wait(mut self) {
        for handler in self.handlers.drain(..) {
            let _ = handler.join();
        }
    }

    /// Stops serving.
    pub fn stop(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for _ in 0..HANDLERS {
            self.server.unblock();
        }
        for handler in self.handlers.drain(..) {
            let _ = handler.join();
        }
    }
}

impl Drop for TestSealServer {
    fn drop(&mut self) {
        self.halt();
    }
}

/// An HTTP answer: status and JSON body.
struct Reply {
    status: u16,
    body: Value,
}

impl Reply {
    fn ok(body: Value) -> Reply {
        Reply { status: 200, body }
    }

    fn error(status: u16, code: &str, message: &str) -> Reply {
        Reply { status, body: json!({ "status": "error", "error": code, "message": message }) }
    }
}

fn handle(relay: &Relay, mut request: Request) {
    let reply = answer(relay, &mut request);
    let content_type = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("a valid header");
    let no_store = Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]).expect("a valid header");
    let response = Response::from_string(reply.body.to_string())
        .with_status_code(reply.status)
        .with_header(content_type)
        .with_header(no_store);
    // A phone that went away before its answer is no concern of the relay:
    // its session times out.
    let _ = request.respond(response);
}

fn answer(relay: &Relay, request: &mut Request) -> Reply {
    let path = request.url().split('?').next().unwrap_or("").to_owned();
    if !matches!(path.as_str(), "/v1/check/start" | "/v1/relay/step" | "/v1/relay/abort") {
        return Reply::error(404, "not-found", "no such path");
    }
    if *request.method() != Method::Post {
        return Reply::error(405, "method", "use POST");
    }
    if request.body_length().is_some_and(|length| length > MAX_BODY_BYTES) {
        return Reply::error(413, "too-large", "the request is too large");
    }
    let mut body = Vec::new();
    match request.as_reader().take(MAX_BODY_BYTES as u64 + 1).read_to_end(&mut body) {
        Ok(_) if body.len() <= MAX_BODY_BYTES => {}
        Ok(_) => return Reply::error(413, "too-large", "the request is too large"),
        Err(_) => return Reply::error(400, "bad-request", "the request body could not be read"),
    }
    let Ok(fields) = serde_json::from_slice::<Value>(&body) else {
        return Reply::error(400, "bad-request", "the body is not JSON");
    };
    let result = match path.as_str() {
        "/v1/check/start" => start_check(relay, &fields),
        "/v1/relay/step" => step(relay, &fields),
        _ => abort(relay, &fields),
    };
    match result {
        Ok(reply) => reply,
        Err(error) => refusal(&error),
    }
}

fn hex_field<const N: usize>(fields: &Value, name: &'static str) -> Result<[u8; N], RelayError> {
    fields
        .get(name)
        .and_then(Value::as_str)
        .and_then(from_hex)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(RelayError::BadRequest(name))
}

fn session_field(fields: &Value) -> Result<SessionId, RelayError> {
    hex_field::<16>(fields, "session").map(SessionId)
}

fn step_reply(step: Step) -> Reply {
    match step {
        Step::Apdu { session, apdu } => {
            Reply::ok(json!({ "status": "apdu", "session": session.to_hex(), "apdu": to_hex(&apdu) }))
        }
        Step::Done(answer) => Reply::ok(json!({
            "status": "done",
            "answer": to_hex(&answer.bytes),
            "signature": to_hex(&answer.signature),
        })),
    }
}

fn start_check(relay: &Relay, fields: &Value) -> Result<Reply, RelayError> {
    let uid = CardUid(hex_field::<7>(fields, "uid")?);
    let challenge = hex_field::<32>(fields, "challenge")?;
    relay.start_check(uid, challenge).map(step_reply)
}

fn step(relay: &Relay, fields: &Value) -> Result<Reply, RelayError> {
    let session = session_field(fields)?;
    let answer = fields
        .get("answer")
        .and_then(Value::as_str)
        .and_then(from_hex)
        .ok_or(RelayError::BadRequest("answer"))?;
    relay.step(&session, &answer).map(step_reply)
}

fn abort(relay: &Relay, fields: &Value) -> Result<Reply, RelayError> {
    let session = session_field(fields)?;
    relay.abort(&session).map(|()| Reply::ok(json!({ "status": "aborted" })))
}

fn refusal(error: &RelayError) -> Reply {
    let message = error.to_string();
    match error {
        RelayError::UnknownSession => Reply::error(404, "unknown-session", &message),
        RelayError::Expired => Reply::error(410, "expired", &message),
        RelayError::Busy => Reply::error(503, "busy", &message),
        RelayError::BadRequest(_) => Reply::error(400, "bad-request", &message),
        RelayError::Seal(SealError::Dropped) => Reply::error(422, "card-dropped", &message),
        RelayError::Seal(_) => Reply::error(422, "refused", &message),
    }
}
