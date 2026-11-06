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
//!
//! Every request must arrive whole in time: its body within
//! `--body-ms` (5 seconds by default) of its head, and each head within
//! [`CONNECTION_IDLE`] of the connection opening or its last answer. A
//! connection that misses either is closed, and an unfinished body never
//! holds up any other request.

use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

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
/// How long a request's body may take to arrive, counted from when its head
/// is in, without `--body-ms`. A body still unfinished then has its
/// connection closed, however slowly it was trickling in.
pub const DEFAULT_BODY_DEADLINE: Duration = Duration::from_secs(5);
/// The longest `--body-ms` may set.
pub const MAX_BODY_DEADLINE: Duration = Duration::from_secs(30);
/// How long a connection may take to bring its next request's head, after it
/// opens or after its last answer. Past that it is closed.
pub const CONNECTION_IDLE: Duration = Duration::from_secs(30);
/// How long writing to a connection may stall before it is closed.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// How many connections the server holds at once; more are closed at once.
pub const MAX_CONNECTIONS: usize = 128;
/// How many of those may come from one address.
pub const MAX_CONNECTIONS_PER_ADDRESS: usize = 32;
/// How many requests may be served at once: at most two per connection (one
/// finishing its answer while the next one's head is in).
const MAX_IN_FLIGHT: usize = 2 * MAX_CONNECTIONS;
/// How often the deadlines are checked.
const WATCH_TICK: Duration = Duration::from_millis(20);

/// The usage line.
pub const USAGE: &str = "usage: GHOST_DEV_TEST_SEAL=1 test_seal_server --dev-test-seal [--listen ADDR:PORT] \
[--tls-cert CERT.pem --tls-key KEY.pem] [--idle-ms N] [--total-ms N] [--max-sessions N] [--body-ms N]";

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
    body_deadline: Duration,
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
        let mut body_deadline = DEFAULT_BODY_DEADLINE;
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
                "--body-ms" => body_deadline = Duration::from_millis(number(flag, value)?),
                _ => return Err(StartError::Usage(format!("unknown argument {flag}"))),
            }
            at += 2;
        }
        if body_deadline.is_zero() || body_deadline > MAX_BODY_DEADLINE {
            return Err(StartError::Usage("--body-ms must be more than zero and at most 30 seconds".into()));
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
        Ok(Options { listen, tls, limits, body_deadline })
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

    /// How long a request's body may take to arrive once its head is in.
    pub fn body_deadline(&self) -> Duration {
        self.body_deadline
    }
}

fn number(flag: &str, value: &str) -> Result<u64, StartError> {
    value.parse().map_err(|_| StartError::Usage(format!("{flag} is not a number")))
}

/// A running test server. Stops when dropped.
///
/// tiny_http sets no deadline on a connection and never lets go of its
/// socket, so the server does not let the world reach tiny_http directly. It
/// listens itself, and carries each connection's bytes (still TLS for HTTPS)
/// to tiny_http on a loopback port of its own. Holding both ends of every
/// connection, it closes one whose request does not arrive in time: a body
/// unfinished [`Options::body_deadline`] after its head, or a head not in
/// [`CONNECTION_IDLE`] after the connection opened or was last answered.
/// Closing it ends tiny_http's read of the body at once. Each request is
/// served on its own thread, so a slow body holds up nobody else.
pub struct TestSealServer {
    addr: SocketAddr,
    https: bool,
    shared: Arc<Shared>,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

/// What the server's threads share.
struct Shared {
    relay: Relay,
    links: Links,
    body_deadline: Duration,
    in_flight: AtomicUsize,
}

impl TestSealServer {
    /// Starts serving the relay protocol on `options`' address.
    pub fn start(options: &Options) -> Result<TestSealServer, StartError> {
        // Checked again here: plain HTTP never leaves the machine.
        if options.tls.is_none() && !options.listen.ip().is_loopback() {
            return Err(StartError::PlainNotLoopback(options.listen));
        }
        // tiny_http listens on loopback only; the world reaches it through
        // the front below.
        let inner = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let server = match &options.tls {
            Some(files) => {
                let certificate = std::fs::read(&files.cert)
                    .map_err(|e| StartError::Tls(format!("cannot read {}: {e}", files.cert.display())))?;
                let private_key = std::fs::read(&files.key)
                    .map_err(|e| StartError::Tls(format!("cannot read {}: {e}", files.key.display())))?;
                Server::https(inner, SslConfig { certificate, private_key })
                    .map_err(|e| StartError::Tls(e.to_string()))?
            }
            None => Server::http(inner).map_err(|e| StartError::Listen(e.to_string()))?,
        };
        let inner = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| StartError::Listen("not an IP address".into()))?;
        let front = TcpListener::bind(options.listen).map_err(|e| StartError::Listen(e.to_string()))?;
        let addr = front.local_addr().map_err(|e| StartError::Listen(e.to_string()))?;

        let shared = Arc::new(Shared {
            relay: Relay::new(Arc::new(dev_test_seal), options.limits),
            links: Links::default(),
            body_deadline: options.body_deadline,
            in_flight: AtomicUsize::new(0),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();
        {
            let (shared, stop) = (Arc::clone(&shared), Arc::clone(&stop));
            threads.push(std::thread::spawn(move || accept_front(&front, inner, &shared, &stop)));
        }
        {
            let (shared, stop) = (Arc::clone(&shared), Arc::clone(&stop));
            threads.push(std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(WATCH_TICK);
                    shared.links.expire(Instant::now());
                }
            }));
        }
        {
            let (shared, stop) = (Arc::clone(&shared), Arc::clone(&stop));
            threads.push(std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match server.recv_timeout(Duration::from_millis(100)) {
                        Ok(Some(request)) => dispatch(&shared, request),
                        Ok(None) => {}
                        Err(_) => break,
                    }
                }
            }));
        }
        Ok(TestSealServer { addr, https: options.tls.is_some(), shared, stop, threads })
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
        self.shared.relay.session_count()
    }

    /// How many connections it holds open.
    pub fn connection_count(&self) -> usize {
        self.shared.links.count()
    }

    /// Serves until the process ends.
    pub fn wait(mut self) {
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }

    /// Stops serving.
    pub fn stop(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        if self.threads.is_empty() {
            return;
        }
        self.stop.store(true, Ordering::SeqCst);
        // Wakes the front's accept, which then sees the stop.
        let wake = match self.addr.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => SocketAddr::from((Ipv4Addr::LOCALHOST, self.addr.port())),
            IpAddr::V6(ip) if ip.is_unspecified() => SocketAddr::from((Ipv6Addr::LOCALHOST, self.addr.port())),
            _ => self.addr,
        };
        let _ = TcpStream::connect_timeout(&wake, Duration::from_secs(1));
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        self.shared.links.close_all();
    }
}

/// Where a connection is in its current request.
#[derive(Debug, Clone, Copy)]
enum Phase {
    /// Waiting for the next request's head, until then.
    AwaitingHead(Instant),
    /// The head of request number `.1` is in; its body must be in by `.0`.
    Body(Instant, u64),
    /// Request number `.0` is in whole and being answered: the server's
    /// turn, no deadline on the connection.
    Working(u64),
}

/// One connection: the phone's socket and the loopback socket to tiny_http.
struct Link {
    id: u64,
    peer: IpAddr,
    client: TcpStream,
    upstream: TcpStream,
    phase: Phase,
    requests: u64,
}

impl Link {
    /// Closes both sockets. Every blocked read or write on them, the pumps'
    /// and tiny_http's, ends at once.
    fn close(&self) {
        let _ = self.client.shutdown(Shutdown::Both);
        let _ = self.upstream.shutdown(Shutdown::Both);
    }

    fn due(&self) -> Option<Instant> {
        match self.phase {
            Phase::AwaitingHead(due) | Phase::Body(due, _) => Some(due),
            Phase::Working(_) => None,
        }
    }
}

/// The open connections, by the address tiny_http sees them from (the local
/// end of the loopback socket).
#[derive(Default)]
struct Links {
    next_id: AtomicU64,
    map: Mutex<HashMap<SocketAddr, Link>>,
}

impl Links {
    fn lock(&self) -> MutexGuard<'_, HashMap<SocketAddr, Link>> {
        self.map.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn count(&self) -> usize {
        self.lock().len()
    }

    /// Whether a connection of the front's is at `key`.
    fn holds(&self, key: SocketAddr) -> bool {
        self.lock().contains_key(&key)
    }

    /// Takes in a new connection, unless there are too many already. Its
    /// first head must arrive within [`CONNECTION_IDLE`].
    fn admit(&self, key: SocketAddr, peer: IpAddr, client: &TcpStream, upstream: &TcpStream) -> Option<u64> {
        let mut map = self.lock();
        if map.len() >= MAX_CONNECTIONS
            || map.values().filter(|link| link.peer == peer).count() >= MAX_CONNECTIONS_PER_ADDRESS
        {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let link = Link {
            id,
            peer,
            client: client.try_clone().ok()?,
            upstream: upstream.try_clone().ok()?,
            phase: Phase::AwaitingHead(Instant::now() + CONNECTION_IDLE),
            requests: 0,
        };
        map.insert(key, link);
        Some(id)
    }

    /// Closes and forgets connection `id`, if it is still the one at `key`.
    fn remove(&self, key: SocketAddr, id: u64) {
        let mut map = self.lock();
        if map.get(&key).is_some_and(|link| link.id == id) {
            if let Some(link) = map.remove(&key) {
                link.close();
            }
        }
    }

    /// Closes and forgets whatever connection is at `key`.
    fn kill(&self, key: SocketAddr) {
        if let Some(link) = self.lock().remove(&key) {
            link.close();
        }
    }

    /// A request's head is in: its body must follow within `deadline`.
    /// Returns the request's number on its connection, or `None` when the
    /// connection is not one of the front's or is already reading a body.
    fn begin_body(&self, key: SocketAddr, deadline: Duration) -> Option<u64> {
        let mut map = self.lock();
        let link = map.get_mut(&key)?;
        // `Working` is fine: the previous answer is being finished while the
        // phone, which already has it, sends its next request.
        if matches!(link.phase, Phase::Body(..)) {
            return None;
        }
        link.requests += 1;
        link.phase = Phase::Body(Instant::now() + deadline, link.requests);
        Some(link.requests)
    }

    /// Request `request`'s body has been read. True when it came in time and
    /// its connection is still open; the server's turn then has no deadline.
    fn end_body(&self, key: SocketAddr, request: u64) -> bool {
        let mut map = self.lock();
        let Some(link) = map.get_mut(&key) else { return false };
        match link.phase {
            Phase::Body(due, number) if number == request && Instant::now() < due => {
                link.phase = Phase::Working(request);
                true
            }
            _ => false,
        }
    }

    /// Request `request` is answered: the next head must arrive within
    /// [`CONNECTION_IDLE`]. A later request already under way is left alone.
    fn answered(&self, key: SocketAddr, request: u64) {
        let mut map = self.lock();
        if let Some(link) = map.get_mut(&key) {
            if matches!(link.phase, Phase::Working(n) | Phase::Body(_, n) if n == request) {
                link.phase = Phase::AwaitingHead(Instant::now() + CONNECTION_IDLE);
            }
        }
    }

    /// Closes every connection past its deadline.
    fn expire(&self, now: Instant) {
        self.lock().retain(|_, link| {
            let late = link.due().is_some_and(|due| due <= now);
            if late {
                link.close();
            }
            !late
        });
    }

    fn close_all(&self) {
        for (_, link) in self.lock().drain() {
            link.close();
        }
    }
}

/// The front: takes each connection and carries its bytes to tiny_http.
fn accept_front(front: &TcpListener, inner: SocketAddr, shared: &Arc<Shared>, stop: &AtomicBool) {
    loop {
        let accepted = front.accept();
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match accepted {
            Ok((client, peer)) => connect(client, peer, inner, shared),
            // Out of file descriptors, say: let some connections end.
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn connect(client: TcpStream, peer: SocketAddr, inner: SocketAddr, shared: &Arc<Shared>) {
    let Ok(upstream) = TcpStream::connect_timeout(&inner, Duration::from_secs(1)) else { return };
    let Ok(key) = upstream.local_addr() else { return };
    for stream in [&client, &upstream] {
        let _ = stream.set_nodelay(true);
        let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    }
    // Too many: dropping both closes them.
    let Some(id) = shared.links.admit(key, peer.ip(), &client, &upstream) else { return };
    let (Ok(client_reader), Ok(upstream_reader)) = (client.try_clone(), upstream.try_clone()) else {
        shared.links.remove(key, id);
        return;
    };
    let ends = Arc::new(AtomicUsize::new(2));
    for (from, to) in [(client_reader, upstream), (upstream_reader, client)] {
        let (pumping, ends) = (Arc::clone(shared), Arc::clone(&ends));
        let spawned = std::thread::Builder::new().spawn(move || {
            pump(from, to, &pumping.links, key, id);
            if ends.fetch_sub(1, Ordering::SeqCst) == 1 {
                pumping.links.remove(key, id);
            }
        });
        if spawned.is_err() {
            shared.links.remove(key, id);
        }
    }
}

/// Carries bytes one way until either side ends. An end of stream is passed
/// on as one; anything else closes the connection both ways.
fn pump(mut from: TcpStream, mut to: TcpStream, links: &Links, key: SocketAddr, id: u64) {
    let mut buffer = [0u8; 16 * 1024];
    loop {
        match from.read(&mut buffer) {
            Ok(0) => {
                let _ = to.shutdown(Shutdown::Write);
                return;
            }
            Ok(n) => {
                if to.write_all(&buffer[..n]).is_err() {
                    links.remove(key, id);
                    return;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                links.remove(key, id);
                return;
            }
        }
    }
}

/// Hands a request whose head is in to a thread of its own, with its body's
/// deadline running. Never blocks on this thread: a request that cannot be
/// served is discarded without an answer, its connection closed first so
/// that tiny_http's drain of the unread body ends at once.
fn dispatch(shared: &Arc<Shared>, request: Request) {
    let Some(key) = request.remote_addr().copied() else { return discard_unknown(shared, request) };
    if !shared.links.holds(key) {
        // Straight to the loopback port, not through the front: there is no
        // connection to close, so its body may never end.
        return discard_unknown(shared, request);
    }
    let Some(number) = shared.links.begin_body(key, shared.body_deadline) else {
        // A second body at once on one connection.
        shared.links.kill(key);
        drop(request.into_writer());
        return;
    };
    if shared.in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_IN_FLIGHT {
        shared.in_flight.fetch_sub(1, Ordering::SeqCst);
        shared.links.kill(key);
        drop(request.into_writer());
        return;
    }
    let worker = Arc::clone(shared);
    let spawned = std::thread::Builder::new().spawn(move || {
        handle(&worker, key, number, request);
        worker.in_flight.fetch_sub(1, Ordering::SeqCst);
    });
    if spawned.is_err() {
        shared.in_flight.fetch_sub(1, Ordering::SeqCst);
        shared.links.kill(key);
    }
}

/// Discards, unanswered, a request that did not come through the front.
/// Dropping it waits for the rest of its body, which nothing here can cut
/// short, so that is done on a thread of its own; past the cap the request
/// is left to its connection rather than ever holding up the dispatcher.
fn discard_unknown(shared: &Arc<Shared>, request: Request) {
    if shared.in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_IN_FLIGHT {
        shared.in_flight.fetch_sub(1, Ordering::SeqCst);
        std::mem::forget(request);
        return;
    }
    let worker = Arc::clone(shared);
    let spawned = std::thread::Builder::new().spawn(move || {
        drop(request.into_writer());
        worker.in_flight.fetch_sub(1, Ordering::SeqCst);
    });
    if spawned.is_err() {
        shared.in_flight.fetch_sub(1, Ordering::SeqCst);
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

fn handle(shared: &Shared, key: SocketAddr, number: u64, mut request: Request) {
    let reply = answer(shared, key, number, &mut request);
    let content_type = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("a valid header");
    let no_store = Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]).expect("a valid header");
    let response = Response::from_string(reply.body.to_string())
        .with_status_code(reply.status)
        .with_header(content_type)
        .with_header(no_store);
    // A phone that went away before its answer is no concern of the relay:
    // its session times out.
    let _ = request.respond(response);
    shared.links.answered(key, number);
}

fn answer(shared: &Shared, key: SocketAddr, number: u64, request: &mut Request) -> Reply {
    let relay = &shared.relay;
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
    // Blocks only until the body is in or its deadline closes the connection.
    let mut body = Vec::new();
    let read = request.as_reader().take(MAX_BODY_BYTES as u64 + 1).read_to_end(&mut body);
    if !shared.links.end_body(key, number) {
        // Closed already: nobody is left to read this.
        return Reply::error(408, "timeout", "the request body did not arrive in time");
    }
    match read {
        Ok(_) if body.len() > MAX_BODY_BYTES => return Reply::error(413, "too-large", "the request is too large"),
        Ok(_) if request.body_length().is_some_and(|length| body.len() < length) => {
            return Reply::error(400, "bad-request", "the request body was cut short");
        }
        Ok(_) => {}
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
