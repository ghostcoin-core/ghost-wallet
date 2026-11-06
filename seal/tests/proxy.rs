//! The parent proxy over local sockets: TCP in front, a Unix socket standing
//! in for the enclave's vsock.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use std::collections::VecDeque;
use std::io;
use std::path::Path;

use ghost_seal::key_share::{read_frame, write_frame};
use ghost_seal::proxy::{
    BoundedService, CloseReason, DeadlineStream, MemoryLog, Proxy, ProxyEvent, ProxyLimits, ProxyListener, ProxyLog,
    ServiceLimits, ServiceStats, UnixConnector,
};

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn socket_path() -> PathBuf {
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!("seal-proxy-test-{}-{n}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

/// What the stand-in enclave does with each connection.
#[derive(Clone, Copy)]
enum Upstream {
    /// Sends a greeting, then echoes everything back.
    Echo,
    /// Reads until the other side closes, and reports that it saw the close.
    Sink,
    /// Closes as soon as it accepts.
    Close,
}

struct Running {
    address: String,
    log: Arc<MemoryLog>,
    upstream_saw_close: Arc<AtomicUsize>,
    upstream_received: Arc<Mutex<Vec<u8>>>,
}

fn start(limits: ProxyLimits, upstream: Upstream) -> Running {
    let path = socket_path();
    let enclave = UnixListener::bind(&path).unwrap();
    let upstream_saw_close = Arc::new(AtomicUsize::new(0));
    let upstream_received = Arc::new(Mutex::new(Vec::new()));
    let (saw_close, received) = (upstream_saw_close.clone(), upstream_received.clone());
    thread::spawn(move || {
        for stream in enclave.incoming() {
            let mut stream = stream.unwrap();
            let (saw_close, received) = (saw_close.clone(), received.clone());
            thread::spawn(move || match upstream {
                Upstream::Echo => {
                    stream.write_all(b"hello from the enclave\n").unwrap();
                    let mut buffer = [0u8; 4096];
                    loop {
                        match stream.read(&mut buffer) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if stream.write_all(&buffer[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
                Upstream::Sink => {
                    let mut all = Vec::new();
                    let _ = stream.read_to_end(&mut all);
                    received.lock().unwrap().extend_from_slice(&all);
                    saw_close.fetch_add(1, Ordering::SeqCst);
                }
                Upstream::Close => drop(stream),
            });
        }
    });
    let front = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = front.local_addr().unwrap().to_string();
    let log = Arc::new(MemoryLog::default());
    let proxy_log: Arc<dyn ProxyLog> = log.clone();
    thread::spawn(move || Proxy::new(front, UnixConnector(path), limits, proxy_log).serve(None));
    Running { address, log, upstream_saw_close, upstream_received }
}

fn limits(max_connections: usize, idle_ms: u64) -> ProxyLimits {
    ProxyLimits { max_connections, idle_timeout: Duration::from_millis(idle_ms) }
}

fn connect(address: &str) -> TcpStream {
    let stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    stream
}

fn read_greeting(stream: &mut TcpStream) {
    let mut greeting = [0u8; 23];
    stream.read_exact(&mut greeting).unwrap();
    assert_eq!(&greeting, b"hello from the enclave\n");
}

/// Test bytes: every value, in a pattern that repeats rarely.
fn pattern(seed: u8, length: usize) -> Vec<u8> {
    (0..length).map(|i| (i as u32).wrapping_mul(2_654_435_761).to_be_bytes()[0] ^ seed).collect()
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn events(log: &MemoryLog) -> Vec<ProxyEvent> {
    log.0.lock().unwrap().clone()
}

/// Reads until the stream closes; true if it closed (EOF or reset).
fn closes(stream: &mut TcpStream) -> bool {
    let mut buffer = [0u8; 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => return true,
            Ok(_) => continue,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => return false,
            Err(_) => return true,
        }
    }
}

#[test]
fn bytes_arrive_unchanged_in_both_directions() {
    let running = start(limits(8, 5_000), Upstream::Echo);
    let mut client = connect(&running.address);
    read_greeting(&mut client);
    let sent = pattern(0x3c, 1 << 20);
    let mut writer = client.try_clone().unwrap();
    let to_send = sent.clone();
    let sender = thread::spawn(move || writer.write_all(&to_send).unwrap());
    let mut echoed = vec![0u8; sent.len()];
    client.read_exact(&mut echoed).unwrap();
    sender.join().unwrap();
    assert!(echoed == sent, "the echo differs from what was sent");
}

#[test]
fn many_connections_at_once_each_get_their_own_bytes() {
    let running = start(limits(64, 5_000), Upstream::Echo);
    let clients: Vec<_> = (0..24u8)
        .map(|i| {
            let address = running.address.clone();
            thread::spawn(move || {
                let mut client = connect(&address);
                read_greeting(&mut client);
                let sent = pattern(i, 64 * 1024 + usize::from(i));
                client.write_all(&sent).unwrap();
                let mut echoed = vec![0u8; sent.len()];
                client.read_exact(&mut echoed).unwrap();
                assert!(echoed == sent, "connection {i} got another's bytes");
            })
        })
        .collect();
    for client in clients {
        client.join().unwrap();
    }
    let accepted = events(&running.log).iter().filter(|e| matches!(e, ProxyEvent::Accepted { .. })).count();
    assert_eq!(accepted, 24);
}

#[test]
fn connections_over_the_limit_are_closed_at_once() {
    let running = start(limits(2, 10_000), Upstream::Echo);
    let mut first = connect(&running.address);
    let mut second = connect(&running.address);
    read_greeting(&mut first);
    read_greeting(&mut second);
    let mut third = connect(&running.address);
    assert!(closes(&mut third), "the third connection is closed");
    wait_for("the refusal", || events(&running.log).iter().any(|e| matches!(e, ProxyEvent::Refused { open: 2 })));
    // When one closes, a new one is let in.
    drop(first);
    wait_for("a closed slot", || events(&running.log).iter().any(|e| matches!(e, ProxyEvent::Closed { .. })));
    let mut fourth = connect(&running.address);
    read_greeting(&mut fourth);
    drop(second);
}

#[test]
fn an_idle_connection_is_closed() {
    let running = start(limits(8, 300), Upstream::Echo);
    let mut client = connect(&running.address);
    read_greeting(&mut client);
    let began = Instant::now();
    assert!(closes(&mut client), "the idle connection is closed");
    let waited = began.elapsed();
    assert!(waited >= Duration::from_millis(200), "closed after {waited:?}, before the idle timeout");
    assert!(waited < Duration::from_secs(5), "closed only after {waited:?}");
    wait_for("the idle event", || {
        events(&running.log).iter().any(|e| matches!(e, ProxyEvent::Closed { reason: CloseReason::Idle, .. }))
    });
}

#[test]
fn a_busy_connection_is_not_closed_as_idle() {
    let running = start(limits(8, 400), Upstream::Echo);
    let mut client = connect(&running.address);
    read_greeting(&mut client);
    for i in 0..10u8 {
        thread::sleep(Duration::from_millis(100));
        client.write_all(&[i]).unwrap();
        let mut back = [0u8; 1];
        client.read_exact(&mut back).unwrap();
        assert_eq!(back, [i]);
    }
}

#[test]
fn a_closed_client_closes_the_enclave_side() {
    let running = start(limits(8, 10_000), Upstream::Sink);
    let mut client = connect(&running.address);
    client.write_all(b"last words before closing").unwrap();
    drop(client);
    wait_for("the enclave side to close", || running.upstream_saw_close.load(Ordering::SeqCst) == 1);
    assert_eq!(&running.upstream_received.lock().unwrap()[..], b"last words before closing");
    wait_for("the close event", || {
        events(&running.log)
            .iter()
            .any(|e| matches!(e, ProxyEvent::Closed { reason: CloseReason::ClientClosed, .. }))
    });
}

#[test]
fn a_closed_enclave_side_closes_the_client() {
    let running = start(limits(8, 10_000), Upstream::Close);
    let mut client = connect(&running.address);
    assert!(closes(&mut client), "the client is closed");
    wait_for("the close event", || {
        events(&running.log)
            .iter()
            .any(|e| matches!(e, ProxyEvent::Closed { reason: CloseReason::UpstreamClosed, .. }))
    });
}

#[test]
fn an_unreachable_enclave_closes_the_client() {
    let front = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = front.local_addr().unwrap().to_string();
    let log = Arc::new(MemoryLog::default());
    let proxy_log: Arc<dyn ProxyLog> = log.clone();
    let missing = socket_path();
    thread::spawn(move || Proxy::new(front, UnixConnector(missing), limits(8, 1_000), proxy_log).serve(None));
    let mut client = connect(&address);
    assert!(closes(&mut client));
    wait_for("the event", || events(&log).iter().any(|e| matches!(e, ProxyEvent::UpstreamUnreachable { .. })));
}

#[test]
fn nothing_carried_is_logged() {
    let running = start(limits(8, 300), Upstream::Echo);
    let marker = b"MARKER-carried-bytes-7f3a";
    for _ in 0..3 {
        let mut client = connect(&running.address);
        read_greeting(&mut client);
        client.write_all(marker).unwrap();
        let mut back = vec![0u8; marker.len()];
        client.read_exact(&mut back).unwrap();
        assert_eq!(&back, marker);
    }
    wait_for("the idle closes", || {
        events(&running.log).iter().filter(|e| matches!(e, ProxyEvent::Closed { .. })).count() == 3
    });
    let logged: String = events(&running.log).iter().map(|e| format!("{e} {e:?}\n")).collect();
    assert!(!logged.contains("MARKER"), "the log holds carried bytes: {logged}");
    assert!(!logged.contains("hello"), "the log holds carried bytes: {logged}");
    assert!(!logged.contains("7f3a"));
    // Every event is one of the payload-free kinds.
    for event in events(&running.log) {
        match event {
            ProxyEvent::Accepted { .. }
            | ProxyEvent::Refused { .. }
            | ProxyEvent::UpstreamUnreachable { .. }
            | ProxyEvent::Closed { .. }
            | ProxyEvent::AcceptFailed => {}
        }
    }
    // The proxy's source never logs or prints what it reads.
    let source = include_str!("../src/proxy.rs");
    for word in ["println!", "eprintln!", "dbg!", "{buffer", "buffer:?"] {
        assert!(!source.contains(word), "proxy.rs has {word}");
    }
}

#[test]
fn a_unix_stream_pair_relays_too() {
    let (mut a, proxy_a) = UnixStream::pair().unwrap();
    let (proxy_b, mut b) = UnixStream::pair().unwrap();
    let relay = thread::spawn(move || ghost_seal::proxy::relay(proxy_a, proxy_b, Duration::from_secs(5)));
    a.write_all(b"one way").unwrap();
    let mut got = [0u8; 7];
    b.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"one way");
    b.write_all(b"other way").unwrap();
    let mut got = [0u8; 9];
    a.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"other way");
    drop(b);
    assert_eq!(relay.join().unwrap(), CloseReason::UpstreamClosed);
    let mut rest = Vec::new();
    assert_eq!(a.read_to_end(&mut rest).unwrap(), 0);
}

// The enclave's service port: a fixed pool, a short queue, a time limit on
// each whole connection.

struct Service {
    path: PathBuf,
    stats: Arc<ServiceStats>,
    /// The most requests worked on at once.
    most_at_once: Arc<AtomicUsize>,
}

/// A stand-in for the enclave's service: answers each frame with
/// `answer:` and the frame, after holding one shared lock for `work`, as the
/// enclave holds its state through an attestation. The frame `panic` makes
/// the handler panic.
fn start_service(limits: ServiceLimits, work: Duration) -> Service {
    let path = socket_path();
    let service = BoundedService::new(UnixListener::bind(&path).unwrap(), limits);
    let stats = service.stats();
    let state = Arc::new(Mutex::new(()));
    let working = Arc::new(AtomicUsize::new(0));
    let most_at_once = Arc::new(AtomicUsize::new(0));
    let most = most_at_once.clone();
    thread::spawn(move || {
        let handler = move |stream: &mut DeadlineStream<UnixStream>| {
            while let Ok(frame) = read_frame(stream) {
                if frame == b"panic" {
                    panic!("a handler panics (test)");
                }
                most.fetch_max(working.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                {
                    let _held = state.lock().unwrap_or_else(|e| e.into_inner());
                    thread::sleep(work);
                }
                working.fetch_sub(1, Ordering::SeqCst);
                if write_frame(stream, &[&b"answer:"[..], &frame].concat()).is_err() {
                    break;
                }
            }
        };
        let _ = service.serve(handler, None);
    });
    Service { path, stats, most_at_once }
}

/// Asks once: `None` if the service closed the connection or did not answer
/// within `wait`.
fn ask(path: &Path, request: &[u8], wait: Duration) -> Option<Vec<u8>> {
    let mut stream = UnixStream::connect(path).ok()?;
    stream.set_read_timeout(Some(wait)).ok()?;
    stream.set_write_timeout(Some(wait)).ok()?;
    write_frame(&mut stream, request).ok()?;
    read_frame(&mut stream).ok()
}

/// Asks again and again until answered, for at most `within`; the answer
/// and how long it took.
fn ask_until_answered(path: &Path, request: &[u8], within: Duration) -> Option<(Vec<u8>, Duration)> {
    let started = Instant::now();
    while started.elapsed() < within {
        if let Some(answer) = ask(path, request, Duration::from_millis(500)) {
            return Some((answer, started.elapsed()));
        }
        thread::sleep(Duration::from_millis(10));
    }
    None
}

#[test]
fn a_flood_of_disconnected_requests_is_bounded_and_the_service_keeps_answering() {
    let limits = ServiceLimits { workers: 2, queue: 2, connection_time: Duration::from_secs(2) };
    let service = start_service(limits, Duration::from_millis(20));
    // 400 clients each send a whole request and hang up at once, far faster
    // than the service can work (20 ms each, one at a time).
    let flooders: Vec<_> = (0..4)
        .map(|_| {
            let path = service.path.clone();
            thread::spawn(move || {
                for _ in 0..100 {
                    if let Ok(mut stream) = UnixStream::connect(&path) {
                        let _ = write_frame(&mut stream, b"a request from a client that already left");
                    }
                }
            })
        })
        .collect();
    for flooder in flooders {
        flooder.join().unwrap();
    }
    // A full queue turned connections away instead of piling up work.
    let refused = service.stats.refused.load(Ordering::SeqCst);
    let accepted = service.stats.accepted.load(Ordering::SeqCst);
    assert!(refused > 0, "no connection was refused ({accepted} accepted)");
    assert!(accepted < 400);
    // And it still answers, soon: at most the pool and the queue were left to
    // work through (400 queued requests would take 8 seconds).
    let (answer, waited) =
        ask_until_answered(&service.path, b"hello", Duration::from_secs(3)).expect("answered after the flood");
    assert_eq!(answer, b"answer:hello");
    assert!(waited < Duration::from_secs(2), "answered only after {waited:?}");
    // Never more requests in hand at once than workers.
    assert!(service.most_at_once.load(Ordering::SeqCst) <= 2);
    assert_eq!(service.stats.handler_panics.load(Ordering::SeqCst), 0);
}

#[test]
fn a_connection_that_drips_bytes_is_cut_off_at_its_time_limit() {
    let limits = ServiceLimits { workers: 1, queue: 1, connection_time: Duration::from_millis(400) };
    let service = start_service(limits, Duration::ZERO);
    // The header of a 1000-byte frame, then a byte every 50 ms: no single
    // read ever waits long, so only a limit on the whole connection frees
    // the one worker.
    let mut slow = UnixStream::connect(&service.path).unwrap();
    slow.write_all(&1000u32.to_be_bytes()).unwrap();
    // Drips for up to 4 seconds; true once the service has closed it.
    let drip = thread::spawn(move || {
        for _ in 0..80 {
            if slow.write_all(b"x").is_err() {
                return true;
            }
            thread::sleep(Duration::from_millis(50));
        }
        false
    });
    thread::sleep(Duration::from_millis(50));
    let answered = ask_until_answered(&service.path, b"quick", Duration::from_secs(3));
    let (answer, waited) = answered.expect("answered while the slow client still drips");
    assert_eq!(answer, b"answer:quick");
    assert!(waited < Duration::from_secs(2), "answered only after {waited:?}");
    assert!(drip.join().unwrap(), "the service closed the slow connection");
}

#[test]
fn a_handler_that_panics_does_not_stop_the_service() {
    let limits = ServiceLimits { workers: 1, queue: 4, connection_time: Duration::from_secs(2) };
    let service = start_service(limits, Duration::ZERO);
    assert_eq!(ask(&service.path, b"panic", Duration::from_secs(2)), None);
    let (answer, _) =
        ask_until_answered(&service.path, b"after", Duration::from_secs(3)).expect("the one worker still serves");
    assert_eq!(answer, b"answer:after");
    assert_eq!(service.stats.handler_panics.load(Ordering::SeqCst), 1);
}

/// A listener that fails as a process out of file descriptors does, between
/// the connections a test gives it.
struct ScriptedListener(Mutex<VecDeque<io::Result<UnixStream>>>);

impl ProxyListener for ScriptedListener {
    type Stream = UnixStream;
    fn accept_stream(&self) -> io::Result<UnixStream> {
        let next = self.0.lock().unwrap().pop_front();
        next.unwrap_or_else(|| Err(io::Error::from_raw_os_error(24)))
    }
}

#[test]
fn failed_accepts_never_stop_the_accept_loop() {
    let (mut client, served) = UnixStream::pair().unwrap();
    let mut script: VecDeque<io::Result<UnixStream>> = (0..5).map(|_| Err(io::Error::from_raw_os_error(24))).collect();
    script.push_back(Ok(served));
    let limits = ServiceLimits { workers: 1, queue: 1, connection_time: Duration::from_secs(2) };
    let service = BoundedService::new(ScriptedListener(Mutex::new(script)), limits);
    let stats = service.stats();
    write_frame(&mut client, b"after five failed accepts").unwrap();
    let echo = |stream: &mut DeadlineStream<UnixStream>| {
        if let Ok(frame) = read_frame(stream) {
            let _ = write_frame(stream, &frame);
        }
    };
    // The loop ends only at the test's limit of 8 failures in a row.
    assert!(service.serve(echo, Some(8)).is_err());
    client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    assert_eq!(read_frame(&mut client).unwrap(), b"after five failed accepts");
    assert_eq!(stats.accept_failures.load(Ordering::SeqCst), 5 + 8);
    assert_eq!(stats.accepted.load(Ordering::SeqCst), 1);
}
