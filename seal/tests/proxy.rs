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

use ghost_seal::proxy::{CloseReason, MemoryLog, Proxy, ProxyEvent, ProxyLimits, ProxyLog, UnixConnector};

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
