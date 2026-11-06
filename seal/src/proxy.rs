//! The parent proxy: a host-side relay between TCP and a stream to the
//! enclave (vsock on a Nitro host; any stream in the tests).
//!
//! It copies bytes both ways and does nothing else with them: it never
//! parses, logs or stores what it carries (the traffic is TLS or a key-share
//! package, both encrypted end to end to the enclave). Its log is a
//! [`ProxyEvent`], which has no field that could hold carried bytes. It
//! limits how many connections are open at once and closes a connection
//! idle for longer than its idle timeout; when either side closes, it closes
//! the other.
//!
//! [`BoundedService`] is the enclave's side of a service port: a fixed pool
//! of worker threads fed by a short queue, a connection refused at once when
//! the queue is full, and a time limit on each whole connection (not only
//! on each read), so no client, connected or gone, can make the enclave hold
//! more work than the pool and the queue. Running out of threads or file
//! descriptors never panics its accept loop.

use core::fmt;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver as QueueReceiver, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// The default most connections open at once.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;
/// The default idle timeout.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// How long a TCP connect may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const BUFFER_BYTES: usize = 16 * 1024;

/// A byte stream the proxy can relay.
pub trait ProxyStream: Read + Write + Send + Sized + 'static {
    /// A second handle on the same stream, for the other direction.
    fn duplicate(&self) -> io::Result<Self>;
    /// Sets the read and the write timeout.
    fn set_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> io::Result<()>;
    /// Closes both directions.
    fn close(&self);
}

macro_rules! proxy_stream {
    ($stream:ty) => {
        impl ProxyStream for $stream {
            fn duplicate(&self) -> io::Result<Self> {
                self.try_clone()
            }
            fn set_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> io::Result<()> {
                self.set_read_timeout(read)?;
                self.set_write_timeout(write)
            }
            fn close(&self) {
                let _ = self.shutdown(Shutdown::Both);
            }
        }
    };
}

proxy_stream!(TcpStream);
proxy_stream!(UnixStream);
proxy_stream!(vsock::VsockStream);

/// Where the proxy takes connections from.
pub trait ProxyListener: Send + 'static {
    /// The accepted streams.
    type Stream: ProxyStream;
    /// Waits for the next connection.
    fn accept_stream(&self) -> io::Result<Self::Stream>;
}

impl ProxyListener for TcpListener {
    type Stream = TcpStream;
    fn accept_stream(&self) -> io::Result<TcpStream> {
        self.accept().map(|(stream, _)| stream)
    }
}

impl ProxyListener for UnixListener {
    type Stream = UnixStream;
    fn accept_stream(&self) -> io::Result<UnixStream> {
        self.accept().map(|(stream, _)| stream)
    }
}

impl ProxyListener for vsock::VsockListener {
    type Stream = vsock::VsockStream;
    fn accept_stream(&self) -> io::Result<vsock::VsockStream> {
        self.accept().map(|(stream, _)| stream)
    }
}

/// Where the proxy relays each connection to.
pub trait Connector: Send + Sync + 'static {
    /// The upstream streams.
    type Stream: ProxyStream;
    /// Opens one upstream connection.
    fn connect_stream(&self) -> io::Result<Self::Stream>;
}

/// Connects to a TCP address (a host name is looked up on every connect).
#[derive(Debug, Clone)]
pub struct TcpConnector(pub String);

impl Connector for TcpConnector {
    type Stream = TcpStream;
    fn connect_stream(&self) -> io::Result<TcpStream> {
        let addresses: Vec<SocketAddr> = self.0.to_socket_addrs()?.collect();
        let mut last = io::Error::new(ErrorKind::NotFound, "the upstream name has no address");
        for address in addresses {
            match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
                Ok(stream) => return Ok(stream),
                Err(error) => last = error,
            }
        }
        Err(last)
    }
}

/// Connects to a vsock address: the enclave's CID and port.
#[derive(Debug, Clone, Copy)]
pub struct VsockConnector {
    /// The enclave's context ID.
    pub cid: u32,
    /// Its port.
    pub port: u32,
}

impl Connector for VsockConnector {
    type Stream = vsock::VsockStream;
    fn connect_stream(&self) -> io::Result<vsock::VsockStream> {
        vsock::VsockStream::connect_with_cid_port(self.cid, self.port)
    }
}

/// Connects to a Unix socket.
#[derive(Debug, Clone)]
pub struct UnixConnector(pub PathBuf);

impl Connector for UnixConnector {
    type Stream = UnixStream;
    fn connect_stream(&self) -> io::Result<UnixStream> {
        UnixStream::connect(&self.0)
    }
}

/// The proxy's limits.
#[derive(Debug, Clone, Copy)]
pub struct ProxyLimits {
    /// The most connections open at once; more are closed at once.
    pub max_connections: usize,
    /// A connection with no byte either way for this long is closed.
    pub idle_timeout: Duration,
}

impl Default for ProxyLimits {
    fn default() -> ProxyLimits {
        ProxyLimits { max_connections: DEFAULT_MAX_CONNECTIONS, idle_timeout: DEFAULT_IDLE_TIMEOUT }
    }
}

/// Why a relayed connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// The connecting side closed.
    ClientClosed,
    /// The upstream side closed.
    UpstreamClosed,
    /// Nothing moved for the idle timeout.
    Idle,
    /// A read or write failed.
    Failed,
}

/// What the proxy logs. No variant has a field for carried bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyEvent {
    /// A connection was accepted and relayed.
    Accepted {
        /// The connection's number.
        id: u64,
        /// Connections now open.
        open: usize,
    },
    /// A connection was closed at once: the limit was reached.
    Refused {
        /// Connections open.
        open: usize,
    },
    /// The upstream could not be reached.
    UpstreamUnreachable {
        /// The connection's number.
        id: u64,
    },
    /// A connection ended.
    Closed {
        /// The connection's number.
        id: u64,
        /// Why.
        reason: CloseReason,
    },
    /// Accepting failed (the proxy carries on).
    AcceptFailed,
}

impl fmt::Display for ProxyEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyEvent::Accepted { id, open } => write!(f, "connection {id} accepted, {open} open"),
            ProxyEvent::Refused { open } => write!(f, "connection refused, {open} open is the limit"),
            ProxyEvent::UpstreamUnreachable { id } => write!(f, "connection {id}: upstream unreachable"),
            ProxyEvent::Closed { id, reason } => write!(f, "connection {id} closed: {reason:?}"),
            ProxyEvent::AcceptFailed => f.write_str("accept failed"),
        }
    }
}

/// Where the proxy's events go.
pub trait ProxyLog: Send + Sync {
    /// Records one event.
    fn event(&self, event: ProxyEvent);
}

/// Keeps every event in memory (tests read them back).
#[derive(Debug, Default)]
pub struct MemoryLog(pub Mutex<Vec<ProxyEvent>>);

impl ProxyLog for MemoryLog {
    fn event(&self, event: ProxyEvent) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).push(event);
    }
}

/// The proxy: accepts from `listener` and relays each connection to a new
/// connection from `connector`.
pub struct Proxy<L: ProxyListener, C: Connector> {
    listener: L,
    connector: Arc<C>,
    limits: ProxyLimits,
    log: Arc<dyn ProxyLog>,
    open: Arc<AtomicUsize>,
}

impl<L: ProxyListener, C: Connector> Proxy<L, C> {
    /// A proxy with these limits, logging to `log`.
    pub fn new(listener: L, connector: C, limits: ProxyLimits, log: Arc<dyn ProxyLog>) -> Proxy<L, C> {
        Proxy { listener, connector: Arc::new(connector), limits, log, open: Arc::new(AtomicUsize::new(0)) }
    }

    /// Connections open now.
    pub fn open_connections(&self) -> Arc<AtomicUsize> {
        self.open.clone()
    }

    /// Takes one connection slot if one is free.
    fn reserve(&self) -> bool {
        let mut open = self.open.load(Ordering::SeqCst);
        while open < self.limits.max_connections {
            match self.open.compare_exchange(open, open + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return true,
                Err(now) => open = now,
            }
        }
        false
    }

    /// Accepts and relays connections until accepting fails `max_failures`
    /// times in a row (`None`: forever).
    pub fn serve(self, max_failures: Option<u32>) -> io::Result<()> {
        let mut next_id = 0u64;
        let mut failures = 0u32;
        loop {
            let client = match self.listener.accept_stream() {
                Ok(stream) => {
                    failures = 0;
                    stream
                }
                Err(error) => {
                    self.log.event(ProxyEvent::AcceptFailed);
                    failures += 1;
                    if max_failures.is_some_and(|max| failures >= max) {
                        return Err(error);
                    }
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }
            };
            next_id += 1;
            let id = next_id;
            // Reserve a slot, or close the connection at once.
            let reserved = self.reserve();
            if !reserved {
                client.close();
                self.log.event(ProxyEvent::Refused { open: self.open.load(Ordering::SeqCst) });
                continue;
            }
            self.log.event(ProxyEvent::Accepted { id, open: self.open.load(Ordering::SeqCst) });
            let connector = self.connector.clone();
            let log = self.log.clone();
            let open = self.open.clone();
            let limits = self.limits;
            let spawned = thread::Builder::new().spawn(move || {
                let reason = match connector.connect_stream() {
                    Ok(upstream) => Some(relay(client, upstream, limits.idle_timeout)),
                    Err(_) => {
                        client.close();
                        None
                    }
                };
                open.fetch_sub(1, Ordering::SeqCst);
                match reason {
                    Some(reason) => log.event(ProxyEvent::Closed { id, reason }),
                    None => log.event(ProxyEvent::UpstreamUnreachable { id }),
                }
            });
            // No thread to be had: the connection (dropped with the closure)
            // is closed, its slot freed, and the proxy carries on.
            if spawned.is_err() {
                self.open.fetch_sub(1, Ordering::SeqCst);
                self.log.event(ProxyEvent::Refused { open: self.open.load(Ordering::SeqCst) });
            }
        }
    }
}

/// The limits of an enclave service port.
#[derive(Debug, Clone, Copy)]
pub struct ServiceLimits {
    /// Worker threads, all started up front; no thread is made per
    /// connection.
    pub workers: usize,
    /// Accepted connections that may wait for a worker; one more is closed
    /// at once.
    pub queue: usize,
    /// The longest a connection may last from the moment it is accepted,
    /// waiting in the queue included, however slowly its bytes come.
    pub connection_time: Duration,
}

impl Default for ServiceLimits {
    fn default() -> ServiceLimits {
        ServiceLimits { workers: 4, queue: 16, connection_time: Duration::from_secs(30) }
    }
}

/// What a [`BoundedService`] counts. No field could hold carried bytes.
#[derive(Debug, Default)]
pub struct ServiceStats {
    /// Connections handed to the queue.
    pub accepted: AtomicU64,
    /// Connections closed at once because the queue was full.
    pub refused: AtomicU64,
    /// Accepts that failed (the loop carries on).
    pub accept_failures: AtomicU64,
    /// Connections a worker finished with.
    pub handled: AtomicU64,
    /// Connections whose time ran out while they waited in the queue.
    pub expired_in_queue: AtomicU64,
    /// Handler runs that panicked (the worker carries on).
    pub handler_panics: AtomicU64,
    /// Handler runs going on now.
    pub busy: AtomicUsize,
}

/// A stream whose every read and write waits at most until one deadline,
/// then fails with [`ErrorKind::TimedOut`]: a time limit on a whole
/// connection, which per-read socket timeouts are not.
pub struct DeadlineStream<S: ProxyStream> {
    inner: S,
    deadline: Instant,
}

impl<S: ProxyStream> DeadlineStream<S> {
    /// `inner`, limited to `deadline`.
    pub fn new(inner: S, deadline: Instant) -> DeadlineStream<S> {
        DeadlineStream { inner, deadline }
    }

    /// Whether the deadline has passed.
    pub fn expired(&self) -> bool {
        self.left().is_none()
    }

    /// Closes both directions.
    pub fn close(&self) {
        self.inner.close();
    }

    fn left(&self) -> Option<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() { None } else { Some(left) }
    }

    fn arm(&self) -> io::Result<()> {
        let left = self.left().ok_or_else(|| io::Error::new(ErrorKind::TimedOut, "the connection's time is up"))?;
        self.inner.set_timeouts(Some(left), Some(left))
    }
}

impl<S: ProxyStream> Read for DeadlineStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.arm()?;
        self.inner.read(buf)
    }
}

impl<S: ProxyStream> Write for DeadlineStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.arm()?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.arm()?;
        self.inner.flush()
    }
}

type Queued<S> = (S, Instant);

/// A service port with a fixed pool of workers: see the module docs.
pub struct BoundedService<L: ProxyListener> {
    listener: L,
    limits: ServiceLimits,
    stats: Arc<ServiceStats>,
}

impl<L: ProxyListener> BoundedService<L> {
    /// A service on `listener` with these limits.
    pub fn new(listener: L, limits: ServiceLimits) -> BoundedService<L> {
        BoundedService { listener, limits, stats: Arc::new(ServiceStats::default()) }
    }

    /// What it has counted.
    pub fn stats(&self) -> Arc<ServiceStats> {
        self.stats.clone()
    }

    /// Starts the workers, then accepts connections and queues each for
    /// `handler`, until accepting fails `max_failures` times in a row
    /// (`None`: forever). A full queue closes the new connection at once; a
    /// failed accept (out of file descriptors, say) waits a moment and goes
    /// on. Fails only when no worker could be started, or every worker has
    /// stopped.
    pub fn serve<H>(self, handler: H, max_failures: Option<u32>) -> io::Result<()>
    where
        H: Fn(&mut DeadlineStream<L::Stream>) + Send + Sync + 'static,
    {
        let (queue, waiting) = sync_channel::<Queued<L::Stream>>(self.limits.queue);
        let waiting = Arc::new(Mutex::new(waiting));
        let handler = Arc::new(handler);
        let mut started = 0usize;
        for n in 0..self.limits.workers.max(1) {
            let (waiting, handler, stats) = (waiting.clone(), handler.clone(), self.stats.clone());
            let spawned = thread::Builder::new()
                .name(format!("service-worker-{n}"))
                .spawn(move || work(&waiting, handler.as_ref(), &stats));
            if spawned.is_ok() {
                started += 1;
            }
        }
        if started == 0 {
            return Err(io::Error::other("no service worker could be started"));
        }
        let mut failures = 0u32;
        loop {
            let stream = match self.listener.accept_stream() {
                Ok(stream) => {
                    failures = 0;
                    stream
                }
                Err(error) => {
                    self.stats.accept_failures.fetch_add(1, Ordering::SeqCst);
                    failures = failures.saturating_add(1);
                    if max_failures.is_some_and(|max| failures >= max) {
                        return Err(error);
                    }
                    thread::sleep(Duration::from_millis(20));
                    continue;
                }
            };
            let deadline = Instant::now() + self.limits.connection_time;
            match queue.try_send((stream, deadline)) {
                Ok(()) => {
                    self.stats.accepted.fetch_add(1, Ordering::SeqCst);
                }
                Err(TrySendError::Full((stream, _))) => {
                    stream.close();
                    self.stats.refused.fetch_add(1, Ordering::SeqCst);
                }
                Err(TrySendError::Disconnected((stream, _))) => {
                    stream.close();
                    return Err(io::Error::other("every service worker has stopped"));
                }
            }
        }
    }
}

/// One worker: takes queued connections one at a time, for ever.
fn work<S: ProxyStream, H: Fn(&mut DeadlineStream<S>)>(
    waiting: &Mutex<QueueReceiver<Queued<S>>>,
    handler: &H,
    stats: &ServiceStats,
) {
    loop {
        let next = waiting.lock().unwrap_or_else(|e| e.into_inner()).recv();
        let Ok((stream, deadline)) = next else {
            return;
        };
        let mut stream = DeadlineStream::new(stream, deadline);
        if stream.expired() {
            stream.close();
            stats.expired_in_queue.fetch_add(1, Ordering::SeqCst);
            continue;
        }
        stats.busy.fetch_add(1, Ordering::SeqCst);
        if catch_unwind(AssertUnwindSafe(|| handler(&mut stream))).is_err() {
            stats.handler_panics.fetch_add(1, Ordering::SeqCst);
        }
        stats.busy.fetch_sub(1, Ordering::SeqCst);
        stream.close();
        stats.handled.fetch_add(1, Ordering::SeqCst);
    }
}

/// Relays one connection until a side closes, a side fails, or nothing
/// moves for `idle`. Returns why it ended.
pub fn relay<A: ProxyStream, B: ProxyStream>(client: A, upstream: B, idle: Duration) -> CloseReason {
    let idle = idle.max(Duration::from_millis(10));
    let tick = (idle / 4).clamp(Duration::from_millis(5), Duration::from_millis(250));
    let started = Instant::now();
    let shared = Arc::new(Shared {
        last_activity_ms: AtomicU64::new(0),
        done: AtomicBool::new(false),
        first_reason: Mutex::new(None),
        started,
        idle,
    });
    let duplicated = (|| -> io::Result<(A, B)> {
        // Reads wake every tick to look at the idle clock; a write may wait
        // for the peer as long as the idle timeout.
        client.set_timeouts(Some(tick), Some(idle))?;
        upstream.set_timeouts(Some(tick), Some(idle))?;
        Ok((client.duplicate()?, upstream.duplicate()?))
    })();
    let (client_writer, upstream_writer) = match duplicated {
        Ok(pair) => pair,
        Err(_) => {
            client.close();
            upstream.close();
            return CloseReason::Failed;
        }
    };
    let up_shared = shared.clone();
    let spawned =
        thread::Builder::new().spawn(move || pump(client, upstream_writer, &up_shared, CloseReason::ClientClosed));
    let Ok(up) = spawned else {
        // No thread for the other direction: the halves moved into the
        // closure are dropped with it; close the rest.
        upstream.close();
        client_writer.close();
        return CloseReason::Failed;
    };
    pump(upstream, client_writer, &shared, CloseReason::UpstreamClosed);
    let _ = up.join();
    // The first direction to stop says why; the other stopped because of it.
    let first = *shared.first_reason.lock().unwrap_or_else(|e| e.into_inner());
    first.unwrap_or(CloseReason::Failed)
}

struct Shared {
    last_activity_ms: AtomicU64,
    done: AtomicBool,
    first_reason: Mutex<Option<CloseReason>>,
    started: Instant,
    idle: Duration,
}

impl Shared {
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }
}

/// Copies `from` into `to` until something ends it, then closes both ends of
/// both streams so the other direction ends too.
fn pump<R: ProxyStream, W: ProxyStream>(mut from: R, mut to: W, shared: &Shared, eof: CloseReason) {
    let mut buffer = [0u8; BUFFER_BYTES];
    let reason = loop {
        if shared.done.load(Ordering::SeqCst) {
            return finish(&mut buffer, &from, &to);
        }
        match from.read(&mut buffer) {
            Ok(0) => break eof,
            Ok(n) => {
                if to.write_all(&buffer[..n]).is_err() {
                    break CloseReason::Failed;
                }
                shared.last_activity_ms.store(shared.now_ms(), Ordering::SeqCst);
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                let quiet = shared.now_ms().saturating_sub(shared.last_activity_ms.load(Ordering::SeqCst));
                if Duration::from_millis(quiet) >= shared.idle {
                    break CloseReason::Idle;
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => break CloseReason::Failed,
        }
    };
    {
        let mut first = shared.first_reason.lock().unwrap_or_else(|e| e.into_inner());
        if first.is_none() {
            *first = Some(reason);
        }
    }
    shared.done.store(true, Ordering::SeqCst);
    finish(&mut buffer, &from, &to);
}

fn finish<R: ProxyStream, W: ProxyStream>(buffer: &mut [u8], from: &R, to: &W) {
    from.close();
    to.close();
    buffer.fill(0);
}
