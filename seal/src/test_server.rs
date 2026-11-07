//! The development test Seal server: the relay protocol
//! (`docs/seal-relay.md`) over HTTP, for development and the phone's speed
//! test only. **Never for real money.**
//!
//! It runs the Seal's Check against the public test M, the 32 bytes
//! SHA3-256(`ghost-seal/dev-test-master/v1`), which anyone can derive: a
//! card set up with it protects nothing. Its answers carry an all-zero code
//! measurement, so a phone that pins a real Seal's measurement never takes
//! one. There is no enclave.
//!
//! Its Seal is built like every Seal, by `Seal::new` with a chain status
//! check and a card registry: the card registry file the card setup writes
//! (`--registry FILE`, a `FileRegistry`, read again for each Check, so cards
//! set up later are served without a restart), and the chain check over two
//! or more real nodes (`--node URL`, each an `RpcNode`: `https://` and any
//! host, or `http://` and a loopback address only, a development
//! convenience) on the release network, or the one `--network` names. A
//! card the registry does not hold is refused "Not a Ghost card"
//! (`not-a-ghost-card`) before any card traffic.
//!
//! Its Fill factory is the enclave's Phantom Key maker: a fresh
//! `CoreKeyMaker` per Fill, the wallet core's derivation, making coins on
//! the chain of `--network` (the network its chain check follows). It
//! serves no Fill over HTTP; [`TestSealServer::fill`] runs one on the
//! server's Seal and journal, for the tests and development tools.
//!
//! Its journal is the enclave's log code (`journal_log`) over the host's
//! file store (`host_journal::HostStore`) in this process, under the test M:
//! the file `--journal FILE` (created mode 0600), read and verified whole at
//! the start, shared by every session, so a Fill or an Open cut off before
//! a restart is finished after it on the same file. A Sealed card whose
//! Fill entry is not in that file (sealed by another Seal) is refused
//! rather than answered Sealed unchecked.
//!
//! It refuses to start unless it is given `--dev-test-seal` and the
//! environment variable `GHOST_DEV_TEST_SEAL=1`, `--registry`, at least two
//! `--node`s and `--journal`, and refuses a journal file that fails its
//! checks. It serves HTTPS when given `--tls-cert` and `--tls-key`
//! (PEM files); without them it serves plain HTTP, and only on a loopback
//! address. [`TestSealServer::start_with`] takes the nodes and the registry
//! from the caller (the tests), with no network.
//!
//! **Regions.** Given `--region ID`, `--regions A,B,C` (the ordered region
//! list, as the enclave has it compiled in) and, for each other region,
//! `--peer REGION=ADDR:PORT` (that region's test server's peer port) and
//! `--peer-listen ADDR:PORT` (its own), it runs as one region of several,
//! as the enclaves do (`journal_anchor`): a Check start of a card whose
//! home is another region is refused HTTP 422 `refused`, reason
//! `wrong-region`, naming the home region (`homeRegion`), before any card
//! traffic, and [`TestSealServer::fill`] refuses such a card the same way
//! before any card command. Its journal's head is anchored in its peers:
//! the journal file is opened at the first session, after every peer was
//! asked for its head and what they hold past the file was restored; each
//! save is `Ok` only once every peer took it. On its peer port (plain TCP,
//! loopback only) it keeps the other regions' logs, each in
//! `peer-<region>.log` beside the journal file, and answers their framed
//! service requests kind 3 under the test M.
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
use crate::chain_check::{ChainNode, CoinQuery, CoinStatus, CoinStatusCheck, Network, NodeChainCheck};
use crate::error::SealError;
use crate::flows::{FillOutcome, FillRequest, Seal, SealConfig};
use crate::host_journal::HostStore;
use crate::journal::{EntryKind, Journal, MemoryJournal};
use crate::journal_anchor::{
    Anchor, PEER_DEADLINE, Peer, PeerLink, PeerLogs, Regions, SERVICE_KIND, WRONG_REGION_MESSAGE, WRONG_REGION_REASON,
};
use crate::journal_log::{JournalLog, LogStore, SharedLog};
use crate::key_maker::CoreKeyMaker;
use crate::node_list::NodeList;
use crate::node_rpc::{NodeAddress, RpcNode, TcpTransport};
use crate::primitives::sha3_256;
use crate::registry::{CardRegistry, FileRegistry, MemoryRegistry};
use crate::relay::{KeyMakerFactory, Relay, RelayError, RelayLimits, SessionId, Step, from_hex, to_hex};
use crate::secrets::MasterKey;
use crate::traits::{CardTransport, PhantomKeyMaker, SystemClock, SystemRandom};

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
pub const USAGE: &str = "usage: GHOST_DEV_TEST_SEAL=1 test_seal_server --dev-test-seal --registry FILE \
--node URL --node URL [--node URL ...] --journal FILE [--network CHAIN_ID:GENESIS_HEX] [--listen ADDR:PORT] \
[--tls-cert CERT.pem --tls-key KEY.pem] [--idle-ms N] [--total-ms N] [--max-sessions N] [--body-ms N] \
[--region ID --regions A,B,C --peer-listen ADDR:PORT --peer REGION=ADDR:PORT ...]";

/// The largest frame on the peer port.
const MAX_PEER_FRAME_BYTES: usize = 64 * 1024;
/// How many peer connections are served at once; more are closed.
const MAX_PEER_CONNECTIONS: usize = 16;

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

/// A Seal holding the test M, with the system's random source and clock, a
/// journal in memory only, and `chain_status` and `registry`.
pub fn dev_test_seal(chain_status: Box<dyn CoinStatusCheck>, registry: Box<dyn CardRegistry>) -> Seal {
    dev_test_seal_with(chain_status, registry, Box::new(MemoryJournal::new()))
}

/// A Seal holding the test M, with the system's random source and clock,
/// and `chain_status`, `registry` and `journal`.
pub fn dev_test_seal_with(
    chain_status: Box<dyn CoinStatusCheck>,
    registry: Box<dyn CardRegistry>,
    journal: Box<dyn Journal>,
) -> Seal {
    Seal::new(
        dev_test_master(),
        SealConfig { measurement: DEV_MEASUREMENT, answer_lifetime_secs: DEV_ANSWER_LIFETIME_SECS },
        Box::new(SystemRandom),
        Box::new(SystemClock),
        journal,
        chain_status,
        registry,
    )
}

/// The journal log in the file at `path` (made mode 0600 if missing),
/// opened and verified with the test M.
pub fn open_dev_journal(path: &std::path::Path) -> Result<JournalLog, StartError> {
    let store = HostStore::open(path)
        .map_err(|e| StartError::Journal(format!("cannot open the journal file {}: {e}", path.display())))?;
    JournalLog::open(&dev_test_master(), Box::new(store))
        .map_err(|e| StartError::Journal(format!("the journal file {} is refused: {e}", path.display())))
}

/// Makes the nodes a session's chain check asks, on the session's thread.
pub type NodesFactory = Arc<dyn Fn() -> Vec<Box<dyn ChainNode>> + Send + Sync>;
/// Makes the registry a session's Seal looks cards up in, on the session's
/// thread.
pub type RegistryFactory = Arc<dyn Fn() -> Box<dyn CardRegistry> + Send + Sync>;

/// The chain check and the registry the server's Seals are built with.
#[derive(Clone)]
pub struct Installed {
    /// The network the nodes must follow.
    pub network: Network,
    /// The nodes: at least two, each named once.
    pub nodes: NodesFactory,
    /// The card registry.
    pub registry: RegistryFactory,
}

impl Installed {
    /// What `options` name: [`RpcNode`]s over TCP for its `--node`s and
    /// its `--registry` file, read again for each session.
    pub fn from_options(options: &Options) -> Result<Installed, StartError> {
        let nodes = options
            .nodes
            .iter()
            .map(|address| RpcNode::new(address.clone(), Arc::new(TcpTransport)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(StartError::Usage)?;
        let path = options.registry.clone();
        if !path.is_file() || FileRegistry::open(&path).is_err() {
            return Err(StartError::Missing(format!("cannot read the registry file {}", path.display())));
        }
        Ok(Installed {
            network: options.network,
            nodes: Arc::new(move || nodes.iter().map(|node| Box::new(node.clone()) as Box<dyn ChainNode>).collect()),
            registry: Arc::new(move || match FileRegistry::open(&path) {
                Ok(registry) => Box::new(registry) as Box<dyn CardRegistry>,
                // A file that cannot be read now registers no card.
                Err(_) => Box::new(MemoryRegistry::new()),
            }),
        })
    }

    /// A session's chain status check.
    fn status_check(&self) -> Box<dyn CoinStatusCheck> {
        match NodeChainCheck::new(self.network, (self.nodes)()) {
            Ok(check) => Box::new(check),
            Err(_) => Box::new(NoCheck),
        }
    }
}

/// A check that could not be made: it never answers Sealed.
struct NoCheck;

impl CoinStatusCheck for NoCheck {
    fn coin_status(&self, _query: &CoinQuery) -> CoinStatus {
        CoinStatus::CantCheckNow
    }
}

/// Why the server would not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    /// `--dev-test-seal` or `GHOST_DEV_TEST_SEAL=1` is missing.
    NotDevelopment(&'static str),
    /// The card registry, the nodes or the journal are missing or unusable.
    Missing(String),
    /// The journal file could not be opened, or failed its checks.
    Journal(String),
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
            StartError::Missing(what) | StartError::Journal(what) => write!(f, "refusing to start: {what}"),
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
    registry: PathBuf,
    nodes: Vec<NodeAddress>,
    network: Network,
    journal: PathBuf,
    regions: Option<RegionOptions>,
}

/// Where a test server runs as one region of several.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionOptions {
    /// The ordered region list and this region.
    pub regions: Regions,
    /// Each other region and its test server's peer port, in list order.
    pub peers: Vec<(String, SocketAddr)>,
    /// This server's own peer port.
    pub peer_listen: SocketAddr,
}

/// A loopback `ADDR:PORT` for `flag`.
fn loopback(flag: &str, value: &str) -> Result<SocketAddr, StartError> {
    value
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .filter(|addr| addr.ip().is_loopback())
        .ok_or_else(|| StartError::Usage(format!("{flag} takes a loopback ADDR:PORT (the peer port is plain TCP)")))
}

/// The region options from the flags, checked: `--region` and `--regions`
/// together, a well-formed list naming this region, and exactly one
/// `--peer` for each other region and a `--peer-listen`.
fn region_options(
    region: Option<String>,
    list: Option<String>,
    peers: Vec<(String, String)>,
    peer_listen: Option<String>,
) -> Result<Option<RegionOptions>, StartError> {
    let (region, list) = match (region, list) {
        (None, None) if peers.is_empty() && peer_listen.is_none() => return Ok(None),
        (Some(region), Some(list)) => (region, list),
        _ => return Err(StartError::Usage("--region, --regions, --peer-listen and --peer go together".into())),
    };
    let names: Vec<&str> = list.split(',').map(str::trim).collect();
    let regions = Regions::new(&names, &region).map_err(|why| StartError::Usage(format!("--regions: {why}")))?;
    let mut addressed = Vec::new();
    for other in regions.peers() {
        let given: Vec<&(String, String)> = peers.iter().filter(|(name, _)| name == other).collect();
        let [(_, address)] = given.as_slice() else {
            return Err(StartError::Missing(format!("one --peer {other}=ADDR:PORT is needed for each other region")));
        };
        addressed.push((other.to_owned(), loopback("--peer", address)?));
    }
    if peers.len() != addressed.len() {
        return Err(StartError::Usage("a --peer names a region that is not another region on --regions".into()));
    }
    let peer_listen = peer_listen
        .ok_or_else(|| StartError::Missing("--peer-listen ADDR:PORT is needed with --regions".into()))?;
    Ok(Some(RegionOptions { regions, peers: addressed, peer_listen: loopback("--peer-listen", &peer_listen)? }))
}

impl Options {
    /// Reads the command line (`args`, without the program name) and the
    /// value of `GHOST_DEV_TEST_SEAL` (`dev_env`). Refuses unless both
    /// development flags are given, without `--registry`, with fewer than
    /// two `--node`s or without `--journal`, and refuses plain HTTP on any
    /// address that is not loopback.
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
        let mut registry = None;
        let mut journal = None;
        let mut nodes: Vec<NodeAddress> = Vec::new();
        let mut network = NodeList::release().network;
        let (mut region, mut region_list, mut peers, mut peer_listen) = (None, None, Vec::new(), None);
        let mut at = 0;
        while at < args.len() {
            let flag = args[at].as_str();
            if flag == DEV_FLAG {
                at += 1;
                continue;
            }
            let value = args.get(at + 1).ok_or_else(|| StartError::Usage(format!("{flag} needs a value")))?;
            match flag {
                "--registry" => registry = Some(PathBuf::from(value)),
                "--journal" => journal = Some(PathBuf::from(value)),
                // A node is named by its URL: the same URL twice is one node.
                "--node" => nodes.push(NodeAddress::from_url(value, value).map_err(StartError::Usage)?),
                "--network" => network = parse_network(value)?,
                "--listen" => listen = value.clone(),
                "--tls-cert" => cert = Some(PathBuf::from(value)),
                "--tls-key" => key = Some(PathBuf::from(value)),
                "--idle-ms" => limits.idle_timeout = Duration::from_millis(number(flag, value)?),
                "--total-ms" => limits.total_limit = Duration::from_millis(number(flag, value)?),
                "--max-sessions" => limits.max_sessions = number(flag, value)? as usize,
                "--body-ms" => body_deadline = Duration::from_millis(number(flag, value)?),
                "--region" => region = Some(value.clone()),
                "--regions" => region_list = Some(value.clone()),
                "--peer-listen" => peer_listen = Some(value.clone()),
                "--peer" => {
                    let (name, address) = value
                        .split_once('=')
                        .ok_or_else(|| StartError::Usage("--peer is REGION=ADDR:PORT".into()))?;
                    peers.push((name.to_owned(), address.to_owned()));
                }
                _ => return Err(StartError::Usage(format!("unknown argument {flag}"))),
            }
            at += 2;
        }
        let registry = registry.ok_or_else(|| {
            StartError::Missing("--registry FILE is missing (the card registry the card setup writes)".into())
        })?;
        if nodes.len() < crate::chain_check::MIN_NODES {
            return Err(StartError::Missing("at least two --node URL are needed for the chain check".into()));
        }
        if nodes.iter().enumerate().any(|(i, node)| nodes[..i].iter().any(|other| other.name == node.name)) {
            return Err(StartError::Missing("a --node is given twice; the chain check needs two nodes".into()));
        }
        let journal = journal.ok_or_else(|| {
            StartError::Missing("--journal FILE is missing (the file the test Seal keeps its journal in)".into())
        })?;
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
        let regions = region_options(region, region_list, peers, peer_listen)?;
        Ok(Options { listen, tls, limits, body_deadline, registry, nodes, network, journal, regions })
    }

    /// Where it runs as one region of several, if it does.
    pub fn regions(&self) -> Option<&RegionOptions> {
        self.regions.as_ref()
    }

    /// The card registry file.
    pub fn registry(&self) -> &std::path::Path {
        &self.registry
    }

    /// The journal file.
    pub fn journal(&self) -> &std::path::Path {
        &self.journal
    }

    /// The nodes the chain check asks.
    pub fn nodes(&self) -> &[NodeAddress] {
        &self.nodes
    }

    /// The network the nodes must follow.
    pub fn network(&self) -> Network {
        self.network
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

/// `CHAIN_ID:GENESIS_HEX`: a chain id and block 0's hash (64 hex digits).
fn parse_network(value: &str) -> Result<Network, StartError> {
    let bad = || StartError::Usage("--network is CHAIN_ID:GENESIS_HEX (block 0's hash, 64 hex digits)".into());
    let (chain_id, genesis) = value.split_once(':').ok_or_else(bad)?;
    let chain_id = chain_id.parse::<u64>().ok().filter(|id| *id > 0).ok_or_else(bad)?;
    let genesis = from_hex(genesis.trim_start_matches("0x")).and_then(|g| g.try_into().ok()).ok_or_else(bad)?;
    Ok(Network { chain_id, genesis })
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
    sessions: SessionSeals,
    key_maker: KeyMakerFactory,
    peer_addr: Option<SocketAddr>,
}

/// The server's journal: the file's log, opened at the start, or (as one
/// region of several) the same log anchored in the peers, opened at the
/// first session.
#[derive(Clone)]
enum SessionJournal {
    Plain(JournalLog),
    Anchored(Arc<SharedLog>),
}

impl SessionJournal {
    fn journal(&self) -> Box<dyn Journal> {
        match self {
            SessionJournal::Plain(log) => Box::new(log.clone()),
            SessionJournal::Anchored(shared) => match shared.journal(&dev_test_master()) {
                Ok(log) => Box::new(log),
                // No peer answered, a fork, a bad restore or a rollback: the
                // session's Seal changes no card.
                Err(_) => Box::new(RefusedJournal),
            },
        }
    }
}

/// A journal that holds nothing and takes no save.
struct RefusedJournal;

impl Journal for RefusedJournal {
    fn load(&self, _uid: &CardUid, _kind: EntryKind) -> Option<Vec<u8>> {
        None
    }

    fn save(&mut self, _uid: &CardUid, _kind: EntryKind, _sealed: Vec<u8>) -> Result<(), SealError> {
        Err(SealError::Journal("the journal could not be anchored in the peer regions"))
    }
}

/// How the server's Seals are made.
#[derive(Clone)]
struct SessionSeals {
    installed: Installed,
    journal: SessionJournal,
}

impl SessionSeals {
    fn seal(&self) -> Seal {
        dev_test_seal_with(self.installed.status_check(), (self.installed.registry)(), self.journal.journal())
    }
}

/// What the server's threads share.
struct Shared {
    relay: Relay,
    links: Links,
    body_deadline: Duration,
    in_flight: AtomicUsize,
    regions: Option<Regions>,
}

/// A peer region's test server, reached on its peer port: one framed
/// service request kind 3 per connection.
struct TcpPeer(SocketAddr);

impl PeerLink for TcpPeer {
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        let mut stream = TcpStream::connect_timeout(&self.0, Duration::from_secs(2)).map_err(|e| e.to_string())?;
        let _ = stream.set_read_timeout(Some(PEER_DEADLINE));
        let _ = stream.set_write_timeout(Some(PEER_DEADLINE));
        write_peer_frame(&mut stream, &[&[SERVICE_KIND][..], request].concat()).map_err(|e| e.to_string())?;
        let answer = read_peer_frame(&mut stream).map_err(|e| e.to_string())?;
        match answer.split_first() {
            Some((&0, body)) => Ok(body.to_vec()),
            Some((&1, why)) => Err(String::from_utf8_lossy(why).into_owned()),
            _ => Err("the peer's answer is malformed".into()),
        }
    }
}

/// A frame on the peer port: a 4-byte big-endian length and the bytes.
fn write_peer_frame(out: &mut dyn Write, bytes: &[u8]) -> std::io::Result<()> {
    if bytes.len() > MAX_PEER_FRAME_BYTES {
        return Err(std::io::Error::other("the frame is too long"));
    }
    out.write_all(&[&(bytes.len() as u32).to_be_bytes()[..], bytes].concat())?;
    out.flush()
}

fn read_peer_frame(input: &mut dyn Read) -> std::io::Result<Vec<u8>> {
    let mut length = [0u8; 4];
    input.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_PEER_FRAME_BYTES {
        return Err(std::io::Error::other("the frame is too long"));
    }
    let mut bytes = vec![0u8; length];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Answers the peer regions' requests on `listener` until `stop`, one
/// thread per connection, at most [`MAX_PEER_CONNECTIONS`] at once.
fn serve_peers(listener: TcpListener, logs: Arc<PeerLogs>, stop: Arc<AtomicBool>) {
    let open = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let Ok(mut stream) = stream else { continue };
        if open.fetch_add(1, Ordering::SeqCst) >= MAX_PEER_CONNECTIONS {
            open.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let (logs, held) = (Arc::clone(&logs), Arc::clone(&open));
        let spawned = std::thread::Builder::new().spawn(move || {
            let _ = stream.set_read_timeout(Some(CONNECTION_IDLE));
            let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
            while let Ok(frame) = read_peer_frame(&mut stream) {
                let answer = match frame.split_first() {
                    Some((&SERVICE_KIND, body)) => logs.answer(&dev_test_master(), body),
                    _ => Err("unknown request".into()),
                };
                let framed = match answer {
                    Ok(body) => [&[0u8][..], &body].concat(),
                    Err(why) => [&[1u8][..], why.as_bytes()].concat(),
                };
                if write_peer_frame(&mut stream, &framed).is_err() {
                    break;
                }
            }
            held.fetch_sub(1, Ordering::SeqCst);
        });
        if spawned.is_err() {
            open.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// The journal of a server running as one region of several: the file's
/// log anchored in the peers, and the peers' logs beside the file.
fn anchored_journal(path: &std::path::Path, options: &RegionOptions) -> Result<(SharedLog, PeerLogs), StartError> {
    let open = |file: &std::path::Path| {
        HostStore::open(file)
            .map_err(|e| StartError::Journal(format!("cannot open the journal file {}: {e}", file.display())))
    };
    let own = options.regions.own();
    let peers = options
        .peers
        .iter()
        .map(|(region, addr)| Peer { region: region.clone(), link: Arc::new(TcpPeer(*addr)) as Arc<dyn PeerLink> })
        .collect();
    let journal = SharedLog::anchored(Box::new(open(path)?), Box::new(Anchor::new(own, peers)));
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut stores: Vec<(String, Box<dyn LogStore>)> = Vec::new();
    for (region, _) in &options.peers {
        stores.push((region.clone(), Box::new(open(&dir.join(format!("peer-{region}.log")))?)));
    }
    Ok((journal, PeerLogs::new(own, stores)))
}

/// The refusal of a card whose home is region `home`.
fn wrong_region_reply(home: &str) -> Reply {
    Reply {
        status: 422,
        body: json!({
            "status": "error",
            "error": "refused",
            "reason": WRONG_REGION_REASON,
            "homeRegion": home,
            "message": WRONG_REGION_MESSAGE,
        }),
    }
}

impl TestSealServer {
    /// Starts serving the relay protocol on `options`' address, with the
    /// chain check over its `--node`s and its `--registry` file.
    pub fn start(options: &Options) -> Result<TestSealServer, StartError> {
        TestSealServer::start_with(options, Installed::from_options(options)?)
    }

    /// Starts serving the relay protocol on `options`' address, with the
    /// chain check and the registry of `installed` (the tests' fakes);
    /// `options`' nodes and registry file are not used. Its journal is
    /// `options`' journal file, verified with the test M before anything is
    /// served: a file that fails is [`StartError::Journal`].
    pub fn start_with(options: &Options, installed: Installed) -> Result<TestSealServer, StartError> {
        if NodeChainCheck::new(installed.network, (installed.nodes)()).is_err() {
            return Err(StartError::Missing("the chain check needs at least two nodes, each named once".into()));
        }
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

        // The journal file, read and verified whole before anything is
        // served; as one region of several, opened at the first session,
        // once the peers were asked (they may start after this server).
        let mut peer_service = None;
        let journal = match &options.regions {
            None => SessionJournal::Plain(open_dev_journal(&options.journal)?),
            Some(regions) => {
                let (journal, logs) = anchored_journal(&options.journal, regions)?;
                let listener = TcpListener::bind(regions.peer_listen).map_err(|e| StartError::Listen(e.to_string()))?;
                let peer_addr = listener.local_addr().map_err(|e| StartError::Listen(e.to_string()))?;
                peer_service = Some((listener, peer_addr, Arc::new(logs)));
                SessionJournal::Anchored(Arc::new(journal))
            }
        };

        // A Fill's Phantom Key maker: the wallet core's derivation, for coins
        // on the network the chain check follows (`--network`).
        let chain_id = installed.network.chain_id;
        let key_maker: KeyMakerFactory =
            Arc::new(move || Box::new(CoreKeyMaker::new(chain_id)) as Box<dyn PhantomKeyMaker>);

        // Each session's Seal: the test M, its own check over the nodes, the
        // registry as it stands and the one shared journal.
        let sessions = SessionSeals { installed, journal };
        let seals = sessions.clone();
        let factory = move || seals.seal();
        let shared = Arc::new(Shared {
            relay: Relay::new(Arc::new(factory), options.limits),
            links: Links::default(),
            body_deadline: options.body_deadline,
            in_flight: AtomicUsize::new(0),
            regions: options.regions.as_ref().map(|r| r.regions.clone()),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();
        let mut peer_addr = None;
        if let Some((listener, addr, logs)) = peer_service {
            peer_addr = Some(addr);
            let stop = Arc::clone(&stop);
            threads.push(std::thread::spawn(move || serve_peers(listener, logs, stop)));
        }
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
        Ok(TestSealServer { addr, https: options.tls.is_some(), shared, stop, threads, sessions, key_maker, peer_addr })
    }

    /// The address of its peer port, when it runs as one region of several.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    /// The region list and its own region, when it runs as one of several.
    pub fn regions(&self) -> Option<&Regions> {
        self.shared.regions.as_ref()
    }

    /// A Seal as each of the server's sessions runs: the test M, the chain
    /// check, the registry and the server's journal. For the tests and
    /// development tools that run a flow the server does not serve over
    /// HTTP (a Fill) on the same journal.
    pub fn seal(&self) -> Seal {
        self.sessions.seal()
    }

    /// A fresh Phantom Key maker from the server's Fill factory: the wallet
    /// core's derivation on the chain check's network.
    pub fn key_maker(&self) -> Box<dyn PhantomKeyMaker> {
        (self.key_maker)()
    }

    /// A Fill of `card` on the server's Seal and journal, its key made by
    /// the server's Fill factory. A card whose home is another region is
    /// refused before any card command.
    pub fn fill(&self, card: &mut dyn CardTransport, request: &FillRequest) -> Result<FillOutcome, SealError> {
        if self.regions().is_some_and(|regions| !regions.is_home(&request.uid)) {
            return Err(SealError::Registry("this card is served by its home region"));
        }
        self.seal().fill(card, request, self.key_maker().as_mut())
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
        // And the peer port's accept.
        if let Some(peer) = self.peer_addr {
            let _ = TcpStream::connect_timeout(&peer, Duration::from_secs(1));
        }
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
    // A card whose home is another region: refused before any session.
    if path == "/v1/check/start"
        && let Some(regions) = &shared.regions
        && let Ok(uid) = hex_field::<7>(&fields, "uid").map(CardUid)
        && !regions.is_home(&uid)
    {
        return wrong_region_reply(regions.home(&uid));
    }
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
        // As the enclave's routes answer it: refused, with the reason the
        // phone shows as "Not a Ghost card".
        RelayError::Seal(SealError::NotAGhostCard) => Reply {
            status: 422,
            body: json!({ "status": "error", "error": "refused", "reason": "not-a-ghost-card", "message": message }),
        },
        RelayError::Seal(_) => Reply::error(422, "refused", &message),
    }
}
