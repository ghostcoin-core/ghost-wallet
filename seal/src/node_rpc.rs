//! The real chain node (features `nitro` and `test-server`): a
//! [`ChainNode`] that asks a Ghost node over JSON-RPC, HTTP/1.1 and TLS 1.3.
//!
//! - **Calls.** Only those the wallet already makes (`lib/vanish/node.ts`):
//!   `eth_chainId`, `eth_getBlockByNumber`, `eth_getBlockReceipts`,
//!   `ghost_getPageRoots`, `ghost_getPageSet` and `ghost_getTreePage` (the
//!   spend marker list), on coin tree 0.
//! - **One request per connection.** Each exchange opens a stream through a
//!   [`NodeTransport`] (in the enclave a vsock stream to the host, which
//!   carries the bytes to the node; in the test server a TCP connection),
//!   sends one `POST` with `Connection: close` (a JSON-RPC batch) and reads
//!   the reply to its end. HTTP heads are read with `httparse`, bodies with
//!   `serde_json`.
//! - **Bounds.** A reply is at most [`MAX_REPLY_BYTES`] (1 MiB); an exchange
//!   has [`CALL_DEADLINE`] (10 seconds) in all, however slowly the bytes
//!   come. A refused, malformed, oversized or slow reply is
//!   [`NodeError::Unreachable`] or [`NodeError::Inconsistent`], never a
//!   guess, so the chain check answers "can't check right now".
//! - **TLS 1.3 to every node, ended here.** `rustls` with its `ring`
//!   provider and TLS 1.3 only. The one trust anchor compiled in is the ISRG
//!   Root X1 certificate ([`ISRG_ROOT_X1_PEM`]); the server's certificate is
//!   checked by rustls's own `WebPkiServerVerifier` over that root alone,
//!   for the node entry's host name. Tests hand in their own root
//!   ([`RpcNode::with_roots`]). Plain HTTP is only for a test server's node
//!   on a loopback address.
//! - **Finding a Vanish by its fingerprint.** [`RpcNode`] scans the chain
//!   forward from block 1 (`eth_getBlockByNumber` and
//!   `eth_getBlockReceipts`), keeping the transactions to the coin commit
//!   entry. It reads at most [`BLOCKS_PER_CALL`] blocks per call. What it
//!   found in blocks more than [`SETTLED_DEPTH`] below the tip it keeps in
//!   memory (shared by every session, per node); newer blocks are read again
//!   on every call, so a reorganisation among them is seen. Until it has
//!   caught up with the tip it answers [`NodeError::Unreachable`], and the
//!   next call carries on where it stopped. The leaf position of a Vanish is
//!   found among the leaves its block added, from the coin tree as of its
//!   block and of its parent.
//!
//! Nothing here logs, and no error text carries a request or a reply.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use ghost_wallet_core::coin_tree::PAGE_LEAVES;
use ghost_wallet_core::vanish::COMMIT_ENTRY;
use ghost_wallet_core::{CoinPage, commit_leaf};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde_json::{Value, json};

use crate::chain_check::{BlockRef, ChainNode, CoinTreeAt, Network, NodeError, TxOutcome, VanishReceipt};
use crate::node_list::NodeEntry;

/// The largest reply body read from a node.
pub const MAX_REPLY_BYTES: usize = 1024 * 1024;
/// How long one exchange with a node may take, from connecting to the end
/// of its reply.
pub const CALL_DEADLINE: Duration = Duration::from_secs(10);
/// The most blocks one [`ChainNode::vanish_receipts`] call reads.
pub const BLOCKS_PER_CALL: u64 = 500;
/// Blocks more than this far below the tip are settled: what they hold is
/// kept and not read again.
pub const SETTLED_DEPTH: u64 = 128;
/// Blocks asked for in one request while scanning.
pub const BLOCKS_PER_REQUEST: u64 = 10;
/// The most spend marker pages read for one question.
pub const MAX_MARKER_PAGES: u64 = 64;
/// The most markers a marker page holds: a page with fewer is the last.
pub const MARKER_PAGE_LEAVES: usize = 4096;
/// The most coin tree pages read to find the leaf one block added.
const MAX_POSITION_PAGES: u64 = 4;
/// The largest HTTP head read.
const MAX_HEAD_BYTES: usize = 16 * 1024;
/// The coin tree's kind, as `ghost_` calls name it.
const COIN_KIND: &str = "coin";
/// The spend marker list's kind.
const MARKER_KIND: &str = "coin-markers";
/// The one coin tree.
const TREE_INDEX: &str = "0x0";
/// Where the fingerprint sits in the commit data: after the 2-byte version.
const FINGERPRINT_AT: usize = 2;
/// The leaf position of a transaction that added no leaf the check can use.
const NO_POSITION: u64 = u64::MAX;

/// The only trust anchor compiled in: ISRG Root X1 (SHA-256 of its DER
/// `96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6`).
pub const ISRG_ROOT_X1_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
";

/// The compiled-in trust anchor, as DER.
pub fn isrg_root_x1() -> CertificateDer<'static> {
    // A test checks this text's fingerprint: it always reads.
    CertificateDer::from_pem_slice(ISRG_ROOT_X1_PEM.as_bytes()).unwrap_or_else(|_| panic!("the compiled-in root"))
}

/// Where a node is: its name in the node list, its host, port and JSON-RPC
/// path, and whether it is reached over TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeAddress {
    /// The node's name; the chain check counts nodes by it.
    pub name: String,
    /// The host name its certificate must carry (or, without TLS, a
    /// loopback address).
    pub host: String,
    /// Its port.
    pub port: u16,
    /// The JSON-RPC path.
    pub path: String,
    /// Whether TLS is used: always, except for a loopback test node.
    pub tls: bool,
}

impl NodeAddress {
    /// The address of a release node list entry: HTTPS.
    pub fn from_entry(entry: &NodeEntry) -> NodeAddress {
        NodeAddress {
            name: entry.name.clone(),
            host: entry.host.clone(),
            port: entry.port,
            path: entry.path.clone(),
            tls: true,
        }
    }

    /// The node at `url`, named `name`: `https://` and any host, or
    /// `http://` and a loopback address only (a development convenience).
    pub fn from_url(name: &str, url: &str) -> Result<NodeAddress, String> {
        let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(format!("{url}: a node URL starts with https:// (or http:// to a loopback address)"));
        };
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, "/"),
        };
        if path.contains(['?', '#', ' ']) || !path.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(format!("{url}: the path is not a plain path"));
        }
        let (host, port) = split_authority(authority).ok_or_else(|| format!("{url}: no host and port"))?;
        let port = match port {
            Some(port) => port.parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(|| format!("{url}: a bad port"))?,
            None if tls => 443,
            None => 80,
        };
        if host.is_empty() || !host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':')) {
            return Err(format!("{url}: a bad host"));
        }
        if !tls && !host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()) {
            return Err(format!("{url}: plain http:// only to a loopback address; use https://"));
        }
        Ok(NodeAddress { name: name.to_owned(), host: host.to_owned(), port, path: path.to_owned(), tls })
    }
}

/// `host[:port]` or `[v6]:port`.
fn split_authority(authority: &str) -> Option<(&str, Option<&str>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        return match after {
            "" => Some((host, None)),
            _ => Some((host, Some(after.strip_prefix(':')?))),
        };
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host, Some(port))),
        None => Some((authority, None)),
    }
}

/// A stream to a node, as a [`NodeTransport`] opens it.
pub trait NodeStream: Read + Write + Send {
    /// Bounds each later read and write to `timeout`.
    fn set_timeouts(&mut self, timeout: Duration) -> io::Result<()>;
}

impl NodeStream for TcpStream {
    fn set_timeouts(&mut self, timeout: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(timeout))?;
        self.set_write_timeout(Some(timeout))
    }
}

#[cfg(feature = "nitro")]
impl NodeStream for vsock::VsockStream {
    fn set_timeouts(&mut self, timeout: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(timeout))?;
        self.set_write_timeout(Some(timeout))
    }
}

/// How the bytes reach a node: one stream per exchange.
pub trait NodeTransport: Send + Sync {
    /// Opens a stream to `address`, by `deadline`.
    fn connect(&self, address: &NodeAddress, deadline: Instant) -> io::Result<Box<dyn NodeStream>>;
}

/// A TCP connection to the node's host and port (the test server).
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpTransport;

impl NodeTransport for TcpTransport {
    fn connect(&self, address: &NodeAddress, deadline: Instant) -> io::Result<Box<dyn NodeStream>> {
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
        for addr in (address.host.as_str(), address.port).to_socket_addrs()? {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline"));
            }
            match TcpStream::connect_timeout(&addr, left) {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    return Ok(Box::new(stream));
                }
                Err(error) => last = error,
            }
        }
        Err(last)
    }
}

/// A vsock stream to the parent instance on one port, which the host's
/// outbound proxy carries to one node (the enclave).
#[cfg(feature = "nitro")]
#[derive(Debug, Clone, Copy)]
pub struct VsockTransport {
    /// The parent's context ID (3 from inside an enclave).
    pub cid: u32,
    /// The host's port for this node.
    pub port: u32,
}

#[cfg(feature = "nitro")]
impl NodeTransport for VsockTransport {
    fn connect(&self, _address: &NodeAddress, _deadline: Instant) -> io::Result<Box<dyn NodeStream>> {
        Ok(Box::new(vsock::VsockStream::connect_with_cid_port(self.cid, self.port)?))
    }
}

/// A node's bounds: the reply size, the deadline of one exchange and the
/// scan's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcLimits {
    /// The largest reply body.
    pub max_reply_bytes: usize,
    /// One exchange's deadline.
    pub deadline: Duration,
    /// The most blocks one scan call reads.
    pub blocks_per_call: u64,
    /// How deep a block must be for what it holds to be kept.
    pub settled_depth: u64,
}

impl Default for RpcLimits {
    fn default() -> RpcLimits {
        RpcLimits {
            max_reply_bytes: MAX_REPLY_BYTES,
            deadline: CALL_DEADLINE,
            blocks_per_call: BLOCKS_PER_CALL,
            settled_depth: SETTLED_DEPTH,
        }
    }
}

/// A transaction to the coin commit entry found by the scan, with what
/// finding its leaf needs.
#[derive(Clone)]
struct Found {
    receipt: VanishReceipt,
    /// Its block's parent: the coin tree before its block.
    parent: [u8; 32],
    /// Whether `receipt.leaf_position` is final.
    placed: bool,
}

/// What the scan of one node has read: shared by every clone of the node.
#[derive(Default)]
struct Scan {
    /// Block 0's hash, once read.
    genesis: Option<[u8; 32]>,
    /// The first block not read yet.
    next: u64,
    /// The hash of block `next - 1`.
    last_hash: [u8; 32],
    /// The transactions to the coin commit entry of the settled blocks, by
    /// fingerprint, in chain order.
    settled: HashMap<[u8; 32], Vec<Found>>,
}

/// A Ghost node over JSON-RPC (see the module notes). Clones share the
/// scan's memory; each clone keeps the tip it last read, which its scan
/// reads up to.
pub struct RpcNode {
    address: Arc<NodeAddress>,
    transport: Arc<dyn NodeTransport>,
    tls: Option<Arc<ClientConfig>>,
    limits: RpcLimits,
    scan: Arc<Mutex<Scan>>,
    anchor: Mutex<Option<BlockRef>>,
}

impl Clone for RpcNode {
    fn clone(&self) -> RpcNode {
        RpcNode {
            address: Arc::clone(&self.address),
            transport: Arc::clone(&self.transport),
            tls: self.tls.clone(),
            limits: self.limits,
            scan: Arc::clone(&self.scan),
            anchor: Mutex::new(None),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl RpcNode {
    /// The node at `address` over `transport`, trusting only the compiled-in
    /// ISRG Root X1.
    pub fn new(address: NodeAddress, transport: Arc<dyn NodeTransport>) -> Result<RpcNode, String> {
        RpcNode::with_roots(address, transport, vec![isrg_root_x1()])
    }

    /// The node at `address` over `transport`, trusting only `roots` (tests
    /// hand in their own).
    pub fn with_roots(
        address: NodeAddress,
        transport: Arc<dyn NodeTransport>,
        roots: Vec<CertificateDer<'static>>,
    ) -> Result<RpcNode, String> {
        let tls = if address.tls {
            ServerName::try_from(address.host.clone()).map_err(|_| format!("{}: not a server name", address.host))?;
            Some(client_config(roots)?)
        } else {
            None
        };
        Ok(RpcNode {
            address: Arc::new(address),
            transport,
            tls,
            limits: RpcLimits::default(),
            scan: Arc::new(Mutex::new(Scan::default())),
            anchor: Mutex::new(None),
        })
    }

    /// The same node with other bounds (tests use shorter deadlines).
    pub fn with_limits(mut self, limits: RpcLimits) -> RpcNode {
        self.limits = limits;
        self
    }

    /// Where the node is.
    pub fn address(&self) -> &NodeAddress {
        &self.address
    }

    /// How far the scan has read: the first block not read yet (0 before
    /// the first call).
    pub fn scanned_to(&self) -> u64 {
        lock(&self.scan).next
    }

    /// One exchange: the JSON-RPC batch `calls`, and each call's result, in
    /// order.
    fn call(&self, calls: &[(&str, Value)]) -> Result<Vec<Value>, NodeError> {
        let batch: Vec<Value> = calls
            .iter()
            .enumerate()
            .map(|(id, (method, params))| json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))
            .collect();
        let body = self.exchange(Value::Array(batch).to_string().as_bytes())?;
        let reply: Value = serde_json::from_slice(&body).map_err(|_| NodeError::Inconsistent("a reply is not JSON"))?;
        let Value::Array(answers) = reply else {
            return Err(NodeError::Inconsistent("a reply is not a batch"));
        };
        if answers.len() != calls.len() {
            return Err(NodeError::Inconsistent("a reply does not answer every call"));
        }
        let mut results: Vec<Option<Value>> = vec![None; calls.len()];
        for answer in answers {
            let Value::Object(mut fields) = answer else {
                return Err(NodeError::Inconsistent("an answer is not an object"));
            };
            let id = fields
                .get("id")
                .and_then(Value::as_u64)
                .and_then(|id| usize::try_from(id).ok())
                .filter(|id| *id < calls.len())
                .ok_or(NodeError::Inconsistent("an answer has no call's id"))?;
            if fields.contains_key("error") {
                return Err(NodeError::Inconsistent("the node refused a call"));
            }
            let result = fields.remove("result").ok_or(NodeError::Inconsistent("an answer has no result"))?;
            if results[id].replace(result).is_some() {
                return Err(NodeError::Inconsistent("a call is answered twice"));
            }
        }
        results.into_iter().map(|r| r.ok_or(NodeError::Inconsistent("a call is not answered"))).collect()
    }

    /// One HTTP exchange: posts `body`, returns the reply's body.
    fn exchange(&self, body: &[u8]) -> Result<Vec<u8>, NodeError> {
        let deadline = Instant::now() + self.limits.deadline;
        let stream = self.transport.connect(&self.address, deadline).map_err(|_| NodeError::Unreachable)?;
        let mut io = DeadlineStream { inner: stream, deadline };
        let host = if self.address.host.contains(':') {
            format!("[{}]", self.address.host)
        } else {
            self.address.host.clone()
        };
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.address.path,
            host,
            body.len()
        );
        let request = [head.as_bytes(), body].concat();
        let limit = MAX_HEAD_BYTES + 2 * self.limits.max_reply_bytes;
        let raw = match &self.tls {
            Some(config) => {
                let name = ServerName::try_from(self.address.host.clone()).map_err(|_| NodeError::Unreachable)?;
                let mut connection = ClientConnection::new(Arc::clone(config), name).map_err(|_| NodeError::Unreachable)?;
                let mut tls = rustls::Stream::new(&mut connection, &mut io);
                tls.write_all(&request).map_err(|_| NodeError::Unreachable)?;
                tls.flush().map_err(|_| NodeError::Unreachable)?;
                read_to_end(&mut tls, limit)?
            }
            None => {
                io.write_all(&request).map_err(|_| NodeError::Unreachable)?;
                io.flush().map_err(|_| NodeError::Unreachable)?;
                read_to_end(&mut io, limit)?
            }
        };
        reply_body(&raw, self.limits.max_reply_bytes)
    }

    // ---------------------------------------------------------------------
    // Reading the chain

    fn block_header(&self, value: &Value) -> Result<Header, NodeError> {
        Header::parse(value)
    }

    fn latest(&self) -> Result<BlockRef, NodeError> {
        let [block] = self.calls::<1>(&[("eth_getBlockByNumber", json!(["latest", false]))])?;
        let header = self.block_header(&block)?;
        Ok(BlockRef { height: header.height, hash: header.hash })
    }

    fn calls<const N: usize>(&self, calls: &[(&str, Value); N]) -> Result<[Value; N], NodeError> {
        self.call(calls)?.try_into().map_err(|_| NodeError::Inconsistent("a reply does not answer every call"))
    }

    /// Reads blocks `from..from + count`: their headers and receipts, and
    /// the transactions to the coin commit entry they hold.
    fn read_blocks(&self, from: u64, count: u64) -> Result<Vec<ScannedBlock>, NodeError> {
        let calls: Vec<(&str, Value)> = (from..from + count)
            .flat_map(|height| {
                [
                    ("eth_getBlockByNumber", json!([quantity(height), false])),
                    ("eth_getBlockReceipts", json!([quantity(height)])),
                ]
            })
            .collect();
        let answers = self.call(&calls)?;
        let mut blocks = Vec::with_capacity(count as usize);
        for (i, pair) in answers.chunks(2).enumerate() {
            let height = from + i as u64;
            let header = self.block_header(&pair[0])?;
            if header.height != height {
                return Err(NodeError::Inconsistent("a block is not at the height asked for"));
            }
            let hashes = header.transaction_hashes.clone().ok_or(NodeError::Inconsistent("a block lists no transactions"))?;
            let receipts = parse_receipts(&pair[1], &header)?;
            if receipts.len() != hashes.len() || receipts.iter().zip(&hashes).any(|(r, h)| r.transaction_hash != *h) {
                return Err(NodeError::Inconsistent("a block's receipts are not its transactions'"));
            }
            // Only a block that may hold a transaction to the coin commit
            // entry is read again with its transactions.
            let wanted = receipts.iter().any(|r| r.to.is_none_or(|to| to == Some(COMMIT_ENTRY)));
            let found = if wanted { self.read_vanishes(&header, &receipts)? } else { Vec::new() };
            blocks.push(ScannedBlock { height, hash: header.hash, parent: header.parent, found });
        }
        Ok(blocks)
    }

    /// The transactions to the coin commit entry of a block, read with its
    /// transactions.
    fn read_vanishes(&self, header: &Header, receipts: &[Receipt]) -> Result<Vec<Found>, NodeError> {
        let [block] = self.calls::<1>(&[("eth_getBlockByNumber", json!([quantity(header.height), true]))])?;
        let full = Header::parse(&block)?;
        if full.hash != header.hash {
            return Err(NodeError::Inconsistent("a block changed while it was read"));
        }
        let transactions = block
            .get("transactions")
            .and_then(Value::as_array)
            .ok_or(NodeError::Inconsistent("a block lists no transactions"))?;
        if transactions.len() != receipts.len() {
            return Err(NodeError::Inconsistent("a block's receipts are not its transactions'"));
        }
        let at = BlockRef { height: header.height, hash: header.hash };
        let mut found = Vec::new();
        for (tx, receipt) in transactions.iter().zip(receipts) {
            if hash32(tx.get("hash"))? != receipt.transaction_hash {
                return Err(NodeError::Inconsistent("a block's receipts are not its transactions'"));
            }
            let to = match tx.get("to") {
                None | Some(Value::Null) => None,
                Some(value) => Some(address(value)?),
            };
            if to != Some(COMMIT_ENTRY) {
                continue;
            }
            let data = bytes(tx.get("input"))?;
            if data.len() < FINGERPRINT_AT + 32 {
                continue;
            }
            let receipt = VanishReceipt {
                transaction_hash: receipt.transaction_hash,
                chain_id: number(tx.get("chainId"))?,
                to: COMMIT_ENTRY,
                value_wei: amount(tx.get("value"))?,
                data,
                outcome: receipt.outcome,
                block: at,
                leaf_position: NO_POSITION,
            };
            found.push(Found { receipt, parent: header.parent, placed: false });
        }
        Ok(found)
    }

    /// Block 0's hash.
    fn genesis(&self) -> Result<[u8; 32], NodeError> {
        let [block] = self.calls::<1>(&[("eth_getBlockByNumber", json!([quantity(0), false]))])?;
        let header = Header::parse(&block)?;
        if header.height != 0 {
            return Err(NodeError::Inconsistent("block 0 is not at height 0"));
        }
        Ok(header.hash)
    }

    /// Scans up to `tip`: the transactions to the coin commit entry carrying
    /// `fingerprint`, settled and recent, in chain order.
    fn scan(&self, tip: &BlockRef, fingerprint: &[u8; 32]) -> Result<Vec<Found>, NodeError> {
        let mut scan = lock(&self.scan);
        if scan.genesis.is_none() {
            let genesis = self.genesis()?;
            *scan = Scan { genesis: Some(genesis), next: 1, last_hash: genesis, settled: HashMap::new() };
        }
        let mut budget = self.limits.blocks_per_call;
        // The settled blocks: more than `settled_depth` below the tip.
        let settled_top = tip.height.checked_sub(self.limits.settled_depth + 1);
        while let Some(top) = settled_top.filter(|top| scan.next <= *top) {
            if budget == 0 {
                // Not caught up yet: the next call carries on from here.
                return Err(NodeError::Unreachable);
            }
            let count = BLOCKS_PER_REQUEST.min(budget).min(top + 1 - scan.next);
            let blocks = self.read_blocks(scan.next, count)?;
            budget -= count;
            for block in blocks {
                if block.parent != scan.last_hash {
                    // The chain changed below the settled depth: start over.
                    *scan = Scan::default();
                    return Err(NodeError::Inconsistent("the chain changed below the settled depth"));
                }
                for found in block.found {
                    let key = fingerprint_of(&found.receipt.data);
                    scan.settled.entry(key).or_default().push(found);
                }
                scan.next = block.height + 1;
                scan.last_hash = block.hash;
            }
        }
        // The recent blocks, read again on every call.
        let mut recent = Vec::new();
        if scan.next <= tip.height {
            let total = tip.height + 1 - scan.next;
            if total > budget {
                return Err(NodeError::Unreachable);
            }
            let mut parent = scan.last_hash;
            let mut height = scan.next;
            while height <= tip.height {
                let count = BLOCKS_PER_REQUEST.min(tip.height + 1 - height);
                for block in self.read_blocks(height, count)? {
                    if block.parent != parent {
                        return Err(NodeError::Inconsistent("the chain moved while it was read"));
                    }
                    parent = block.hash;
                    recent.extend(block.found);
                }
                height += count;
            }
            if parent != tip.hash {
                return Err(NodeError::Inconsistent("the chain moved while it was read"));
            }
        } else if scan.next == tip.height + 1 && scan.last_hash != tip.hash {
            return Err(NodeError::Inconsistent("the tip is not the block the scan read"));
        } else if scan.next > tip.height + 1 {
            return Err(NodeError::Inconsistent("the tip is below what the scan read"));
        }

        // Place each found transaction's leaf; the settled ones are kept placed.
        if let Some(found) = scan.settled.get_mut(fingerprint) {
            for item in found.iter_mut().filter(|f| !f.placed) {
                item.receipt.leaf_position = self.leaf_position(&item.receipt, &item.parent)?;
                item.placed = true;
            }
        }
        let mut matched: Vec<Found> = scan.settled.get(fingerprint).cloned().unwrap_or_default();
        for mut item in recent.into_iter().filter(|f| fingerprint_of(&f.receipt.data) == *fingerprint) {
            item.receipt.leaf_position = self.leaf_position(&item.receipt, &item.parent)?;
            matched.push(item);
        }
        Ok(matched)
    }

    /// The coin tree position of the leaf `receipt` added, from the leaves
    /// its block added: those of the tree as of its block that the tree as
    /// of its parent does not hold. [`NO_POSITION`] for a transaction that
    /// failed or whose commit data the wallet core does not read.
    fn leaf_position(&self, receipt: &VanishReceipt, parent: &[u8; 32]) -> Result<u64, NodeError> {
        if receipt.outcome != TxOutcome::Succeeded {
            return Ok(NO_POSITION);
        }
        let Ok(leaf) = commit_leaf(receipt.data.clone(), receipt.value_wei.to_string()) else {
            return Ok(NO_POSITION);
        };
        let before = self.leaf_count(parent)?;
        let after = self.leaf_count(&receipt.block.hash)?;
        if after <= before {
            return Err(NodeError::Inconsistent("a Vanish's block added no leaf"));
        }
        let first_page = before / PAGE_LEAVES as u64;
        let last_page = (after - 1) / PAGE_LEAVES as u64;
        if last_page - first_page >= MAX_POSITION_PAGES {
            return Err(NodeError::Unreachable);
        }
        let pages: Vec<u64> = (first_page..=last_page).collect();
        for page in self.page_set(&receipt.block.hash, &pages)? {
            for (index, held) in page.leaves.iter().enumerate() {
                let position = u64::from(page.page) * PAGE_LEAVES as u64 + index as u64;
                if (before..after).contains(&position) && held.as_slice() == leaf.commitment.as_slice() {
                    return Ok(position);
                }
            }
        }
        Err(NodeError::Inconsistent("a Vanish's leaf is not among the leaves its block added"))
    }

    /// How many leaves the coin tree holds as of block `anchor`.
    fn leaf_count(&self, anchor: &[u8; 32]) -> Result<u64, NodeError> {
        let [roots] = self.calls::<1>(&[("ghost_getPageRoots", json!([COIN_KIND, TREE_INDEX, hex0x(anchor)]))])?;
        let roots = roots.as_array().ok_or(NodeError::Inconsistent("the page roots are not a list"))?;
        let Some(last) = (roots.len() as u64).checked_sub(1) else { return Ok(0) };
        let page = self.page_set(anchor, &[last])?.pop().ok_or(NodeError::Inconsistent("a page set is empty"))?;
        Ok(last * PAGE_LEAVES as u64 + page.leaves.len() as u64)
    }

    /// Pages `numbers` of the coin tree as of block `anchor`, in one call.
    fn page_set(&self, anchor: &[u8; 32], numbers: &[u64]) -> Result<Vec<CoinPage>, NodeError> {
        let wanted: Vec<String> = numbers.iter().map(|n| quantity(*n)).collect();
        let [set] = self.calls::<1>(&[("ghost_getPageSet", json!([COIN_KIND, TREE_INDEX, wanted, hex0x(anchor)]))])?;
        let set = set.as_array().ok_or(NodeError::Inconsistent("a page set is not a list"))?;
        if set.len() != numbers.len() {
            return Err(NodeError::Inconsistent("a page set is not the pages asked for"));
        }
        set.iter().zip(numbers).map(|(page, number)| parse_page(page, *number)).collect()
    }
}

/// A block as the scan read it.
struct ScannedBlock {
    height: u64,
    hash: [u8; 32],
    parent: [u8; 32],
    found: Vec<Found>,
}

/// The header fields the node is read for.
struct Header {
    height: u64,
    hash: [u8; 32],
    parent: [u8; 32],
    coin_tree_root: Option<[u8; 32]>,
    transaction_hashes: Option<Vec<[u8; 32]>>,
}

impl Header {
    fn parse(value: &Value) -> Result<Header, NodeError> {
        if !value.is_object() {
            return Err(NodeError::Inconsistent("a block is missing"));
        }
        let height = number(value.get("number"))?;
        let hash = hash32(value.get("hash"))?;
        let parent = if height == 0 { [0u8; 32] } else { hash32(value.get("parentHash"))? };
        let coin_tree_root = match value.get("coinTreeRoot") {
            None | Some(Value::Null) => None,
            Some(root) => Some(hash32(Some(root))?),
        };
        let transaction_hashes = match value.get("transactions").and_then(Value::as_array) {
            None => None,
            Some(list) => Some(
                list.iter()
                    .map(|tx| match tx {
                        Value::String(_) => hash32(Some(tx)),
                        _ => hash32(tx.get("hash")),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        };
        Ok(Header { height, hash, parent, coin_tree_root, transaction_hashes })
    }
}

/// A receipt's fields the scan reads. `to` is `None` when the receipt does
/// not say, `Some(None)` for no address.
struct Receipt {
    transaction_hash: [u8; 32],
    outcome: TxOutcome,
    to: Option<Option<[u8; 20]>>,
}

fn parse_receipts(value: &Value, header: &Header) -> Result<Vec<Receipt>, NodeError> {
    let list = value.as_array().ok_or(NodeError::Inconsistent("a block's receipts are missing"))?;
    list.iter()
        .map(|receipt| {
            if hash32(receipt.get("blockHash"))? != header.hash || number(receipt.get("blockNumber"))? != header.height {
                return Err(NodeError::Inconsistent("a receipt is not of its block"));
            }
            let outcome = match number(receipt.get("status"))? {
                1 => TxOutcome::Succeeded,
                0 => TxOutcome::Failed,
                _ => return Err(NodeError::Inconsistent("a receipt's status is neither 0 nor 1")),
            };
            let to = match receipt.get("to") {
                None => None,
                Some(Value::Null) => Some(None),
                Some(to) => Some(Some(address(to)?)),
            };
            Ok(Receipt { transaction_hash: hash32(receipt.get("transactionHash"))?, outcome, to })
        })
        .collect()
}

fn parse_page(value: &Value, number_asked: u64) -> Result<CoinPage, NodeError> {
    let bad = NodeError::Inconsistent("a coin tree page is not the page asked for");
    if value.get("kind").and_then(Value::as_str) != Some(COIN_KIND) || number(value.get("treeIndex"))? != 0 {
        return Err(bad);
    }
    if number(value.get("page"))? != number_asked {
        return Err(bad);
    }
    let entries = value.get("entries").and_then(Value::as_array).ok_or(bad)?;
    let filled = number(value.get("filled"))?;
    if filled != entries.len() as u64 || entries.len() > PAGE_LEAVES {
        return Err(NodeError::Inconsistent("a coin tree page is not laid out as one"));
    }
    let leaves =
        entries.iter().map(|entry| hash32(entry.get("leaf")).map(|leaf| leaf.to_vec())).collect::<Result<Vec<_>, _>>()?;
    let page = u32::try_from(number_asked).map_err(|_| NodeError::Inconsistent("a page number is past the tree"))?;
    Ok(CoinPage { page, leaves })
}

fn fingerprint_of(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&data[FINGERPRINT_AT..FINGERPRINT_AT + 32]);
    out
}

impl ChainNode for RpcNode {
    fn name(&self) -> &str {
        &self.address.name
    }

    fn network(&self) -> Result<Network, NodeError> {
        let [chain_id, block] = self.calls::<2>(&[
            ("eth_chainId", json!([])),
            ("eth_getBlockByNumber", json!([quantity(0), false])),
        ])?;
        let header = Header::parse(&block)?;
        if header.height != 0 {
            return Err(NodeError::Inconsistent("block 0 is not at height 0"));
        }
        Ok(Network { chain_id: number(Some(&chain_id))?, genesis: header.hash })
    }

    fn tip(&self) -> Result<BlockRef, NodeError> {
        let tip = self.latest()?;
        *lock(&self.anchor) = Some(tip);
        Ok(tip)
    }

    fn vanish_receipts(&self, fingerprint: &[u8; 32]) -> Result<Vec<VanishReceipt>, NodeError> {
        let anchor = *lock(&self.anchor);
        let tip = match anchor {
            Some(tip) => tip,
            None => self.tip()?,
        };
        Ok(self.scan(&tip, fingerprint)?.into_iter().map(|found| found.receipt).collect())
    }

    fn coin_tree(&self, anchor: &BlockRef, page: u32) -> Result<CoinTreeAt, NodeError> {
        let [block, roots, set] = self.calls::<3>(&[
            ("eth_getBlockByNumber", json!([quantity(anchor.height), false])),
            ("ghost_getPageRoots", json!([COIN_KIND, TREE_INDEX, hex0x(&anchor.hash)])),
            ("ghost_getPageSet", json!([COIN_KIND, TREE_INDEX, [quantity(u64::from(page))], hex0x(&anchor.hash)])),
        ])?;
        let header = Header::parse(&block)?;
        if header.hash != anchor.hash || header.height != anchor.height {
            return Err(NodeError::Inconsistent("the anchor block is not the one asked for"));
        }
        let coin_tree_root = header.coin_tree_root.ok_or(NodeError::Inconsistent("a block has no coin tree root"))?;
        let page_roots = roots
            .as_array()
            .ok_or(NodeError::Inconsistent("the page roots are not a list"))?
            .iter()
            .map(|root| hash32(Some(root)).map(|root| root.to_vec()))
            .collect::<Result<Vec<_>, _>>()?;
        let [held] = set
            .as_array()
            .map(Vec::as_slice)
            .ok_or(NodeError::Inconsistent("a page set is not a list"))?
        else {
            return Err(NodeError::Inconsistent("a page set is not the pages asked for"));
        };
        let page = parse_page(held, u64::from(page))?;
        Ok(CoinTreeAt { block: *anchor, coin_tree_root, page_roots, page })
    }

    fn marker_spent(&self, marker: &[u8; 32], anchor: &BlockRef) -> Result<bool, NodeError> {
        for page in 0..MAX_MARKER_PAGES {
            let [answer] = self.calls::<1>(&[(
                "ghost_getTreePage",
                json!([MARKER_KIND, TREE_INDEX, quantity(page), hex0x(&anchor.hash)]),
            )])?;
            let count = number(answer.get("count"))?;
            let markers = answer
                .get("markers")
                .and_then(Value::as_array)
                .ok_or(NodeError::Inconsistent("a marker page is not laid out as one"))?;
            if count != markers.len() as u64 || markers.len() > MARKER_PAGE_LEAVES {
                return Err(NodeError::Inconsistent("a marker page is not laid out as one"));
            }
            for held in markers {
                if hash32(Some(held))? == *marker {
                    return Ok(true);
                }
            }
            if markers.len() < MARKER_PAGE_LEAVES {
                return Ok(false);
            }
        }
        Err(NodeError::Unreachable)
    }
}

/// The TLS 1.3 client configuration: the `ring` provider, rustls's own
/// `WebPkiServerVerifier` over `roots` alone, no resumption.
fn client_config(roots: Vec<CertificateDer<'static>>) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut store = RootCertStore::empty();
    for root in roots {
        store.add(root).map_err(|e| format!("a trust anchor: {e}"))?;
    }
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(store), Arc::clone(&provider))
        .build()
        .map_err(|e| format!("the certificate check: {e}"))?;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS: {e}"))?
        .with_webpki_verifier(verifier)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// A stream whose every read and write waits at most until `deadline`.
struct DeadlineStream {
    inner: Box<dyn NodeStream>,
    deadline: Instant,
}

impl DeadlineStream {
    fn arm(&mut self) -> io::Result<()> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline"));
        }
        self.inner.set_timeouts(left)
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.arm()?;
        self.inner.read(buf)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.arm()?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.arm()?;
        self.inner.flush()
    }
}

/// Reads until the stream ends, at most `limit` bytes. A TLS stream that
/// ends without its close message ends there too: the reply's own length
/// is checked afterwards.
fn read_to_end(stream: &mut dyn Read, limit: usize) -> Result<Vec<u8>, NodeError> {
    let mut raw = Vec::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(raw),
            Ok(n) => {
                if raw.len() + n > limit {
                    return Err(NodeError::Unreachable);
                }
                raw.extend_from_slice(&buffer[..n]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof && !raw.is_empty() => return Ok(raw),
            Err(_) => return Err(NodeError::Unreachable),
        }
    }
}

/// The body of a whole HTTP/1.1 reply: status 200, at most `limit` bytes,
/// framed by its length, chunked, or by the end of the connection.
fn reply_body(raw: &[u8], limit: usize) -> Result<Vec<u8>, NodeError> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    let head = match response.parse(raw) {
        Ok(httparse::Status::Complete(head)) => head,
        Ok(httparse::Status::Partial) => return Err(NodeError::Unreachable),
        Err(_) => return Err(NodeError::Inconsistent("a reply is not HTTP")),
    };
    if head > MAX_HEAD_BYTES {
        return Err(NodeError::Unreachable);
    }
    if response.code != Some(200) {
        return Err(NodeError::Unreachable);
    }
    let header = |name: &str| {
        response
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| core::str::from_utf8(h.value).map(str::trim))
            .collect::<Vec<_>>()
    };
    let rest = &raw[head..];
    let chunked = header("transfer-encoding").iter().any(|v| v.is_ok_and(|v| v.eq_ignore_ascii_case("chunked")));
    let lengths = header("content-length");
    let body = if chunked {
        dechunk(rest, limit)?
    } else if let [length] = lengths.as_slice() {
        let length: usize = length
            .ok()
            .and_then(|l| l.parse().ok())
            .ok_or(NodeError::Inconsistent("a reply's length does not read"))?;
        if length > limit {
            return Err(NodeError::Unreachable);
        }
        if rest.len() < length {
            return Err(NodeError::Unreachable);
        }
        rest[..length].to_vec()
    } else if lengths.is_empty() {
        rest.to_vec()
    } else {
        return Err(NodeError::Inconsistent("a reply gives two lengths"));
    };
    if body.len() > limit {
        return Err(NodeError::Unreachable);
    }
    Ok(body)
}

/// A chunked body, whole.
fn dechunk(mut rest: &[u8], limit: usize) -> Result<Vec<u8>, NodeError> {
    let malformed = NodeError::Inconsistent("a chunked reply does not read");
    let mut body = Vec::new();
    loop {
        let end = rest.windows(2).position(|w| w == b"\r\n").ok_or(NodeError::Unreachable)?;
        let line = core::str::from_utf8(&rest[..end]).map_err(|_| malformed)?;
        let size = line.split(';').next().unwrap_or("").trim();
        if size.is_empty() || size.len() > 8 {
            return Err(malformed);
        }
        let size = usize::from_str_radix(size, 16).map_err(|_| malformed)?;
        rest = &rest[end + 2..];
        if size == 0 {
            return Ok(body);
        }
        if body.len() + size > limit {
            return Err(NodeError::Unreachable);
        }
        if rest.len() < size + 2 {
            return Err(NodeError::Unreachable);
        }
        if &rest[size..size + 2] != b"\r\n" {
            return Err(malformed);
        }
        body.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

fn quantity(value: u64) -> String {
    format!("{value:#x}")
}

fn hex0x(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + 2 * bytes.len());
    out.push_str("0x");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The hex digits of a `0x` string.
fn digits(value: Option<&Value>) -> Result<&str, NodeError> {
    let text = value.and_then(Value::as_str).ok_or(NodeError::Inconsistent("a field is missing"))?;
    let digits = text.strip_prefix("0x").ok_or(NodeError::Inconsistent("a field is not 0x hex"))?;
    if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(NodeError::Inconsistent("a field is not 0x hex"));
    }
    Ok(digits)
}

fn number(value: Option<&Value>) -> Result<u64, NodeError> {
    let digits = digits(value)?;
    let digits = digits.trim_start_matches('0');
    if digits.len() > 16 {
        return Err(NodeError::Inconsistent("a number is too large"));
    }
    if digits.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(digits, 16).map_err(|_| NodeError::Inconsistent("a number does not read"))
}

fn amount(value: Option<&Value>) -> Result<u128, NodeError> {
    let digits = digits(value)?;
    let digits = digits.trim_start_matches('0');
    if digits.len() > 32 {
        return Err(NodeError::Inconsistent("an amount is too large"));
    }
    if digits.is_empty() {
        return Ok(0);
    }
    u128::from_str_radix(digits, 16).map_err(|_| NodeError::Inconsistent("an amount does not read"))
}

fn bytes(value: Option<&Value>) -> Result<Vec<u8>, NodeError> {
    let digits = digits(value)?;
    if digits.len() % 2 != 0 {
        return Err(NodeError::Inconsistent("bytes are not whole"));
    }
    (0..digits.len() / 2)
        .map(|i| u8::from_str_radix(&digits[2 * i..2 * i + 2], 16).map_err(|_| NodeError::Inconsistent("bytes do not read")))
        .collect()
}

fn hash32(value: Option<&Value>) -> Result<[u8; 32], NodeError> {
    bytes(value)?.try_into().map_err(|_| NodeError::Inconsistent("a hash is not 32 bytes"))
}

fn address(value: &Value) -> Result<[u8; 20], NodeError> {
    bytes(Some(value))?.try_into().map_err(|_| NodeError::Inconsistent("an address is not 20 bytes"))
}
