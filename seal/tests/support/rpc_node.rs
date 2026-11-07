//! A fake Ghost node for `RpcNode`: a chain of blocks in memory and an
//! in-process JSON-RPC server over TLS 1.3 (rustls, a test root made with
//! rcgen) or plain HTTP, answering the calls the wallet makes
//! (`eth_chainId`, `eth_getBlockByNumber`, `eth_getBlockReceipts`,
//! `ghost_getPageRoots`, `ghost_getPageSet`, `ghost_getTreePage`). The test
//! can make it go down, answer slowly, too much, malformed or chunked, speak
//! only TLS 1.2, or serve another certificate, and it records every request
//! it got. Included by path by the tests that need it (feature `nitro`).
#![allow(dead_code)]

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ghost_seal::node_rpc::{NodeAddress, NodeStream, NodeTransport, RpcNode};
use ghost_seal::primitives::sha3_256;
use ghost_seal::{CoinQuery, Network};
use ghost_wallet_core::coin_tree::PAGE_LEAVES;
use ghost_wallet_core::vanish::COMMIT_ENTRY;
use ghost_wallet_core::{commit_leaf, page_root, tree_root_of_pages};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};

/// The fake network's chain id.
pub const CHAIN_ID: u64 = 6_777_972;

/// A transaction in a fake block.
#[derive(Clone, Debug)]
pub struct Tx {
    pub hash: [u8; 32],
    pub to: Option<[u8; 20]>,
    pub input: Vec<u8>,
    pub value: u128,
    pub chain_id: u64,
    pub success: bool,
}

/// A fake block: its transactions, and the coin tree and marker list sizes
/// after it.
#[derive(Clone, Debug)]
pub struct Block {
    pub hash: [u8; 32],
    pub parent: [u8; 32],
    pub txs: Vec<Tx>,
    pub leaves: usize,
    pub markers: usize,
}

/// A chain in memory.
#[derive(Clone, Debug)]
pub struct RpcChain {
    pub chain_id: u64,
    pub blocks: Vec<Block>,
    pub leaves: Vec<[u8; 32]>,
    pub markers: Vec<[u8; 32]>,
    /// Mixed into every new block's hash, so a reorganised chain has other
    /// blocks.
    pub salt: u64,
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn quantity(value: u128) -> String {
    format!("{value:#x}")
}

impl RpcChain {
    /// A chain of block 0 alone, whose hash comes from `genesis_label`.
    pub fn new(genesis_label: &str) -> RpcChain {
        let genesis = Block {
            hash: sha3_256(&[b"fake rpc genesis", genesis_label.as_bytes()]),
            parent: [0u8; 32],
            txs: Vec::new(),
            leaves: 0,
            markers: 0,
        };
        RpcChain { chain_id: CHAIN_ID, blocks: vec![genesis], leaves: Vec::new(), markers: Vec::new(), salt: 0 }
    }

    /// Its network.
    pub fn network(&self) -> Network {
        Network { chain_id: self.chain_id, genesis: self.blocks[0].hash }
    }

    pub fn height(&self) -> u64 {
        self.blocks.len() as u64 - 1
    }

    /// A new block holding `txs`; each successful transaction to the coin
    /// commit entry, and each one with no address, adds a leaf.
    fn push(&mut self, txs: Vec<Tx>, markers: Vec<[u8; 32]>) {
        for tx in &txs {
            if !tx.success {
                continue;
            }
            if tx.to == Some(COMMIT_ENTRY) {
                let leaf = commit_leaf(tx.input.clone(), tx.value.to_string()).expect("commit data the core reads");
                self.leaves.push(leaf.commitment.try_into().unwrap());
            } else if tx.to.is_none() {
                // A private transaction's remainder note.
                self.leaves.push(sha3_256(&[b"remainder note", &tx.hash]));
            }
        }
        self.markers.extend(markers);
        let parent = self.blocks.last().unwrap().hash;
        let height = self.blocks.len() as u64;
        let tx_hashes: Vec<u8> = txs.iter().flat_map(|tx| tx.hash).collect();
        let hash = sha3_256(&[b"fake rpc block", &parent, &height.to_be_bytes(), &self.salt.to_be_bytes(), &tx_hashes]);
        self.blocks.push(Block { hash, parent, txs, leaves: self.leaves.len(), markers: self.markers.len() });
    }

    /// `count` empty blocks.
    pub fn mine(&mut self, count: u64) {
        for _ in 0..count {
            self.push(Vec::new(), Vec::new());
        }
    }

    fn tx(&self, to: Option<[u8; 20]>, input: &[u8], value: u128, chain_id: u64, success: bool) -> Tx {
        let n = self.blocks.len() as u64;
        Tx {
            hash: sha3_256(&[b"fake rpc tx", input, &value.to_be_bytes(), &n.to_be_bytes(), &self.salt.to_be_bytes()]),
            to,
            input: input.to_vec(),
            value,
            chain_id,
            success,
        }
    }

    /// A block with a transaction to the coin commit entry.
    pub fn send(&mut self, data: &[u8], value: u128, chain_id: u64, success: bool) {
        let tx = self.tx(Some(COMMIT_ENTRY), data, value, chain_id, success);
        self.push(vec![tx], Vec::new());
    }

    /// A block with a successful Vanish of `data` paying `value`.
    pub fn vanish(&mut self, data: &[u8], value: u128) {
        let chain_id = self.chain_id;
        self.send(data, value, chain_id, true);
    }

    /// A block crowded with other coins' leaves, a private transaction and a
    /// plain send, then `data`'s Vanish, then more of them: its leaf is not
    /// the block's only one.
    pub fn vanish_among_others(&mut self, data: &[u8], value: u128, label: u8) {
        let chain_id = self.chain_id;
        let mut txs = Vec::new();
        for i in 0..3u8 {
            let other = crate::support::nodes::test_commit_data(label.wrapping_mul(7).wrapping_add(100 + i));
            txs.push(self.tx(Some(COMMIT_ENTRY), &other, 1_000 + u128::from(i), chain_id, true));
        }
        txs.push(self.tx(None, &[0x50, label], 0, chain_id, true));
        txs.push(self.tx(Some([0x11; 20]), &[], 5, chain_id, true));
        txs.push(self.tx(Some(COMMIT_ENTRY), data, value, chain_id, true));
        let last = crate::support::nodes::test_commit_data(label.wrapping_mul(7).wrapping_add(110));
        txs.push(self.tx(Some(COMMIT_ENTRY), &last, 77, chain_id, true));
        self.push(txs, Vec::new());
    }

    /// The exact Vanish of `coin`, then blocks until it is `depth` deep.
    pub fn pay(&mut self, coin: &CoinQuery, depth: u64) {
        self.vanish(&coin.commit_data, coin.amount_wei);
        self.mine(depth.saturating_sub(1));
    }

    /// Uses spend marker `marker` in a new block.
    pub fn spend(&mut self, marker: [u8; 32]) {
        self.push(Vec::new(), vec![marker]);
    }

    /// Other spend markers, `count` of them, in one block.
    pub fn spend_others(&mut self, count: usize) {
        let markers = (0..count).map(|i| sha3_256(&[b"other marker", &(i as u64).to_be_bytes()])).collect();
        self.push(Vec::new(), markers);
    }

    /// Drops the top `depth` blocks (and what they added): the start of a
    /// reorganisation. Blocks pushed afterwards have other hashes.
    pub fn unwind(&mut self, depth: u64) {
        let keep = self.blocks.len() - depth as usize;
        self.blocks.truncate(keep);
        let last = self.blocks.last().unwrap();
        self.leaves.truncate(last.leaves);
        self.markers.truncate(last.markers);
        self.salt += 1;
    }

    fn block_by_hash(&self, hash: &[u8; 32]) -> Option<&Block> {
        self.blocks.iter().find(|b| b.hash == *hash)
    }

    fn roots(&self, count: usize) -> Vec<[u8; 32]> {
        self.leaves[..count].chunks(PAGE_LEAVES).map(page_root).collect()
    }

    fn block_json(&self, height: u64, full: bool) -> Value {
        let Some(block) = self.blocks.get(height as usize) else { return Value::Null };
        let transactions: Vec<Value> = block
            .txs
            .iter()
            .map(|tx| {
                if full {
                    json!({
                        "hash": hex0x(&tx.hash),
                        "to": tx.to.map(|to| hex0x(&to)),
                        "input": hex0x(&tx.input),
                        "value": quantity(tx.value),
                        "chainId": quantity(u128::from(tx.chain_id)),
                    })
                } else {
                    json!(hex0x(&tx.hash))
                }
            })
            .collect();
        json!({
            "number": quantity(u128::from(height)),
            "hash": hex0x(&block.hash),
            "parentHash": hex0x(&block.parent),
            "coinTreeRoot": hex0x(&tree_root_of_pages(&self.roots(block.leaves))),
            "transactions": transactions,
        })
    }

    fn receipts_json(&self, height: u64, with_to: bool) -> Value {
        let Some(block) = self.blocks.get(height as usize) else { return Value::Null };
        Value::Array(
            block
                .txs
                .iter()
                .map(|tx| {
                    let mut receipt = json!({
                        "transactionHash": hex0x(&tx.hash),
                        "status": if tx.success { "0x1" } else { "0x0" },
                        "blockHash": hex0x(&block.hash),
                        "blockNumber": quantity(u128::from(height)),
                    });
                    if with_to {
                        receipt["to"] = json!(tx.to.map(|to| hex0x(&to)));
                    }
                    receipt
                })
                .collect(),
        )
    }

    /// The answer to one call, or the error message.
    fn answer(&self, method: &str, params: &Value, behaviour: &Behaviour) -> Result<Value, String> {
        let number = |value: &Value| -> Result<u64, String> {
            let text = value.as_str().ok_or("not a quantity")?;
            u64::from_str_radix(text.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
        };
        let anchor = |value: &Value| -> Result<&Block, String> {
            let text = value.as_str().ok_or("not a hash")?;
            let bytes = crate::support::unhex(text.trim_start_matches("0x"));
            let hash: [u8; 32] = bytes.try_into().map_err(|_| "not 32 bytes")?;
            self.block_by_hash(&hash).ok_or_else(|| "unknown block".to_owned())
        };
        match method {
            "eth_chainId" => Ok(json!(quantity(u128::from(self.chain_id)))),
            "eth_getBlockByNumber" => {
                let height = match params[0].as_str() {
                    Some("latest") => self.height(),
                    _ => number(&params[0])?,
                };
                Ok(self.block_json(height, params[1].as_bool().unwrap_or(false)))
            }
            "eth_getBlockReceipts" => Ok(self.receipts_json(number(&params[0])?, !behaviour.receipts_without_to)),
            "ghost_getPageRoots" => {
                let block = anchor(&params[2])?;
                Ok(json!(self.roots(block.leaves).iter().map(|r| hex0x(r)).collect::<Vec<_>>()))
            }
            "ghost_getPageSet" => {
                let block = anchor(&params[3])?;
                let pages = params[2].as_array().ok_or("no pages")?;
                let mut answer = Vec::new();
                for page in pages {
                    let page = number(page)? as usize;
                    let start = (page * PAGE_LEAVES).min(block.leaves);
                    let end = (start + PAGE_LEAVES).min(block.leaves);
                    let entries: Vec<Value> =
                        self.leaves[start..end].iter().map(|leaf| json!({ "leaf": hex0x(leaf) })).collect();
                    answer.push(json!({
                        "kind": "coin",
                        "treeIndex": "0x0",
                        "page": quantity(page as u128),
                        "filled": quantity(entries.len() as u128),
                        "entries": entries,
                    }));
                }
                Ok(Value::Array(answer))
            }
            "ghost_getTreePage" => {
                if params[0] != "coin-markers" {
                    return Err("only the marker list".into());
                }
                let block = anchor(&params[3])?;
                let page = number(&params[2])? as usize;
                let start = (page * 4096).min(block.markers);
                let end = (start + 4096).min(block.markers);
                let markers: Vec<String> = self.markers[start..end].iter().map(|m| hex0x(m)).collect();
                Ok(json!({ "count": quantity(markers.len() as u128), "markers": markers }))
            }
            _ => Err(format!("unknown method {method}")),
        }
    }
}

/// How the fake node misbehaves.
#[derive(Clone, Debug, Default)]
pub struct Behaviour {
    /// Every connection is closed at once.
    pub down: bool,
    /// Every answer waits this long first.
    pub slow: Option<Duration>,
    /// Every answer is padded past 1 MiB.
    pub oversized: bool,
    /// Every answer is cut off JSON.
    pub malformed: bool,
    /// Every answer is chunked.
    pub chunked: bool,
    /// Receipts do not say where they went.
    pub receipts_without_to: bool,
    /// The server speaks TLS 1.2 only: it answers a ClientHello with a
    /// TLS 1.2 ServerHello.
    pub tls_1_2_only: bool,
}

/// A test certificate authority.
pub struct TestPki {
    pub root: CertificateDer<'static>,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

impl TestPki {
    pub fn new(name: &str) -> TestPki {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign];
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, name);
        params.distinguished_name = dn;
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2090, 1, 1);
        let root = params.self_signed(&key).unwrap().der().clone();
        TestPki { root, issuer: rcgen::Issuer::new(params, key) }
    }

    /// A server certificate for `name` (expired if asked) and its key.
    pub fn leaf(&self, name: &str, expired: bool) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, name);
        params.distinguished_name = dn;
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        if expired {
            params.not_before = rcgen::date_time_ymd(2019, 1, 1);
            params.not_after = rcgen::date_time_ymd(2020, 1, 1);
        } else {
            params.not_before = rcgen::date_time_ymd(2021, 1, 1);
            params.not_after = rcgen::date_time_ymd(2080, 1, 1);
        }
        let cert = params.signed_by(&key, &self.issuer).unwrap().der().clone();
        (vec![cert], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())))
    }
}

/// What the server shares with the test.
pub struct ServerState {
    pub chain: Arc<Mutex<RpcChain>>,
    pub behaviour: Mutex<Behaviour>,
    /// Every request body received.
    pub requests: Mutex<Vec<String>>,
    /// How many blocks' receipts were asked for: one per block scanned.
    pub block_reads: AtomicUsize,
}

/// A fake node listening on loopback.
pub struct FakeServer {
    pub addr: SocketAddr,
    pub state: Arc<ServerState>,
}

impl FakeServer {
    /// Serves `chain`, over TLS with `certificate` if given, else plain.
    pub fn start(
        chain: &Arc<Mutex<RpcChain>>,
        certificate: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    ) -> FakeServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(ServerState {
            chain: Arc::clone(chain),
            behaviour: Mutex::new(Behaviour::default()),
            requests: Mutex::new(Vec::new()),
            block_reads: AtomicUsize::new(0),
        });
        let config = certificate.map(|(chain, key)| {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            Arc::new(
                rustls::ServerConfig::builder_with_provider(provider)
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(chain, key)
                    .unwrap(),
            )
        });
        let served = Arc::clone(&state);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let (state, config) = (Arc::clone(&served), config.clone());
                thread::spawn(move || serve(stream, &state, config));
            }
        });
        FakeServer { addr, state }
    }

    pub fn set(&self, change: impl FnOnce(&mut Behaviour)) {
        change(&mut self.state.behaviour.lock().unwrap());
    }

    pub fn block_reads(&self) -> usize {
        self.state.block_reads.load(Ordering::SeqCst)
    }

    pub fn requests(&self) -> Vec<String> {
        self.state.requests.lock().unwrap().clone()
    }
}

fn serve(mut tcp: TcpStream, state: &ServerState, config: Option<Arc<rustls::ServerConfig>>) {
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(20)));
    let behaviour = state.behaviour.lock().unwrap().clone();
    if behaviour.down {
        let _ = tcp.shutdown(Shutdown::Both);
        return;
    }
    if behaviour.tls_1_2_only {
        let mut hello = [0u8; 512];
        let _ = tcp.read(&mut hello);
        // A ServerHello choosing TLS 1.2 (no supported_versions extension)
        // and TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.
        let mut server_hello = vec![0x16, 0x03, 0x03, 0x00, 0x2a, 0x02, 0x00, 0x00, 0x26, 0x03, 0x03];
        server_hello.extend_from_slice(&[0x42; 32]);
        server_hello.extend_from_slice(&[0x00, 0xc0, 0x2f, 0x00]);
        let _ = tcp.write_all(&server_hello);
        let mut rest = [0u8; 512];
        let _ = tcp.read(&mut rest);
        return;
    }
    match config {
        Some(config) => {
            let Ok(mut connection) = rustls::ServerConnection::new(config) else { return };
            {
                let mut tls = rustls::Stream::new(&mut connection, &mut tcp);
                exchange(&mut tls, state, &behaviour);
            }
            connection.send_close_notify();
            let _ = connection.complete_io(&mut tcp);
        }
        None => exchange(&mut tcp, state, &behaviour),
    }
    let _ = tcp.shutdown(Shutdown::Both);
}

/// Reads one request and answers it.
fn exchange(stream: &mut dyn ReadWrite, state: &ServerState, behaviour: &Behaviour) {
    let Some(body) = read_request(stream) else { return };
    state.requests.lock().unwrap().push(String::from_utf8_lossy(&body).into_owned());
    let reply = answer_batch(&body, state, behaviour);
    if let Some(wait) = behaviour.slow {
        thread::sleep(wait);
    }
    let reply = if behaviour.malformed {
        "{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":[\"0x".to_owned()
    } else if behaviour.oversized {
        format!("[{{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":\"0x{}\"}}]", "0".repeat(1024 * 1024 + 64))
    } else {
        reply
    };
    let head = if behaviour.chunked {
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            .to_owned()
    } else {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            reply.len()
        )
    };
    let _ = stream.write_all(head.as_bytes());
    if behaviour.chunked {
        for chunk in reply.as_bytes().chunks(700) {
            let _ = stream.write_all(format!("{:x};ext=1\r\n", chunk.len()).as_bytes());
            let _ = stream.write_all(chunk);
            let _ = stream.write_all(b"\r\n");
        }
        let _ = stream.write_all(b"0\r\n\r\n");
    } else {
        let _ = stream.write_all(reply.as_bytes());
    }
    let _ = stream.flush();
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn read_request(stream: &mut dyn ReadWrite) -> Option<Vec<u8>> {
    let mut raw = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = stream.read(&mut buffer).ok()?;
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&buffer[..n]);
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut request = httparse::Request::new(&mut headers);
        if let Ok(httparse::Status::Complete(head)) = request.parse(&raw) {
            let length: usize = request
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                .and_then(|h| std::str::from_utf8(h.value).ok()?.parse().ok())
                .unwrap_or(0);
            if raw.len() >= head + length {
                return Some(raw[head..head + length].to_vec());
            }
        }
    }
}

fn answer_batch(body: &[u8], state: &ServerState, behaviour: &Behaviour) -> String {
    let Ok(Value::Array(calls)) = serde_json::from_slice::<Value>(body) else {
        return json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32600, "message": "not a batch" } }).to_string();
    };
    let chain = state.chain.lock().unwrap();
    let answers: Vec<Value> = calls
        .iter()
        .map(|call| {
            let method = call["method"].as_str().unwrap_or("");
            if method == "eth_getBlockReceipts" {
                state.block_reads.fetch_add(1, Ordering::SeqCst);
            }
            match chain.answer(method, &call["params"], behaviour) {
                Ok(result) => json!({ "jsonrpc": "2.0", "id": call["id"], "result": result }),
                Err(message) => json!({ "jsonrpc": "2.0", "id": call["id"], "error": { "code": -32000, "message": message } }),
            }
        })
        .collect();
    Value::Array(answers).to_string()
}

/// Connects to one loopback address whatever the node's host name is, as
/// the enclave's vsock transport reaches its node whatever the name.
pub struct Loopback(pub SocketAddr);

impl NodeTransport for Loopback {
    fn connect(&self, _address: &NodeAddress, deadline: Instant) -> io::Result<Box<dyn NodeStream>> {
        let left = deadline.saturating_duration_since(Instant::now());
        Ok(Box::new(TcpStream::connect_timeout(&self.0, left.max(Duration::from_millis(1)))?))
    }
}

/// The address of node `name` at host `host`, over TLS.
pub fn address(name: &str, host: &str) -> NodeAddress {
    NodeAddress { name: name.to_owned(), host: host.to_owned(), port: 443, path: "/ghost-rpc".to_owned(), tls: true }
}

/// An `RpcNode` named `name` for host `host`, reaching `server`, trusting
/// `root` only.
pub fn rpc_node(name: &str, host: &str, server: &FakeServer, root: &CertificateDer<'static>) -> RpcNode {
    RpcNode::with_roots(address(name, host), Arc::new(Loopback(server.addr)), vec![root.clone()]).unwrap()
}
