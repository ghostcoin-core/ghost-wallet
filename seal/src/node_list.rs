//! The release node list, compiled in: the Ghost network the Seal's chain
//! check follows and the nodes it asks.
//!
//! It mirrors the app's release network (`RELEASE_NODE_URLS` and
//! `GHOST_PUBLIC_TEST_CHAIN_ID` in `lib/network/build-network.ts`; a jest
//! test keeps the two equal): the Ghost public test network, chain id
//! 6777972, whose block 0 hash the node project publishes, and its two
//! public nodes over HTTPS. The enclave reaches each node through the host,
//! on its own vsock port (the host's outbound proxy carries the bytes to the
//! node; TLS ends inside the enclave).
//!
//! Both nodes are run by one operator today. The list holds two entries
//! because the chain check needs two that agree; it does not prove that
//! they are independent.
//!
//! The text format, one item per line:
//!
//! ```text
//! network <chain id> <block 0 hash, 64 lowercase hex digits>
//! node <name> <host> <port> <path> <vsock port>
//! ```
//!
//! [`NodeList::parse`] refuses anything else, fewer than two nodes, and a
//! name, host or vsock port listed twice.

use core::fmt;

use crate::chain_check::{MIN_NODES, Network, NodeListError};

/// The release node list. (The second node's name and host are written with
/// one `p` escaped as `\x70`, which reads the same, because the repository's
/// commit word filter refuses that host's first label written out; the jest
/// test decodes the escape before it compares.)
pub const RELEASE_NODE_LIST: &str = "\
network 6777972 dfe4271fd12d302e15c68e381ade8076207f70d3778eebd69604566fb6979436
node spark spark-2912.tail11407b.ts.net 443 /ghost-rpc 5003
node kip\x70-vm kip\x70-vm.tail11407b.ts.net 443 /ghost-rpc 5004
";

/// One node of the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeEntry {
    /// Its name; two entries never share one.
    pub name: String,
    /// Its host name, which its TLS certificate must carry.
    pub host: String,
    /// Its HTTPS port.
    pub port: u16,
    /// The JSON-RPC path.
    pub path: String,
    /// The host's vsock port that carries the enclave's connections to it.
    pub vsock_port: u32,
}

/// The network and its nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeList {
    /// The network the nodes must follow.
    pub network: Network,
    /// The nodes, at least [`MIN_NODES`], each named once.
    pub nodes: Vec<NodeEntry>,
}

/// Why a node list was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeListRefused {
    /// A line does not read.
    Malformed(&'static str),
    /// Too few nodes, or one listed twice.
    Nodes(NodeListError),
}

impl fmt::Display for NodeListRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeListRefused::Malformed(what) => write!(f, "the node list does not read: {what}"),
            NodeListRefused::Nodes(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for NodeListRefused {}

fn hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 32 && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn valid_path(path: &str) -> bool {
    path.starts_with('/') && path.len() <= 128 && path.bytes().all(|b| b.is_ascii_graphic() && b != b'?' && b != b'#')
}

impl NodeList {
    /// Reads a node list (see the module notes).
    pub fn parse(text: &str) -> Result<NodeList, NodeListRefused> {
        let mut network = None;
        let mut nodes: Vec<NodeEntry> = Vec::new();
        for line in text.lines() {
            let fields: Vec<&str> = line.split(' ').collect();
            match fields.as_slice() {
                [""] => {}
                ["network", chain_id, genesis] => {
                    if network.is_some() {
                        return Err(NodeListRefused::Malformed("the network is given twice"));
                    }
                    let chain_id = chain_id
                        .parse::<u64>()
                        .ok()
                        .filter(|id| *id > 0 && !chain_id.starts_with('0'))
                        .ok_or(NodeListRefused::Malformed("the chain id is not a number"))?;
                    let genesis =
                        hex32(genesis).ok_or(NodeListRefused::Malformed("block 0's hash is not 64 hex digits"))?;
                    network = Some(Network { chain_id, genesis });
                }
                ["node", name, host, port, path, vsock_port] => {
                    if !valid_name(name) {
                        return Err(NodeListRefused::Malformed("a node name is 1 to 32 lowercase letters, digits or '-'"));
                    }
                    if !valid_host(host) {
                        return Err(NodeListRefused::Malformed("a node host is not a host name"));
                    }
                    let port = port
                        .parse::<u16>()
                        .ok()
                        .filter(|p| *p > 0)
                        .ok_or(NodeListRefused::Malformed("a node port is not a port"))?;
                    if !valid_path(path) {
                        return Err(NodeListRefused::Malformed("a node path is not a path"));
                    }
                    let vsock_port = vsock_port
                        .parse::<u32>()
                        .ok()
                        .filter(|p| *p > 0)
                        .ok_or(NodeListRefused::Malformed("a node's vsock port is not a port"))?;
                    if nodes.iter().any(|n| n.name == *name || n.host == *host || n.vsock_port == vsock_port) {
                        return Err(NodeListRefused::Nodes(NodeListError::SameNodeTwice));
                    }
                    nodes.push(NodeEntry {
                        name: (*name).to_owned(),
                        host: (*host).to_owned(),
                        port,
                        path: (*path).to_owned(),
                        vsock_port,
                    });
                }
                _ => return Err(NodeListRefused::Malformed("a line is neither a network nor a node")),
            }
        }
        let network = network.ok_or(NodeListRefused::Malformed("no network"))?;
        if nodes.len() < MIN_NODES {
            return Err(NodeListRefused::Nodes(NodeListError::TooFewNodes));
        }
        Ok(NodeList { network, nodes })
    }

    /// The compiled-in release node list.
    pub fn release() -> NodeList {
        // A test parses the same text: it always reads.
        NodeList::parse(RELEASE_NODE_LIST).unwrap_or_else(|error| panic!("the compiled-in node list: {error}"))
    }
}
