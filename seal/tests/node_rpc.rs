//! The real chain node, `RpcNode`, against fake Ghost nodes in this process
//! speaking JSON-RPC over TLS 1.3 with a test root: it reads the tip, the
//! network, the Vanish receipts (with their leaf positions), the coin tree
//! and the spend markers; two that agree give Sealed; a node down, a tip
//! that disagrees, a wrong chain id or genesis, a wrong server name, an
//! expired or untrusted certificate, a TLS 1.2 only node, an oversized,
//! malformed or slow reply each give no answer and never Sealed; the scan
//! reads at most 500 blocks a call and resumes where it stopped; a
//! reorganisation inside the last 128 blocks is read again; and no request
//! or error text carries the coin's spend marker or fingerprint.

#[path = "support/rpc_node.rs"]
mod rpc_node;
mod support;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ghost_seal::chain_check::safe_depth;
use ghost_seal::node_rpc::{
    BLOCKS_PER_CALL, CALL_DEADLINE, ISRG_ROOT_X1_PEM, MAX_REPLY_BYTES, RpcLimits, RpcNode, SETTLED_DEPTH,
    isrg_root_x1,
};
use ghost_seal::{
    BlockRef, ChainNode, CoinQuery, CoinStatus, CoinStatusCheck, Network, NodeChainCheck, NodeError, TxOutcome,
};
use ghost_wallet_core::commit_leaf;
use rpc_node::{FakeServer, Loopback, RpcChain, TestPki, address, rpc_node};
use sha2::{Digest, Sha256};
use support::nodes::test_coin;

const HOST_A: &str = "node-a.test";
const HOST_B: &str = "node-b.test";
const AMOUNT: u128 = 1_500_000_000_000_000_000;
/// The published SHA-256 fingerprint of ISRG Root X1.
const ISRG_ROOT_X1_SHA256: &str = "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn shared(chain: RpcChain) -> Arc<Mutex<RpcChain>> {
    Arc::new(Mutex::new(chain))
}

/// Two fake nodes over one chain, each with a certificate for its host
/// from the test root.
struct Rig {
    chain: Arc<Mutex<RpcChain>>,
    pki: TestPki,
    a: FakeServer,
    b: FakeServer,
}

impl Rig {
    fn new(build: impl FnOnce(&mut RpcChain)) -> Rig {
        let mut chain = RpcChain::new("test network");
        chain.mine(3);
        build(&mut chain);
        let chain = shared(chain);
        let pki = TestPki::new("test root");
        let a = FakeServer::start(&chain, Some(pki.leaf(HOST_A, false)));
        let b = FakeServer::start(&chain, Some(pki.leaf(HOST_B, false)));
        Rig { chain, pki, a, b }
    }

    fn network(&self) -> Network {
        self.chain.lock().unwrap().network()
    }

    fn node_a(&self) -> RpcNode {
        rpc_node("node-a", HOST_A, &self.a, &self.pki.root)
    }

    fn node_b(&self) -> RpcNode {
        rpc_node("node-b", HOST_B, &self.b, &self.pki.root)
    }

    fn mutate(&self, change: impl FnOnce(&mut RpcChain)) {
        change(&mut self.chain.lock().unwrap());
    }
}

/// The chain check on `network` over clones of `nodes` (sharing their scans).
fn check(network: Network, nodes: &[&RpcNode]) -> NodeChainCheck {
    NodeChainCheck::new(network, nodes.iter().map(|n| Box::new((*n).clone()) as Box<dyn ChainNode>).collect()).unwrap()
}

fn fingerprint(coin: &CoinQuery) -> [u8; 32] {
    coin.commit_data[2..34].try_into().unwrap()
}

#[test]
fn the_compiled_in_root_is_isrg_root_x1_and_the_bounds_are_the_published_ones() {
    let root = isrg_root_x1();
    assert_eq!(hex(&Sha256::digest(root.as_ref())), ISRG_ROOT_X1_SHA256);
    assert_eq!(ISRG_ROOT_X1_PEM.matches("BEGIN CERTIFICATE").count(), 1);
    assert_eq!(
        RpcLimits::default(),
        RpcLimits { max_reply_bytes: 1024 * 1024, deadline: Duration::from_secs(10), blocks_per_call: 500, settled_depth: 128 }
    );
    assert_eq!((MAX_REPLY_BYTES, CALL_DEADLINE, BLOCKS_PER_CALL, SETTLED_DEPTH), (1 << 20, Duration::from_secs(10), 500, 128));

    // A node built with the compiled-in root alone does not trust the test
    // root's certificate.
    let rig = Rig::new(|_| {});
    let node = RpcNode::new(address("node-a", HOST_A), Arc::new(Loopback(rig.a.addr))).unwrap();
    assert_eq!(node.tip(), Err(NodeError::Unreachable));
    // With the test root it does.
    assert_eq!(rig.node_a().tip().unwrap().height, 3);
}

#[test]
fn it_reads_the_tip_network_receipts_coin_tree_and_spent_marker() {
    let coin = test_coin(1, AMOUNT);
    let rig = Rig::new(|chain| {
        // A failed payment first, then the coin's Vanish among others.
        let chain_id = chain.chain_id;
        chain.send(&coin.commit_data, AMOUNT, chain_id, false);
        chain.mine(2);
        chain.vanish_among_others(&coin.commit_data, AMOUNT, 1);
        chain.mine(4);
        chain.spend_others(3);
    });
    let leaf: [u8; 32] = commit_leaf(coin.commit_data.clone(), AMOUNT.to_string()).unwrap().commitment.try_into().unwrap();
    let (position, expected_tip, vanish_height) = {
        let chain = rig.chain.lock().unwrap();
        let position = chain.leaves.iter().position(|l| *l == leaf).unwrap() as u64;
        let tip = BlockRef { height: chain.height(), hash: chain.blocks.last().unwrap().hash };
        (position, tip, 7)
    };
    assert!(position > 0, "the coin's leaf is not its block's first");
    // Server b answers chunked, with receipts that do not say where they
    // went (so whole blocks are read).
    rig.b.set(|b| {
        b.chunked = true;
        b.receipts_without_to = true;
    });

    for node in [rig.node_a(), rig.node_b()] {
        assert_eq!(node.network().unwrap(), rig.network());
        let tip = node.tip().unwrap();
        assert_eq!(tip, expected_tip);

        let receipts = node.vanish_receipts(&fingerprint(&coin)).unwrap();
        assert_eq!(receipts.len(), 2, "the failed payment and the Vanish");
        assert_eq!(receipts[0].outcome, TxOutcome::Failed);
        let paid = &receipts[1];
        assert_eq!(paid.outcome, TxOutcome::Succeeded);
        assert_eq!((paid.data.as_slice(), paid.value_wei, paid.chain_id), (coin.commit_data.as_slice(), AMOUNT, rpc_node::CHAIN_ID));
        assert_eq!(paid.block.height, vanish_height);
        assert_eq!(paid.leaf_position, position);
        assert_eq!(paid.to, ghost_wallet_core::vanish::COMMIT_ENTRY);
        // Another fingerprint: none.
        assert!(node.vanish_receipts(&[0x5a; 32]).unwrap().is_empty());

        let tree = node.coin_tree(&tip, 0).unwrap();
        assert_eq!(tree.block, tip);
        assert_eq!(tree.page.leaves[position as usize], leaf.to_vec());
        ghost_wallet_core::check_coin_pages(tree.page_roots.clone(), vec![tree.page.clone()], tree.coin_tree_root.to_vec())
            .expect("the page checks against the header's root");

        assert!(!node.marker_spent(&coin.spend_marker, &tip).unwrap());
    }

    rig.mutate(|chain| chain.spend(coin.spend_marker));
    for node in [rig.node_a(), rig.node_b()] {
        let tip = node.tip().unwrap();
        assert!(node.marker_spent(&coin.spend_marker, &tip).unwrap());
    }
}

#[test]
fn two_nodes_that_agree_give_sealed() {
    let coin = test_coin(2, AMOUNT);
    let rig = Rig::new(|chain| chain.vanish_among_others(&coin.commit_data, AMOUNT, 2));
    let (a, b) = (rig.node_a(), rig.node_b());
    let status = || check(rig.network(), &[&a, &b]).coin_status(&coin);
    assert_eq!(status(), CoinStatus::Filling { confirmations: 1, needed: safe_depth(AMOUNT) });
    rig.mutate(|chain| chain.mine(safe_depth(AMOUNT)));
    assert_eq!(status(), CoinStatus::ExactSettledUnspent);
    rig.mutate(|chain| chain.spend(coin.spend_marker));
    assert_eq!(status(), CoinStatus::Spent);
}

/// A settled coin and its rig, whose two nodes say so.
fn settled() -> (Rig, CoinQuery) {
    let coin = test_coin(3, AMOUNT);
    let rig = Rig::new(|chain| chain.pay(&coin, safe_depth(AMOUNT) + 2));
    assert_eq!(check(rig.network(), &[&rig.node_a(), &rig.node_b()]).coin_status(&coin), CoinStatus::ExactSettledUnspent);
    (rig, coin)
}

/// What a check over node a and `b` (a node the case breaks) says, and
/// what `b` says of its tip.
fn with_b(rig: &Rig, coin: &CoinQuery, b: &RpcNode) -> (CoinStatus, Result<BlockRef, NodeError>) {
    (check(rig.network(), &[&rig.node_a(), b]).coin_status(coin), b.tip())
}

#[test]
fn a_node_down_or_a_tip_that_disagrees_gives_no_answer() {
    let (rig, coin) = settled();
    rig.b.set(|b| b.down = true);
    let (status, tip) = with_b(&rig, &coin, &rig.node_b());
    assert_eq!(status, CoinStatus::CantCheckNow);
    assert_eq!(tip, Err(NodeError::Unreachable));
    rig.b.set(|b| b.down = false);

    // Node b follows its own copy, a block ahead.
    let ahead = shared(rig.chain.lock().unwrap().clone());
    ahead.lock().unwrap().mine(1);
    let server = FakeServer::start(&ahead, Some(rig.pki.leaf(HOST_B, false)));
    let (status, tip) = with_b(&rig, &coin, &rpc_node("node-b", HOST_B, &server, &rig.pki.root));
    assert_eq!(status, CoinStatus::CantCheckNow);
    assert!(tip.is_ok());
}

#[test]
fn a_wrong_chain_id_or_genesis_is_never_sealed() {
    let (rig, coin) = settled();
    // Node b reports another chain id.
    let other_id = shared(rig.chain.lock().unwrap().clone());
    other_id.lock().unwrap().chain_id += 1;
    let server = FakeServer::start(&other_id, Some(rig.pki.leaf(HOST_B, false)));
    let b = rpc_node("node-b", HOST_B, &server, &rig.pki.root);
    assert_eq!(with_b(&rig, &coin, &b).0, CoinStatus::CantCheckNow);
    // Both on the other chain id: the wrong chain.
    let a_other = FakeServer::start(&other_id, Some(rig.pki.leaf(HOST_A, false)));
    let a = rpc_node("node-a", HOST_A, &a_other, &rig.pki.root);
    assert_eq!(check(rig.network(), &[&a, &b]).coin_status(&coin), CoinStatus::WrongChain);

    // Both nodes on the right chain, but the check expects another block 0.
    let other_genesis = Network { genesis: [0x77; 32], ..rig.network() };
    assert_eq!(check(other_genesis, &[&rig.node_a(), &rig.node_b()]).coin_status(&coin), CoinStatus::WrongChain);
    // A node whose block 0 is another one.
    let mut forked = RpcChain::new("another network");
    forked.mine(3);
    forked.pay(&coin, safe_depth(AMOUNT) + 2);
    let forked = shared(forked);
    let server = FakeServer::start(&forked, Some(rig.pki.leaf(HOST_B, false)));
    assert_eq!(with_b(&rig, &coin, &rpc_node("node-b", HOST_B, &server, &rig.pki.root)).0, CoinStatus::CantCheckNow);
}

#[test]
fn a_wrong_name_or_an_expired_or_untrusted_certificate_gives_no_answer() {
    let (rig, coin) = settled();
    let stranger = TestPki::new("another root");
    for (why, certificate) in [
        ("a certificate for another name", rig.pki.leaf("other.test", false)),
        ("an expired certificate", rig.pki.leaf(HOST_B, true)),
        ("a certificate from another root", stranger.leaf(HOST_B, false)),
    ] {
        let server = FakeServer::start(&rig.chain, Some(certificate));
        let (status, tip) = with_b(&rig, &coin, &rpc_node("node-b", HOST_B, &server, &rig.pki.root));
        assert_eq!(status, CoinStatus::CantCheckNow, "{why}");
        assert_eq!(tip, Err(NodeError::Unreachable), "{why}");
        assert!(server.requests().is_empty(), "{why}: no request crossed an untrusted connection");
    }
}

#[test]
fn a_node_speaking_only_tls_1_2_gives_no_answer() {
    let (rig, coin) = settled();
    rig.b.set(|b| b.tls_1_2_only = true);
    let (status, tip) = with_b(&rig, &coin, &rig.node_b());
    assert_eq!(status, CoinStatus::CantCheckNow);
    assert_eq!(tip, Err(NodeError::Unreachable));
}

#[test]
fn an_oversized_malformed_or_slow_reply_gives_no_answer() {
    let (rig, coin) = settled();
    rig.b.set(|b| b.oversized = true);
    let (status, tip) = with_b(&rig, &coin, &rig.node_b());
    assert_eq!((status, tip), (CoinStatus::CantCheckNow, Err(NodeError::Unreachable)));

    rig.b.set(|b| {
        b.oversized = false;
        b.malformed = true;
    });
    let (status, tip) = with_b(&rig, &coin, &rig.node_b());
    assert_eq!(status, CoinStatus::CantCheckNow);
    assert!(matches!(tip, Err(NodeError::Inconsistent(_))), "{tip:?}");

    rig.b.set(|b| {
        b.malformed = false;
        b.slow = Some(Duration::from_millis(1500));
    });
    let quick = RpcLimits { deadline: Duration::from_millis(300), ..RpcLimits::default() };
    let slow_b = rig.node_b().with_limits(quick);
    let started = Instant::now();
    assert_eq!(slow_b.tip(), Err(NodeError::Unreachable));
    assert!(started.elapsed() < Duration::from_millis(1200), "waited past the deadline: {:?}", started.elapsed());
    assert_eq!(check(rig.network(), &[&rig.node_a(), &slow_b]).coin_status(&coin), CoinStatus::CantCheckNow);
}

#[test]
fn the_scan_reads_at_most_500_blocks_a_call_and_resumes_where_it_stopped() {
    // The coin is paid at block 700; the tip is 1129, so blocks 1 to 1000
    // are settled and 1001 to 1129 are read again on every call.
    let coin = test_coin(4, AMOUNT);
    let rig = Rig::new(|chain| {
        chain.mine(696);
        chain.vanish(&coin.commit_data, AMOUNT);
        chain.mine(429);
    });
    assert_eq!(rig.chain.lock().unwrap().height(), 1129);
    let node = rig.node_a();
    let fp = fingerprint(&coin);

    node.tip().unwrap();
    assert_eq!(node.vanish_receipts(&fp), Err(NodeError::Unreachable), "not caught up");
    assert_eq!((rig.a.block_reads(), node.scanned_to()), (500, 501));

    node.tip().unwrap();
    assert_eq!(node.vanish_receipts(&fp), Err(NodeError::Unreachable), "not caught up");
    assert_eq!((rig.a.block_reads(), node.scanned_to()), (1000, 1001));

    node.tip().unwrap();
    let found = node.vanish_receipts(&fp).expect("caught up");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].block.height, 700);
    assert_eq!(rig.a.block_reads(), 1129, "the newer blocks only");
    assert_eq!(node.scanned_to(), 1001, "the newer blocks are not kept");

    // Again: only the newer blocks are read; the settled ones come from memory.
    let fresh_clone = node.clone();
    fresh_clone.tip().unwrap();
    assert_eq!(fresh_clone.vanish_receipts(&fp).unwrap(), found);
    assert_eq!(rig.a.block_reads(), 1129 + 129);

    // The full check: no answer until both nodes have caught up, then Sealed.
    let (a, b) = (node.clone(), rig.node_b());
    let mut answers = Vec::new();
    for _ in 0..6 {
        let status = check(rig.network(), &[&a, &b]).coin_status(&coin);
        answers.push(status);
        if status == CoinStatus::ExactSettledUnspent {
            break;
        }
        assert_eq!(status, CoinStatus::CantCheckNow);
    }
    assert_eq!(answers.last(), Some(&CoinStatus::ExactSettledUnspent), "{answers:?}");
    assert_eq!(answers.len(), 3, "node b needed three calls: {answers:?}");
}

#[test]
fn a_reorganisation_inside_the_last_128_blocks_is_read_again() {
    let coin = test_coin(5, AMOUNT);
    let rig = Rig::new(|chain| {
        chain.mine(197);
        chain.pay(&coin, 11);
    });
    let (a, b) = (rig.node_a(), rig.node_b());
    let status = || check(rig.network(), &[&a, &b]).coin_status(&coin);
    assert_eq!(status(), CoinStatus::ExactSettledUnspent);
    let kept = a.scanned_to();
    assert!(kept <= 211 - SETTLED_DEPTH, "the Vanish's block is not kept yet: {kept}");

    // The last 30 blocks, the Vanish's among them, are replaced by others
    // without it.
    rig.mutate(|chain| {
        chain.unwind(30);
        chain.mine(40);
    });
    assert_eq!(status(), CoinStatus::Filling { confirmations: 0, needed: safe_depth(AMOUNT) });

    // Paid again on the new branch: Sealed once settled.
    rig.mutate(|chain| chain.pay(&coin, safe_depth(AMOUNT)));
    assert_eq!(status(), CoinStatus::ExactSettledUnspent);
}

#[test]
fn no_request_or_error_text_carries_the_coins_spend_marker_or_fingerprint() {
    let coin = test_coin(6, AMOUNT);
    let rig = Rig::new(|chain| {
        chain.pay(&coin, safe_depth(AMOUNT));
        chain.spend_others(5);
    });
    let (a, b) = (rig.node_a(), rig.node_b());
    assert_eq!(check(rig.network(), &[&a, &b]).coin_status(&coin), CoinStatus::ExactSettledUnspent);
    rig.mutate(|chain| chain.spend(coin.spend_marker));
    assert_eq!(check(rig.network(), &[&a, &b]).coin_status(&coin), CoinStatus::Spent);

    // Errors, from every way a node fails here.
    let mut texts: Vec<String> = Vec::new();
    for change in [
        (|b: &mut rpc_node::Behaviour| b.malformed = true) as fn(&mut rpc_node::Behaviour),
        |b| b.oversized = true,
        |b| b.down = true,
    ] {
        rig.b.set(|b| *b = rpc_node::Behaviour::default());
        rig.b.set(change);
        let node = rig.node_b();
        for error in [node.tip().err(), node.network().err(), node.vanish_receipts(&fingerprint(&coin)).err()]
            .into_iter()
            .flatten()
        {
            texts.push(error.to_string());
            texts.push(format!("{error:?}"));
        }
    }
    assert!(!texts.is_empty());
    texts.extend(rig.a.requests());
    texts.extend(rig.b.requests());

    let marker = hex(&coin.spend_marker);
    let fp = hex(&fingerprint(&coin));
    for text in &texts {
        let lower = text.to_lowercase();
        assert!(!lower.contains(&marker), "the spend marker went out: {text}");
        assert!(!lower.contains(&fp), "the fingerprint went out: {text}");
    }
}
