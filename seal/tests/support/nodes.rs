//! Fake chain nodes for the chain check: a small chain in memory (tip, coin
//! tree, Vanish receipts and spent markers) and nodes that answer from it,
//! each of which the test can take down. Two nodes over one chain agree; a
//! node over a cloned chain that then moves on its own disagrees.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::rc::Rc;

use ghost_seal::primitives::sha3_256;
use ghost_seal::{
    BlockRef, ChainNode, CoinQuery, CoinTreeAt, Network, NodeChainCheck, NodeError, TxOutcome, VanishReceipt,
};
use ghost_wallet_core::coin_tree::PAGE_LEAVES;
use ghost_wallet_core::vanish::COMMIT_ENTRY;
use ghost_wallet_core::{CoinPage, commit_leaf, page_root, tree_root_of_pages};

/// The test network.
pub const NETWORK: Network = Network { chain_id: ghost_wallet_core::TEST_CHAIN_ID, genesis: [0x6e; 32] };

/// Another network: a different chain id.
pub const OTHER_CHAIN: Network = Network { chain_id: ghost_wallet_core::TEST_CHAIN_ID + 1000, genesis: [0x6e; 32] };

/// Another network: the same chain id with another block 0.
pub const OTHER_GENESIS: Network = Network { chain_id: ghost_wallet_core::TEST_CHAIN_ID, genesis: [0x6f; 32] };

/// A chain in memory.
#[derive(Clone)]
pub struct FakeChain {
    /// The network the chain's nodes say they follow.
    pub network: Network,
    /// The tip's height.
    pub height: u64,
    /// Mixed into every block hash: two chains with another fork number have
    /// other blocks at the same height.
    pub fork: u64,
    /// Every coin tree leaf, in position order.
    pub leaves: Vec<[u8; 32]>,
    /// Every transaction to the coin commit entry.
    pub receipts: Vec<VanishReceipt>,
    /// Every spend marker used.
    pub spent: BTreeSet<[u8; 32]>,
    /// Leave the leaves of Vanishes out of the tree (a node that lies).
    pub drop_leaves: bool,
    /// Serve a header root the pages do not make (a node that lies).
    pub wrong_root: bool,
}

impl FakeChain {
    /// A chain at height 100 whose tree already holds a few other coins.
    pub fn new() -> FakeChain {
        let leaves = (0..5u8).map(|i| sha3_256(&[b"other coin", &[i]])).collect();
        FakeChain {
            network: NETWORK,
            height: 100,
            fork: 0,
            leaves,
            receipts: Vec::new(),
            spent: BTreeSet::new(),
            drop_leaves: false,
            wrong_root: false,
        }
    }

    /// The shared handle nodes read from.
    pub fn shared(self) -> Rc<RefCell<FakeChain>> {
        Rc::new(RefCell::new(self))
    }

    /// The block at `height`.
    pub fn block(&self, height: u64) -> BlockRef {
        let chain_id = self.network.chain_id.to_be_bytes();
        BlockRef {
            height,
            hash: sha3_256(&[b"fake block", &chain_id, &self.fork.to_be_bytes(), &height.to_be_bytes()]),
        }
    }

    /// The tip block.
    pub fn tip(&self) -> BlockRef {
        self.block(self.height)
    }

    /// Adds `blocks` empty blocks.
    pub fn mine(&mut self, blocks: u64) {
        self.height += blocks;
    }

    /// A transaction to the coin commit entry with `data` paying
    /// `value_wei`, signed for `chain_id`, in a new block. A successful one
    /// adds its leaf to the tree, as the node does.
    pub fn send(&mut self, data: &[u8], value_wei: u128, chain_id: u64, outcome: TxOutcome) {
        self.mine(1);
        let position = self.leaves.len() as u64;
        if outcome == TxOutcome::Succeeded && !self.drop_leaves {
            let leaf = commit_leaf(data.to_vec(), value_wei.to_string()).expect("commit data the core reads");
            self.leaves.push(leaf.commitment.try_into().expect("32 bytes"));
        }
        let block = self.tip();
        self.receipts.push(VanishReceipt {
            transaction_hash: sha3_256(&[b"fake tx", data, &value_wei.to_be_bytes(), &block.hash]),
            chain_id,
            to: COMMIT_ENTRY,
            value_wei,
            data: data.to_vec(),
            outcome,
            block,
            leaf_position: position,
        });
    }

    /// A successful Vanish of `data` paying `value_wei` on this chain.
    pub fn vanish(&mut self, data: &[u8], value_wei: u128) {
        let chain_id = self.network.chain_id;
        self.send(data, value_wei, chain_id, TxOutcome::Succeeded);
    }

    /// The exact Vanish of `coin`, then blocks on top until it is `depth`
    /// blocks deep.
    pub fn pay(&mut self, coin: &CoinQuery, depth: u64) {
        self.vanish(&coin.commit_data, coin.amount_wei);
        self.mine(depth.saturating_sub(1));
    }

    /// Uses spend marker `marker`, in a new block.
    pub fn spend(&mut self, marker: [u8; 32]) {
        self.mine(1);
        self.spent.insert(marker);
    }

    fn page_roots(&self) -> Vec<[u8; 32]> {
        self.leaves.chunks(PAGE_LEAVES).map(page_root).collect()
    }

    fn coin_tree(&self, page: u32) -> CoinTreeAt {
        let roots = self.page_roots();
        let start = (page as usize * PAGE_LEAVES).min(self.leaves.len());
        let end = (start + PAGE_LEAVES).min(self.leaves.len());
        let root = if self.wrong_root { sha3_256(&[b"a root no pages make"]) } else { tree_root_of_pages(&roots) };
        CoinTreeAt {
            block: self.tip(),
            coin_tree_root: root,
            page_roots: roots.iter().map(|root| root.to_vec()).collect(),
            page: CoinPage { page, leaves: self.leaves[start..end].iter().map(|leaf| leaf.to_vec()).collect() },
        }
    }
}

/// A node answering from a [`FakeChain`].
#[derive(Clone)]
pub struct FakeNode {
    pub name: String,
    pub chain: Rc<RefCell<FakeChain>>,
    /// While set, every call fails as unreachable.
    pub down: Rc<Cell<bool>>,
    /// Calls answered so far.
    pub calls: Rc<Cell<usize>>,
}

impl FakeNode {
    pub fn new(name: &str, chain: &Rc<RefCell<FakeChain>>) -> FakeNode {
        FakeNode {
            name: name.to_owned(),
            chain: chain.clone(),
            down: Rc::new(Cell::new(false)),
            calls: Rc::new(Cell::new(0)),
        }
    }

    fn reach(&self) -> Result<std::cell::Ref<'_, FakeChain>, NodeError> {
        if self.down.get() {
            return Err(NodeError::Unreachable);
        }
        self.calls.set(self.calls.get() + 1);
        Ok(self.chain.borrow())
    }
}

impl ChainNode for FakeNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn network(&self) -> Result<Network, NodeError> {
        Ok(self.reach()?.network)
    }

    fn tip(&self) -> Result<BlockRef, NodeError> {
        Ok(self.reach()?.tip())
    }

    fn vanish_receipts(&self, fingerprint: &[u8; 32]) -> Result<Vec<VanishReceipt>, NodeError> {
        let chain = self.reach()?;
        Ok(chain.receipts.iter().filter(|r| r.data.get(2..34) == Some(&fingerprint[..])).cloned().collect())
    }

    fn coin_tree(&self, anchor: &BlockRef, page: u32) -> Result<CoinTreeAt, NodeError> {
        let chain = self.reach()?;
        if *anchor != chain.tip() {
            return Err(NodeError::Inconsistent("this fake node serves the tree at its tip only"));
        }
        Ok(chain.coin_tree(page))
    }

    fn marker_spent(&self, marker: &[u8; 32], anchor: &BlockRef) -> Result<bool, NodeError> {
        let chain = self.reach()?;
        if *anchor != chain.tip() {
            return Err(NodeError::Inconsistent("this fake node answers at its tip only"));
        }
        Ok(chain.spent.contains(marker))
    }
}

/// Two nodes over `chain`.
pub fn two_nodes(chain: &Rc<RefCell<FakeChain>>) -> (FakeNode, FakeNode) {
    (FakeNode::new("node-a", chain), FakeNode::new("node-b", chain))
}

/// A chain check on [`NETWORK`] over `nodes`.
pub fn node_check(nodes: &[&FakeNode]) -> NodeChainCheck {
    NodeChainCheck::new(NETWORK, nodes.iter().map(|node| Box::new((*node).clone()) as Box<dyn ChainNode>).collect())
        .expect("two or more nodes")
}

/// 430 bytes of version-3 commit data for test coin `label` (fake: the core
/// reads only its version, its fingerprint and its length).
pub fn test_commit_data(label: u8) -> Vec<u8> {
    let mut data = vec![0x00, 0x03];
    let mut n = 0u32;
    while data.len() < 430 {
        data.extend_from_slice(&sha3_256(&[b"test commit data", &[label], &n.to_be_bytes()]));
        n += 1;
    }
    data.truncate(430);
    data
}

/// Test coin `label` of `amount_wei`, with its test spend marker.
pub fn test_coin(label: u8, amount_wei: u128) -> CoinQuery {
    CoinQuery {
        commit_data: test_commit_data(label),
        amount_wei,
        spend_marker: sha3_256(&[b"test spend marker", &[label]]),
    }
}
