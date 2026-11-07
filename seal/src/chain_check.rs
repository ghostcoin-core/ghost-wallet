//! The chain check: whether a card's coin was paid exactly, is settled and is
//! still unspent, as at least two independent nodes agree.
//!
//! - **Exact payment.** A Vanish to the coin commit entry, on the Seal's
//!   network (chain id and genesis), carrying exactly the card's commit data
//!   and exactly the card's amount; its transaction succeeded, and the leaf it
//!   adds (the wallet core's [`commit_leaf`]) is in the coin tree at the tip,
//!   in a page the wallet core's [`check_coin_pages`] checked against the tip
//!   header's coin tree root.
//! - **Settled.** The Vanish's block is at least [`safe_depth`] deep: the
//!   wallet's own settlement policy ([`settle_confirmations`]). Until then the
//!   coin is [`CoinStatus::Filling`], never Sealed.
//! - **Unspent.** The coin's spend marker is not used.
//! - **More than one node.** [`NodeChainCheck`] asks every node it was given
//!   (two or more, from the release node list) and answers only when all of
//!   them agree on the chain tip and on the result. A node that cannot be
//!   reached, or any disagreement, is [`CoinStatus::CantCheckNow`].
//!
//! A node is a [`ChainNode`]: a trait, so the enclave reaches its nodes
//! through its outside proxy. Nothing here opens a socket; the real node,
//! JSON-RPC over TLS, is `node_rpc` (features `nitro` and `test-server`).
//!
//! Every Seal is built with a [`CoinStatusCheck`] ([`crate::Seal::new`]
//! takes one): there is no Seal that answers Sealed unchecked.

use core::fmt;

use ghost_wallet_core::coin_tree::PAGE_LEAVES;
use ghost_wallet_core::vanish::COMMIT_ENTRY;
use ghost_wallet_core::{CoinPage, check_coin_pages, commit_leaf, settle_confirmations};

use crate::error::SealError;
use crate::journal::FillEntry;
use crate::primitives::sha3_256;
use crate::traits::{ChainCheck, CoinClaim, PaymentVerdict};

/// The fewest nodes a [`NodeChainCheck`] asks.
pub const MIN_NODES: usize = 2;

/// Where the fingerprint `F` sits in the commit data: after the 2-byte version.
const FINGERPRINT_AT: usize = 2;

/// A Ghost network: its chain id and the hash of its block 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    /// The chain id every transaction is signed for.
    pub chain_id: u64,
    /// The hash of block 0.
    pub genesis: [u8; 32],
}

/// A block, by height and hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRef {
    /// The block's height.
    pub height: u64,
    /// The block's hash.
    pub hash: [u8; 32],
}

/// The coin tree as of one block: the block's header fields that anchor it,
/// the list of page roots and one page of leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinTreeAt {
    /// The anchor block.
    pub block: BlockRef,
    /// The anchor block header's `coinTreeRoot`.
    pub coin_tree_root: [u8; 32],
    /// Every page root, in page order (32 bytes each).
    pub page_roots: Vec<Vec<u8>>,
    /// The page asked for: its number and its leaves, in position order.
    pub page: CoinPage,
}

/// Whether a transaction in a block did what it was sent to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxOutcome {
    /// The receipt's status is success.
    Succeeded,
    /// The receipt's status is failure: nothing was paid.
    Failed,
}

/// The receipt of a transaction to the coin commit entry, with the fields of
/// the transaction it is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VanishReceipt {
    /// The transaction's hash.
    pub transaction_hash: [u8; 32],
    /// The chain id the transaction was signed for.
    pub chain_id: u64,
    /// The address it pays.
    pub to: [u8; 20],
    /// The value it pays, in wei.
    pub value_wei: u128,
    /// Its input: the commit data.
    pub data: Vec<u8>,
    /// Whether it succeeded.
    pub outcome: TxOutcome,
    /// The block it is in.
    pub block: BlockRef,
    /// The coin tree position of the leaf it added.
    pub leaf_position: u64,
}

/// Why a node gave no usable answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeError {
    /// The node could not be reached, or did not answer in time.
    Unreachable,
    /// The node's answers do not fit together.
    Inconsistent(&'static str),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::Unreachable => f.write_str("the node could not be reached"),
            NodeError::Inconsistent(what) => write!(f, "the node's answers do not fit together: {what}"),
        }
    }
}

impl std::error::Error for NodeError {}

/// One node of the release node list, as the chain check asks it. The
/// enclave backs it with its outside proxy; tests back it with a fake chain.
pub trait ChainNode {
    /// The node's name in the release node list. Two nodes with one name are
    /// one node.
    fn name(&self) -> &str;
    /// The network the node follows.
    fn network(&self) -> Result<Network, NodeError>;
    /// The node's chain tip.
    fn tip(&self) -> Result<BlockRef, NodeError>;
    /// The receipts of every transaction to the coin commit entry whose
    /// commit data carries the fingerprint `F` (bytes 2 to 34 of the commit
    /// data), in chain order.
    fn vanish_receipts(&self, fingerprint: &[u8; 32]) -> Result<Vec<VanishReceipt>, NodeError>;
    /// The coin tree as of block `anchor`: the page roots and page `page`.
    fn coin_tree(&self, anchor: &BlockRef, page: u32) -> Result<CoinTreeAt, NodeError>;
    /// Whether spend marker `marker` is used as of block `anchor`.
    fn marker_spent(&self, marker: &[u8; 32], anchor: &BlockRef) -> Result<bool, NodeError>;
}

/// What the chain check is asked about a card's coin: its commit data, the
/// amount the card says it holds and its spend marker, all public (a spend
/// marker is public once the coin is spent and tells nothing before).
#[derive(Clone, PartialEq, Eq)]
pub struct CoinQuery {
    /// The coin's commit data.
    pub commit_data: Vec<u8>,
    /// The amount the coin must hold, in wei.
    pub amount_wei: u128,
    /// The coin's spend marker.
    pub spend_marker: [u8; 32],
}

impl CoinQuery {
    /// SHA3-256 of the commit data: the coin the card names.
    pub fn coin(&self) -> [u8; 32] {
        sha3_256(&[&self.commit_data])
    }
}

impl fmt::Debug for CoinQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The spend marker is left out: logged before a spend, it would let
        // a log reader tie the spend to this card.
        f.debug_struct("CoinQuery")
            .field("commit_data_len", &self.commit_data.len())
            .field("amount_wei", &self.amount_wei)
            .finish_non_exhaustive()
    }
}

/// Where a card's coin stands on the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinStatus {
    /// Paid exactly, settled and unspent: the only status a card is Sealed on.
    ExactSettledUnspent,
    /// Filling, waiting to settle: no exact payment yet (`confirmations` 0),
    /// or one fewer than `needed` blocks deep.
    Filling {
        /// How deep the exact payment's block is (0: none seen yet).
        confirmations: u64,
        /// How deep it must be.
        needed: u64,
    },
    /// A Vanish with exactly this commit data paid another amount.
    WrongAmount,
    /// A Vanish carries this coin's fingerprint with other commit data.
    WrongCommitData,
    /// The payment, or the nodes, are on another network.
    WrongChain,
    /// The coin's spend marker is used.
    Spent,
    /// The nodes could not be reached or do not agree.
    CantCheckNow,
}

impl CoinStatus {
    /// The [`PaymentVerdict`] a Fill's confirmation takes from this status.
    pub fn verdict(self) -> PaymentVerdict {
        match self {
            CoinStatus::ExactSettledUnspent => PaymentVerdict::Paid,
            CoinStatus::Filling { .. } | CoinStatus::CantCheckNow => PaymentVerdict::NotYet,
            CoinStatus::WrongAmount | CoinStatus::WrongCommitData | CoinStatus::WrongChain | CoinStatus::Spent => {
                PaymentVerdict::Mismatch
            }
        }
    }
}

/// The chain status check the Seal asks before it answers Sealed.
pub trait CoinStatusCheck {
    /// Where the coin of `query` stands.
    fn coin_status(&self, query: &CoinQuery) -> CoinStatus;
}

/// How deep a coin of `amount_wei` must be to be settled: the wallet's own
/// settlement policy, today the same for every amount.
pub fn safe_depth(amount_wei: u128) -> u64 {
    let _ = amount_wei;
    settle_confirmations()
}

/// Why a [`NodeChainCheck`] was not made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeListError {
    /// Fewer than [`MIN_NODES`] nodes.
    TooFewNodes,
    /// The same node twice.
    SameNodeTwice,
}

impl fmt::Display for NodeListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeListError::TooFewNodes => write!(f, "the chain check needs at least {MIN_NODES} nodes"),
            NodeListError::SameNodeTwice => f.write_str("a node is listed twice"),
        }
    }
}

impl std::error::Error for NodeListError {}

/// The chain check over two or more independent nodes: an answer only when
/// they all agree on the tip and on the result.
pub struct NodeChainCheck {
    network: Network,
    nodes: Vec<Box<dyn ChainNode>>,
    coins: Vec<CoinQuery>,
}

impl NodeChainCheck {
    /// A check on `network` over `nodes`, at least [`MIN_NODES`] of them, each
    /// named once.
    pub fn new(network: Network, nodes: Vec<Box<dyn ChainNode>>) -> Result<NodeChainCheck, NodeListError> {
        if nodes.len() < MIN_NODES {
            return Err(NodeListError::TooFewNodes);
        }
        for (i, node) in nodes.iter().enumerate() {
            if nodes[..i].iter().any(|other| other.name() == node.name()) {
                return Err(NodeListError::SameNodeTwice);
            }
        }
        Ok(NodeChainCheck { network, nodes, coins: Vec::new() })
    }

    /// Hands over the commit data and spend marker of a coin this check will
    /// confirm as a [`ChainCheck`], which names the coin by its hash only.
    /// (A Seal hands them over itself, from its journal, to the status check
    /// [`crate::Seal::new`] takes.)
    pub fn with_coin(mut self, coin: CoinQuery) -> NodeChainCheck {
        self.coins.retain(|known| known.coin() != coin.coin());
        self.coins.push(coin);
        self
    }

    /// The network this check is for.
    pub fn network(&self) -> Network {
        self.network
    }

    /// What one node says: its tip and the coin's status there.
    fn observe(
        &self,
        node: &dyn ChainNode,
        query: &CoinQuery,
        leaf: &[u8; 32],
    ) -> Result<(BlockRef, CoinStatus), NodeError> {
        let network = node.network()?;
        let tip = node.tip()?;
        if network != self.network {
            return Ok((tip, CoinStatus::WrongChain));
        }
        Ok((tip, self.status_at(node, query, leaf, &tip)?))
    }

    fn status_at(
        &self,
        node: &dyn ChainNode,
        query: &CoinQuery,
        leaf: &[u8; 32],
        tip: &BlockRef,
    ) -> Result<CoinStatus, NodeError> {
        let fingerprint: [u8; 32] =
            query.commit_data[FINGERPRINT_AT..FINGERPRINT_AT + 32].try_into().expect("checked commit data");
        let receipts = node.vanish_receipts(&fingerprint)?;
        let Some(paid) = self.exact_receipt(&receipts, query, tip)? else {
            return Ok(self.closest_miss(&receipts, query));
        };

        // The leaf it added, in a checked page of the tree at the tip.
        let page_number = u32::try_from(paid.leaf_position / PAGE_LEAVES as u64)
            .map_err(|_| NodeError::Inconsistent("the leaf position is past the tree"))?;
        let index = (paid.leaf_position % PAGE_LEAVES as u64) as usize;
        let tree = node.coin_tree(tip, page_number)?;
        if tree.block != *tip {
            return Err(NodeError::Inconsistent("the coin tree is not anchored at the tip"));
        }
        if tree.page.page != page_number {
            return Err(NodeError::Inconsistent("the coin tree page is not the one asked for"));
        }
        check_coin_pages(tree.page_roots, vec![tree.page.clone()], tree.coin_tree_root.to_vec())
            .map_err(|_| NodeError::Inconsistent("the coin tree pages fail their check"))?;
        if tree.page.leaves.get(index).map(Vec::as_slice) != Some(&leaf[..]) {
            return Err(NodeError::Inconsistent("the paid coin's leaf is not in the coin tree"));
        }

        if node.marker_spent(&query.spend_marker, tip)? {
            return Ok(CoinStatus::Spent);
        }
        let confirmations = (tip.height + 1).saturating_sub(paid.block.height);
        let needed = safe_depth(query.amount_wei);
        if confirmations < needed {
            return Ok(CoinStatus::Filling { confirmations, needed });
        }
        Ok(CoinStatus::ExactSettledUnspent)
    }

    /// The successful Vanish paying exactly this commit data and amount on
    /// this network, if any.
    fn exact_receipt<'a>(
        &self,
        receipts: &'a [VanishReceipt],
        query: &CoinQuery,
        tip: &BlockRef,
    ) -> Result<Option<&'a VanishReceipt>, NodeError> {
        let found = receipts.iter().find(|r| {
            r.to == COMMIT_ENTRY
                && r.outcome == TxOutcome::Succeeded
                && r.chain_id == self.network.chain_id
                && r.data == query.commit_data
                && r.value_wei == query.amount_wei
        });
        match found {
            Some(r) if r.block.height > tip.height => Err(NodeError::Inconsistent("a receipt is above the tip")),
            other => Ok(other),
        }
    }

    /// With no exact payment: why the nearest one is not, or Filling when
    /// nothing was paid toward this coin.
    fn closest_miss(&self, receipts: &[VanishReceipt], query: &CoinQuery) -> CoinStatus {
        let paid: Vec<&VanishReceipt> =
            receipts.iter().filter(|r| r.to == COMMIT_ENTRY && r.outcome == TxOutcome::Succeeded).collect();
        let on_network: Vec<&&VanishReceipt> = paid.iter().filter(|r| r.chain_id == self.network.chain_id).collect();
        if on_network.iter().any(|r| r.data == query.commit_data) {
            CoinStatus::WrongAmount
        } else if !on_network.is_empty() {
            CoinStatus::WrongCommitData
        } else if !paid.is_empty() {
            CoinStatus::WrongChain
        } else {
            CoinStatus::Filling { confirmations: 0, needed: safe_depth(query.amount_wei) }
        }
    }
}

impl CoinStatusCheck for NodeChainCheck {
    fn coin_status(&self, query: &CoinQuery) -> CoinStatus {
        // The leaf the exact Vanish adds, from the wallet core. Commit data it
        // refuses can never be paid exactly.
        let leaf = match commit_leaf(query.commit_data.clone(), query.amount_wei.to_string()) {
            Ok(leaf) => leaf,
            Err(_) => return CoinStatus::WrongCommitData,
        };
        let Ok(leaf) = <[u8; 32]>::try_from(leaf.commitment.as_slice()) else {
            return CoinStatus::WrongCommitData;
        };
        let mut agreed: Option<(BlockRef, CoinStatus)> = None;
        for node in &self.nodes {
            let Ok(seen) = self.observe(node.as_ref(), query, &leaf) else {
                return CoinStatus::CantCheckNow;
            };
            match agreed {
                None => agreed = Some(seen),
                Some(first) if first == seen => {}
                Some(_) => return CoinStatus::CantCheckNow,
            }
        }
        agreed.map_or(CoinStatus::CantCheckNow, |(_, status)| status)
    }
}

impl ChainCheck for NodeChainCheck {
    /// Exact, settled and unspent is Paid; Filling and can't check now are
    /// NotYet; a wrong payment or a spent coin is Mismatch. A coin whose
    /// commit data and spend marker were not handed over is NotYet.
    fn confirm_payment(&self, claim: &CoinClaim) -> PaymentVerdict {
        match self.coins.iter().find(|known| known.coin() == claim.coin) {
            None => PaymentVerdict::NotYet,
            Some(known) => {
                let query = CoinQuery { amount_wei: claim.amount_wei, ..known.clone() };
                self.coin_status(&query).verdict()
            }
        }
    }
}

/// The Seal's gate before any Sealed answer: the card's coin, from the Fill
/// journal entry, must be exact, settled and unspent.
pub(crate) fn require_sealable(
    check: &dyn CoinStatusCheck,
    fill: Option<FillEntry>,
    generation: u32,
    coin: [u8; 32],
    amount_wei: u128,
) -> Result<(), SealError> {
    let fill = fill.ok_or(SealError::Journal("no Fill entry for this card's coin"))?;
    if fill.coin != coin || fill.generation != generation || fill.amount_wei != amount_wei {
        return Err(SealError::Journal("the Fill entry is not this card's coin"));
    }
    let query = CoinQuery { commit_data: fill.commit_data, amount_wei, spend_marker: fill.spend_marker };
    match check.coin_status(&query) {
        CoinStatus::ExactSettledUnspent => Ok(()),
        CoinStatus::Filling { .. } => Err(SealError::NotSettled),
        CoinStatus::Spent => Err(SealError::CoinSpent),
        CoinStatus::CantCheckNow => Err(SealError::CantCheckNow),
        CoinStatus::WrongAmount | CoinStatus::WrongCommitData | CoinStatus::WrongChain => {
            Err(SealError::PaymentMismatch)
        }
    }
}
