//! The coin tree from the node's pages (spec 05, section 8, "Wallet tree
//! data"), checked here, where the tree hashing is.
//!
//! The node serves the tree as pages of 4,096 leaves and one list of page
//! roots, all as of an anchor block whose header holds `coinTreeRoot`.
//! [`check_coin_pages`] rebuilds each page root from its leaves (empty
//! positions are `E`) and the tree root from the page-root list (pages after
//! the list are `Z_12`), and refuses the node's data on any mismatch: the app
//! never fills a gap and never uses a page it could not check.
//!
//! For a large tree the app reads only the note buckets of the key's lookup
//! tags first: [`note_bucket_bits`] is the bucket size of a tree, and
//! [`key_note_buckets`] and [`key_bucket_positions`] turn the typed key into
//! its bucket prefixes and pick its notes out of the buckets. A bucket is a
//! hint with no root over it: a coin counts only from a checked page. The key
//! text is wiped once read, and nothing here formats it.

use core::fmt;

use ghost_client::PhantomKey;
use ghost_client::account::WalletSeed;
use ghost_client::note_tag::{TAG_BATCH, bucket_bits, bucket_prefix, lookup_tag, note_lookup_tag};
use ghost_client::reveal::TREE_DEPTH;
use ghost_client::NOTE_BYTES;
use ghost_proofs::{Tree, empty_leaf, tree_node};

use crate::accounts::wipe_string;
use crate::vanish::VanishError;

/// Leaves per page.
pub const PAGE_LEAVES: usize = 4096;
/// The levels a page spans: its root is the level-11 node.
pub const PAGE_LEVELS: usize = 12;
/// Pages in one tree.
pub const TREE_PAGES: u64 = 1 << (TREE_DEPTH - PAGE_LEVELS);

/// One page the node sent: its number and its leaves, in position order.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CoinPage {
    pub page: u32,
    pub leaves: Vec<Vec<u8>>,
}

/// Why the node's tree data was refused. No message holds a hash.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum CoinTreeError {
    /// The data is not laid out as pages and roots.
    Malformed { reason: String },
    /// The data does not hash to the root above it.
    Mismatch { reason: String },
}

impl fmt::Display for CoinTreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { reason } => write!(f, "the node's coin tree pages cannot be read: {reason}"),
            Self::Mismatch { reason } => write!(f, "the node's coin tree pages do not match its block: {reason}"),
        }
    }
}

impl std::error::Error for CoinTreeError {}

fn malformed(reason: &str) -> CoinTreeError {
    CoinTreeError::Malformed { reason: reason.to_owned() }
}

fn mismatch(reason: &str) -> CoinTreeError {
    CoinTreeError::Mismatch { reason: reason.to_owned() }
}

fn hash32(bytes: &[u8], what: &str) -> Result<[u8; 32], CoinTreeError> {
    bytes.try_into().map_err(|_| malformed(&format!("{what} is not 32 bytes")))
}

/// The node at level `from + levels - 1` over `nodes` (level `from - 1`
/// nodes, or leaves when `from` is 0), the rest of the span being `zero`.
fn fold(mut nodes: Vec<[u8; 32]>, from: usize, levels: usize, mut zero: [u8; 32]) -> [u8; 32] {
    for level in from..from + levels {
        nodes = nodes
            .chunks(2)
            .map(|pair| tree_node(Tree::Coin, level as u8, &pair[0], pair.get(1).unwrap_or(&zero)))
            .collect();
        zero = tree_node(Tree::Coin, level as u8, &zero, &zero);
    }
    nodes.first().copied().unwrap_or(zero)
}

/// `Z_12`: the root of an empty page.
fn empty_page_root() -> [u8; 32] {
    fold(Vec::new(), 0, PAGE_LEVELS, empty_leaf())
}

/// The root of a page holding `leaves` from its first position on.
pub fn page_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    fold(leaves.to_vec(), 0, PAGE_LEVELS, empty_leaf())
}

/// The tree root over the page roots, pages after the list being empty.
pub fn tree_root_of_pages(page_roots: &[[u8; 32]]) -> [u8; 32] {
    fold(page_roots.to_vec(), PAGE_LEVELS, TREE_DEPTH - PAGE_LEVELS, empty_page_root())
}

/// Checks the node's page roots against the anchor header's `coinTreeRoot`,
/// and each page against its root in the list (spec 05, section 8, steps 1
/// and 2). Refuses on any mismatch.
#[uniffi::export]
pub fn check_coin_pages(
    page_roots: Vec<Vec<u8>>,
    pages: Vec<CoinPage>,
    coin_tree_root: Vec<u8>,
) -> Result<(), CoinTreeError> {
    if page_roots.len() as u64 > TREE_PAGES {
        return Err(malformed("there are more page roots than pages in a tree"));
    }
    let roots = page_roots
        .iter()
        .map(|root| hash32(root, "a page root"))
        .collect::<Result<Vec<_>, _>>()?;
    let header_root = hash32(&coin_tree_root, "the block's coin tree root")?;
    if tree_root_of_pages(&roots) != header_root {
        return Err(mismatch("the page roots do not make the block's coin tree root"));
    }
    for page in &pages {
        let listed = roots
            .get(page.page as usize)
            .ok_or_else(|| malformed("a page is not in the page-root list"))?;
        if page.leaves.len() > PAGE_LEAVES {
            return Err(malformed("a page holds more than 4,096 leaves"));
        }
        let leaves = page
            .leaves
            .iter()
            .map(|leaf| hash32(leaf, "a leaf"))
            .collect::<Result<Vec<_>, _>>()?;
        if page_root(&leaves) != *listed {
            return Err(mismatch("a page's leaves do not make its page root"));
        }
    }
    Ok(())
}

/// The prefix bits of a tree of `note_count` notes, Ghost's `bucket_bits`:
/// 0 (one bucket, read as whole pages) below 8,192 notes.
#[uniffi::export]
pub fn note_bucket_bits(note_count: u64) -> u32 {
    bucket_bits(note_count)
}

/// The buckets to ask for a key, in a tree of `note_count` notes.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BucketQuery {
    pub bits: u32,
    /// The distinct prefixes of the key's first 16 lookup tags, in number order.
    pub prefixes: Vec<u32>,
}

/// One note a bucket holds, at its position in the tree.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BucketNote {
    pub position: u32,
    pub note: Vec<u8>,
}

/// Parses the typed key and wipes the text, as `vanish` does: account words
/// are refused by name, never parsed as a key.
fn parse_key(text: String) -> Result<PhantomKey, VanishError> {
    let result = if WalletSeed::from_words(&text).is_ok() {
        Err(VanishError::NotAKey { reason: "these are account words, not a Phantom Key".to_owned() })
    } else {
        PhantomKey::parse(&text).map_err(|error| VanishError::NotAKey { reason: error.to_string() })
    };
    wipe_string(text);
    result
}

fn key_tags(key: &PhantomKey) -> Vec<[u8; 3]> {
    let note_key = key.note_key();
    (0..TAG_BATCH).map(|number| lookup_tag(&note_key, number)).collect()
}

/// The buckets of the typed key's first 16 commitment numbers, each prefix once.
#[uniffi::export]
pub fn key_note_buckets(key_text: String, note_count: u64) -> Result<BucketQuery, VanishError> {
    let key = parse_key(key_text)?;
    let bits = bucket_bits(note_count);
    let mut prefixes = Vec::new();
    for tag in key_tags(&key) {
        let prefix = bucket_prefix(&tag, bits);
        if !prefixes.contains(&prefix) {
            prefixes.push(prefix);
        }
    }
    Ok(BucketQuery { bits, prefixes })
}

/// The positions, ascending and each once, of the notes whose lookup tag is
/// one of the typed key's first 16. Notes of the wrong size are skipped.
#[uniffi::export]
pub fn key_bucket_positions(key_text: String, notes: Vec<BucketNote>) -> Result<Vec<u32>, VanishError> {
    let key = parse_key(key_text)?;
    let tags = key_tags(&key);
    let mut positions: Vec<u32> = notes
        .iter()
        .filter_map(|entry| {
            let note: &[u8; NOTE_BYTES] = entry.note.as_slice().try_into().ok()?;
            tags.contains(&note_lookup_tag(note)).then_some(entry.position)
        })
        .collect();
    positions.sort_unstable();
    positions.dedup();
    Ok(positions)
}
