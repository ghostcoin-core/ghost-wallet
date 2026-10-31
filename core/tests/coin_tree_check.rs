//! The coin tree from the node's pages: page roots rebuilt from leaves, the
//! tree root from the page-root list, checked against the block's
//! `coinTreeRoot`, and the typed key's note buckets. The expected roots are
//! built here the plain way, over every position of the tree, with Ghost's own
//! `tree_node`.

use ghost_client::note_tag::{bucket_bits, bucket_prefix, lookup_tag};
use ghost_client::{KeyFormat, PhantomKey};
use ghost_proofs::{Tree, empty_leaf, tree_node};
use ghost_wallet_core::{
    BucketNote, CoinPage, CoinTreeError, PAGE_LEAVES, TEST_CHAIN_ID, VanishError, check_coin_pages, commit_leaf,
    key_bucket_positions, key_note_buckets, note_bucket_bits, vanish_commit_with,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

/// A stand-in leaf for position `i`: distinct for every position.
fn leaf(i: u32) -> [u8; 32] {
    let mut bytes = [0x5a; 32];
    bytes[..4].copy_from_slice(&i.to_be_bytes());
    bytes
}

/// The root over `leaves` from position 0, every other position empty, all
/// 32 levels hashed position by position.
fn plain_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut level = leaves.to_vec();
    let mut zero = empty_leaf();
    for depth in 0..32u8 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let right = if i + 1 < level.len() { level[i + 1] } else { zero };
            next.push(tree_node(Tree::Coin, depth, &level[i], &right));
            i += 2;
        }
        level = next;
        zero = tree_node(Tree::Coin, depth, &zero, &zero);
    }
    level.first().copied().unwrap_or(zero)
}

/// The node's page roots and pages for `leaves`: each page root is the plain
/// root of the page's leaves taken over only 12 levels.
fn served(leaves: &[[u8; 32]]) -> (Vec<Vec<u8>>, Vec<CoinPage>) {
    let mut roots = Vec::new();
    let mut pages = Vec::new();
    for (page, chunk) in leaves.chunks(PAGE_LEAVES).enumerate() {
        let mut level = chunk.to_vec();
        let mut zero = empty_leaf();
        for depth in 0..12u8 {
            let mut next = Vec::new();
            let mut i = 0;
            while i < level.len() {
                let right = if i + 1 < level.len() { level[i + 1] } else { zero };
                next.push(tree_node(Tree::Coin, depth, &level[i], &right));
                i += 2;
            }
            level = next;
            zero = tree_node(Tree::Coin, depth, &zero, &zero);
        }
        roots.push(level[0].to_vec());
        pages.push(CoinPage { page: page as u32, leaves: chunk.iter().map(|leaf| leaf.to_vec()).collect() });
    }
    (roots, pages)
}

fn leaves(count: u32) -> Vec<[u8; 32]> {
    (0..count).map(leaf).collect()
}

#[test]
fn pages_and_roots_of_ten_thousand_leaves_check_against_the_block_root() {
    let all = leaves(10_000);
    let (roots, pages) = served(&all);
    assert_eq!(roots.len(), 3);
    assert_eq!(pages[2].leaves.len(), 10_000 - 2 * PAGE_LEAVES);
    check_coin_pages(roots, pages, plain_root(&all).to_vec()).expect("the node's pages match its block");
}

#[test]
fn a_full_page_and_an_empty_tree_check() {
    let all = leaves(PAGE_LEAVES as u32);
    let (roots, pages) = served(&all);
    check_coin_pages(roots, pages, plain_root(&all).to_vec()).unwrap();
    check_coin_pages(Vec::new(), Vec::new(), plain_root(&[]).to_vec()).unwrap();
}

#[test]
fn roots_alone_check_without_any_page() {
    let all = leaves(5_000);
    let (roots, _) = served(&all);
    check_coin_pages(roots, Vec::new(), plain_root(&all).to_vec()).unwrap();
}

#[test]
fn a_page_whose_leaves_do_not_make_its_root_is_refused() {
    let all = leaves(10_000);
    let (roots, mut pages) = served(&all);
    pages[1].leaves[17][31] ^= 1;
    let refused = check_coin_pages(roots, pages, plain_root(&all).to_vec());
    assert!(matches!(refused, Err(CoinTreeError::Mismatch { .. })), "{refused:?}");
}

#[test]
fn a_page_missing_its_last_leaf_is_refused() {
    let all = leaves(10_000);
    let (roots, mut pages) = served(&all);
    pages[2].leaves.pop();
    assert!(matches!(
        check_coin_pages(roots, pages, plain_root(&all).to_vec()),
        Err(CoinTreeError::Mismatch { .. })
    ));
}

#[test]
fn page_roots_that_do_not_make_the_block_root_are_refused() {
    let all = leaves(10_000);
    let (mut roots, pages) = served(&all);
    roots[0][0] ^= 1;
    assert!(matches!(
        check_coin_pages(roots.clone(), Vec::new(), plain_root(&all).to_vec()),
        Err(CoinTreeError::Mismatch { .. })
    ));
    // Consistent pages and roots of another tree are refused by the block root too.
    let (other_roots, other_pages) = served(&leaves(9_999));
    assert!(matches!(
        check_coin_pages(other_roots, other_pages, plain_root(&all).to_vec()),
        Err(CoinTreeError::Mismatch { .. })
    ));
    // A root list with a page dropped does not stand for the same tree.
    let (mut short, _) = served(&all);
    short.pop();
    assert!(check_coin_pages(short, pages, plain_root(&all).to_vec()).is_err());
}

#[test]
fn malformed_data_is_refused() {
    let all = leaves(10);
    let (roots, mut pages) = served(&all);
    let root = plain_root(&all).to_vec();
    assert!(matches!(
        check_coin_pages(roots.clone(), pages.clone(), root[..31].to_vec()),
        Err(CoinTreeError::Malformed { .. })
    ));
    pages[0].page = 1;
    assert!(matches!(
        check_coin_pages(roots.clone(), pages.clone(), root.clone()),
        Err(CoinTreeError::Malformed { .. })
    ));
    pages[0].page = 0;
    pages[0].leaves[3] = vec![1; 31];
    assert!(matches!(check_coin_pages(roots, pages, root), Err(CoinTreeError::Malformed { .. })));
}

#[test]
fn bucket_bits_are_ghosts() {
    assert_eq!(note_bucket_bits(0), 0);
    assert_eq!(note_bucket_bits(8_191), 0);
    assert_eq!(note_bucket_bits(8_192), 1);
    assert_eq!(note_bucket_bits(10_000), 1);
    assert_eq!(note_bucket_bits(40_000), bucket_bits(40_000));
}

fn key(seed: u64) -> PhantomKey {
    PhantomKey::generate(KeyFormat::Words, &mut StdRng::seed_from_u64(seed))
}

fn words_of(key: &PhantomKey) -> String {
    key.format_words().expect("a words key").as_str().to_owned()
}

#[test]
fn a_keys_buckets_are_its_first_sixteen_tags_each_prefix_once() {
    let key = key(41);
    let query = key_note_buckets(words_of(&key), 40_000).unwrap();
    let bits = bucket_bits(40_000);
    assert_eq!(query.bits, bits);
    let mut expected = Vec::new();
    for number in 0..16 {
        let prefix = bucket_prefix(&lookup_tag(&key.note_key(), number), bits);
        if !expected.contains(&prefix) {
            expected.push(prefix);
        }
    }
    assert_eq!(query.prefixes, expected);
    // One bit: at most the two buckets.
    let small = key_note_buckets(words_of(&key), 10_000).unwrap();
    assert_eq!(small.bits, 1);
    assert!(!small.prefixes.is_empty() && small.prefixes.len() <= 2);
}

#[test]
fn a_keys_notes_are_picked_out_of_a_bucket() {
    let ours = key(51);
    let other = key(52);
    let note_of = |key: &PhantomKey, seed: u64| {
        let commit = vanish_commit_with(key, TEST_CHAIN_ID, 1_000_000, &mut StdRng::seed_from_u64(seed)).unwrap();
        commit_leaf(commit.commit_data, commit.amount_wei).unwrap().note
    };
    let notes = vec![
        BucketNote { position: 9, note: note_of(&other, 1) },
        BucketNote { position: 7, note: note_of(&ours, 2) },
        BucketNote { position: 12, note: vec![0; 10] },
        BucketNote { position: 7, note: note_of(&ours, 2) },
    ];
    assert_eq!(key_bucket_positions(words_of(&ours), notes).unwrap(), vec![7]);
}

#[test]
fn account_words_are_never_taken_as_a_key_for_buckets() {
    let words = ghost_client::account::WalletSeed::from_bytes([3; 32]).to_words().as_str().to_owned();
    assert!(matches!(key_note_buckets(words, 10_000), Err(VanishError::NotAKey { .. })));
}
