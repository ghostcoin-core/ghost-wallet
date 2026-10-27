//! The header sync of `header_sync`: a short synthetic chain built here, as
//! Ghost's `client/tests/header_chain.rs` builds its own, fed to `HeaderSync`
//! in batches. Every header is accepted in order; a header with a corrupted
//! byte in its parent hash, a changed difficulty field, an unknown parent or
//! a batch out of order is refused, reported by index, and the best height
//! does not move; a batch split in two (a sync that resumes) ends exactly
//! where one batch does.
//!
//! The headers are mined at difficulty 1 (`D_START = D_MIN = 1`, Ghost's
//! internal network test constants), 30 seconds apart, so every seal passes
//! at nonce 0. Each chain still builds its 256 MiB RandomX cache, so the
//! tests run one at a time.

use std::sync::{Mutex, MutexGuard};

use ghost_client::seal::header_fields;
use ghost_wallet_core::{HeaderChainConstants, HeaderProgress, HeaderSync, HeaderSyncError, PinnedKeyBlock};

/// Ghost's internal network test constants.
const TEST_CHAIN: HeaderChainConstants =
    HeaderChainConstants { block_time: 30, half_life: 3600, start_difficulty: 1, min_difficulty: 1, future_drift: 30 };
/// The internal network's genesis timestamp.
const GENESIS_TIME: u64 = 0x6abd_a280;
/// A clock well after every test header.
const LATER: u64 = GENESIS_TIME + 1_000_000_000;
/// How many headers follow genesis.
const CHAIN_LENGTH: usize = 20;

static ONE_CHAIN_AT_A_TIME: Mutex<()> = Mutex::new(());

fn one_chain() -> MutexGuard<'static, ()> {
    ONE_CHAIN_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner())
}

/// A test-side RLP encoder, written apart from the client's decoder.
fn int(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    bytes[first..].to_vec()
}

fn rlp_length(len: usize, base: u8) -> Vec<u8> {
    if len < 56 {
        return vec![base + len as u8];
    }
    let digits = int(len as u64);
    let mut out = vec![base + 55 + digits.len() as u8];
    out.extend(digits);
    out
}

fn rlp_list(fields: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::new();
    for field in fields {
        if field.len() == 1 && field[0] < 0x80 {
            payload.push(field[0]);
        } else {
            payload.extend(rlp_length(field.len(), 0x80));
            payload.extend(field);
        }
    }
    let mut out = rlp_length(payload.len(), 0xc0);
    out.extend(payload);
    out
}

/// A header under construction.
#[derive(Clone)]
struct Draft {
    parent: [u8; 32],
    number: u64,
    timestamp: u64,
    difficulty: u64,
}

impl Draft {
    /// The header's 19 items, `dataMarkerRoot` last.
    fn rlp(&self) -> Vec<u8> {
        rlp_list(&[
            self.parent.to_vec(),
            vec![0x1d; 32],
            vec![0; 20],
            vec![0x11; 32],
            vec![0x22; 32],
            vec![0x33; 32],
            vec![0; 256],
            int(self.difficulty),
            int(self.number),
            int(30_000_000),
            int(0),
            int(self.timestamp),
            vec![],
            vec![0; 32],
            vec![0; 8],
            int(1_000_000_000),
            vec![0x44; 32],
            vec![0x55; 32],
            vec![0x66; 32],
        ])
    }

    /// The header's hash, as Ghost's decoder computes it.
    fn hash(&self) -> [u8; 32] {
        header_fields(&self.rlp()).unwrap().hash
    }

    /// The child 30 seconds later, at difficulty 1.
    fn child(&self) -> Draft {
        Draft { parent: self.hash(), number: self.number + 1, timestamp: self.timestamp + 30, difficulty: 1 }
    }
}

fn genesis() -> Draft {
    Draft { parent: [0; 32], number: 0, timestamp: GENESIS_TIME, difficulty: 1 }
}

/// The headers after `from`, `count` of them.
fn headers_after(from: &Draft, count: usize) -> Vec<Draft> {
    let mut out: Vec<Draft> = Vec::new();
    for _ in 0..count {
        out.push(out.last().unwrap_or(from).child());
    }
    out
}

fn chain() -> Vec<Draft> {
    headers_after(&genesis(), CHAIN_LENGTH)
}

fn bytes(drafts: &[Draft]) -> Vec<Vec<u8>> {
    drafts.iter().map(Draft::rlp).collect()
}

fn genesis_sync() -> std::sync::Arc<HeaderSync> {
    HeaderSync::from_genesis(genesis().rlp(), TEST_CHAIN).unwrap()
}

fn all_accepted(count: usize, best_height: u64) -> HeaderProgress {
    HeaderProgress { accepted: count as u64, already_held: 0, best_height, refused_index: None, refused_reason: None }
}

#[test]
fn whole_chain_is_accepted() {
    let _one = one_chain();
    let headers = chain();
    let sync = genesis_sync();
    assert_eq!(sync.best_height(), 0);
    assert_eq!(sync.cache_count(), 0);

    let progress = sync.add_headers(bytes(&headers), LATER);
    assert_eq!(progress, all_accepted(CHAIN_LENGTH, CHAIN_LENGTH as u64));
    assert_eq!(sync.best_height(), CHAIN_LENGTH as u64);
    assert_eq!(sync.best_hash(), headers.last().unwrap().hash().to_vec());
    // Every header's seal was checked, under the genesis key block's cache.
    assert_eq!(sync.cache_count(), 1);
}

#[test]
fn corrupted_parent_hash_byte_is_refused() {
    let _one = one_chain();
    let headers = chain();
    let mut batch = bytes(&headers);
    // Flip one byte of header 10's parent hash, in the bytes as downloaded.
    let parent = headers[9].parent;
    let at = batch[9].windows(32).position(|w| w == parent).unwrap();
    batch[9][at + 7] ^= 0x01;

    let sync = genesis_sync();
    let progress = sync.add_headers(batch, LATER);
    assert_eq!(progress.accepted, 9);
    assert_eq!(progress.refused_index, Some(9));
    assert_eq!(progress.refused_reason.as_deref(), Some("the header's parent is not held"));
    assert_eq!(progress.best_height, 9);
    assert_eq!(sync.best_height(), 9);
    assert_eq!(sync.best_hash(), headers[8].hash().to_vec());

    // The real header 10 and the rest still go on top.
    let rest = sync.add_headers(bytes(&headers[9..]), LATER);
    assert_eq!(rest, all_accepted(CHAIN_LENGTH - 9, CHAIN_LENGTH as u64));
}

#[test]
fn changed_difficulty_field_is_refused() {
    let _one = one_chain();
    let headers = chain();
    let sync = genesis_sync();
    assert_eq!(sync.add_headers(bytes(&headers[..5]), LATER), all_accepted(5, 5));

    for difficulty in [0, 2, 1 << 17] {
        let wrong = Draft { difficulty, ..headers[5].clone() };
        let progress = sync.add_headers(vec![wrong.rlp(), headers[6].rlp()], LATER);
        assert_eq!(progress.accepted, 0, "difficulty {difficulty}");
        assert_eq!(progress.refused_index, Some(0), "difficulty {difficulty}");
        assert_eq!(
            progress.refused_reason.as_deref(),
            Some("the header does not carry the required difficulty"),
            "difficulty {difficulty}"
        );
        assert_eq!(progress.best_height, 5, "difficulty {difficulty}");
        assert_eq!(sync.best_height(), 5, "difficulty {difficulty}");
    }
}

#[test]
fn out_of_order_batch_is_refused() {
    let _one = one_chain();
    let headers = chain();
    let mut batch = bytes(&headers);
    batch.swap(3, 4);

    let sync = genesis_sync();
    let progress = sync.add_headers(batch, LATER);
    assert_eq!(progress.accepted, 3);
    assert_eq!(progress.refused_index, Some(3));
    assert_eq!(progress.refused_reason.as_deref(), Some("the header's parent is not held"));
    assert_eq!(progress.best_height, 3);
    assert_eq!(sync.best_height(), 3);
}

#[test]
fn batch_split_in_two_accepts_like_one_batch() {
    let _one = one_chain();
    let headers = chain();

    let whole_hash = {
        let whole = genesis_sync();
        assert_eq!(whole.add_headers(bytes(&headers), LATER), all_accepted(CHAIN_LENGTH, CHAIN_LENGTH as u64));
        whole.best_hash()
    };

    let split = genesis_sync();
    let first = split.add_headers(bytes(&headers[..12]), LATER);
    assert_eq!(first, all_accepted(12, 12));
    // Resume from the best height the sync reports, as the app does.
    let from = split.best_height() as usize;
    let second = split.add_headers(bytes(&headers[from..]), LATER);
    assert_eq!(second, all_accepted(CHAIN_LENGTH - 12, CHAIN_LENGTH as u64));
    assert_eq!(first.accepted + second.accepted, CHAIN_LENGTH as u64);
    assert_eq!(split.best_hash(), whole_hash);
    assert_eq!(split.cache_count(), 1);

    // Headers offered again are reported as already held, not as accepted.
    let again = split.add_headers(bytes(&headers[15..]), LATER);
    assert_eq!(
        again,
        HeaderProgress {
            accepted: 0,
            already_held: (CHAIN_LENGTH - 15) as u64,
            best_height: CHAIN_LENGTH as u64,
            refused_index: None,
            refused_reason: None,
        }
    );
}

#[test]
fn unknown_parent_is_refused() {
    let _one = one_chain();
    let headers = chain();
    let sync = genesis_sync();

    let orphan = Draft { parent: [0x42; 32], ..headers[0].clone() };
    let progress = sync.add_headers(vec![orphan.rlp()], LATER);
    assert_eq!(progress.refused_index, Some(0));
    assert_eq!(progress.refused_reason.as_deref(), Some("the header's parent is not held"));
    assert_eq!(progress.best_height, 0);

    // A header two above the tip, its parent missing.
    let progress = sync.add_headers(vec![headers[1].rlp()], LATER);
    assert_eq!(progress.refused_index, Some(0));
    assert_eq!(progress.best_height, 0);
    assert_eq!(sync.best_hash(), genesis().hash().to_vec());
}

#[test]
fn pinned_checkpoint_starts_the_chain() {
    let _one = one_chain();
    let pin = Draft { parent: [0x77; 32], number: 1000, timestamp: GENESIS_TIME + 30 * 1000, difficulty: 1 };
    let key_block = PinnedKeyBlock { height: 0, hash: vec![0x99; 32] };
    let sync = HeaderSync::from_checkpoint(
        pin.rlp(),
        1000,
        int(1001),
        GENESIS_TIME,
        vec![key_block.clone()],
        TEST_CHAIN,
    )
    .unwrap();
    assert_eq!(sync.best_height(), 1000);
    assert_eq!(sync.add_headers(bytes(&headers_after(&pin, 5)), LATER), all_accepted(5, 1005));
    assert_eq!(sync.cache_count(), 1);

    // A header below the pin does not link to it.
    assert_eq!(sync.add_headers(vec![genesis().child().rlp()], LATER).refused_index, Some(0));

    // The pin's own checks.
    let refused = |height: u64, work: Vec<u8>, key: Vec<u8>| {
        HeaderSync::from_checkpoint(
            pin.rlp(),
            height,
            work,
            GENESIS_TIME,
            vec![PinnedKeyBlock { height: 0, hash: key }],
            TEST_CHAIN,
        )
        .err()
    };
    assert!(matches!(refused(999, int(1001), vec![0x99; 32]), Some(HeaderSyncError::Start { .. })));
    assert!(matches!(refused(1000, vec![], vec![0x99; 32]), Some(HeaderSyncError::Start { .. })));
    assert!(matches!(refused(1000, int(1001), vec![0x99; 31]), Some(HeaderSyncError::Start { .. })));
    assert!(matches!(refused(1000, vec![1; 33], vec![0x99; 32]), Some(HeaderSyncError::Start { .. })));
}

#[test]
fn bad_genesis_is_refused() {
    let _one = one_chain();
    let at_two = Draft { difficulty: 2, ..genesis() };
    assert!(matches!(HeaderSync::from_genesis(at_two.rlp(), TEST_CHAIN).err(), Some(HeaderSyncError::Start { .. })));
    assert!(matches!(
        HeaderSync::from_genesis(genesis().child().rlp(), TEST_CHAIN).err(),
        Some(HeaderSyncError::Start { .. })
    ));
    let mut broken = genesis().rlp();
    broken.push(0);
    assert!(matches!(HeaderSync::from_genesis(broken, TEST_CHAIN).err(), Some(HeaderSyncError::Start { .. })));
}
