//! Header sync: checks the headers a Ghost node sends, from a start pinned in
//! the build, with Ghost's own `ghost_client::header_chain::HeaderChain`.
//!
//! The chain starts at a pinned genesis header (`HeaderChain::from_genesis`)
//! or a pinned checkpoint (`HeaderChain::from_pinned`). Every header after it
//! goes through `HeaderChain::add_header`, which checks its parent, number,
//! timestamp, its ASERT difficulty and its RandomX seal. RandomX runs in
//! `ghost_client::randomx`, interpreted with light caches (no JIT, no
//! dataset), so it runs on iOS; the chain holds at most two 256 MiB caches
//! (`SealKey`) at a time. No consensus or seal code lives here.
//!
//! There is no network code either: the app downloads the header bytes and
//! passes them in, in batches. The chain stays in memory between batches, so
//! a sync that resumes (after the app was backgrounded, say) continues from
//! the best height without checking anything twice.

use core::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use ghost_client::header_chain::{Added, ChainParams, HeaderChain, PinnedStart, StartError, U256};

/// The chain constants of spec 06, section 4.2, as the app passes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct HeaderChainConstants {
    /// The block time, in seconds.
    pub block_time: u64,
    /// The ASERT half-life, in seconds.
    pub half_life: u64,
    /// The genesis difficulty, the ASERT anchor.
    pub start_difficulty: u64,
    /// Difficulty never goes below this.
    pub min_difficulty: u64,
    /// How many seconds a header may be ahead of the phone's clock.
    pub future_drift: u64,
}

impl From<HeaderChainConstants> for ChainParams {
    fn from(c: HeaderChainConstants) -> Self {
        ChainParams {
            block_time: c.block_time,
            half_life: c.half_life,
            start_difficulty: c.start_difficulty,
            min_difficulty: c.min_difficulty,
            future_drift: c.future_drift,
        }
    }
}

/// A key block below a pinned checkpoint that the headers after it use.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PinnedKeyBlock {
    /// Its height: 0 or a multiple of the epoch length.
    pub height: u64,
    /// Its 32-byte hash.
    pub hash: Vec<u8>,
}

/// What one batch did.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HeaderProgress {
    /// Headers of the batch checked and newly held, before the first refused
    /// one.
    pub accepted: u64,
    /// Headers of the batch that were already held (offered again); they
    /// change nothing.
    pub already_held: u64,
    /// The height of the best chain's tip after the batch.
    pub best_height: u64,
    /// The index in the batch of the first refused header. Nothing after it
    /// is looked at: no header is ever passed over.
    pub refused_index: Option<u64>,
    /// Why that header was refused.
    pub refused_reason: Option<String>,
}

/// Why a header sync could not start.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum HeaderSyncError {
    /// The pinned start or the chain constants were refused.
    Start { reason: String },
}

impl fmt::Display for HeaderSyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderSyncError::Start { reason } => write!(f, "the pinned start was refused: {reason}"),
        }
    }
}

impl std::error::Error for HeaderSyncError {}

impl From<StartError> for HeaderSyncError {
    fn from(error: StartError) -> Self {
        HeaderSyncError::Start { reason: error.to_string() }
    }
}

/// A header chain checked from a pinned start, fed in batches.
#[derive(uniffi::Object)]
pub struct HeaderSync {
    chain: Mutex<HeaderChain>,
}

#[uniffi::export]
impl HeaderSync {
    /// Starts at a pinned genesis header (its RLP bytes).
    #[uniffi::constructor]
    pub fn from_genesis(genesis: Vec<u8>, constants: HeaderChainConstants) -> Result<Arc<Self>, HeaderSyncError> {
        let chain = HeaderChain::from_genesis(&genesis, constants.into())?;
        Ok(Arc::new(Self { chain: Mutex::new(chain) }))
    }

    /// Starts at a pinned checkpoint: its RLP bytes, its height, the total
    /// work up to and including it (big-endian), the genesis timestamp and
    /// the key blocks below it that the headers after it use.
    #[uniffi::constructor]
    pub fn from_checkpoint(
        header: Vec<u8>,
        height: u64,
        total_work: Vec<u8>,
        genesis_timestamp: u64,
        key_blocks: Vec<PinnedKeyBlock>,
        constants: HeaderChainConstants,
    ) -> Result<Arc<Self>, HeaderSyncError> {
        let total_work = U256::from_be_bytes(&total_work)
            .ok_or_else(|| HeaderSyncError::Start { reason: "the total work does not fit in 256 bits".to_owned() })?;
        let key_blocks = key_blocks
            .into_iter()
            .map(|block| {
                let hash: [u8; 32] = block.hash.as_slice().try_into().map_err(|_| HeaderSyncError::Start {
                    reason: "a key block hash is not 32 bytes".to_owned(),
                })?;
                Ok((block.height, hash))
            })
            .collect::<Result<Vec<_>, HeaderSyncError>>()?;
        let pin = PinnedStart { header, height, total_work, genesis_timestamp, key_blocks };
        let chain = HeaderChain::from_pinned(pin, constants.into())?;
        Ok(Arc::new(Self { chain: Mutex::new(chain) }))
    }

    /// Checks each header of `batch` in order with `HeaderChain::add_header`
    /// and stops at the first one refused. `now` is the phone's clock in Unix
    /// seconds.
    pub fn add_headers(&self, batch: Vec<Vec<u8>>, now: u64) -> HeaderProgress {
        let mut chain = self.chain();
        let mut progress =
            HeaderProgress { accepted: 0, already_held: 0, best_height: 0, refused_index: None, refused_reason: None };
        for (index, header) in batch.iter().enumerate() {
            match chain.add_header(header, now) {
                Ok(Added::AlreadyHeld) => progress.already_held += 1,
                Ok(Added::Extended | Added::SideBranch | Added::Reorganised { .. }) => progress.accepted += 1,
                Err(error) => {
                    progress.refused_index = Some(index as u64);
                    progress.refused_reason = Some(error.to_string());
                    break;
                }
            }
        }
        progress.best_height = chain.best_height();
        progress
    }

    /// The height of the best chain's tip.
    pub fn best_height(&self) -> u64 {
        self.chain().best_height()
    }

    /// The hash of the best chain's tip.
    pub fn best_hash(&self) -> Vec<u8> {
        self.chain().best_hash().to_vec()
    }

    /// How many RandomX caches are held now (at most two).
    pub fn cache_count(&self) -> u64 {
        self.chain().cache_count() as u64
    }
}

impl HeaderSync {
    fn chain(&self) -> MutexGuard<'_, HeaderChain> {
        // A panic while holding the lock leaves the chain as it was before the
        // header being added: nothing is held until every check passed.
        self.chain.lock().unwrap_or_else(|e| e.into_inner())
    }
}
