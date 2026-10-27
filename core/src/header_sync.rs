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
//! passes them in, in batches.
//!
//! Progress is saved: after each batch that adopted a header, the verified
//! tip and the [`RECENT_HEADERS`] best-chain headers below it are encoded
//! ([`HeaderSync::saved_state`]) and handed to the app's [`HeaderStore`], so
//! a sync opened again from the store continues where it stopped. The saved
//! headers are read back with `HeaderChain::add_saved_header`: every check
//! but the seal is made again, so reading them back builds no RandomX cache.
//!
//! The pinned ghost-client cannot drop a cache on its own, so
//! [`HeaderSync::release_caches`] drops the whole `HeaderChain` and the next
//! run rebuilds it from the saved state. The app releases the caches before a
//! proof starts, so the caches and the prover are not held at once.
//!
//! A budgeted run ([`HeaderSync::start_run`]) stops on its CPU time, header
//! count or byte budget, when cancelled, at thermal state serious or above,
//! and in Low Power Mode. Nothing waits on another caller: a run that finds
//! the chain in use returns at once, and the readers (`best_height`,
//! `cache_count`, `state`, ...) read a copy that is updated after every
//! header. A header that fails, or a saved chain that conflicts with the
//! pinned checkpoint, puts the sync in [`ChainState::Invalid`].

use core::fmt;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::Instant;

use ghost_client::header_chain::{Added, ChainError, ChainParams, HeaderChain, PinnedStart, StartError, U256};
use ghost_client::seal::{EPOCH_BLOCKS, header_fields, seed_height};
use tiny_keccak::{Hasher, Keccak};

/// How many best-chain headers below the tip are saved with it. A reorg up to
/// this deep still links after a restart.
pub const RECENT_HEADERS: u64 = 512;

/// The layout of [`HeaderSync::saved_state`].
pub const SAVED_STATE_VERSION: u32 = 1;

const SAVED_MAGIC: &[u8; 4] = b"GHSS";

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

/// The best chain switched branches.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ReorgEvent {
    /// The hash of the best chain's tip before the switch.
    pub old_tip: Vec<u8>,
    /// Its height.
    pub old_height: u64,
    /// The hash of the new tip.
    pub new_tip: Vec<u8>,
    /// Its height.
    pub new_height: u64,
    /// How many headers of the old best chain are no longer on it.
    pub depth: u64,
    /// How many headers of the new branch are now on it, the new tip included.
    pub added: u64,
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
    /// The reorganisations the batch caused, in order.
    pub reorgs: Vec<ReorgEvent>,
}

/// Whether the chain can still be trusted.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ChainState {
    /// Every header held passed its checks.
    Valid,
    /// A header failed its checks, or the saved chain conflicts with the
    /// pinned checkpoint. Budgeted runs stop; open the sync again (from the
    /// store, against another node) to go on.
    Invalid { reason: String },
}

/// The phone's thermal state, as `ProcessInfo.thermalState` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, uniffi::Enum)]
pub enum ThermalState {
    Nominal,
    Fair,
    Serious,
    Critical,
}

impl ThermalState {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Nominal,
            1 => Self::Fair,
            2 => Self::Serious,
            _ => Self::Critical,
        }
    }
}

/// What the phone reports about itself; a run stops at thermal state serious
/// or above and in Low Power Mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct DeviceConditions {
    pub thermal: ThermalState,
    pub low_power_mode: bool,
}

/// The most one run may spend, over all its batches.
#[derive(Debug, Clone, Copy, PartialEq, uniffi::Record)]
pub struct RunBudget {
    /// Seconds spent checking headers (and rebuilding the chain) on the
    /// calling thread. The checks do no I/O, so this is CPU time.
    pub cpu_seconds: f64,
    /// Headers looked at, already held ones included.
    pub max_headers: u64,
    /// Bytes of header RLP looked at.
    pub max_bytes: u64,
}

/// What a run has spent so far.
#[derive(Debug, Clone, Copy, PartialEq, uniffi::Record)]
pub struct RunSpent {
    pub cpu_seconds: f64,
    pub headers: u64,
    pub bytes: u64,
}

/// Why a run stopped before the end of a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum StopReason {
    /// The CPU time budget is spent.
    CpuBudget,
    /// The header budget is spent.
    HeaderBudget,
    /// The next header would go over the byte budget.
    ByteBudget,
    /// The run was cancelled.
    Cancelled,
    /// The thermal state is serious or above.
    Thermal,
    /// Low Power Mode is on.
    LowPowerMode,
    /// The caches were released for a proof.
    CachesReleased,
    /// The chain is in [`ChainState::Invalid`].
    InvalidChain,
    /// A header is too far ahead of the clock; offer it again later.
    HeaderAhead,
    /// Another call is checking headers now; nothing was looked at. The only
    /// reason that does not end the run.
    Busy,
}

/// What one batch of a run did.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct RunProgress {
    /// Headers checked and newly held.
    pub accepted: u64,
    /// Headers already held.
    pub already_held: u64,
    /// Headers of the batch not looked at, because the run stopped.
    pub unchecked: u64,
    /// The best chain's tip after the batch.
    pub best_height: u64,
    pub best_hash: Vec<u8>,
    /// Why the run stopped, if it did. A stopped run looks at nothing more;
    /// start another one.
    pub stopped: Option<StopReason>,
    /// The reorganisations of the batch, in order.
    pub reorgs: Vec<ReorgEvent>,
    /// What the run has spent, this batch included.
    pub spent: RunSpent,
    /// Why saving the progress failed, if it did. The progress is still held
    /// in memory and saved again after the next batch.
    pub save_error: Option<String>,
}

/// Why a header sync could not start.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum HeaderSyncError {
    /// The pinned start or the chain constants were refused.
    Start { reason: String },
    /// The store could not be read.
    Store { reason: String },
    /// The saved state does not decode or does not rebuild.
    Saved { reason: String },
}

impl fmt::Display for HeaderSyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderSyncError::Start { reason } => write!(f, "the pinned start was refused: {reason}"),
            HeaderSyncError::Store { reason } => write!(f, "the header store failed: {reason}"),
            HeaderSyncError::Saved { reason } => write!(f, "the saved header state is refused: {reason}"),
        }
    }
}

impl std::error::Error for HeaderSyncError {}

impl From<StartError> for HeaderSyncError {
    fn from(error: StartError) -> Self {
        HeaderSyncError::Start { reason: error.to_string() }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for HeaderSyncError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        HeaderSyncError::Store { reason: error.reason }
    }
}

/// Where the saved state lives between launches: on the phone, a file in
/// protected app storage. It holds headers only, nothing secret.
#[uniffi::export(callback_interface)]
pub trait HeaderStore: Send + Sync {
    /// The state saved last, if any.
    fn load(&self) -> Result<Option<Vec<u8>>, HeaderSyncError>;
    /// Replaces the saved state. Must be durable when it returns.
    fn save(&self, state: Vec<u8>) -> Result<(), HeaderSyncError>;
}

/// The verified tip and the headers below it, enough to rebuild the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Saved {
    /// The pinned start the chain grew from.
    pin_height: u64,
    pin_hash: [u8; 32],
    /// The lowest saved header, taken as the rebuilt chain's start.
    anchor: Vec<u8>,
    anchor_work: U256,
    /// The key blocks below the anchor that the headers after it use.
    key_blocks: Vec<(u64, [u8; 32])>,
    /// The best-chain headers above the anchor, lowest first.
    headers: Vec<Vec<u8>>,
}

impl Saved {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SAVED_MAGIC);
        out.extend_from_slice(&SAVED_STATE_VERSION.to_be_bytes());
        out.extend_from_slice(&self.pin_height.to_be_bytes());
        out.extend_from_slice(&self.pin_hash);
        put_bytes(&mut out, &self.anchor);
        out.extend_from_slice(&self.anchor_work.to_be_bytes());
        out.extend_from_slice(&(self.key_blocks.len() as u32).to_be_bytes());
        for (height, hash) in &self.key_blocks {
            out.extend_from_slice(&height.to_be_bytes());
            out.extend_from_slice(hash);
        }
        out.extend_from_slice(&(self.headers.len() as u32).to_be_bytes());
        for header in &self.headers {
            put_bytes(&mut out, header);
        }
        let checksum = keccak(&out);
        out.extend_from_slice(&checksum);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 32 {
            return Err("it ends early".to_owned());
        }
        let (body, checksum) = bytes.split_at(bytes.len() - 32);
        let mut reader = Reader { rest: body };
        if reader.take(4) != Some(SAVED_MAGIC.as_slice()) {
            return Err("it is not a saved header state".to_owned());
        }
        let version = reader.u32().ok_or("it ends early")?;
        if version != SAVED_STATE_VERSION {
            return Err(format!("it has the unknown version {version}"));
        }
        if keccak(body) != checksum {
            return Err("the checksum does not match".to_owned());
        }
        let short = || "it ends early".to_owned();
        let pin_height = reader.u64().ok_or_else(short)?;
        let pin_hash = reader.hash().ok_or_else(short)?;
        let anchor = reader.bytes().ok_or_else(short)?.to_vec();
        let anchor_work = U256::from_be_bytes(reader.take(32).ok_or_else(short)?).ok_or_else(short)?;
        let mut key_blocks = Vec::new();
        for _ in 0..reader.u32().ok_or_else(short)? {
            key_blocks.push((reader.u64().ok_or_else(short)?, reader.hash().ok_or_else(short)?));
        }
        let mut headers = Vec::new();
        for _ in 0..reader.u32().ok_or_else(short)? {
            headers.push(reader.bytes().ok_or_else(short)?.to_vec());
        }
        if !reader.rest.is_empty() {
            return Err("it has bytes after its end".to_owned());
        }
        Ok(Saved { pin_height, pin_hash, anchor, anchor_work, key_blocks, headers })
    }
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        if self.rest.len() < count {
            return None;
        }
        let (head, rest) = self.rest.split_at(count);
        self.rest = rest;
        Some(head)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    fn hash(&mut self) -> Option<[u8; 32]> {
        self.take(32)?.try_into().ok()
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

/// The pinned start of this build.
struct Start {
    pin: PinnedStart,
    hash: [u8; 32],
}

/// What the readers see, updated after every header.
struct View {
    best_height: u64,
    best_hash: [u8; 32],
    cache_count: u64,
    state: ChainState,
}

/// The chain, or `None` while it is released, and the state it was saved at.
struct Work {
    chain: Option<Built>,
    saved: Saved,
}

/// A header chain checked from a pinned start, fed in batches.
#[derive(uniffi::Object)]
pub struct HeaderSync {
    start: Start,
    params: ChainParams,
    store: Option<Box<dyn HeaderStore>>,
    work: Mutex<Work>,
    view: Mutex<View>,
    /// Set by [`release_caches`](Self::release_caches) until
    /// [`allow_caches`](Self::allow_caches).
    released: AtomicBool,
}

#[uniffi::export]
impl HeaderSync {
    /// Starts at a pinned genesis header (its RLP bytes). Progress is kept in
    /// memory only.
    #[uniffi::constructor]
    pub fn from_genesis(genesis: Vec<u8>, constants: HeaderChainConstants) -> Result<Arc<Self>, HeaderSyncError> {
        Self::open(genesis_start(genesis, constants)?, constants, None)
    }

    /// Starts at a pinned checkpoint: its RLP bytes, its height, the total
    /// work up to and including it (big-endian), the genesis timestamp and
    /// the key blocks below it that the headers after it use. Progress is
    /// kept in memory only.
    #[uniffi::constructor]
    pub fn from_checkpoint(
        header: Vec<u8>,
        height: u64,
        total_work: Vec<u8>,
        genesis_timestamp: u64,
        key_blocks: Vec<PinnedKeyBlock>,
        constants: HeaderChainConstants,
    ) -> Result<Arc<Self>, HeaderSyncError> {
        let start = checkpoint_start(header, height, total_work, genesis_timestamp, key_blocks)?;
        Self::open(start, constants, None)
    }

    /// Like [`from_genesis`](Self::from_genesis), resuming from what `store`
    /// saved and saving there after every batch that adopted a header.
    #[uniffi::constructor]
    pub fn open_genesis(
        genesis: Vec<u8>,
        constants: HeaderChainConstants,
        store: Box<dyn HeaderStore>,
    ) -> Result<Arc<Self>, HeaderSyncError> {
        Self::open(genesis_start(genesis, constants)?, constants, Some(store))
    }

    /// Like [`from_checkpoint`](Self::from_checkpoint), resuming from what
    /// `store` saved and saving there after every batch that adopted a
    /// header.
    #[uniffi::constructor]
    pub fn open_checkpoint(
        header: Vec<u8>,
        height: u64,
        total_work: Vec<u8>,
        genesis_timestamp: u64,
        key_blocks: Vec<PinnedKeyBlock>,
        constants: HeaderChainConstants,
        store: Box<dyn HeaderStore>,
    ) -> Result<Arc<Self>, HeaderSyncError> {
        let start = checkpoint_start(header, height, total_work, genesis_timestamp, key_blocks)?;
        Self::open(start, constants, Some(store))
    }

    /// Checks each header of `batch` in order with `HeaderChain::add_header`
    /// and stops at the first one refused, with no budget. `now` is the
    /// phone's clock in Unix seconds. A refused header puts the sync in
    /// [`ChainState::Invalid`]; this call still checks later batches, for the
    /// benchmarks, but budgeted runs stop.
    pub fn add_headers(&self, batch: Vec<Vec<u8>>, now: u64) -> HeaderProgress {
        let mut progress = HeaderProgress {
            accepted: 0,
            already_held: 0,
            best_height: self.best_height(),
            refused_index: None,
            refused_reason: None,
            reorgs: Vec::new(),
        };
        if batch.is_empty() {
            return progress;
        }
        let busy = |reason: &str, mut progress: HeaderProgress| {
            progress.refused_index = Some(0);
            progress.refused_reason = Some(reason.to_owned());
            progress
        };
        if self.released.load(Ordering::SeqCst) {
            return busy("the caches are released for a proof; nothing was checked", progress);
        }
        let Some(mut work) = self.try_work() else {
            return busy("another call is checking headers; nothing was checked", progress);
        };
        if let Err(reason) = self.ensure_chain(&mut work) {
            return busy(&reason, progress);
        }
        for (index, header) in batch.iter().enumerate() {
            match self.add_one(&mut work, header, now) {
                Ok((Added::AlreadyHeld, _)) => progress.already_held += 1,
                Ok((_, reorg)) => {
                    progress.accepted += 1;
                    progress.reorgs.extend(reorg);
                }
                Err(error) => {
                    progress.refused_index = Some(index as u64);
                    progress.refused_reason = Some(error.to_string());
                    break;
                }
            }
        }
        progress.best_height = self.best_height();
        if progress.accepted > 0 {
            // Saving is best effort here; a budgeted run reports the error.
            let _ = self.save(&mut work);
        }
        progress
    }

    /// Starts a budgeted run. Its batches go through
    /// [`HeaderRun::add_headers`].
    pub fn start_run(self: Arc<Self>, budget: RunBudget, conditions: DeviceConditions) -> Arc<HeaderRun> {
        Arc::new(HeaderRun {
            sync: self,
            budget,
            spent: Mutex::new(RunSpent { cpu_seconds: 0.0, headers: 0, bytes: 0 }),
            cancelled: AtomicBool::new(false),
            thermal: AtomicU8::new(conditions.thermal as u8),
            low_power_mode: AtomicBool::new(conditions.low_power_mode),
            stopped: Mutex::new(None),
        })
    }

    /// Drops the chain, and with it every RandomX cache, before a proof
    /// starts; runs stop with [`StopReason::CachesReleased`] until
    /// [`allow_caches`](Self::allow_caches). Returns whether the caches are
    /// gone now; if a run is checking a header, it drops them as soon as that
    /// header is done, and `cache_count` reads 0 from then on. Never waits.
    pub fn release_caches(&self) -> bool {
        self.released.store(true, Ordering::SeqCst);
        match self.try_work() {
            Some(mut work) => {
                self.drop_chain(&mut work);
                true
            }
            None => false,
        }
    }

    /// Lets runs check headers again after a proof. The next one rebuilds the
    /// chain from the saved state.
    pub fn allow_caches(&self) {
        self.released.store(false, Ordering::SeqCst);
    }

    /// The saved state as last handed to the store, which
    /// [`open_genesis`](Self::open_genesis) and
    /// [`open_checkpoint`](Self::open_checkpoint) resume from. `None` while a
    /// run holds the chain.
    pub fn saved_state(&self) -> Option<Vec<u8>> {
        self.try_work().map(|work| work.saved.encode())
    }

    /// Whether the chain can still be trusted.
    pub fn state(&self) -> ChainState {
        self.view().state.clone()
    }

    /// The height of the best chain's tip.
    pub fn best_height(&self) -> u64 {
        self.view().best_height
    }

    /// The hash of the best chain's tip.
    pub fn best_hash(&self) -> Vec<u8> {
        self.view().best_hash.to_vec()
    }

    /// How many RandomX caches are held now (at most two; 0 once released).
    pub fn cache_count(&self) -> u64 {
        self.view().cache_count
    }
}

/// One budgeted run over a [`HeaderSync`], fed in batches.
#[derive(uniffi::Object)]
pub struct HeaderRun {
    sync: Arc<HeaderSync>,
    budget: RunBudget,
    spent: Mutex<RunSpent>,
    cancelled: AtomicBool,
    thermal: AtomicU8,
    low_power_mode: AtomicBool,
    stopped: Mutex<Option<StopReason>>,
}

#[uniffi::export]
impl HeaderRun {
    /// Checks the headers of `batch` in order until the run stops. `now` is
    /// the phone's clock in Unix seconds.
    pub fn add_headers(&self, batch: Vec<Vec<u8>>, now: u64) -> RunProgress {
        let sync = &self.sync;
        let mut progress = RunProgress {
            accepted: 0,
            already_held: 0,
            unchecked: batch.len() as u64,
            best_height: 0,
            best_hash: Vec::new(),
            stopped: None,
            reorgs: Vec::new(),
            spent: self.spent(),
            save_error: None,
        };
        let stop = self.stop_before(&batch[..batch.len().min(1)]);
        let work = match stop {
            None => match sync.try_work() {
                Some(work) => Some(work),
                None => {
                    progress.stopped = Some(StopReason::Busy);
                    None
                }
            },
            Some(reason) => {
                progress.stopped = Some(self.end(reason));
                None
            }
        };
        if let Some(mut work) = work {
            self.check(&mut work, &batch, now, &mut progress);
            if progress.accepted > 0 {
                progress.save_error = sync.save(&mut work).err();
            }
            if sync.released.load(Ordering::SeqCst) {
                sync.drop_chain(&mut work);
            }
        }
        let view = sync.view();
        progress.best_height = view.best_height;
        progress.best_hash = view.best_hash.to_vec();
        drop(view);
        progress.spent = self.spent();
        progress
    }

    /// Stops the run after the header being checked. Never waits.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Passes the phone's current thermal state and Low Power Mode; the run
    /// stops before its next header if either calls for it.
    pub fn set_conditions(&self, conditions: DeviceConditions) {
        self.thermal.store(conditions.thermal as u8, Ordering::SeqCst);
        self.low_power_mode.store(conditions.low_power_mode, Ordering::SeqCst);
    }

    /// What the run has spent so far.
    pub fn spent(&self) -> RunSpent {
        *lock(&self.spent)
    }

    /// Why the run stopped, if it did ([`StopReason::Busy`] does not stop it).
    pub fn stopped(&self) -> Option<StopReason> {
        *lock(&self.stopped)
    }
}

impl HeaderRun {
    fn check(&self, work: &mut Work, batch: &[Vec<u8>], now: u64, progress: &mut RunProgress) {
        let sync = &self.sync;
        for (index, header) in batch.iter().enumerate() {
            if let Some(reason) = self.stop_before(std::slice::from_ref(header)) {
                progress.stopped = Some(self.end(reason));
                return;
            }
            let began = Instant::now();
            // `None`: the chain did not rebuild.
            let outcome = match sync.ensure_chain(work) {
                Ok(()) => sync.add_one(work, header, now).map_err(Some),
                Err(_) => Err(None),
            };
            {
                let mut spent = lock(&self.spent);
                spent.cpu_seconds += began.elapsed().as_secs_f64();
                spent.headers += 1;
                spent.bytes += header.len() as u64;
            }
            progress.unchecked = (batch.len() - index - 1) as u64;
            match outcome {
                Ok((Added::AlreadyHeld, _)) => progress.already_held += 1,
                Ok((_, reorg)) => {
                    progress.accepted += 1;
                    progress.reorgs.extend(reorg);
                }
                Err(Some(ChainError::TooFarAhead)) => {
                    progress.unchecked += 1;
                    progress.stopped = Some(self.end(StopReason::HeaderAhead));
                    return;
                }
                Err(_) => {
                    // add_one or ensure_chain put the sync in Invalid.
                    progress.stopped = Some(self.end(StopReason::InvalidChain));
                    return;
                }
            }
        }
    }

    /// Why the run must not look at `next` (the next header), if it must
    /// not. A run that stopped stays stopped.
    fn stop_before(&self, next: &[Vec<u8>]) -> Option<StopReason> {
        if let Some(reason) = *lock(&self.stopped) {
            return Some(reason);
        }
        if self.cancelled.load(Ordering::SeqCst) {
            return Some(StopReason::Cancelled);
        }
        if self.sync.released.load(Ordering::SeqCst) {
            return Some(StopReason::CachesReleased);
        }
        if ThermalState::from_u8(self.thermal.load(Ordering::SeqCst)) >= ThermalState::Serious {
            return Some(StopReason::Thermal);
        }
        if self.low_power_mode.load(Ordering::SeqCst) {
            return Some(StopReason::LowPowerMode);
        }
        if matches!(self.sync.view().state, ChainState::Invalid { .. }) {
            return Some(StopReason::InvalidChain);
        }
        let spent = self.spent();
        if spent.headers >= self.budget.max_headers {
            return Some(StopReason::HeaderBudget);
        }
        let next_bytes = next.first().map_or(0, |header| header.len() as u64);
        if spent.bytes.saturating_add(next_bytes) > self.budget.max_bytes {
            return Some(StopReason::ByteBudget);
        }
        if !(spent.cpu_seconds < self.budget.cpu_seconds) {
            return Some(StopReason::CpuBudget);
        }
        None
    }

    /// Ends the run for `reason`; [`StopReason::Busy`] does not end it.
    fn end(&self, reason: StopReason) -> StopReason {
        if reason != StopReason::Busy {
            lock(&self.stopped).get_or_insert(reason);
        }
        reason
    }
}

impl HeaderSync {
    fn open(
        start: Start,
        constants: HeaderChainConstants,
        store: Option<Box<dyn HeaderStore>>,
    ) -> Result<Arc<Self>, HeaderSyncError> {
        let params: ChainParams = constants.into();
        let mut built = Built {
            chain: HeaderChain::from_pinned(start.pin.clone(), params)?,
            keys_below: start.pin.key_blocks.clone(),
        };
        let mut state = ChainState::Valid;
        let loaded = match &store {
            Some(store) => store.load()?,
            None => None,
        };
        if let Some(bytes) = loaded {
            let saved = Saved::decode(&bytes).map_err(|reason| HeaderSyncError::Saved { reason })?;
            let rebuilt = rebuild(&saved, &start, params).map_err(|reason| HeaderSyncError::Saved { reason })?;
            match resume(&rebuilt.chain, &saved, &start) {
                Resume::Saved => built = rebuilt,
                Resume::Fresh => {}
                Resume::Conflict(reason) => state = ChainState::Invalid { reason },
            }
        }
        let view = View {
            best_height: built.chain.best_height(),
            best_hash: built.chain.best_hash(),
            cache_count: built.chain.cache_count() as u64,
            state,
        };
        let saved = snapshot(&built, &start);
        Ok(Arc::new(Self {
            start,
            params,
            store,
            work: Mutex::new(Work { chain: Some(built), saved }),
            view: Mutex::new(view),
            released: AtomicBool::new(false),
        }))
    }

    /// The chain, unless a run holds it. Never waits.
    fn try_work(&self) -> Option<MutexGuard<'_, Work>> {
        match self.work.try_lock() {
            Ok(work) => Some(work),
            // A panic while holding the lock leaves the chain as it was before
            // the header being added: nothing is held until every check passed.
            Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => None,
        }
    }

    /// The readers' copy; held only to read or write a few fields.
    fn view(&self) -> MutexGuard<'_, View> {
        lock(&self.view)
    }

    fn set_invalid(&self, reason: String) {
        let mut view = self.view();
        if view.state == ChainState::Valid {
            view.state = ChainState::Invalid { reason };
        }
    }

    /// Rebuilds the chain from the saved state if it was released. The saved
    /// headers are read back without their seals, so no cache is built.
    fn ensure_chain(&self, work: &mut Work) -> Result<(), String> {
        if work.chain.is_some() {
            return Ok(());
        }
        match rebuild(&work.saved, &self.start, self.params) {
            Ok(built) => {
                self.view().cache_count = built.chain.cache_count() as u64;
                work.chain = Some(built);
                Ok(())
            }
            Err(reason) => {
                let reason = format!("the saved state does not rebuild: {reason}");
                self.set_invalid(reason.clone());
                Err(reason)
            }
        }
    }

    /// Checks one header on the held chain and updates the readers' copy.
    fn add_one(
        &self,
        work: &mut Work,
        header: &[u8],
        now: u64,
    ) -> Result<(Added, Option<ReorgEvent>), ChainError> {
        let chain = &mut work.chain.as_mut().expect("the chain is built before a header is added").chain;
        let (old_tip, old_height) = (chain.best_hash(), chain.best_height());
        let result = chain.add_header(header, now);
        let mut view = self.view();
        view.best_height = chain.best_height();
        view.best_hash = chain.best_hash();
        view.cache_count = chain.cache_count() as u64;
        drop(view);
        match result {
            Ok(Added::Reorganised { removed, added }) => {
                let event = ReorgEvent {
                    old_tip: old_tip.to_vec(),
                    old_height,
                    new_tip: chain.best_hash().to_vec(),
                    new_height: chain.best_height(),
                    depth: removed,
                    added,
                };
                Ok((Added::Reorganised { removed, added }, Some(event)))
            }
            Ok(added) => Ok((added, None)),
            // Not invalid for ever: the clock may catch up.
            Err(ChainError::TooFarAhead) => Err(ChainError::TooFarAhead),
            Err(error) => {
                self.set_invalid(format!("a header was refused: {error}"));
                Err(error)
            }
        }
    }

    /// Saves the verified tip and the headers below it, in memory for a
    /// rebuild and in the store for a restart. Nothing is saved while the
    /// chain is invalid.
    fn save(&self, work: &mut Work) -> Result<(), String> {
        if let ChainState::Invalid { reason } = &self.view().state {
            return Err(format!("nothing is saved while the chain is invalid: {reason}"));
        }
        let Some(built) = &work.chain else {
            return Ok(());
        };
        work.saved = snapshot(built, &self.start);
        match &self.store {
            Some(store) => store.save(work.saved.encode()).map_err(|error| error.to_string()),
            None => Ok(()),
        }
    }

    fn drop_chain(&self, work: &mut Work) {
        work.chain = None;
        self.view().cache_count = 0;
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// A held chain and the key blocks below its start that it was built with.
struct Built {
    chain: HeaderChain,
    keys_below: Vec<(u64, [u8; 32])>,
}

fn genesis_start(genesis: Vec<u8>, constants: HeaderChainConstants) -> Result<Start, HeaderSyncError> {
    let params: ChainParams = constants.into();
    // The genesis checks of the client; the chain itself is built in `open`.
    HeaderChain::from_genesis(&genesis, params)?;
    let fields = header_fields(&genesis).map_err(StartError::Header)?;
    let pin = PinnedStart {
        header: genesis,
        height: 0,
        total_work: U256::from(params.start_difficulty),
        genesis_timestamp: fields.timestamp,
        key_blocks: Vec::new(),
    };
    Ok(Start { pin, hash: fields.hash })
}

fn checkpoint_start(
    header: Vec<u8>,
    height: u64,
    total_work: Vec<u8>,
    genesis_timestamp: u64,
    key_blocks: Vec<PinnedKeyBlock>,
) -> Result<Start, HeaderSyncError> {
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
    let fields = header_fields(&header).map_err(StartError::Header)?;
    let pin = PinnedStart { header, height, total_work, genesis_timestamp, key_blocks };
    Ok(Start { pin, hash: fields.hash })
}

/// The saved state of a held chain: its tip and up to [`RECENT_HEADERS`]
/// best-chain headers below it, from the lowest of which the chain can be
/// rebuilt.
fn snapshot(built: &Built, start: &Start) -> Saved {
    let chain = &built.chain;
    let start_height =
        header_fields(chain.header(&chain.start_hash()).expect("the start is held")).expect("it decodes").number;
    let tip = chain.best_height();
    let anchor_height = tip.saturating_sub(RECENT_HEADERS).max(start_height);
    let mut headers = Vec::new();
    let mut hash = chain.best_hash();
    for _ in anchor_height..tip {
        let rlp = chain.header(&hash).expect("the best chain is held");
        headers.push(rlp.to_vec());
        hash = header_fields(rlp).expect("a held header decodes").parent_hash;
    }
    headers.reverse();
    let anchor = chain.header(&hash).expect("the anchor is held").to_vec();
    let anchor_work = chain.total_work(&hash).expect("the anchor is held");

    // The key blocks below the anchor that the headers after it use: those
    // below the chain's start it was given, the others on its best chain.
    let mut key_blocks = Vec::new();
    let mut seed = seed_height(anchor_height + 1);
    while seed < anchor_height {
        let known = if seed < start_height {
            built.keys_below.iter().find(|(height, _)| *height == seed).map(|(_, hash)| *hash)
        } else {
            chain.best_hash_at(seed)
        };
        if let Some(hash) = known {
            key_blocks.push((seed, hash));
        }
        seed += EPOCH_BLOCKS;
    }
    Saved { pin_height: start.pin.height, pin_hash: start.hash, anchor, anchor_work, key_blocks, headers }
}

/// The chain the saved state describes. Its headers were checked in full
/// when they were adopted, so they are read back without their seals; the
/// clock is not checked again either.
fn rebuild(saved: &Saved, start: &Start, params: ChainParams) -> Result<Built, String> {
    let fields = header_fields(&saved.anchor).map_err(|error| format!("its lowest header: {error:?}"))?;
    let pin = PinnedStart {
        header: saved.anchor.clone(),
        height: fields.number,
        total_work: saved.anchor_work,
        genesis_timestamp: start.pin.genesis_timestamp,
        key_blocks: saved.key_blocks.clone(),
    };
    let mut chain = HeaderChain::from_pinned(pin, params).map_err(|error| error.to_string())?;
    for header in &saved.headers {
        match chain.add_saved_header(header, u64::MAX) {
            Ok(Added::Extended) => {}
            Ok(_) => return Err("its headers are not one chain".to_owned()),
            Err(error) => return Err(format!("a saved header is refused: {error}")),
        }
    }
    Ok(Built { chain, keys_below: saved.key_blocks.clone() })
}

enum Resume {
    /// Go on from the saved chain.
    Saved,
    /// Start again from the pinned start: the saved chain cannot be checked
    /// against it, and the pin is trusted.
    Fresh,
    /// The saved chain holds another header at the pinned height.
    Conflict(String),
}

/// Whether the saved chain may be resumed under this build's pinned start.
fn resume(rebuilt: &HeaderChain, saved: &Saved, start: &Start) -> Resume {
    if saved.pin_height == start.pin.height {
        return if saved.pin_hash == start.hash {
            Resume::Saved
        } else {
            Resume::Conflict("the saved chain grew from another header at the pinned height".to_owned())
        };
    }
    match rebuilt.best_hash_at(start.pin.height) {
        Some(hash) if hash == start.hash => Resume::Saved,
        Some(_) => Resume::Conflict("the saved chain conflicts with the pinned checkpoint".to_owned()),
        None => Resume::Fresh,
    }
}
