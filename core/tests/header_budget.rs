//! The budgeted runs of `header_sync`: the CPU, header and byte budgets,
//! cancelling, thermal state and Low Power Mode; progress saved to a store
//! and resumed after a restart; the caches released before a proof and the
//! chain rebuilt from the saved state; reorg events; the invalid chain state
//! on a refused header or a conflict with the pinned checkpoint; and calls
//! that return at once while another call holds the chain.
//!
//! The headers are built as in `header_sync.rs`: Ghost's internal network
//! test constants, difficulty 1, so every seal passes at nonce 0. Each chain
//! that checks a seal builds its 256 MiB RandomX cache, so the tests run one
//! at a time.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;

use ghost_client::seal::header_fields;
use ghost_wallet_core::{
    ChainState, DeviceConditions, HeaderChainConstants, HeaderStore, HeaderSync, HeaderSyncError, PinnedKeyBlock,
    RECENT_HEADERS, ReorgEvent, RunBudget, StopReason, ThermalState,
};

const TEST_CHAIN: HeaderChainConstants =
    HeaderChainConstants { block_time: 30, half_life: 3600, start_difficulty: 1, min_difficulty: 1, future_drift: 30 };
const GENESIS_TIME: u64 = 0x6abd_a280;
const LATER: u64 = GENESIS_TIME + 1_000_000_000;
const CHAIN_LENGTH: usize = 20;

static ONE_CHAIN_AT_A_TIME: Mutex<()> = Mutex::new(());

fn one_chain() -> MutexGuard<'static, ()> {
    ONE_CHAIN_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner())
}

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

    fn hash(&self) -> [u8; 32] {
        header_fields(&self.rlp()).unwrap().hash
    }

    /// The child `seconds` later, at difficulty 1.
    fn child_after(&self, seconds: u64) -> Draft {
        Draft { parent: self.hash(), number: self.number + 1, timestamp: self.timestamp + seconds, difficulty: 1 }
    }
}

fn genesis() -> Draft {
    Draft { parent: [0; 32], number: 0, timestamp: GENESIS_TIME, difficulty: 1 }
}

/// `count` headers after `from`, `seconds` apart.
fn branch(from: &Draft, count: usize, seconds: u64) -> Vec<Draft> {
    let mut out: Vec<Draft> = Vec::new();
    for _ in 0..count {
        out.push(out.last().unwrap_or(from).child_after(seconds));
    }
    out
}

fn chain_of(count: usize) -> Vec<Draft> {
    branch(&genesis(), count, 30)
}

fn chain() -> Vec<Draft> {
    chain_of(CHAIN_LENGTH)
}

fn bytes(drafts: &[Draft]) -> Vec<Vec<u8>> {
    drafts.iter().map(Draft::rlp).collect()
}

fn unlimited() -> RunBudget {
    RunBudget { cpu_seconds: 3600.0, max_headers: u64::MAX, max_bytes: u64::MAX }
}

fn cool() -> DeviceConditions {
    DeviceConditions { thermal: ThermalState::Nominal, low_power_mode: false }
}

fn genesis_sync() -> Arc<HeaderSync> {
    HeaderSync::from_genesis(genesis().rlp(), TEST_CHAIN).unwrap()
}

/// A store in memory, shared between the syncs opened on it.
#[derive(Clone, Default)]
struct MemoryStore {
    state: Arc<Mutex<Option<Vec<u8>>>>,
    saves: Arc<AtomicUsize>,
}

impl MemoryStore {
    fn state(&self) -> Option<Vec<u8>> {
        self.state.lock().unwrap().clone()
    }
}

impl HeaderStore for MemoryStore {
    fn load(&self) -> Result<Option<Vec<u8>>, HeaderSyncError> {
        Ok(self.state())
    }

    fn save(&self, state: Vec<u8>) -> Result<(), HeaderSyncError> {
        *self.state.lock().unwrap() = Some(state);
        self.saves.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn open_genesis(store: &MemoryStore) -> Arc<HeaderSync> {
    HeaderSync::open_genesis(genesis().rlp(), TEST_CHAIN, Box::new(store.clone())).unwrap()
}

/// A checkpoint at `pin`, on the genesis chain's work schedule (1 per header).
fn open_checkpoint(pin: &Draft, store: &MemoryStore) -> Result<Arc<HeaderSync>, HeaderSyncError> {
    HeaderSync::open_checkpoint(
        pin.rlp(),
        pin.number,
        int(pin.number + 1),
        GENESIS_TIME,
        vec![PinnedKeyBlock { height: 0, hash: genesis().hash().to_vec() }],
        TEST_CHAIN,
        Box::new(store.clone()),
    )
}

#[test]
fn header_budget_stops_the_run_and_it_stays_stopped() {
    let _one = one_chain();
    let headers = chain();
    let sync = genesis_sync();
    let run = sync.clone().start_run(RunBudget { max_headers: 5, ..unlimited() }, cool());

    let progress = run.add_headers(bytes(&headers[..8]), LATER);
    assert_eq!(progress.accepted, 5);
    assert_eq!(progress.unchecked, 3);
    assert_eq!(progress.stopped, Some(StopReason::HeaderBudget));
    assert_eq!(progress.best_height, 5);
    assert_eq!(progress.best_hash, headers[4].hash().to_vec());
    assert_eq!(progress.spent.headers, 5);
    assert_eq!(run.stopped(), Some(StopReason::HeaderBudget));

    // A stopped run looks at nothing more.
    let again = run.add_headers(bytes(&headers[5..8]), LATER);
    assert_eq!((again.accepted, again.unchecked, again.stopped), (0, 3, Some(StopReason::HeaderBudget)));
    assert_eq!(sync.best_height(), 5);

    // The next run goes on from there.
    let next = sync.clone().start_run(unlimited(), cool());
    let rest = next.add_headers(bytes(&headers[5..]), LATER);
    assert_eq!((rest.accepted, rest.stopped, rest.best_height), (15, None, CHAIN_LENGTH as u64));
}

#[test]
fn byte_budget_stops_before_the_header_that_would_go_over() {
    let _one = one_chain();
    let headers = bytes(&chain());
    let three: u64 = headers[..3].iter().map(|h| h.len() as u64).sum();
    let sync = genesis_sync();
    let budget = RunBudget { max_bytes: three + headers[3].len() as u64 - 1, ..unlimited() };
    let run = sync.clone().start_run(budget, cool());

    let progress = run.add_headers(headers.clone(), LATER);
    assert_eq!(progress.accepted, 3);
    assert_eq!(progress.stopped, Some(StopReason::ByteBudget));
    assert_eq!(progress.spent.bytes, three);
    assert_eq!(progress.unchecked, (CHAIN_LENGTH - 3) as u64);
    assert_eq!(sync.best_height(), 3);
}

#[test]
fn cpu_budget_is_checked_before_every_header() {
    let _one = one_chain();
    let headers = chain();
    let sync = genesis_sync();

    let none = sync.clone().start_run(RunBudget { cpu_seconds: 0.0, ..unlimited() }, cool());
    let progress = none.add_headers(bytes(&headers), LATER);
    assert_eq!((progress.accepted, progress.stopped), (0, Some(StopReason::CpuBudget)));
    assert_eq!(sync.cache_count(), 0);

    // The first header spends more than a nanosecond (it builds the cache).
    let one = sync.clone().start_run(RunBudget { cpu_seconds: 1e-9, ..unlimited() }, cool());
    let progress = one.add_headers(bytes(&headers), LATER);
    assert_eq!(progress.accepted, 1);
    assert_eq!(progress.stopped, Some(StopReason::CpuBudget));
    assert!(progress.spent.cpu_seconds > 1e-9);
    assert_eq!(sync.best_height(), 1);
}

#[test]
fn cancel_thermal_and_low_power_stop_a_run() {
    let _one = one_chain();
    let headers = chain();
    let sync = genesis_sync();

    for thermal in [ThermalState::Serious, ThermalState::Critical] {
        let run = sync.clone().start_run(unlimited(), DeviceConditions { thermal, low_power_mode: false });
        let progress = run.add_headers(bytes(&headers), LATER);
        assert_eq!((progress.accepted, progress.stopped), (0, Some(StopReason::Thermal)), "{thermal:?}");
    }
    let low_power =
        sync.clone().start_run(unlimited(), DeviceConditions { thermal: ThermalState::Nominal, low_power_mode: true });
    let progress = low_power.add_headers(bytes(&headers), LATER);
    assert_eq!((progress.accepted, progress.stopped), (0, Some(StopReason::LowPowerMode)));
    assert_eq!(sync.best_height(), 0);

    // Fair is fine; the phone heating up between batches stops the run.
    let run =
        sync.clone().start_run(unlimited(), DeviceConditions { thermal: ThermalState::Fair, low_power_mode: false });
    assert_eq!(run.add_headers(bytes(&headers[..4]), LATER).accepted, 4);
    run.set_conditions(DeviceConditions { thermal: ThermalState::Serious, low_power_mode: false });
    let progress = run.add_headers(bytes(&headers[4..]), LATER);
    assert_eq!((progress.accepted, progress.stopped), (0, Some(StopReason::Thermal)));
    // It stays stopped when the phone cools down: start another run.
    run.set_conditions(cool());
    assert_eq!(run.add_headers(bytes(&headers[4..]), LATER).stopped, Some(StopReason::Thermal));

    let cancelled = sync.clone().start_run(unlimited(), cool());
    assert_eq!(cancelled.add_headers(bytes(&headers[4..8]), LATER).accepted, 4);
    cancelled.cancel();
    let progress = cancelled.add_headers(bytes(&headers[8..]), LATER);
    assert_eq!((progress.accepted, progress.stopped), (0, Some(StopReason::Cancelled)));
    assert_eq!(sync.best_height(), 8);
}

#[test]
fn reorgs_are_reported_with_old_tip_new_tip_and_depth() {
    let _one = one_chain();
    let main = chain_of(6);
    // A branch from height 3, one second later per header so its hashes
    // differ; still difficulty 1.
    let fork = branch(&main[2], 4, 31);
    let sync = genesis_sync();
    let run = sync.clone().start_run(unlimited(), cool());

    let progress = run.add_headers(bytes(&main), LATER);
    assert_eq!((progress.accepted, progress.reorgs.len()), (6, 0));
    // Heights 4 to 6 of the branch tie with the best chain: the first seen wins.
    let progress = run.add_headers(bytes(&fork[..3]), LATER);
    assert_eq!((progress.accepted, progress.reorgs.len()), (3, 0));
    assert_eq!(sync.best_hash(), main[5].hash().to_vec());

    let progress = run.add_headers(bytes(&fork[3..]), LATER);
    assert_eq!(
        progress.reorgs,
        vec![ReorgEvent {
            old_tip: main[5].hash().to_vec(),
            old_height: 6,
            new_tip: fork[3].hash().to_vec(),
            new_height: 7,
            depth: 3,
            added: 4,
        }]
    );
    assert_eq!(progress.best_hash, fork[3].hash().to_vec());

    // The plain path reports them too: back to the first branch.
    let longer = branch(&main[5], 2, 30);
    let plain = sync.add_headers(bytes(&longer), LATER);
    assert_eq!(plain.accepted, 2);
    assert_eq!(
        plain.reorgs,
        vec![ReorgEvent {
            old_tip: fork[3].hash().to_vec(),
            old_height: 7,
            new_tip: longer[1].hash().to_vec(),
            new_height: 8,
            depth: 4,
            added: 5,
        }]
    );
}

#[test]
fn saved_progress_resumes_after_a_restart_without_checking_twice() {
    let _one = one_chain();
    let headers = chain();
    let store = MemoryStore::default();

    {
        let sync = open_genesis(&store);
        assert_eq!(store.state(), None);
        let run = sync.clone().start_run(unlimited(), cool());
        assert_eq!(run.add_headers(bytes(&headers[..12]), LATER).accepted, 12);
        assert_eq!(store.state(), sync.saved_state());
        assert!(store.state().is_some());
    }

    let resumed = open_genesis(&store);
    assert_eq!(resumed.state(), ChainState::Valid);
    assert_eq!(resumed.best_height(), 12);
    assert_eq!(resumed.best_hash(), headers[11].hash().to_vec());
    // Reading the saved headers back checks no seal, so builds no cache.
    assert_eq!(resumed.cache_count(), 0);

    let run = resumed.clone().start_run(unlimited(), cool());
    let again = run.add_headers(bytes(&headers[8..12]), LATER);
    assert_eq!((again.accepted, again.already_held), (0, 4));
    let rest = run.add_headers(bytes(&headers[12..]), LATER);
    assert_eq!((rest.accepted, rest.best_height), (8, CHAIN_LENGTH as u64));
    assert_eq!(resumed.cache_count(), 1);

    assert_eq!(open_genesis(&store).best_hash(), headers[CHAIN_LENGTH - 1].hash().to_vec());
}

#[test]
fn only_recent_headers_are_saved_and_the_chain_still_extends() {
    let _one = one_chain();
    let length = RECENT_HEADERS as usize + 18;
    let headers = chain_of(length + 3);
    let store = MemoryStore::default();
    let sync = open_genesis(&store);
    let run = sync.clone().start_run(unlimited(), cool());
    assert_eq!(run.add_headers(bytes(&headers[..length]), LATER).accepted, length as u64);
    drop((run, sync));

    let resumed = open_genesis(&store);
    assert_eq!(resumed.best_height(), length as u64);
    // Heights 18 and up are held; 17 is not, and its parent neither.
    let held = resumed.add_headers(bytes(&headers[17..19]), LATER);
    assert_eq!((held.already_held, held.refused_index), (2, None));
    let below = resumed.add_headers(vec![headers[16].rlp()], LATER);
    assert_eq!(below.refused_reason.as_deref(), Some("the header's parent is not held"));

    // New headers above it still find their key block (block 0, below the
    // saved headers) and pass their seals.
    let fresh = open_genesis(&store);
    let run = fresh.clone().start_run(unlimited(), cool());
    let progress = run.add_headers(bytes(&headers[length..]), LATER);
    assert_eq!((progress.accepted, progress.stopped), (3, None));
    assert_eq!(fresh.cache_count(), 1);
}

#[test]
fn releasing_the_caches_drops_them_until_allowed_and_rebuilds_from_saved_state() {
    let _one = one_chain();
    let headers = chain();
    let sync = genesis_sync();
    let run = sync.clone().start_run(unlimited(), cool());
    assert_eq!(run.add_headers(bytes(&headers[..10]), LATER).accepted, 10);
    assert_eq!(sync.cache_count(), 1);

    assert!(sync.release_caches());
    assert_eq!(sync.cache_count(), 0);
    assert_eq!(sync.best_height(), 10);
    // While a proof runs, no run builds them again.
    let progress = run.add_headers(bytes(&headers[10..]), LATER);
    assert_eq!((progress.accepted, progress.stopped), (0, Some(StopReason::CachesReleased)));
    let plain = sync.add_headers(bytes(&headers[10..]), LATER);
    assert_eq!((plain.accepted, plain.refused_index), (0, Some(0)));
    assert_eq!(sync.cache_count(), 0);

    sync.allow_caches();
    let after = sync.clone().start_run(unlimited(), cool());
    let again = after.add_headers(bytes(&headers[5..10]), LATER);
    assert_eq!((again.accepted, again.already_held), (0, 5));
    assert_eq!(sync.cache_count(), 0);
    let rest = after.add_headers(bytes(&headers[10..]), LATER);
    assert_eq!((rest.accepted, rest.best_height), (10, CHAIN_LENGTH as u64));
    assert_eq!(sync.best_hash(), headers[CHAIN_LENGTH - 1].hash().to_vec());
    assert_eq!(sync.cache_count(), 1);
}

#[test]
fn a_refused_header_makes_the_chain_invalid() {
    let _one = one_chain();
    let headers = chain();
    let store = MemoryStore::default();
    let sync = open_genesis(&store);
    let run = sync.clone().start_run(unlimited(), cool());
    assert_eq!(run.add_headers(bytes(&headers[..3]), LATER).accepted, 3);
    let saves = store.saves.load(Ordering::SeqCst);

    let wrong = Draft { difficulty: 2, ..headers[3].clone() };
    let progress = run.add_headers(vec![wrong.rlp(), headers[4].rlp()], LATER);
    assert_eq!((progress.accepted, progress.unchecked), (0, 1));
    assert_eq!(progress.stopped, Some(StopReason::InvalidChain));
    assert_eq!(
        sync.state(),
        ChainState::Invalid {
            reason: "a header was refused: the header does not carry the required difficulty".to_owned()
        }
    );

    // A new run does not check even good headers, and nothing is saved.
    let next = sync.clone().start_run(unlimited(), cool());
    let progress = next.add_headers(bytes(&headers[3..]), LATER);
    assert_eq!((progress.accepted, progress.stopped), (0, Some(StopReason::InvalidChain)));
    sync.add_headers(bytes(&headers[3..]), LATER);
    assert_eq!(store.saves.load(Ordering::SeqCst), saves);

    // Opened again (against another node), it goes on from the saved tip.
    let reopened = open_genesis(&store);
    assert_eq!((reopened.state(), reopened.best_height()), (ChainState::Valid, 3));
}

#[test]
fn a_header_that_does_not_link_to_the_checkpoint_makes_the_chain_invalid() {
    let _one = one_chain();
    let headers = chain();
    let sync = open_checkpoint(&headers[9], &MemoryStore::default()).unwrap();
    assert_eq!(sync.best_height(), 10);
    let other = Draft { parent: [0x42; 32], ..headers[10].clone() };
    let progress = sync.clone().start_run(unlimited(), cool()).add_headers(vec![other.rlp()], LATER);
    assert_eq!(progress.stopped, Some(StopReason::InvalidChain));
    assert!(matches!(sync.state(), ChainState::Invalid { .. }));
}

#[test]
fn a_saved_chain_that_conflicts_with_the_pinned_checkpoint_is_invalid() {
    let _one = one_chain();
    let headers = chain();
    let store = MemoryStore::default();
    {
        let sync = open_genesis(&store);
        assert_eq!(sync.clone().start_run(unlimited(), cool()).add_headers(bytes(&headers), LATER).accepted, 20);
    }

    // A later build pins height 10 of this chain: the saved chain goes on.
    let agrees = open_checkpoint(&headers[9], &store).unwrap();
    assert_eq!((agrees.state(), agrees.best_height()), (ChainState::Valid, CHAIN_LENGTH as u64));

    // A build pinning another header at height 10 refuses it.
    let other = Draft { timestamp: headers[9].timestamp + 1, ..headers[9].clone() };
    let conflicts = open_checkpoint(&other, &store).unwrap();
    assert_eq!(
        conflicts.state(),
        ChainState::Invalid { reason: "the saved chain conflicts with the pinned checkpoint".to_owned() }
    );
    let progress = conflicts.clone().start_run(unlimited(), cool()).add_headers(bytes(&headers[10..]), LATER);
    assert_eq!((progress.accepted, progress.stopped), (0, Some(StopReason::InvalidChain)));

    // Saved under one checkpoint, opened under another at the same height.
    let pinned = MemoryStore::default();
    let first = open_checkpoint(&headers[9], &pinned).unwrap();
    assert_eq!(first.clone().start_run(unlimited(), cool()).add_headers(bytes(&headers[10..12]), LATER).accepted, 2);
    let second = open_checkpoint(&other, &pinned).unwrap();
    assert!(matches!(second.state(), ChainState::Invalid { .. }));
    // The conflicting store is left as it was.
    assert_eq!(pinned.state(), first.saved_state());
}

#[test]
fn a_damaged_saved_state_is_refused() {
    let _one = one_chain();
    let headers = chain();
    let store = MemoryStore::default();
    let sync = open_genesis(&store);
    sync.clone().start_run(unlimited(), cool()).add_headers(bytes(&headers[..2]), LATER);
    let mut state = store.state().unwrap();
    let middle = state.len() / 2;
    state[middle] ^= 0x01;
    *store.state.lock().unwrap() = Some(state);
    let reopened = HeaderSync::open_genesis(genesis().rlp(), TEST_CHAIN, Box::new(store.clone()));
    assert!(matches!(reopened.err(), Some(HeaderSyncError::Saved { .. })));
}

/// A store whose saves wait until the test lets them go.
struct SlowStore {
    entered: Mutex<Sender<()>>,
    go: Mutex<Receiver<()>>,
}

impl HeaderStore for SlowStore {
    fn load(&self) -> Result<Option<Vec<u8>>, HeaderSyncError> {
        Ok(None)
    }

    fn save(&self, _state: Vec<u8>) -> Result<(), HeaderSyncError> {
        self.entered.lock().unwrap().send(()).unwrap();
        self.go.lock().unwrap().recv().unwrap();
        Ok(())
    }
}

#[test]
fn nothing_waits_while_a_run_holds_the_chain() {
    let _one = one_chain();
    let headers = chain();
    let (entered_tx, entered) = channel();
    let (go, go_rx) = channel();
    let store = SlowStore { entered: Mutex::new(entered_tx), go: Mutex::new(go_rx) };
    let sync = HeaderSync::open_genesis(genesis().rlp(), TEST_CHAIN, Box::new(store)).unwrap();

    let running = {
        let run = sync.clone().start_run(unlimited(), cool());
        let batch = bytes(&headers[..5]);
        thread::spawn(move || run.add_headers(batch, LATER))
    };
    // The run holds the chain while its store saves.
    entered.recv().unwrap();

    assert_eq!(sync.best_height(), 5);
    assert_eq!(sync.cache_count(), 1);
    assert_eq!(sync.state(), ChainState::Valid);
    assert_eq!(sync.saved_state(), None);
    let other = sync.clone().start_run(unlimited(), cool());
    let busy = other.add_headers(bytes(&headers[5..]), LATER);
    assert_eq!((busy.accepted, busy.stopped), (0, Some(StopReason::Busy)));
    // Busy does not end a run.
    assert_eq!(other.stopped(), None);
    let plain = sync.add_headers(bytes(&headers[5..]), LATER);
    assert_eq!(plain.refused_reason.as_deref(), Some("another call is checking headers; nothing was checked"));
    // The release is taken now and done when the run lets go.
    assert!(!sync.release_caches());

    go.send(()).unwrap();
    let done = running.join().unwrap();
    assert_eq!((done.accepted, done.save_error), (5, None));
    assert_eq!(sync.cache_count(), 0);
    assert_eq!(other.add_headers(bytes(&headers[5..]), LATER).stopped, Some(StopReason::CachesReleased));
}
