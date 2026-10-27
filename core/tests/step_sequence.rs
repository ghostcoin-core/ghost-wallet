//! The restart-safe step sequence of `step_sequence`, over an in-memory
//! `StepStore` (records kept in their stored form) and a fake chain that
//! counts every broadcast.
//!
//! For each of the six steps, and right after the broadcast before its reply,
//! the payment is killed (the sequence is dropped), reopened from the store
//! and recovered: it ends on the chain exactly once, broadcast once, signed
//! once, with the hash it had at the kill, and the record is gone. A record
//! on the chain is never resent, a tampered or unreadable record is refused
//! and nothing is sent, and a record never moves backwards.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ghost_wallet_core::{
    ChainView, RECORD_VERSION, Recovery, SETTLE_CONFIRMATIONS, Step, StepError, StepRecord, StepSequence, StepStore,
    decode_step_record, encode_step_record, recover, transaction_hash,
};

const ID: &str = "test-payment-1";

#[derive(Default)]
struct StoreState {
    /// Every record in its stored form, as the Keychain holds it.
    records: BTreeMap<String, Vec<u8>>,
    /// Every save, in order.
    saves: Vec<(String, Step)>,
    fail_saves: bool,
}

/// An in-memory store. Clones share the records, as two launches share the
/// Keychain.
#[derive(Clone, Default)]
struct MemoryStore(Arc<Mutex<StoreState>>);

impl MemoryStore {
    fn state(&self) -> std::sync::MutexGuard<'_, StoreState> {
        self.0.lock().unwrap()
    }

    fn saved_steps(&self, id: &str) -> Vec<Step> {
        self.state().saves.iter().filter(|(saved, _)| saved == id).map(|(_, step)| *step).collect()
    }

    fn stored(&self, id: &str) -> Option<StepRecord> {
        self.state().records.get(id).map(|bytes| decode_step_record(bytes.clone()).unwrap())
    }

    fn put_raw(&self, id: &str, bytes: Vec<u8>) {
        self.state().records.insert(id.to_owned(), bytes);
    }
}

impl StepStore for MemoryStore {
    fn save(&self, record: StepRecord) -> Result<(), StepError> {
        let mut state = self.state();
        if state.fail_saves {
            return Err(StepError::Store { reason: "the test store refuses saves".to_owned() });
        }
        state.saves.push((record.id.clone(), record.step));
        state.records.insert(record.id.clone(), encode_step_record(record));
        Ok(())
    }

    fn load(&self, id: String) -> Result<Option<StepRecord>, StepError> {
        let Some(bytes) = self.state().records.get(&id).cloned() else { return Ok(None) };
        decode_step_record(bytes).map(Some).map_err(|error| match error {
            StepError::Unreadable { reason, .. } => StepError::Unreadable { id, reason },
            other => other,
        })
    }

    fn list(&self) -> Result<Vec<String>, StepError> {
        Ok(self.state().records.keys().cloned().collect())
    }

    fn remove(&self, id: String) -> Result<(), StepError> {
        self.state().records.remove(&id);
        Ok(())
    }
}

#[derive(Default)]
struct ChainState {
    height: u64,
    /// Every transaction in a block: its bytes and the height of its block.
    included: Vec<(Vec<u8>, u64)>,
    /// How many times each hash was broadcast.
    broadcasts: BTreeMap<Vec<u8>, u32>,
}

/// A fake chain: a broadcast transaction goes into the next block, once.
#[derive(Clone, Default)]
struct FakeChain(Arc<Mutex<ChainState>>);

impl FakeChain {
    fn state(&self) -> std::sync::MutexGuard<'_, ChainState> {
        self.0.lock().unwrap()
    }

    fn view(&self) -> Box<dyn ChainView> {
        Box::new(self.clone())
    }

    fn broadcast(&self, bytes: Vec<u8>) {
        let hash = transaction_hash(bytes.clone());
        let mut state = self.state();
        *state.broadcasts.entry(hash.clone()).or_default() += 1;
        if !state.included.iter().any(|(tx, _)| transaction_hash(tx.clone()) == hash) {
            state.height += 1;
            let height = state.height;
            state.included.push((bytes, height));
        }
    }

    fn mine(&self) {
        self.state().height += 1;
    }

    fn broadcasts(&self, hash: &[u8]) -> u32 {
        self.state().broadcasts.get(hash).copied().unwrap_or(0)
    }

    fn total_broadcasts(&self) -> u32 {
        self.state().broadcasts.values().sum()
    }

    /// The hashes of every transaction in a block that pays `id`.
    fn payments(&self, id: &str) -> Vec<Vec<u8>> {
        let tag = format!(" {id} ");
        self.state()
            .included
            .iter()
            .filter(|(tx, _)| String::from_utf8_lossy(tx).contains(&tag))
            .map(|(tx, _)| transaction_hash(tx.clone()))
            .collect()
    }

    fn included_height(&self, hash: &[u8]) -> Option<u64> {
        let state = self.state();
        state.included.iter().find(|(tx, _)| transaction_hash(tx.clone()) == hash).map(|(_, height)| *height)
    }
}

impl ChainView for FakeChain {
    fn has_transaction(&self, hash: Vec<u8>) -> Result<bool, StepError> {
        Ok(self.included_height(&hash).is_some())
    }

    fn confirmations(&self, hash: Vec<u8>) -> Result<u64, StepError> {
        let height = self.state().height;
        Ok(self.included_height(&hash).map_or(0, |at| height - at + 1))
    }
}

/// A test signer whose every signature differs, so a second signing would
/// show as a second payment.
#[derive(Default)]
struct Signer {
    calls: u32,
}

impl Signer {
    fn sign(&mut self, id: &str) -> Vec<u8> {
        self.calls += 1;
        format!("synthetic test-chain send {id} attempt {}", self.calls).into_bytes()
    }
}

/// Where a run is killed: right after a step is saved, or right after the
/// broadcast, before its reply is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kill {
    At(Step),
    AfterBroadcast,
}

const KILL_POINTS: [Kill; 7] = [
    Kill::At(Step::Prepared),
    Kill::At(Step::BackedUp),
    Kill::At(Step::Signed),
    Kill::At(Step::Sent),
    Kill::AfterBroadcast,
    Kill::At(Step::Seen),
    Kill::At(Step::Settled),
];

#[derive(Debug, PartialEq, Eq)]
struct Killed;

/// Moves a payment on until it is settled and removed, as the app does:
/// ask `recover`, do what it says, repeat. Stops early at `kill`.
fn drive(seq: &StepSequence, chain: &FakeChain, signer: &mut Signer, kill: Option<Kill>) -> Result<(), Killed> {
    let id = seq.record().id;
    for _ in 0..100 {
        match seq.recover(chain.view()).unwrap() {
            Recovery::Done => {
                seq.finish().unwrap();
                return Ok(());
            }
            Recovery::Resume { step } => {
                match step {
                    Step::Prepared => panic!("nothing resumes at prepared"),
                    Step::BackedUp => seq.mark_backed_up().unwrap(),
                    Step::Signed => {
                        seq.mark_signed(signer.sign(&id)).unwrap();
                    }
                    Step::Sent => seq.mark_sent().unwrap(),
                    Step::Seen => seq.mark_seen(chain.view()).unwrap(),
                    Step::Settled => seq.mark_settled(chain.view()).unwrap(),
                }
                if kill == Some(Kill::At(step)) {
                    return Err(Killed);
                }
            }
            Recovery::ResendSame { bytes } => {
                assert_eq!(Some(&bytes), seq.record().signed_transaction.as_ref(), "only the stored bytes are sent");
                if seq.step() == Step::Signed {
                    seq.mark_sent().unwrap();
                    if kill == Some(Kill::At(Step::Sent)) {
                        return Err(Killed);
                    }
                }
                chain.broadcast(bytes);
                if kill == Some(Kill::AfterBroadcast) {
                    return Err(Killed);
                }
            }
            Recovery::Wait => chain.mine(),
        }
    }
    panic!("the payment did not settle");
}

/// Starts the payment and drives it to `kill`.
fn start_and_kill(store: &MemoryStore, chain: &FakeChain, signer: &mut Signer, kill: Kill) {
    let seq = StepSequence::start(Box::new(store.clone()), ID.to_owned()).unwrap();
    if kill == Kill::At(Step::Prepared) {
        return;
    }
    assert_eq!(drive(&seq, chain, signer, Some(kill)), Err(Killed));
    // `seq` is dropped here: the kill.
}

/// What the next launch does: open every unfinished payment and drive it.
fn relaunch(store: &MemoryStore, chain: &FakeChain, signer: &mut Signer, kill: Option<Kill>) -> Result<(), Killed> {
    let ids = store.list().unwrap();
    assert_eq!(ids, vec![ID.to_owned()], "the killed payment is found");
    let seq = StepSequence::open(Box::new(store.clone()), ID.to_owned()).unwrap();
    drive(&seq, chain, signer, kill)
}

/// The payment is on the chain once, broadcast once, signed once, settled,
/// every step saved once in order, and its record removed.
fn assert_paid_once(
    store: &MemoryStore,
    chain: &FakeChain,
    signer: &Signer,
    hash_at_kill: Option<Vec<u8>>,
    kill: Kill,
) {
    let payments = chain.payments(ID);
    assert_eq!(payments.len(), 1, "{kill:?}: the payment is on the chain exactly once");
    let hash = &payments[0];
    assert_eq!(chain.broadcasts(hash), 1, "{kill:?}: broadcast exactly once");
    assert_eq!(chain.total_broadcasts(), 1, "{kill:?}: nothing else was broadcast");
    assert_eq!(signer.calls, 1, "{kill:?}: signed exactly once");
    if let Some(at_kill) = hash_at_kill {
        assert_eq!(&at_kill, hash, "{kill:?}: the transaction hash never changed");
    }
    assert!(chain.confirmations(hash.clone()).unwrap() >= SETTLE_CONFIRMATIONS, "{kill:?}: settled");
    assert_eq!(store.saved_steps(ID), Step::ALL.to_vec(), "{kill:?}: every step saved once, in order");
    assert!(store.list().unwrap().is_empty(), "{kill:?}: the settled record is removed");
}

#[test]
fn an_unkilled_payment_settles_once() {
    let (store, chain, mut signer) = (MemoryStore::default(), FakeChain::default(), Signer::default());
    let seq = StepSequence::start(Box::new(store.clone()), ID.to_owned()).unwrap();
    drive(&seq, &chain, &mut signer, None).unwrap();
    let payments = chain.payments(ID);
    assert_eq!(payments.len(), 1);
    assert_eq!(chain.broadcasts(&payments[0]), 1);
    assert_eq!(store.saved_steps(ID), Step::ALL.to_vec());
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn every_kill_point_recovers_paid_exactly_once() {
    for kill in KILL_POINTS {
        let (store, chain, mut signer) = (MemoryStore::default(), FakeChain::default(), Signer::default());
        start_and_kill(&store, &chain, &mut signer, kill);

        let at_kill = store.stored(ID).expect("the record survives the kill");
        let expected_step = match kill {
            Kill::At(step) => step,
            Kill::AfterBroadcast => Step::Sent,
        };
        assert_eq!(at_kill.step, expected_step, "{kill:?}");
        assert_eq!(at_kill.transaction_hash.is_some(), expected_step >= Step::Signed, "{kill:?}");
        let broadcasts_at_kill = chain.total_broadcasts();

        relaunch(&store, &chain, &mut signer, None).unwrap();
        assert_paid_once(&store, &chain, &signer, at_kill.transaction_hash, kill);
        if matches!(kill, Kill::AfterBroadcast | Kill::At(Step::Seen) | Kill::At(Step::Settled)) {
            assert_eq!(broadcasts_at_kill, 1, "{kill:?}: the broadcast happened before the kill");
        }
    }
}

#[test]
fn killed_at_every_point_in_turn_still_pays_once() {
    let (store, chain, mut signer) = (MemoryStore::default(), FakeChain::default(), Signer::default());
    start_and_kill(&store, &chain, &mut signer, Kill::At(Step::Prepared));
    let mut first_hash = None;
    for kill in &KILL_POINTS[1..] {
        assert_eq!(relaunch(&store, &chain, &mut signer, Some(*kill)), Err(Killed), "{kill:?}");
        let hash = store.stored(ID).unwrap().transaction_hash;
        if first_hash.is_none() {
            first_hash = hash.clone();
        }
        if hash.is_some() {
            assert_eq!(hash, first_hash, "{kill:?}: the hash never changes");
        }
    }
    relaunch(&store, &chain, &mut signer, None).unwrap();
    assert_paid_once(&store, &chain, &signer, first_hash, Kill::At(Step::Settled));
}

#[test]
fn a_transaction_on_the_chain_is_never_resent() {
    let (store, chain, mut signer) = (MemoryStore::default(), FakeChain::default(), Signer::default());
    start_and_kill(&store, &chain, &mut signer, Kill::AfterBroadcast);
    let record = store.stored(ID).unwrap();
    assert_eq!(record.step, Step::Sent);
    let hash = record.transaction_hash.clone().unwrap();
    assert_eq!(chain.broadcasts(&hash), 1);

    // The chain has it: go on to seen, send nothing.
    assert_eq!(recover(record.clone(), chain.view()).unwrap(), Recovery::Resume { step: Step::Seen });
    let seq = StepSequence::open(Box::new(store.clone()), ID.to_owned()).unwrap();
    assert_eq!(seq.recover(chain.view()).unwrap(), Recovery::Resume { step: Step::Seen });

    // Had it not reached the chain, the same bytes would go again.
    let empty = FakeChain::default();
    assert_eq!(
        recover(record.clone(), empty.view()).unwrap(),
        Recovery::ResendSame { bytes: record.signed_transaction.clone().unwrap() }
    );

    seq.mark_seen(chain.view()).unwrap();
    chain.mine();
    assert_eq!(seq.recover(chain.view()).unwrap(), Recovery::Wait);
    chain.mine();
    assert_eq!(seq.recover(chain.view()).unwrap(), Recovery::Resume { step: Step::Settled });
    assert_eq!(chain.broadcasts(&hash), 1);
}

#[test]
fn a_tampered_or_unreadable_record_is_refused_and_nothing_is_sent() {
    let (store, chain, mut signer) = (MemoryStore::default(), FakeChain::default(), Signer::default());
    start_and_kill(&store, &chain, &mut signer, Kill::At(Step::Signed));
    let good = store.stored(ID).unwrap();
    let open = || StepSequence::open(Box::new(store.clone()), ID.to_owned()).err();

    let tampered = |record: StepRecord| {
        store.put_raw(ID, encode_step_record(record.clone()));
        let refused = open();
        assert!(matches!(refused, Some(StepError::Tampered { .. })), "{refused:?}");
        let refused = recover(record, chain.view());
        assert!(matches!(refused, Err(StepError::Tampered { .. })), "{refused:?}");
    };
    // A later step, other bytes, another hash, bytes dropped: the checksum fails.
    tampered(StepRecord { step: Step::Settled, ..good.clone() });
    tampered(StepRecord { signed_transaction: Some(b"synthetic other send".to_vec()), ..good.clone() });
    tampered(StepRecord { transaction_hash: Some(vec![0; 32]), ..good.clone() });
    tampered(StepRecord { signed_transaction: None, transaction_hash: None, ..good.clone() });
    tampered(StepRecord { checksum: vec![0; 32], ..good.clone() });
    // A record with no checksum does not even decode once stored.
    let refused = recover(StepRecord { checksum: Vec::new(), ..good.clone() }, chain.view());
    assert!(matches!(refused, Err(StepError::Tampered { .. })), "{refused:?}");

    // Another version.
    store.put_raw(ID, encode_step_record(StepRecord { version: RECORD_VERSION + 1, ..good.clone() }));
    assert!(matches!(open(), Some(StepError::UnsupportedVersion { version, .. }) if version == RECORD_VERSION + 1));

    // Bytes that are no record, or cut short.
    let bytes = encode_step_record(good.clone());
    for broken in [vec![1, 2, 3], bytes[..bytes.len() - 1].to_vec(), Vec::new()] {
        store.put_raw(ID, broken);
        assert!(matches!(open(), Some(StepError::Unreadable { ref id, .. }) if id == ID));
    }
    // A flipped bit anywhere is refused one way or the other.
    for at in 0..bytes.len() {
        let mut flipped = bytes.clone();
        flipped[at] ^= 0x01;
        store.put_raw(ID, flipped);
        assert!(open().is_some(), "a flipped bit at {at} was accepted");
    }
    // A record saved under another id.
    store.put_raw(ID, encode_step_record(StepRecord { id: "test-payment-2".to_owned(), ..good.clone() }));
    assert!(matches!(open(), Some(StepError::Tampered { .. })));

    assert_eq!(chain.total_broadcasts(), 0, "nothing was sent for a refused record");

    // The good record still recovers, paid once.
    store.put_raw(ID, encode_step_record(good.clone()));
    relaunch(&store, &chain, &mut signer, None).unwrap();
    assert_paid_once(&store, &chain, &signer, good.transaction_hash, Kill::At(Step::Signed));
}

#[test]
fn a_record_never_moves_backwards_or_takes_new_bytes() {
    let (store, chain, mut signer) = (MemoryStore::default(), FakeChain::default(), Signer::default());
    start_and_kill(&store, &chain, &mut signer, Kill::At(Step::Sent));
    let seq = StepSequence::open(Box::new(store.clone()), ID.to_owned()).unwrap();
    let before = seq.record();
    let saves = store.saved_steps(ID).len();

    assert_eq!(seq.mark_backed_up(), Err(StepError::OutOfOrder { from: Step::Sent, to: Step::BackedUp }));
    assert_eq!(
        seq.mark_signed(b"synthetic second send".to_vec()),
        Err(StepError::OutOfOrder { from: Step::Sent, to: Step::Signed })
    );
    assert_eq!(seq.mark_sent(), Err(StepError::OutOfOrder { from: Step::Sent, to: Step::Sent }));
    assert_eq!(
        seq.mark_settled(chain.view()),
        Err(StepError::OutOfOrder { from: Step::Sent, to: Step::Settled })
    );
    // Not on the chain yet: not seen.
    assert_eq!(seq.mark_seen(chain.view()), Err(StepError::NotOnChain));
    assert_eq!(seq.finish(), Err(StepError::NotFinished { step: Step::Sent }));
    // The payment cannot be started again under its id.
    assert!(matches!(
        StepSequence::start(Box::new(store.clone()), ID.to_owned()),
        Err(StepError::AlreadyStarted { .. })
    ));

    assert_eq!(seq.record(), before, "a refused step changes nothing");
    assert_eq!(store.stored(ID).unwrap(), before);
    assert_eq!(store.saved_steps(ID).len(), saves, "nothing was saved");

    // Seen too early for settled.
    chain.broadcast(before.signed_transaction.clone().unwrap());
    seq.mark_seen(chain.view()).unwrap();
    assert_eq!(
        seq.mark_settled(chain.view()),
        Err(StepError::NotSettled { confirmations: 1, needed: SETTLE_CONFIRMATIONS })
    );
    assert_eq!(seq.step(), Step::Seen);
}

#[test]
fn a_failed_save_changes_nothing() {
    let (store, chain, mut signer) = (MemoryStore::default(), FakeChain::default(), Signer::default());
    start_and_kill(&store, &chain, &mut signer, Kill::At(Step::BackedUp));
    let seq = StepSequence::open(Box::new(store.clone()), ID.to_owned()).unwrap();
    store.state().fail_saves = true;
    assert!(matches!(seq.mark_signed(signer.sign(ID)), Err(StepError::Store { .. })));
    assert_eq!(seq.step(), Step::BackedUp);
    assert_eq!(store.stored(ID).unwrap().step, Step::BackedUp);
    assert!(matches!(seq.mark_signed(Vec::new()), Err(StepError::EmptyTransaction)));
    store.state().fail_saves = false;
    let hash = seq.mark_signed(signer.sign(ID)).unwrap();
    assert_eq!(Some(hash), store.stored(ID).unwrap().transaction_hash);
}

#[test]
fn the_hash_is_keccak_256() {
    // Keccak-256 of the empty string.
    let empty = transaction_hash(Vec::new());
    let hex: String = empty.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
}
