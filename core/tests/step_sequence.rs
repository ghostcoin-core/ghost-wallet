//! The payment records of `step_sequence`, over an in-memory `PaymentStore`
//! (records kept in their stored form, payloads apart) and a small fake
//! chain where a broadcast goes into the next block.
//!
//! A settled record is kept with its block hash, never deleted; a record
//! moves back only when the chain takes its block away; steps are otherwise
//! saved in order; a tampered or unreadable record or payload is refused and
//! nothing is sent; and new attempts keep the payment's identity.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use ghost_wallet_core::{
    Attempt, ChainView, Identity, Inclusion, MAX_ATTEMPTS, PaymentIntent, PaymentKind, PaymentRecord, PaymentSequence,
    PaymentStore, RECORD_VERSION, Receipt, ReceiptStatus, Recovery, SETTLE_CONFIRMATIONS, Step, StepError,
    decode_payment_record, encode_payment_record, transaction_hash,
};

const ID: &str = "test-payment-1";

fn intent() -> PaymentIntent {
    PaymentIntent {
        kind: PaymentKind::Vanish,
        identity: Identity::AccountNonce { account: b"test-account-1".to_vec(), nonce: 3 },
        details: b"test vanish of 2".to_vec(),
    }
}

#[derive(Default)]
struct StoreState {
    records: BTreeMap<String, Vec<u8>>,
    payloads: BTreeMap<(String, Vec<u8>), Vec<u8>>,
    saves: Vec<Step>,
    fail_saves: bool,
}

#[derive(Clone, Default)]
struct MemoryStore(Arc<Mutex<StoreState>>);

impl MemoryStore {
    fn state(&self) -> MutexGuard<'_, StoreState> {
        self.0.lock().unwrap()
    }

    fn stored(&self) -> PaymentRecord {
        decode_payment_record(self.state().records[ID].clone()).unwrap()
    }

    fn put_raw(&self, bytes: Vec<u8>) {
        self.state().records.insert(ID.to_owned(), bytes);
    }

    fn open(&self) -> Result<Arc<PaymentSequence>, StepError> {
        PaymentSequence::open(Box::new(self.clone()), ID.to_owned())
    }
}

impl PaymentStore for MemoryStore {
    fn save(&self, record: PaymentRecord) -> Result<(), StepError> {
        let mut state = self.state();
        if state.fail_saves {
            return Err(StepError::Store { reason: "the test store refuses saves".to_owned() });
        }
        state.saves.push(record.step);
        state.records.insert(record.id.clone(), encode_payment_record(record));
        Ok(())
    }

    fn load(&self, id: String) -> Result<Option<PaymentRecord>, StepError> {
        let Some(bytes) = self.state().records.get(&id).cloned() else { return Ok(None) };
        decode_payment_record(bytes).map(Some).map_err(|error| match error {
            StepError::Unreadable { reason, .. } => StepError::Unreadable { id, reason },
            other => other,
        })
    }

    fn list(&self) -> Result<Vec<String>, StepError> {
        Ok(self.state().records.keys().cloned().collect())
    }

    fn remove(&self, id: String) -> Result<(), StepError> {
        let mut state = self.state();
        state.records.remove(&id);
        state.payloads.retain(|(owner, _), _| *owner != id);
        Ok(())
    }

    fn save_payload(&self, id: String, hash: Vec<u8>, signed_transaction: Vec<u8>) -> Result<(), StepError> {
        let mut state = self.state();
        if state.fail_saves {
            return Err(StepError::Store { reason: "the test store refuses saves".to_owned() });
        }
        state.payloads.insert((id, hash), signed_transaction);
        Ok(())
    }

    fn load_payload(&self, id: String, hash: Vec<u8>) -> Result<Option<Vec<u8>>, StepError> {
        Ok(self.state().payloads.get(&(id, hash)).cloned())
    }
}

#[derive(Default)]
struct ChainState {
    /// Each block: its hash and its transactions' hashes.
    blocks: Vec<(Vec<u8>, Vec<Vec<u8>>)>,
    broadcasts: u32,
    made: u64,
}

/// A broadcast goes into a new block at once; `reorg` takes blocks away.
#[derive(Clone, Default)]
struct FakeChain(Arc<Mutex<ChainState>>);

impl FakeChain {
    fn state(&self) -> MutexGuard<'_, ChainState> {
        self.0.lock().unwrap()
    }

    fn view(&self) -> Box<dyn ChainView> {
        Box::new(self.clone())
    }

    fn block(&self, txs: Vec<Vec<u8>>) {
        let mut state = self.state();
        state.made += 1;
        let hash = transaction_hash(format!("test block {}", state.made).into_bytes());
        state.blocks.push((hash, txs));
    }

    fn broadcast(&self, bytes: Vec<u8>) {
        self.state().broadcasts += 1;
        if self.receipt(transaction_hash(bytes.clone())).unwrap().is_none() {
            self.block(vec![transaction_hash(bytes)]);
        }
    }

    fn mine(&self) {
        self.block(Vec::new());
    }

    fn reorg(&self, depth: usize) {
        let mut state = self.state();
        let keep = state.blocks.len() - depth;
        state.blocks.truncate(keep);
    }
}

impl ChainView for FakeChain {
    fn receipt(&self, hash: Vec<u8>) -> Result<Option<Receipt>, StepError> {
        let state = self.state();
        Ok(state.blocks.iter().enumerate().find(|(_, (_, txs))| txs.contains(&hash)).map(|(at, (block, _))| {
            Receipt { status: ReceiptStatus::Success, block_hash: block.clone(), block_height: at as u64 + 1 }
        }))
    }

    fn pending(&self, _hash: Vec<u8>) -> Result<bool, StepError> {
        Ok(false)
    }

    fn identity_used_by(&self, _identity: Identity) -> Result<Option<Vec<u8>>, StepError> {
        Ok(None)
    }

    fn effect_applied(&self, _intent: PaymentIntent, hash: Vec<u8>) -> Result<bool, StepError> {
        Ok(self.receipt(hash)?.is_some())
    }

    fn tip_height(&self) -> Result<u64, StepError> {
        Ok(self.state().blocks.len() as u64)
    }
}

fn signed(n: u32) -> Vec<u8> {
    format!("synthetic test vanish attempt {n}").into_bytes()
}

/// Drives the payment to its end as the app does; returns the final step.
fn drive(seq: &PaymentSequence, chain: &FakeChain) -> Step {
    let mut n = 0;
    for _ in 0..50 {
        match seq.recover(chain.view()).unwrap() {
            Recovery::BackUp => seq.mark_backed_up().unwrap(),
            Recovery::Sign | Recovery::Rebuild => {
                n += 1;
                seq.add_attempt(signed(n), None).unwrap();
            }
            Recovery::Send { .. } => chain.broadcast(seq.mark_sent().unwrap()),
            Recovery::Wait => chain.mine(),
            Recovery::Done { step } => return step,
        }
    }
    panic!("the payment never finished");
}

/// A record killed right after its first attempt was saved.
fn signed_record() -> (MemoryStore, Arc<PaymentSequence>) {
    let store = MemoryStore::default();
    let seq = PaymentSequence::start(Box::new(store.clone()), ID.to_owned(), intent()).unwrap();
    seq.mark_backed_up().unwrap();
    seq.add_attempt(signed(1), Some(40)).unwrap();
    (store, seq)
}

#[test]
fn a_settled_record_is_kept_with_its_block_hash() {
    let (store, chain) = (MemoryStore::default(), FakeChain::default());
    let seq = PaymentSequence::start(Box::new(store.clone()), ID.to_owned(), intent()).unwrap();
    assert_eq!(drive(&seq, &chain), Step::Settled);

    assert_eq!(store.list().unwrap(), vec![ID.to_owned()], "the settled record is kept");
    let record = store.stored();
    assert_eq!(record.step, Step::Settled);
    let inclusion = record.inclusion.expect("with where it landed");
    assert_eq!(inclusion.transaction_hash, transaction_hash(signed(1)));
    assert_eq!(inclusion.block_hash, chain.state().blocks[0].0);
    assert_eq!(inclusion.block_height, 1);
    assert_eq!(chain.state().blocks.len() as u64, SETTLE_CONFIRMATIONS);
    assert_eq!(
        store.state().saves,
        vec![Step::Prepared, Step::BackedUp, Step::Signed, Step::Sent, Step::Included, Step::Settled]
    );
    // Reopened later, it is still settled and nothing is sent.
    let reopened = store.open().unwrap();
    assert_eq!(reopened.recover(chain.view()).unwrap(), Recovery::Done { step: Step::Settled });
    assert_eq!(chain.state().broadcasts, 1);
    assert!(store.state().payloads.contains_key(&(ID.to_owned(), transaction_hash(signed(1)))));
}

#[test]
fn a_record_moves_back_only_when_the_chain_takes_its_block_away() {
    let (store, chain) = (MemoryStore::default(), FakeChain::default());
    let seq = PaymentSequence::start(Box::new(store.clone()), ID.to_owned(), intent()).unwrap();
    assert_eq!(drive(&seq, &chain), Step::Settled);
    let settled = seq.record();

    // Nothing the app calls moves a settled record.
    assert_eq!(seq.mark_backed_up(), Err(StepError::OutOfOrder { from: Step::Settled, to: Step::BackedUp }));
    assert_eq!(seq.add_attempt(signed(9), None), Err(StepError::OutOfOrder { from: Step::Settled, to: Step::Signed }));
    assert_eq!(seq.mark_sent(), Err(StepError::OutOfOrder { from: Step::Settled, to: Step::Sent }));
    // New blocks on top do not move it either.
    chain.mine();
    assert_eq!(seq.recover(chain.view()).unwrap(), Recovery::Done { step: Step::Settled });
    assert_eq!(seq.record(), settled);
    assert_eq!(store.stored(), settled);

    // The chain drops the block: back to sent, saved, same attempt.
    chain.reorg(4);
    let hash = transaction_hash(signed(1));
    assert_eq!(seq.recover(chain.view()).unwrap(), Recovery::Send { transaction_hash: hash.clone() });
    assert_eq!(store.stored().step, Step::Sent);
    assert_eq!(store.stored().inclusion, None);
    assert_eq!(store.stored().attempts, settled.attempts);

    // Settles again, in the new block.
    assert_eq!(drive(&seq, &chain), Step::Settled);
    let inclusion = store.stored().inclusion.unwrap();
    assert_eq!(inclusion.transaction_hash, hash);
    assert_ne!(inclusion.block_hash, settled.inclusion.unwrap().block_hash);
}

#[test]
fn steps_are_otherwise_saved_in_order() {
    let store = MemoryStore::default();
    let seq = PaymentSequence::start(Box::new(store.clone()), ID.to_owned(), intent()).unwrap();
    assert_eq!(seq.mark_sent(), Err(StepError::OutOfOrder { from: Step::Prepared, to: Step::Sent }));
    assert_eq!(seq.add_attempt(signed(1), None), Err(StepError::OutOfOrder { from: Step::Prepared, to: Step::Signed }));
    seq.mark_backed_up().unwrap();
    assert_eq!(seq.mark_backed_up(), Err(StepError::OutOfOrder { from: Step::BackedUp, to: Step::BackedUp }));
    assert_eq!(seq.mark_sent(), Err(StepError::OutOfOrder { from: Step::BackedUp, to: Step::Sent }));
    assert_eq!(store.state().saves, vec![Step::Prepared, Step::BackedUp]);
    assert!(store.state().payloads.is_empty(), "a refused attempt stores nothing");
    // The payment cannot be started again under its id.
    assert!(matches!(
        PaymentSequence::start(Box::new(store.clone()), ID.to_owned(), intent()),
        Err(StepError::AlreadyStarted { .. })
    ));
}

#[test]
fn new_attempts_keep_the_identity_and_are_bounded() {
    let (store, seq) = signed_record();
    let first = transaction_hash(signed(1));
    assert_eq!(seq.add_attempt(signed(1), None), Err(StepError::AttemptExists));
    assert_eq!(seq.add_attempt(Vec::new(), None), Err(StepError::EmptyTransaction));
    let sent = seq.mark_sent().unwrap();
    assert_eq!(sent, signed(1));
    assert_eq!(seq.step(), Step::Sent);

    // A rebuild from sent: signed again, the newest is what goes next.
    let second = seq.add_attempt(signed(2), Some(80)).unwrap();
    let record = store.stored();
    assert_eq!(record.step, Step::Signed);
    assert_eq!(record.intent, intent(), "the identity never changes");
    assert_eq!(
        record.attempts,
        vec![
            Attempt { transaction_hash: first, valid_until: Some(40) },
            Attempt { transaction_hash: second.clone(), valid_until: Some(80) },
        ]
    );
    assert_eq!(seq.mark_sent().unwrap(), signed(2));

    for n in 3..=MAX_ATTEMPTS {
        seq.add_attempt(signed(n), None).unwrap();
    }
    assert_eq!(seq.add_attempt(signed(MAX_ATTEMPTS + 1), None), Err(StepError::TooManyAttempts { max: MAX_ATTEMPTS }));
    assert_eq!(store.stored().attempts.len(), MAX_ATTEMPTS as usize);
}

#[test]
fn the_identity_must_fit_the_payment_kind() {
    let store = MemoryStore::default();
    let marker = Identity::RevealMarker { marker: b"test-marker".to_vec() };
    let nonce = Identity::AccountNonce { account: b"test-account".to_vec(), nonce: 0 };
    let refused = [
        (PaymentKind::Send, marker.clone()),
        (PaymentKind::Vanish, marker.clone()),
        (PaymentKind::Summon, nonce.clone()),
        (PaymentKind::Claim, nonce.clone()),
        (PaymentKind::Claim, Identity::RevealMarker { marker: Vec::new() }),
        (PaymentKind::Send, Identity::AccountNonce { account: Vec::new(), nonce: 1 }),
    ];
    for (kind, identity) in refused {
        let intent = PaymentIntent { kind, identity, details: Vec::new() };
        let started = PaymentSequence::start(Box::new(store.clone()), ID.to_owned(), intent);
        assert!(matches!(started, Err(StepError::IdentityMismatch { kind: k }) if k == kind));
    }
    assert!(store.list().unwrap().is_empty());
    for (kind, identity) in [(PaymentKind::Summon, marker), (PaymentKind::Send, nonce)] {
        let id = format!("test-{kind}");
        let intent = PaymentIntent { kind, identity, details: Vec::new() };
        PaymentSequence::start(Box::new(store.clone()), id, intent).unwrap();
    }
}

#[test]
fn a_record_round_trips_through_its_stored_form() {
    let (store, chain) = (MemoryStore::default(), FakeChain::default());
    let seq = PaymentSequence::start(Box::new(store.clone()), ID.to_owned(), intent()).unwrap();
    drive(&seq, &chain);
    let record = seq.record();
    assert_eq!(decode_payment_record(encode_payment_record(record.clone())).unwrap(), record);
    assert_eq!(record.version, RECORD_VERSION);
    let (_, sequence) = signed_record();
    let record = sequence.record();
    assert_eq!(decode_payment_record(encode_payment_record(record.clone())).unwrap(), record);
    assert!(
        !encode_payment_record(record).windows(signed(1).len()).any(|w| w == signed(1)),
        "the record never holds the signed bytes"
    );
}

#[test]
fn a_tampered_or_unreadable_record_is_refused_and_nothing_is_sent() {
    let (store, seq) = signed_record();
    let chain = FakeChain::default();
    let good = seq.record();
    drop(seq);

    let tampered = |record: PaymentRecord| {
        store.put_raw(encode_payment_record(record));
        let refused = store.open().err();
        assert!(matches!(refused, Some(StepError::Tampered { .. })), "{refused:?}");
    };
    // Other fields under the old checksum.
    tampered(PaymentRecord { step: Step::Settled, ..good.clone() });
    tampered(PaymentRecord { attempts: Vec::new(), ..good.clone() });
    tampered(PaymentRecord { checksum: vec![0; 32], ..good.clone() });
    let mut other_nonce = good.clone();
    other_nonce.intent.identity = Identity::AccountNonce { account: b"test-account-1".to_vec(), nonce: 4 };
    tampered(other_nonce);

    // Records that do not hang together.
    let shapes = [
        PaymentRecord { step: Step::Included, ..good.clone() },
        PaymentRecord {
            step: Step::Conflicted,
            inclusion: Some(Inclusion {
                transaction_hash: good.attempts[0].transaction_hash.clone(),
                block_hash: vec![1],
                block_height: 1,
            }),
            ..good.clone()
        },
        PaymentRecord {
            attempts: vec![good.attempts[0].clone(), good.attempts[0].clone()],
            ..good.clone()
        },
    ];
    for shape in shapes {
        tampered(shape);
    }

    // Another version.
    store.put_raw(encode_payment_record(PaymentRecord { version: RECORD_VERSION + 1, ..good.clone() }));
    assert!(matches!(store.open().err(), Some(StepError::UnsupportedVersion { version, .. }) if version == RECORD_VERSION + 1));

    // Bytes that are no record, or cut short.
    let bytes = encode_payment_record(good.clone());
    for broken in [vec![1, 2, 3], bytes[..bytes.len() - 1].to_vec(), Vec::new()] {
        store.put_raw(broken);
        assert!(matches!(store.open().err(), Some(StepError::Unreadable { ref id, .. }) if id == ID));
    }
    // A flipped bit anywhere is refused one way or the other.
    for at in 0..bytes.len() {
        let mut flipped = bytes.clone();
        flipped[at] ^= 0x01;
        store.put_raw(flipped);
        assert!(store.open().is_err(), "a flipped bit at {at} was accepted");
    }
    // A record saved under another id.
    store.put_raw(encode_payment_record(PaymentRecord { id: "test-payment-2".to_owned(), ..good.clone() }));
    assert!(matches!(store.open().err(), Some(StepError::Tampered { .. })));
    assert_eq!(chain.state().broadcasts, 0, "nothing was sent for a refused record");

    // The good record still recovers.
    store.put_raw(encode_payment_record(good));
    assert_eq!(drive(&store.open().unwrap(), &chain), Step::Settled);
    assert_eq!(chain.state().broadcasts, 1);
}

#[test]
fn a_damaged_or_missing_payload_is_refused_and_nothing_is_sent() {
    let (store, seq) = signed_record();
    let key = (ID.to_owned(), transaction_hash(signed(1)));
    store.state().payloads.insert(key.clone(), b"synthetic other bytes".to_vec());
    assert!(matches!(seq.mark_sent(), Err(StepError::Tampered { .. })));
    store.state().payloads.remove(&key);
    assert_eq!(seq.mark_sent(), Err(StepError::PayloadMissing { id: ID.to_owned() }));
    assert_eq!(seq.step(), Step::Signed, "not saved as sent");
    assert_eq!(store.stored().step, Step::Signed);
}

#[test]
fn a_failed_save_changes_nothing() {
    let store = MemoryStore::default();
    let seq = PaymentSequence::start(Box::new(store.clone()), ID.to_owned(), intent()).unwrap();
    seq.mark_backed_up().unwrap();
    store.state().fail_saves = true;
    assert!(matches!(seq.add_attempt(signed(1), None), Err(StepError::Store { .. })));
    assert_eq!(seq.step(), Step::BackedUp);
    assert_eq!(store.stored().step, Step::BackedUp);
    store.state().fail_saves = false;
    let hash = seq.add_attempt(signed(1), None).unwrap();
    assert_eq!(store.stored().attempts[0].transaction_hash, hash);

    store.state().fail_saves = true;
    assert!(matches!(seq.mark_sent(), Err(StepError::Store { .. })));
    assert_eq!(seq.step(), Step::Signed);
}

#[test]
fn the_hash_is_keccak_256() {
    // Keccak-256 of the empty string.
    let empty = transaction_hash(Vec::new());
    let hex: String = empty.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
}
