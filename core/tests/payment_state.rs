//! The payment state machine of `step_sequence` against a fake chain with a
//! mempool, fee windows, receipts that can fail, other transactions and
//! reorgs, over an in-memory store that keeps records and payloads apart.
//!
//! Every scenario ends with the payment paid at most once on the chain and
//! the record in the right final state: a kill at every step, a fee window
//! that passes mid-claim, a reorg after settling, an included transaction
//! whose receipt failed, and a nonce taken by another transaction.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use ghost_wallet_core::{
    ChainView, Identity, PaymentIntent, PaymentKind, PaymentRecord, PaymentSequence, PaymentStore, Receipt,
    ReceiptStatus, Recovery, SETTLE_CONFIRMATIONS, Step, StepError, decode_payment_record, encode_payment_record,
    transaction_hash,
};

const ID: &str = "test-payment-1";

fn send_intent() -> PaymentIntent {
    PaymentIntent {
        kind: PaymentKind::Send,
        identity: Identity::AccountNonce { account: b"test-account-1".to_vec(), nonce: 7 },
        details: b"test send of 1 to account 3".to_vec(),
    }
}

fn claim_intent() -> PaymentIntent {
    PaymentIntent {
        kind: PaymentKind::Claim,
        identity: Identity::RevealMarker { marker: b"test-marker-1".to_vec() },
        details: b"test claim of note 1".to_vec(),
    }
}

/// The identity as one word, as the fake chain reads it from the bytes.
fn identity_key(identity: &Identity) -> String {
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    match identity {
        Identity::AccountNonce { account, nonce } => format!("nonce:{}:{nonce}", hex(account)),
        Identity::RevealMarker { marker } => format!("marker:{}", hex(marker)),
    }
}

// --- The store -------------------------------------------------------------

#[derive(Default)]
struct StoreState {
    /// Every record in its stored form.
    records: BTreeMap<String, Vec<u8>>,
    /// Every payload, by payment id and hash.
    payloads: BTreeMap<(String, Vec<u8>), Vec<u8>>,
    /// Every record save, in order.
    saves: Vec<(String, Step)>,
    /// Refuse the next record save at this step (a kill right after the
    /// payload was written).
    fail_next_save_at: Option<Step>,
}

/// An in-memory store. Clones share their contents, as two launches share
/// the Keychain and the app's files.
#[derive(Clone, Default)]
struct MemoryStore(Arc<Mutex<StoreState>>);

impl MemoryStore {
    fn state(&self) -> MutexGuard<'_, StoreState> {
        self.0.lock().unwrap()
    }

    fn saved_steps(&self) -> Vec<Step> {
        self.state().saves.iter().filter(|(id, _)| id == ID).map(|(_, step)| *step).collect()
    }

    fn stored(&self) -> PaymentRecord {
        decode_payment_record(self.state().records[ID].clone()).unwrap()
    }

    fn payload_count(&self) -> usize {
        self.state().payloads.len()
    }
}

impl PaymentStore for MemoryStore {
    fn save(&self, record: PaymentRecord) -> Result<(), StepError> {
        let mut state = self.state();
        if state.fail_next_save_at == Some(record.step) {
            state.fail_next_save_at = None;
            return Err(StepError::Store { reason: "killed before the record was saved".to_owned() });
        }
        state.saves.push((record.id.clone(), record.step));
        state.records.insert(record.id.clone(), encode_payment_record(record));
        Ok(())
    }

    fn load(&self, id: String) -> Result<Option<PaymentRecord>, StepError> {
        let Some(bytes) = self.state().records.get(&id).cloned() else { return Ok(None) };
        decode_payment_record(bytes).map(Some)
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
        self.state().payloads.insert((id, hash), signed_transaction);
        Ok(())
    }

    fn load_payload(&self, id: String, hash: Vec<u8>) -> Result<Option<Vec<u8>>, StepError> {
        Ok(self.state().payloads.get(&(id, hash)).cloned())
    }
}

// --- The chain -------------------------------------------------------------

/// What a test transaction does once in a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Success, and the payment's effect.
    Pay,
    /// A failed receipt.
    Fail,
    /// A successful receipt but none of the expected effect.
    NoEffect,
}

impl Outcome {
    fn word(self) -> &'static str {
        match self {
            Outcome::Pay => "pay",
            Outcome::Fail => "fail",
            Outcome::NoEffect => "noeffect",
        }
    }
}

/// A transaction as the fake chain reads it from its synthetic bytes:
/// `synthetic <id> <identity> until <height|none> <outcome> attempt <n>`.
#[derive(Clone)]
struct Tx {
    hash: Vec<u8>,
    id: String,
    identity: String,
    until: Option<u64>,
    outcome: String,
}

impl Tx {
    fn parse(bytes: &[u8]) -> Tx {
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        let words: Vec<&str> = text.split(' ').collect();
        assert_eq!(words[0], "synthetic");
        Tx {
            hash: transaction_hash(bytes.to_vec()),
            id: words[1].to_owned(),
            identity: words[2].to_owned(),
            until: words[4].parse().ok(),
            outcome: words[5].to_owned(),
        }
    }
}

struct Block {
    hash: Vec<u8>,
    txs: Vec<Tx>,
}

#[derive(Default)]
struct ChainState {
    /// The canonical chain: block `i` is at height `i + 1`.
    blocks: Vec<Block>,
    mempool: Vec<Tx>,
    /// How many times each hash was broadcast.
    broadcasts: BTreeMap<Vec<u8>, u32>,
    /// Broadcasts the node refused (identity used, window passed).
    rejected: Vec<Vec<u8>>,
    /// Every block ever made, for unique block hashes across branches.
    made: u64,
    /// A broadcast is mined into the next block straight away.
    auto_mine: bool,
}

impl ChainState {
    fn tip(&self) -> u64 {
        self.blocks.len() as u64
    }

    fn find(&self, hash: &[u8]) -> Option<(u64, &Block, &Tx)> {
        self.blocks.iter().enumerate().find_map(|(at, block)| {
            block.txs.iter().find(|tx| tx.hash == hash).map(|tx| (at as u64 + 1, block, tx))
        })
    }

    fn used_by(&self, identity: &str) -> Option<&Tx> {
        self.blocks.iter().flat_map(|block| &block.txs).find(|tx| tx.identity == identity)
    }

    fn mine(&mut self) {
        let height = self.tip() + 1;
        let mut txs: Vec<Tx> = Vec::new();
        for tx in std::mem::take(&mut self.mempool) {
            let used = self.used_by(&tx.identity).is_some() || txs.iter().any(|t| t.identity == tx.identity);
            let expired = tx.until.is_some_and(|until| height > until);
            if !used && !expired {
                txs.push(tx);
            }
        }
        self.made += 1;
        let hash = transaction_hash(format!("test block {}", self.made).into_bytes());
        self.blocks.push(Block { hash, txs });
    }
}

/// A fake chain. Clones share it, as the app and the test see one chain.
#[derive(Clone, Default)]
struct FakeChain(Arc<Mutex<ChainState>>);

impl FakeChain {
    fn auto_mining() -> Self {
        let chain = FakeChain::default();
        chain.state().auto_mine = true;
        chain
    }

    fn state(&self) -> MutexGuard<'_, ChainState> {
        self.0.lock().unwrap()
    }

    fn view(&self) -> Box<dyn ChainView> {
        Box::new(self.clone())
    }

    fn tip(&self) -> u64 {
        self.state().tip()
    }

    fn broadcast(&self, bytes: Vec<u8>) {
        let tx = Tx::parse(&bytes);
        let mut state = self.state();
        *state.broadcasts.entry(tx.hash.clone()).or_default() += 1;
        if state.find(&tx.hash).is_some() || state.mempool.iter().any(|t| t.hash == tx.hash) {
            return;
        }
        let next = state.tip() + 1;
        if state.used_by(&tx.identity).is_some() || tx.until.is_some_and(|until| next > until) {
            state.rejected.push(tx.hash);
            return;
        }
        state.mempool.push(tx);
        if state.auto_mine {
            state.mine();
        }
    }

    fn mine(&self) {
        self.state().mine();
    }

    fn mine_blocks(&self, n: u64) {
        for _ in 0..n {
            self.mine();
        }
    }

    /// The node forgets every pending transaction.
    fn drop_mempool(&self) {
        self.state().mempool.clear();
    }

    /// Takes the top `depth` blocks away. With `replay`, their transactions
    /// go back to the mempool, as a node does; without, they are gone.
    fn reorg(&self, depth: u64, replay: bool) {
        let mut state = self.state();
        for _ in 0..depth {
            let block = state.blocks.pop().expect("a block to take away");
            if replay {
                state.mempool.extend(block.txs);
            }
        }
    }

    /// Mines a block holding another transaction that uses `identity`.
    fn mine_other(&self, identity: &Identity) {
        let bytes = format!("synthetic someone-else {} until none pay attempt 1", identity_key(identity));
        let tx = Tx::parse(bytes.as_bytes());
        let mut state = self.state();
        state.mempool.insert(0, tx);
        state.mine();
    }

    fn broadcasts(&self, hash: &[u8]) -> u32 {
        self.state().broadcasts.get(hash).copied().unwrap_or(0)
    }

    fn total_broadcasts(&self) -> u32 {
        self.state().broadcasts.values().sum()
    }

    fn rejected(&self) -> usize {
        self.state().rejected.len()
    }

    /// The hashes of every transaction on the chain that paid `id`.
    fn payments(&self, id: &str) -> Vec<Vec<u8>> {
        let state = self.state();
        let paid = state.blocks.iter().flat_map(|block| &block.txs);
        paid.filter(|tx| tx.id == id && tx.outcome == "pay").map(|tx| tx.hash.clone()).collect()
    }

    /// The hashes of every transaction on the chain sent for `id`.
    fn landed(&self, id: &str) -> Vec<Vec<u8>> {
        let state = self.state();
        state.blocks.iter().flat_map(|block| &block.txs).filter(|tx| tx.id == id).map(|tx| tx.hash.clone()).collect()
    }

    fn block_hash_of(&self, hash: &[u8]) -> Option<Vec<u8>> {
        self.state().find(hash).map(|(_, block, _)| block.hash.clone())
    }
}

impl ChainView for FakeChain {
    fn receipt(&self, hash: Vec<u8>) -> Result<Option<Receipt>, StepError> {
        let state = self.state();
        Ok(state.find(&hash).map(|(height, block, tx)| Receipt {
            status: if tx.outcome == "fail" { ReceiptStatus::Failed } else { ReceiptStatus::Success },
            block_hash: block.hash.clone(),
            block_height: height,
        }))
    }

    fn pending(&self, hash: Vec<u8>) -> Result<bool, StepError> {
        Ok(self.state().mempool.iter().any(|tx| tx.hash == hash))
    }

    fn identity_used_by(&self, identity: Identity) -> Result<Option<Vec<u8>>, StepError> {
        Ok(self.state().used_by(&identity_key(&identity)).map(|tx| tx.hash.clone()))
    }

    fn effect_applied(&self, intent: PaymentIntent, hash: Vec<u8>) -> Result<bool, StepError> {
        let state = self.state();
        Ok(state.find(&hash).is_some_and(|(_, _, tx)| {
            tx.outcome == "pay" && tx.identity == identity_key(&intent.identity)
        }))
    }

    fn tip_height(&self) -> Result<u64, StepError> {
        Ok(self.tip())
    }
}

// --- The app ---------------------------------------------------------------

/// Signs test transactions. Every signature differs, so signing twice shows.
struct Signer {
    calls: u32,
    outcome: Outcome,
    /// How many blocks past the tip a new attempt stays valid, if limited.
    window: Option<u64>,
}

impl Signer {
    fn new(outcome: Outcome, window: Option<u64>) -> Self {
        Signer { calls: 0, outcome, window }
    }

    fn sign(&mut self, intent: &PaymentIntent, tip: u64) -> (Vec<u8>, Option<u64>) {
        self.calls += 1;
        let until = self.window.map(|blocks| tip + blocks);
        let until_word = until.map_or("none".to_owned(), |h| h.to_string());
        let text = format!(
            "synthetic {ID} {} until {until_word} {} attempt {}",
            identity_key(&intent.identity),
            self.outcome.word(),
            self.calls
        );
        (text.into_bytes(), until)
    }
}

/// Where a run is killed: right after a step is saved, right after a
/// broadcast, or after an attempt's payload is written but before its
/// record is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kill {
    At(Step),
    AfterBroadcast,
    BeforeAttemptRecord,
}

const KILL_POINTS: [Kill; 8] = [
    Kill::At(Step::Prepared),
    Kill::At(Step::BackedUp),
    Kill::BeforeAttemptRecord,
    Kill::At(Step::Signed),
    Kill::At(Step::Sent),
    Kill::AfterBroadcast,
    Kill::At(Step::Included),
    Kill::At(Step::Settled),
];

#[derive(Debug, PartialEq, Eq)]
struct Killed;

/// Does what `recover` says until the payment is done, as the app does.
/// Stops early at `kill`. Returns the final step.
fn drive(
    seq: &PaymentSequence,
    store: &MemoryStore,
    chain: &FakeChain,
    signer: &mut Signer,
    kill: Option<Kill>,
) -> Result<Step, Killed> {
    let intent = seq.record().intent;
    for _ in 0..200 {
        let before = seq.step();
        let action = seq.recover(chain.view()).unwrap();
        let now = seq.step();
        if now != before && kill == Some(Kill::At(now)) {
            return Err(Killed);
        }
        match action {
            Recovery::BackUp => {
                seq.mark_backed_up().unwrap();
                if kill == Some(Kill::At(Step::BackedUp)) {
                    return Err(Killed);
                }
            }
            Recovery::Sign | Recovery::Rebuild => {
                let (bytes, until) = signer.sign(&intent, chain.tip());
                if kill == Some(Kill::BeforeAttemptRecord) {
                    store.state().fail_next_save_at = Some(Step::Signed);
                    assert!(matches!(seq.add_attempt(bytes, until), Err(StepError::Store { .. })));
                    return Err(Killed);
                }
                seq.add_attempt(bytes, until).unwrap();
                if kill == Some(Kill::At(Step::Signed)) {
                    return Err(Killed);
                }
            }
            Recovery::Send { transaction_hash: hash } => {
                let was = seq.step();
                let bytes = seq.mark_sent().unwrap();
                assert_eq!(transaction_hash(bytes.clone()), hash, "only the stored bytes are sent");
                assert_eq!(seq.record().attempts.last().unwrap().transaction_hash, hash, "the newest attempt");
                if was == Step::Signed && kill == Some(Kill::At(Step::Sent)) {
                    return Err(Killed);
                }
                chain.broadcast(bytes);
                if kill == Some(Kill::AfterBroadcast) {
                    return Err(Killed);
                }
            }
            Recovery::Wait => chain.mine(),
            Recovery::Done { step } => {
                assert_eq!(step, seq.step());
                return Ok(step);
            }
        }
    }
    panic!("the payment never finished");
}

fn start(store: &MemoryStore, intent: PaymentIntent) -> Arc<PaymentSequence> {
    PaymentSequence::start(Box::new(store.clone()), ID.to_owned(), intent).unwrap()
}

/// The next launch: open the payment and drive it.
fn relaunch(store: &MemoryStore, chain: &FakeChain, signer: &mut Signer, kill: Option<Kill>) -> Result<Step, Killed> {
    assert_eq!(store.list().unwrap(), vec![ID.to_owned()], "the payment is found");
    let seq = PaymentSequence::open(Box::new(store.clone()), ID.to_owned()).unwrap();
    drive(&seq, store, chain, signer, kill)
}

/// Settled, paid exactly once by one of the record's attempts, in the block
/// the record names, and the record kept. Returns the paying hash.
fn assert_settled_once(store: &MemoryStore, chain: &FakeChain, what: &str) -> Vec<u8> {
    let payments = chain.payments(ID);
    assert_eq!(payments.len(), 1, "{what}: paid exactly once");
    assert_eq!(chain.landed(ID).len(), 1, "{what}: one transaction of it on the chain");
    let record = store.stored();
    assert_eq!(record.step, Step::Settled, "{what}: settled and kept");
    let inclusion = record.inclusion.clone().expect("the inclusion is kept");
    assert_eq!(inclusion.transaction_hash, payments[0], "{what}: the record names the paying transaction");
    assert_eq!(Some(inclusion.block_hash), chain.block_hash_of(&payments[0]), "{what}: with its block hash");
    assert!(record.attempts.iter().any(|a| a.transaction_hash == payments[0]), "{what}: one of its attempts");
    assert!(chain.tip() + 1 - inclusion.block_height >= SETTLE_CONFIRMATIONS, "{what}: deep enough");
    // Asked again, it stays settled and sends nothing.
    let broadcasts = chain.total_broadcasts();
    let seq = PaymentSequence::open(Box::new(store.clone()), ID.to_owned()).unwrap();
    assert_eq!(seq.recover(chain.view()).unwrap(), Recovery::Done { step: Step::Settled }, "{what}");
    assert_eq!(chain.total_broadcasts(), broadcasts, "{what}: nothing more sent");
    payments[0].clone()
}

// --- Kills -------------------------------------------------------------------

#[test]
fn an_unkilled_payment_saves_every_step_once_and_settles_once() {
    let (store, chain) = (MemoryStore::default(), FakeChain::default());
    let mut signer = Signer::new(Outcome::Pay, None);
    let seq = start(&store, send_intent());
    assert_eq!(drive(&seq, &store, &chain, &mut signer, None), Ok(Step::Settled));
    let hash = assert_settled_once(&store, &chain, "unkilled");
    assert_eq!(chain.broadcasts(&hash), 1);
    assert_eq!(signer.calls, 1);
    assert_eq!(
        store.saved_steps(),
        vec![Step::Prepared, Step::BackedUp, Step::Signed, Step::Sent, Step::Included, Step::Settled]
    );
}

#[test]
fn a_kill_at_every_step_recovers_paid_exactly_once() {
    for kill in KILL_POINTS {
        for chain in [FakeChain::default(), FakeChain::auto_mining()] {
            let store = MemoryStore::default();
            let mut signer = Signer::new(Outcome::Pay, None);
            let seq = start(&store, send_intent());
            if kill != Kill::At(Step::Prepared) {
                let killed = drive(&seq, &store, &chain, &mut signer, Some(kill));
                if killed.is_ok() {
                    // An auto-mining chain lands the payment before some
                    // kill points can be reached.
                    assert!(chain.state().auto_mine, "{kill:?}: the kill point was reached");
                    assert_settled_once(&store, &chain, "unkilled");
                    continue;
                }
            }
            drop(seq);

            let at_kill = store.stored();
            let expected = match kill {
                Kill::At(step) => step,
                Kill::AfterBroadcast => Step::Sent,
                Kill::BeforeAttemptRecord => Step::BackedUp,
            };
            assert_eq!(at_kill.step, expected, "{kill:?}");
            let broadcasts_at_kill = chain.total_broadcasts();

            assert_eq!(relaunch(&store, &chain, &mut signer, None), Ok(Step::Settled), "{kill:?}");
            let hash = assert_settled_once(&store, &chain, &format!("{kill:?}"));
            assert_eq!(chain.broadcasts(&hash), 1, "{kill:?}: broadcast once");
            assert_eq!(chain.total_broadcasts(), 1, "{kill:?}: nothing else broadcast");
            assert_eq!(chain.rejected(), 0, "{kill:?}: nothing refused by the node");
            if let Some(attempt) = at_kill.attempts.last() {
                assert_eq!(attempt.transaction_hash, hash, "{kill:?}: the hash it had at the kill");
            }
            match kill {
                // The payload was written but the record never listed it:
                // those bytes were never sent, and a second signing is safe.
                Kill::BeforeAttemptRecord => {
                    assert_eq!(signer.calls, 2, "{kill:?}");
                    assert_eq!(store.stored().attempts.len(), 1, "{kill:?}: the orphan is not an attempt");
                }
                _ => assert_eq!(signer.calls, 1, "{kill:?}: signed once"),
            }
            if matches!(kill, Kill::AfterBroadcast | Kill::At(Step::Included) | Kill::At(Step::Settled)) {
                assert_eq!(broadcasts_at_kill, 1, "{kill:?}: broadcast before the kill");
            }
        }
    }
}

#[test]
fn killed_at_every_point_in_turn_still_pays_once() {
    let (store, chain) = (MemoryStore::default(), FakeChain::default());
    let mut signer = Signer::new(Outcome::Pay, None);
    drop(start(&store, send_intent()));
    for kill in &KILL_POINTS[1..] {
        assert_eq!(relaunch(&store, &chain, &mut signer, Some(*kill)), Err(Killed), "{kill:?}");
    }
    assert_eq!(relaunch(&store, &chain, &mut signer, None), Ok(Step::Settled));
    let hash = assert_settled_once(&store, &chain, "in turn");
    assert_eq!(chain.broadcasts(&hash), 1);
    assert_eq!(chain.rejected(), 0);
}

// --- The fee window ----------------------------------------------------------

#[test]
fn a_fee_window_that_passes_mid_claim_gets_a_new_proof_with_the_same_marker() {
    let (store, chain) = (MemoryStore::default(), FakeChain::default());
    let mut signer = Signer::new(Outcome::Pay, Some(2));
    let seq = start(&store, claim_intent());
    assert_eq!(drive(&seq, &store, &chain, &mut signer, Some(Kill::AfterBroadcast)), Err(Killed));
    drop(seq);
    let first = store.stored().attempts[0].clone();
    assert_eq!(first.valid_until, Some(2));

    // The node drops the claim and the window passes before the relaunch.
    chain.drop_mempool();
    chain.mine_blocks(3);
    let seq = PaymentSequence::open(Box::new(store.clone()), ID.to_owned()).unwrap();
    assert_eq!(seq.recover(chain.view()).unwrap(), Recovery::Rebuild, "the old proof is never resent");
    // Rebuild, killed right after the new attempt is saved.
    drop(seq);
    assert_eq!(relaunch(&store, &chain, &mut signer, Some(Kill::At(Step::Signed))), Err(Killed));
    assert_eq!(relaunch(&store, &chain, &mut signer, None), Ok(Step::Settled));

    let hash = assert_settled_once(&store, &chain, "fee window");
    let record = store.stored();
    assert_eq!(record.attempts.len(), 2, "one rebuild");
    assert_eq!(record.attempts[1].transaction_hash, hash, "the new proof landed");
    assert_eq!(record.intent.identity, claim_intent().identity, "with the same marker");
    assert_eq!(chain.broadcasts(&first.transaction_hash), 1, "the stale proof was sent once, before it went stale");
    assert_eq!(chain.rejected(), 0, "no invalid proof was ever retried");
    assert_eq!(signer.calls, 2);
}

#[test]
fn a_claim_whose_window_passes_while_pending_is_rebuilt_once() {
    let (store, chain) = (MemoryStore::default(), FakeChain::default());
    let mut signer = Signer::new(Outcome::Pay, Some(1));
    let seq = start(&store, claim_intent());
    // Sent and pending; then a block that leaves it out passes the window.
    assert_eq!(drive(&seq, &store, &chain, &mut signer, Some(Kill::AfterBroadcast)), Err(Killed));
    {
        let mut state = chain.state();
        let held = std::mem::take(&mut state.mempool);
        state.mine();
        state.mempool = held;
    }
    assert_eq!(seq.recover(chain.view()).unwrap(), Recovery::Rebuild);
    assert_eq!(drive(&seq, &store, &chain, &mut signer, None), Ok(Step::Settled));
    assert_settled_once(&store, &chain, "pending past its window");
    assert_eq!(store.stored().attempts.len(), 2);
    assert_eq!(chain.rejected(), 0);
}

// --- Reorgs --------------------------------------------------------------------

#[test]
fn a_reorg_after_settled_moves_back_to_sent_and_pays_once() {
    let (store, chain) = (MemoryStore::default(), FakeChain::default());
    let mut signer = Signer::new(Outcome::Pay, None);
    let seq = start(&store, send_intent());
    assert_eq!(drive(&seq, &store, &chain, &mut signer, None), Ok(Step::Settled));
    let hash = assert_settled_once(&store, &chain, "before the reorg");
    let old_block = store.stored().inclusion.unwrap().block_hash;

    // A deeper branch without the payment replaces every block since it.
    let depth = chain.tip() - store.stored().inclusion.unwrap().block_height + 1;
    chain.reorg(depth, false);
    chain.mine_blocks(depth + 1);
    assert!(chain.payments(ID).is_empty(), "the reorg took the payment away");

    let saves = store.saved_steps().len();
    assert_eq!(seq.recover(chain.view()).unwrap(), Recovery::Send { transaction_hash: hash.clone() });
    assert_eq!(store.saved_steps()[saves..], [Step::Sent], "back to sent, saved");
    assert_eq!(store.stored().inclusion, None);

    // Killed there; the next launch resends the same bytes.
    drop(seq);
    assert_eq!(relaunch(&store, &chain, &mut signer, None), Ok(Step::Settled));
    assert_eq!(assert_settled_once(&store, &chain, "after the reorg"), hash, "the same transaction");
    assert_ne!(store.stored().inclusion.unwrap().block_hash, old_block, "with the new block hash");
    assert_eq!(chain.broadcasts(&hash), 2, "sent again once");
    assert_eq!(signer.calls, 1, "never signed again");
    assert_eq!(store.stored().attempts.len(), 1);
}

#[test]
fn a_reorg_that_reincludes_the_payment_updates_its_block_and_sends_nothing() {
    let (store, chain) = (MemoryStore::default(), FakeChain::default());
    let mut signer = Signer::new(Outcome::Pay, None);
    let seq = start(&store, send_intent());
    assert_eq!(drive(&seq, &store, &chain, &mut signer, None), Ok(Step::Settled));
    let old = store.stored().inclusion.unwrap();

    let depth = chain.tip() - old.block_height + 1;
    chain.reorg(depth, true);
    chain.mine_blocks(depth + 1);
    assert_eq!(drive(&seq, &store, &chain, &mut signer, None), Ok(Step::Settled));
    let hash = assert_settled_once(&store, &chain, "re-included");
    assert_eq!(hash, old.transaction_hash);
    assert_ne!(store.stored().inclusion.unwrap().block_hash, old.block_hash);
    assert_eq!(chain.total_broadcasts(), 1, "the node re-included it: nothing resent");
}

#[test]
fn a_reorg_to_a_branch_where_another_tx_took_the_nonce_is_conflicted() {
    let (store, chain) = (MemoryStore::default(), FakeChain::default());
    let mut signer = Signer::new(Outcome::Pay, None);
    let seq = start(&store, send_intent());
    assert_eq!(drive(&seq, &store, &chain, &mut signer, None), Ok(Step::Settled));
    let depth = chain.tip() - store.stored().inclusion.unwrap().block_height + 1;
    chain.reorg(depth, false);
    chain.mine_other(&send_intent().identity);
    chain.mine_blocks(depth);

    assert_eq!(drive(&seq, &store, &chain, &mut signer, None), Ok(Step::Conflicted));
    assert!(chain.payments(ID).is_empty(), "not paid on this branch, and never paid twice");
    assert_eq!(chain.rejected(), 0, "the conflict was seen before any resend");
    let record = store.stored();
    let other = record.inclusion.expect("the other transaction is kept");
    assert!(!record.attempts.iter().any(|a| a.transaction_hash == other.transaction_hash));
}

#[test]
fn an_included_payment_reorged_out_before_settling_goes_back_to_sent() {
    let (store, chain) = (MemoryStore::default(), FakeChain::default());
    let mut signer = Signer::new(Outcome::Pay, None);
    let seq = start(&store, send_intent());
    assert_eq!(drive(&seq, &store, &chain, &mut signer, Some(Kill::At(Step::Included))), Err(Killed));
    chain.reorg(1, false);
    let hash = seq.record().attempts[0].transaction_hash.clone();
    assert_eq!(seq.recover(chain.view()).unwrap(), Recovery::Send { transaction_hash: hash });
    assert_eq!(seq.step(), Step::Sent);
    assert_eq!(drive(&seq, &store, &chain, &mut signer, None), Ok(Step::Settled));
    assert_settled_once(&store, &chain, "included then reorged");
}

// --- Failed receipts -----------------------------------------------------------

#[test]
fn an_included_but_failed_transaction_is_failed_and_never_resent() {
    for kill in [None, Some(Kill::AfterBroadcast)] {
        let (store, chain) = (MemoryStore::default(), FakeChain::default());
        let mut signer = Signer::new(Outcome::Fail, None);
        let seq = start(&store, send_intent());
        let mut end = drive(&seq, &store, &chain, &mut signer, kill);
        if end.is_err() {
            drop(seq);
            end = relaunch(&store, &chain, &mut signer, None);
        }
        assert_eq!(end, Ok(Step::Failed), "{kill:?}: inclusion is not success");

        let record = store.stored();
        let inclusion = record.inclusion.clone().expect("where it failed is kept");
        assert_eq!(inclusion.transaction_hash, record.attempts[0].transaction_hash);
        assert_eq!(Some(inclusion.block_hash), chain.block_hash_of(&inclusion.transaction_hash));
        assert!(chain.payments(ID).is_empty(), "{kill:?}: nothing paid");
        assert_eq!(chain.landed(ID).len(), 1);
        assert_eq!(chain.total_broadcasts(), 1, "{kill:?}: never resent");
        assert_eq!(signer.calls, 1, "{kill:?}: never re-signed");

        let seq = PaymentSequence::open(Box::new(store.clone()), ID.to_owned()).unwrap();
        chain.mine_blocks(5);
        assert_eq!(seq.recover(chain.view()).unwrap(), Recovery::Done { step: Step::Failed });
        assert_eq!(
            seq.add_attempt(b"synthetic later attempt".to_vec(), None),
            Err(StepError::OutOfOrder { from: Step::Failed, to: Step::Signed })
        );
        assert!(seq.mark_sent().is_err());
        assert_eq!(chain.total_broadcasts(), 1);
    }
}

#[test]
fn a_successful_receipt_without_the_expected_effect_is_failed() {
    let (store, chain) = (MemoryStore::default(), FakeChain::default());
    let mut signer = Signer::new(Outcome::NoEffect, None);
    let seq = start(&store, claim_intent());
    assert_eq!(drive(&seq, &store, &chain, &mut signer, None), Ok(Step::Failed));
    assert!(chain.payments(ID).is_empty());
    assert_eq!(chain.total_broadcasts(), 1);
    assert!(store.saved_steps().iter().all(|step| *step != Step::Included), "never taken as success");
}

// --- The nonce taken ---------------------------------------------------------

#[test]
fn a_nonce_taken_by_another_tx_before_the_send_is_conflicted_and_nothing_is_sent() {
    let (store, chain) = (MemoryStore::default(), FakeChain::default());
    let mut signer = Signer::new(Outcome::Pay, None);
    let seq = start(&store, send_intent());
    assert_eq!(drive(&seq, &store, &chain, &mut signer, Some(Kill::At(Step::Signed))), Err(Killed));
    drop(seq);
    chain.mine_other(&send_intent().identity);

    assert_eq!(relaunch(&store, &chain, &mut signer, None), Ok(Step::Conflicted));
    assert_eq!(chain.total_broadcasts(), 0, "nothing of ours was sent");
    assert!(chain.payments(ID).is_empty());
    assert_eq!(signer.calls, 1, "no rebuild for a taken nonce");
    let record = store.stored();
    let other = record.inclusion.expect("the other transaction is kept");
    assert_eq!(chain.landed("someone-else"), vec![other.transaction_hash.clone()]);
    assert_eq!(Some(other.block_hash), chain.block_hash_of(&other.transaction_hash));
}

#[test]
fn a_nonce_taken_while_ours_is_pending_is_conflicted_and_ours_never_lands() {
    let (store, chain) = (MemoryStore::default(), FakeChain::default());
    let mut signer = Signer::new(Outcome::Pay, None);
    let seq = start(&store, send_intent());
    assert_eq!(drive(&seq, &store, &chain, &mut signer, Some(Kill::AfterBroadcast)), Err(Killed));
    // The miner takes the other transaction first; ours can no longer land.
    chain.mine_other(&send_intent().identity);
    chain.mine_blocks(3);

    assert_eq!(drive(&seq, &store, &chain, &mut signer, None), Ok(Step::Conflicted));
    assert!(chain.landed(ID).is_empty());
    assert_eq!(chain.total_broadcasts(), 1, "not resent after the conflict");
    assert_eq!(seq.recover(chain.view()).unwrap(), Recovery::Done { step: Step::Conflicted });
    assert_eq!(
        seq.add_attempt(b"synthetic speed-up".to_vec(), None),
        Err(StepError::OutOfOrder { from: Step::Conflicted, to: Step::Signed })
    );
}

// --- Several attempts, one identity -----------------------------------------

#[test]
fn a_speed_up_and_the_original_with_one_nonce_land_at_most_once() {
    let (store, chain) = (MemoryStore::default(), FakeChain::default());
    let mut signer = Signer::new(Outcome::Pay, None);
    let seq = start(&store, send_intent());
    assert_eq!(drive(&seq, &store, &chain, &mut signer, Some(Kill::AfterBroadcast)), Err(Killed));
    let original = seq.record().attempts[0].transaction_hash.clone();

    // A speed-up with the same nonce, sent while the original is pending.
    let (bytes, until) = signer.sign(&send_intent(), chain.tip());
    let faster = seq.add_attempt(bytes, until).unwrap();
    assert_eq!(seq.step(), Step::Signed);
    assert_eq!(seq.recover(chain.view()).unwrap(), Recovery::Send { transaction_hash: faster.clone() });
    chain.broadcast(seq.mark_sent().unwrap());

    assert_eq!(drive(&seq, &store, &chain, &mut signer, None), Ok(Step::Settled));
    let paid = assert_settled_once(&store, &chain, "speed-up");
    assert!(paid == original || paid == faster);
    assert_eq!(store.stored().attempts.len(), 2);
    assert_eq!(store.payload_count(), 2, "both payloads kept with the record");
}

// --- Nothing signed is formatted ---------------------------------------------

#[test]
fn signed_bytes_are_never_in_a_formatted_record_recovery_or_error() {
    let (store, chain) = (MemoryStore::default(), FakeChain::default());
    let mut signer = Signer::new(Outcome::Pay, None);
    let seq = start(&store, send_intent());
    assert_eq!(drive(&seq, &store, &chain, &mut signer, Some(Kill::At(Step::Sent))), Err(Killed));
    let shown = [
        format!("{:?}", seq.record()),
        format!("{:?}", seq.recover(chain.view()).unwrap()),
        format!("{:?}", seq.add_attempt(Vec::new(), None)),
        seq.add_attempt(Vec::new(), None).unwrap_err().to_string(),
    ];
    for text in shown {
        assert!(!text.contains("synthetic"), "the signed bytes were formatted: {text}");
        assert!(!text.contains("115, 121, 110"), "the signed bytes were formatted as numbers");
    }
}
