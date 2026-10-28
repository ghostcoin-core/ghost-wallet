//! The payment state machine with real signed bytes: test sends signed in
//! the native core (`0x52`, scheme `0x0003`, account 0 of Ghost's
//! counting-bytes test seed), sent to a node-like test double.
//!
//! The double takes a broadcast only if its envelope passes Ghost's
//! `verify_envelope` for the test chain, includes transactions by the
//! sender's nonce, says "already known" for bytes it has, and refuses a
//! second transaction with a nonce in use. A kill at every point recovers to
//! exactly one transaction from the sender with the payment's nonce, with the
//! hash it had at the kill, signed once.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use ghost_client::account::{WalletSeed, verify_envelope};
use ghost_wallet_core::{
    ChainView, Identity, PaymentIntent, PaymentKind, PaymentRecord, PaymentSequence, PaymentStore, RESCUE_TRANSFER_GAS,
    Receipt, ReceiptStatus, Recovery, SETTLE_CONFIRMATIONS, Step, StepError, TEST_CHAIN_ID, TestSend,
    decode_payment_record, encode_payment_record, sign_test_send, transaction_hash,
};

const ID: &str = "test-send-1";
const GENESIS: [u8; 32] = [0x47; 32];
const VALUE: u64 = 1_000_000_000_000;
/// Account 3 of the test words.
const RECIPIENT: [u8; 20] = [
    0xac, 0xf1, 0xb0, 0x34, 0x42, 0x24, 0x4b, 0xc1, 0x49, 0x82, 0xf1, 0xaa, 0xe0, 0xa1, 0x1d, 0x76, 0xe1, 0x85, 0x0e,
    0x09,
];

/// Ghost's counting-bytes test seed: the bytes 0 to 31.
const COUNTING: [u8; 32] = {
    let mut bytes = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        bytes[i] = i as u8;
        i += 1;
    }
    bytes
};

fn test_words() -> String {
    WalletSeed::from_bytes(COUNTING).to_words().as_str().to_owned()
}

fn sender() -> [u8; 20] {
    *WalletSeed::from_bytes(COUNTING).rescue_account(0).address()
}

/// The intent's details as the double reads them: recipient, value, height.
fn details(recipient: [u8; 20], value: u64, start_height: u64) -> Vec<u8> {
    let mut out = recipient.to_vec();
    out.extend_from_slice(&value.to_be_bytes());
    out.extend_from_slice(&start_height.to_be_bytes());
    out
}

fn read_details(details: &[u8]) -> ([u8; 20], u64) {
    (details[..20].try_into().unwrap(), u64::from_be_bytes(details[20..28].try_into().unwrap()))
}

/// A send from account 0 to account 3 with the sender's next nonce.
fn send_intent(node: &Node) -> PaymentIntent {
    let nonce = node.pending_nonce(&sender());
    PaymentIntent {
        kind: PaymentKind::Send,
        identity: Identity::AccountNonce { account: sender().to_vec(), nonce },
        details: details(RECIPIENT, VALUE, node.tip()),
    }
}

fn nonce_of(intent: &PaymentIntent) -> u64 {
    match intent.identity {
        Identity::AccountNonce { nonce, .. } => nonce,
        Identity::RevealMarker { .. } => panic!("a send has a nonce"),
    }
}

// --- The store -------------------------------------------------------------

#[derive(Default)]
struct StoreState {
    records: BTreeMap<String, Vec<u8>>,
    payloads: BTreeMap<(String, Vec<u8>), Vec<u8>>,
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

    fn stored(&self) -> PaymentRecord {
        decode_payment_record(self.state().records[ID].clone()).unwrap()
    }

    fn payloads(&self) -> Vec<Vec<u8>> {
        self.state().payloads.values().cloned().collect()
    }
}

impl PaymentStore for MemoryStore {
    fn save(&self, record: PaymentRecord) -> Result<(), StepError> {
        let mut state = self.state();
        if state.fail_next_save_at == Some(record.step) {
            state.fail_next_save_at = None;
            return Err(StepError::Store { reason: "killed before the record was saved".to_owned() });
        }
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

// --- The node --------------------------------------------------------------

/// A verified transfer as the node keeps it.
#[derive(Clone, Debug)]
struct Tx {
    hash: Vec<u8>,
    sender: [u8; 20],
    nonce: u64,
    to: Option<[u8; 20]>,
    value: u128,
}

struct Block {
    hash: Vec<u8>,
    txs: Vec<Tx>,
}

/// What a broadcast got back.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    /// Taken into the pool; its hash.
    Accepted(Vec<u8>),
    /// The node has these bytes already (pooled or in a block).
    AlreadyKnown,
    /// Refused, with the node's reason.
    Refused(String),
}

#[derive(Default)]
struct NodeState {
    blocks: Vec<Block>,
    pool: Vec<Tx>,
    /// Every broadcast, by the hash of its bytes.
    broadcasts: BTreeMap<Vec<u8>, u32>,
    refused: Vec<String>,
    auto_mine: bool,
}

impl NodeState {
    fn tip(&self) -> u64 {
        self.blocks.len() as u64
    }

    fn mined(&self) -> impl Iterator<Item = (u64, &Block, &Tx)> {
        self.blocks
            .iter()
            .enumerate()
            .flat_map(|(at, block)| block.txs.iter().map(move |tx| (at as u64 + 1, block, tx)))
    }

    fn find(&self, hash: &[u8]) -> Option<(u64, &Block, &Tx)> {
        self.mined().find(|(_, _, tx)| tx.hash == hash)
    }

    /// `eth_getTransactionCount(sender, "latest")`.
    fn latest_nonce(&self, sender: &[u8; 20]) -> u64 {
        self.mined().filter(|(_, _, tx)| tx.sender == *sender).count() as u64
    }

    fn mine(&mut self) {
        let mut txs: Vec<Tx> = Vec::new();
        let mut pool = std::mem::take(&mut self.pool);
        pool.sort_by_key(|tx| tx.nonce);
        for tx in pool {
            let next = self.latest_nonce(&tx.sender) + txs.iter().filter(|t| t.sender == tx.sender).count() as u64;
            if tx.nonce == next {
                txs.push(tx);
            } else if tx.nonce > next {
                self.pool.push(tx);
            }
        }
        let hash = transaction_hash(format!("test block {}", self.tip() + 1).into_bytes());
        self.blocks.push(Block { hash, txs });
    }
}

/// A node-like test double of the test chain. Clones share it.
#[derive(Clone, Default)]
struct Node(Arc<Mutex<NodeState>>);

impl Node {
    fn auto_mining() -> Self {
        let node = Node::default();
        node.state().auto_mine = true;
        node
    }

    fn state(&self) -> MutexGuard<'_, NodeState> {
        self.0.lock().unwrap()
    }

    fn view(&self) -> Box<dyn ChainView> {
        Box::new(self.clone())
    }

    fn tip(&self) -> u64 {
        self.state().tip()
    }

    fn mine(&self) {
        self.state().mine();
    }

    /// `eth_getTransactionCount(sender, "pending")`.
    fn pending_nonce(&self, sender: &[u8; 20]) -> u64 {
        let state = self.state();
        state.latest_nonce(sender) + state.pool.iter().filter(|tx| tx.sender == *sender).count() as u64
    }

    fn latest_nonce(&self, sender: &[u8; 20]) -> u64 {
        self.state().latest_nonce(sender)
    }

    /// `eth_sendRawTransaction`.
    fn broadcast(&self, bytes: &[u8]) -> Answer {
        let mut state = self.state();
        *state.broadcasts.entry(transaction_hash(bytes.to_vec())).or_default() += 1;
        let verified = match verify_envelope(bytes, TEST_CHAIN_ID, &GENESIS) {
            Ok(verified) => verified,
            Err(error) => {
                state.refused.push(error.to_string());
                return Answer::Refused(error.to_string());
            }
        };
        let hash = verified.hash.to_vec();
        if state.find(&hash).is_some() || state.pool.iter().any(|tx| tx.hash == hash) {
            return Answer::AlreadyKnown;
        }
        let tx = Tx {
            hash: hash.clone(),
            sender: verified.sender,
            nonce: verified.tx.nonce,
            to: verified.tx.to,
            value: verified.tx.value,
        };
        let refusal = if tx.nonce < state.latest_nonce(&tx.sender) {
            Some("nonce too low")
        } else if state.pool.iter().any(|t| t.sender == tx.sender && t.nonce == tx.nonce) {
            Some("replacement transaction underpriced")
        } else {
            None
        };
        if let Some(reason) = refusal {
            state.refused.push(reason.to_owned());
            return Answer::Refused(reason.to_owned());
        }
        state.pool.push(tx);
        if state.auto_mine {
            state.mine();
        }
        Answer::Accepted(hash)
    }

    fn broadcasts(&self, hash: &[u8]) -> u32 {
        self.state().broadcasts.get(hash).copied().unwrap_or(0)
    }

    fn total_broadcasts(&self) -> u32 {
        self.state().broadcasts.values().sum()
    }

    fn refused(&self) -> Vec<String> {
        self.state().refused.clone()
    }

    /// Every transaction in a block from `sender` with `nonce`.
    fn landed(&self, sender: &[u8; 20], nonce: u64) -> Vec<Tx> {
        let state = self.state();
        state
            .mined()
            .filter(|(_, _, tx)| tx.sender == *sender && tx.nonce == nonce)
            .map(|(_, _, tx)| tx.clone())
            .collect()
    }

    fn block_hash_of(&self, hash: &[u8]) -> Option<Vec<u8>> {
        self.state().find(hash).map(|(_, block, _)| block.hash.clone())
    }
}

impl ChainView for Node {
    fn receipt(&self, hash: Vec<u8>) -> Result<Option<Receipt>, StepError> {
        Ok(self.state().find(&hash).map(|(height, block, _)| Receipt {
            status: ReceiptStatus::Success,
            block_hash: block.hash.clone(),
            block_height: height,
        }))
    }

    fn pending(&self, hash: Vec<u8>) -> Result<bool, StepError> {
        Ok(self.state().pool.iter().any(|tx| tx.hash == hash))
    }

    fn identity_used_by(&self, identity: Identity) -> Result<Option<Vec<u8>>, StepError> {
        let Identity::AccountNonce { account, nonce } = identity else { return Ok(None) };
        let account: [u8; 20] = account.as_slice().try_into().unwrap();
        let state = self.state();
        if state.latest_nonce(&account) <= nonce {
            return Ok(None);
        }
        Ok(state.mined().find(|(_, _, tx)| tx.sender == account && tx.nonce == nonce).map(|(_, _, tx)| tx.hash.clone()))
    }

    fn effect_applied(&self, intent: PaymentIntent, hash: Vec<u8>) -> Result<bool, StepError> {
        let Identity::AccountNonce { account, .. } = &intent.identity else { return Ok(false) };
        let (recipient, value) = read_details(&intent.details);
        Ok(self.state().find(&hash).is_some_and(|(_, _, tx)| {
            tx.sender.as_slice() == account.as_slice() && tx.to == Some(recipient) && tx.value == u128::from(value)
        }))
    }

    fn tip_height(&self) -> Result<u64, StepError> {
        Ok(self.tip())
    }
}

// --- The app ---------------------------------------------------------------

/// Signs the payment's send in the native core with fresh chain data, and
/// counts every signing.
#[derive(Default)]
struct Signer {
    calls: u32,
}

impl Signer {
    fn sign(&mut self, intent: &PaymentIntent) -> Vec<u8> {
        self.calls += 1;
        let (recipient, value) = read_details(&intent.details);
        let send = TestSend {
            chain_id: TEST_CHAIN_ID,
            genesis_hash: GENESIS.to_vec(),
            nonce: nonce_of(intent),
            recipient: recipient.to_vec(),
            value,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 3_000_000_000,
            gas_limit: RESCUE_TRANSFER_GAS,
        };
        let signed = sign_test_send(test_words(), 0, send).unwrap();
        assert_eq!(signed.sender, sender().to_vec());
        signed.envelope
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

/// The benchmark's seven kill points, then the one between the payload and
/// the record.
const KILL_POINTS: [Kill; 8] = [
    Kill::At(Step::Prepared),
    Kill::At(Step::BackedUp),
    Kill::At(Step::Signed),
    Kill::At(Step::Sent),
    Kill::AfterBroadcast,
    Kill::At(Step::Included),
    Kill::At(Step::Settled),
    Kill::BeforeAttemptRecord,
];

#[derive(Debug, PartialEq, Eq)]
struct Killed;

/// Does what `recover` says until the payment is done, as the benchmark
/// does. Stops early at `kill`. Returns the final step.
fn drive(
    seq: &PaymentSequence,
    store: &MemoryStore,
    node: &Node,
    signer: &mut Signer,
    kill: Option<Kill>,
) -> Result<Step, Killed> {
    let intent = seq.record().intent;
    for _ in 0..200 {
        let before = seq.step();
        let action = seq.recover(node.view()).unwrap();
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
                let bytes = signer.sign(&intent);
                if kill == Some(Kill::BeforeAttemptRecord) {
                    store.state().fail_next_save_at = Some(Step::Signed);
                    assert!(matches!(seq.add_attempt(bytes, None), Err(StepError::Store { .. })));
                    return Err(Killed);
                }
                seq.add_attempt(bytes, None).unwrap();
                if kill == Some(Kill::At(Step::Signed)) {
                    return Err(Killed);
                }
            }
            Recovery::Send { transaction_hash: hash } => {
                let was = seq.step();
                let bytes = seq.mark_sent().unwrap();
                assert_eq!(transaction_hash(bytes.clone()), hash, "only the stored bytes are sent");
                if was == Step::Signed && kill == Some(Kill::At(Step::Sent)) {
                    return Err(Killed);
                }
                match node.broadcast(&bytes) {
                    Answer::Accepted(returned) => assert_eq!(returned, hash, "the node's hash is keccak of the bytes"),
                    Answer::AlreadyKnown => {}
                    Answer::Refused(reason) => panic!("the node refused the stored bytes: {reason}"),
                }
                if kill == Some(Kill::AfterBroadcast) {
                    return Err(Killed);
                }
            }
            Recovery::Wait => node.mine(),
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
fn relaunch(store: &MemoryStore, node: &Node, signer: &mut Signer, kill: Option<Kill>) -> Result<Step, Killed> {
    assert_eq!(store.list().unwrap(), vec![ID.to_owned()], "the payment is found");
    let seq = PaymentSequence::open(Box::new(store.clone()), ID.to_owned()).unwrap();
    drive(&seq, store, node, signer, kill)
}

/// Exactly one transaction from the sender with the payment's nonce is in a
/// block, the nonce count moved by one, the settled record names it and its
/// block. Returns its hash.
fn assert_paid_once(store: &MemoryStore, node: &Node, nonce: u64, what: &str) -> Vec<u8> {
    let landed = node.landed(&sender(), nonce);
    assert_eq!(landed.len(), 1, "{what}: one transaction with the nonce");
    let tx = &landed[0];
    assert_eq!((tx.to, tx.value), (Some(RECIPIENT), u128::from(VALUE)), "{what}: it pays account 3");
    assert_eq!(node.latest_nonce(&sender()), nonce + 1, "{what}: the nonce count is one more");
    let record = store.stored();
    assert_eq!(record.step, Step::Settled, "{what}: settled and kept");
    let inclusion = record.inclusion.clone().expect("the inclusion is kept");
    assert_eq!(inclusion.transaction_hash, tx.hash, "{what}: the record names it");
    assert_eq!(Some(inclusion.block_hash), node.block_hash_of(&tx.hash), "{what}: with its block hash");
    assert!(node.tip() + 1 - inclusion.block_height >= SETTLE_CONFIRMATIONS, "{what}: deep enough");
    // Asked again, it stays settled and sends nothing.
    let broadcasts = node.total_broadcasts();
    let seq = PaymentSequence::open(Box::new(store.clone()), ID.to_owned()).unwrap();
    assert_eq!(seq.recover(node.view()).unwrap(), Recovery::Done { step: Step::Settled }, "{what}");
    assert_eq!(node.total_broadcasts(), broadcasts, "{what}: nothing more sent");
    tx.hash.clone()
}

/// A node with some earlier sends from account 0, so the nonce is not 0.
fn node_with_history(node: Node) -> Node {
    let mut signer = Signer::default();
    for _ in 0..2 {
        let intent = send_intent(&node);
        let bytes = signer.sign(&intent);
        assert!(matches!(node.broadcast(&bytes), Answer::Accepted(_)));
        node.mine();
    }
    node.mine();
    let mut state = node.state();
    state.broadcasts.clear();
    drop(state);
    node
}

// --- The double --------------------------------------------------------------

#[test]
fn the_double_takes_only_verified_envelopes_and_one_transaction_per_nonce() {
    let node = Node::default();
    let mut signer = Signer::default();
    let intent = send_intent(&node);
    let first = signer.sign(&intent);
    let second = signer.sign(&intent);
    assert_ne!(first, second, "hedged: a second signing is other bytes");

    let mut damaged = first.clone();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    assert!(matches!(node.broadcast(&damaged), Answer::Refused(_)), "a damaged signature");
    let mut other_type = first.clone();
    other_type[0] = 0x02;
    assert!(matches!(node.broadcast(&other_type), Answer::Refused(_)), "not type 0x52");

    assert_eq!(node.broadcast(&first), Answer::Accepted(transaction_hash(first.clone())));
    assert_eq!(node.broadcast(&first), Answer::AlreadyKnown);
    assert!(matches!(node.broadcast(&second), Answer::Refused(_)), "the nonce is pooled already");
    node.mine();
    assert_eq!(node.broadcast(&first), Answer::AlreadyKnown);
    assert_eq!(node.broadcast(&second), Answer::Refused("nonce too low".to_owned()), "the nonce is used");
    assert_eq!(node.landed(&sender(), 0).len(), 1);
    assert_eq!(node.latest_nonce(&sender()), 1);
}

// --- Kills -------------------------------------------------------------------

#[test]
fn an_unkilled_send_signs_once_broadcasts_once_and_settles() {
    let node = node_with_history(Node::default());
    let store = MemoryStore::default();
    let mut signer = Signer::default();
    let intent = send_intent(&node);
    let nonce = nonce_of(&intent);
    assert_eq!(nonce, 2);
    let seq = start(&store, intent);
    assert_eq!(drive(&seq, &store, &node, &mut signer, None), Ok(Step::Settled));
    let hash = assert_paid_once(&store, &node, nonce, "unkilled");
    assert_eq!(node.broadcasts(&hash), 1);
    assert_eq!(signer.calls, 1);
    assert!(node.refused().is_empty());
    // The stored bytes are the real envelope.
    let payloads = store.payloads();
    assert_eq!(payloads.len(), 1);
    let verified = verify_envelope(&payloads[0], TEST_CHAIN_ID, &GENESIS).unwrap();
    assert_eq!(verified.hash.to_vec(), hash);
    assert_eq!(verified.tx.nonce, nonce);
}

#[test]
fn a_kill_at_every_point_recovers_to_one_transaction_with_the_same_hash() {
    for kill in KILL_POINTS {
        for node in [Node::default(), Node::auto_mining()] {
            let node = node_with_history(node);
            let store = MemoryStore::default();
            let mut signer = Signer::default();
            let intent = send_intent(&node);
            let nonce = nonce_of(&intent);
            let seq = start(&store, intent);
            if kill != Kill::At(Step::Prepared) {
                let killed = drive(&seq, &store, &node, &mut signer, Some(kill));
                if killed.is_ok() {
                    // An auto-mining node lands the send before some kill
                    // points can be reached.
                    assert!(node.state().auto_mine, "{kill:?}: the kill point was reached");
                    assert_paid_once(&store, &node, nonce, "unkilled");
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
            let signings_at_kill = signer.calls;
            let broadcasts_at_kill = node.total_broadcasts();

            assert_eq!(relaunch(&store, &node, &mut signer, None), Ok(Step::Settled), "{kill:?}");
            let hash = assert_paid_once(&store, &node, nonce, &format!("{kill:?}"));
            assert_eq!(node.broadcasts(&hash), 1, "{kill:?}: broadcast once");
            assert_eq!(node.total_broadcasts(), 1, "{kill:?}: nothing else broadcast");
            assert!(node.refused().is_empty(), "{kill:?}: nothing refused by the node");
            if let Some(attempt) = at_kill.attempts.last() {
                assert_eq!(attempt.transaction_hash, hash, "{kill:?}: the hash it had at the kill");
                // Signed bytes were saved: recovery never signs again.
                assert_eq!(signer.calls, signings_at_kill, "{kill:?}: not signed again");
            }
            match kill {
                Kill::BeforeAttemptRecord => assert_eq!(signer.calls, 2, "{kill:?}: signed again"),
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
    let node = node_with_history(Node::default());
    let store = MemoryStore::default();
    let mut signer = Signer::default();
    let intent = send_intent(&node);
    let nonce = nonce_of(&intent);
    drop(start(&store, intent));
    for kill in &KILL_POINTS[1..7] {
        assert_eq!(relaunch(&store, &node, &mut signer, Some(*kill)), Err(Killed), "{kill:?}");
    }
    assert_eq!(relaunch(&store, &node, &mut signer, None), Ok(Step::Settled));
    let hash = assert_paid_once(&store, &node, nonce, "in turn");
    assert_eq!(node.broadcasts(&hash), 1);
    assert_eq!(signer.calls, 1);
    assert!(node.refused().is_empty());
}

#[test]
fn a_kill_before_the_signed_bytes_are_listed_signs_again_with_the_same_nonce() {
    let node = node_with_history(Node::default());
    let store = MemoryStore::default();
    let mut signer = Signer::default();
    let intent = send_intent(&node);
    let nonce = nonce_of(&intent);
    let seq = start(&store, intent);
    assert_eq!(drive(&seq, &store, &node, &mut signer, Some(Kill::BeforeAttemptRecord)), Err(Killed));
    drop(seq);
    assert_eq!(store.stored().step, Step::BackedUp);
    assert!(store.stored().attempts.is_empty(), "the orphan payload is not an attempt");
    let orphan = store.payloads();
    assert_eq!(orphan.len(), 1);
    assert_eq!(node.total_broadcasts(), 0, "nothing was sent before the kill");

    assert_eq!(relaunch(&store, &node, &mut signer, None), Ok(Step::Settled));
    let hash = assert_paid_once(&store, &node, nonce, "signed again");
    assert_eq!(signer.calls, 2);
    let record = store.stored();
    assert_eq!(record.attempts.len(), 1);
    assert_ne!(transaction_hash(orphan[0].clone()), hash, "a second signing is other bytes");
    assert_eq!(node.broadcasts(&transaction_hash(orphan[0].clone())), 0, "the orphan is never sent");
    // Both signings used the payment's one nonce.
    for bytes in store.payloads() {
        assert_eq!(verify_envelope(&bytes, TEST_CHAIN_ID, &GENESIS).unwrap().tx.nonce, nonce);
    }
}

#[test]
fn a_resend_of_the_stored_bytes_is_already_known_and_pays_once() {
    // The node forgot nothing, but the kill came after the broadcast and
    // before its reply: the same bytes may go out again only if the chain
    // does not show them, and then the node knows them.
    let node = node_with_history(Node::default());
    let store = MemoryStore::default();
    let mut signer = Signer::default();
    let intent = send_intent(&node);
    let nonce = nonce_of(&intent);
    let seq = start(&store, intent);
    assert_eq!(drive(&seq, &store, &node, &mut signer, Some(Kill::AfterBroadcast)), Err(Killed));
    let bytes = seq.mark_sent().unwrap();
    assert_eq!(node.broadcast(&bytes), Answer::AlreadyKnown);
    drop(seq);
    assert_eq!(relaunch(&store, &node, &mut signer, None), Ok(Step::Settled));
    assert_paid_once(&store, &node, nonce, "resent");
    assert_eq!(signer.calls, 1);
}
