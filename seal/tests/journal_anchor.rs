//! The journal log's head anchored in the peer regions, with in-memory
//! stores, peers in this process and a stand-in attestation whose PCR4 the
//! test sets: every save reaches every peer before it is `Ok`; a tail the
//! host cut while the enclave was stopped is caught and restored, and with a
//! peer unreachable the log is refused (every peer must answer at a
//! restart); a replaced host (an empty log) restores the whole log and then
//! finishes an Open it never saw; regions replaced one after another, with
//! no write between, keep the last region's log; an empty or unrestored
//! peer log answers no copy, which never counts as a head; a peer answering
//! an old head with an old nonce is not taken; a forked head is refused; a
//! restored record changed in transit or on a peer's host is refused; an
//! answer from an enclave on the asker's own host, from one instance for two
//! peers, from another region than the port's or the asker's own region is
//! refused; a save with one peer silent fails and leaves the card
//! unchanged; peers see ciphertext only; and the home rule agrees across
//! regions and matches its fixed vectors (`tests/vectors/home-region.json`).

mod support;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ghost_seal::journal_anchor::{
    Anchor, AnswerAttester, BAD_RESTORE, FORKED, FakeAttester, HOME_REGION_LABEL, NO_COPY, NO_COPY_EMPTY,
    NO_COPY_NOT_RESTORED, NO_COPY_UNCONFIRMED, NO_PEER, NOT_ACKNOWLEDGED, OP_APPEND, OP_FETCH, OP_HEAD, PEER_PORTS, Peer,
    PeerLink, PeerLogs, Peers, RELEASE_REGIONS, Regions, RegionsRefused, UNATTESTED, home_region, is_anchor_error,
    valid_region,
};
use ghost_seal::journal_log::{Chain, HeadAnchor, JournalLog, LogStore, MemoryLogStore, SharedLog};
use ghost_seal::primitives::sha3_256;
use ghost_seal::{
    CardState, CardUid, CheckRequest, EntryKind, FillRequest, Journal, MasterKey, OpenRequest, Seal, SealConfig,
    SealError, SealRandom,
};
use support::{AMOUNT, MEASUREMENT, SettledCheck, SimCard, StubChain, StubMaker, TestClock, TestRandom, UID, contains};

const US: &str = "us-east-1";
const EU: &str = "eu-central-1";
const AP: &str = "ap-southeast-1";
const OTHER: CardUid = CardUid([0x04, 0x10, 0x20, 0x30, 0x40, 0x50, 0x62]);

const VECTORS: &str = include_str!("vectors/home-region.json");

/// The stand-in attestation's test key.
const KEY: [u8; 32] = [0x5e; 32];

/// The build of each region's image (one image per region).
fn build_of(region: &str) -> [u8; 48] {
    [match region {
        US => 0xb1,
        EU => 0xb2,
        AP => 0xb3,
        _ => 0xbf,
    }; 48]
}

/// The instance (PCR4) region `region`'s host runs on, its `generation`-th
/// host.
fn instance(region: &str, generation: u8) -> [u8; 48] {
    let mut pcr4 = [match region {
        US => 0x11,
        EU => 0x12,
        AP => 0x13,
        _ => 0x1f,
    }; 48];
    pcr4[47] = generation;
    pcr4
}

/// The stand-in attester of an enclave of `region`'s image on instance
/// `pcr4`, approving the three regions' builds.
fn attester(region: &str, pcr4: [u8; 48]) -> Arc<FakeAttester> {
    Arc::new(FakeAttester::new(KEY, build_of(region), pcr4, RELEASE_REGIONS.iter().map(|r| build_of(r)).collect()))
}

/// A deterministic random source an anchor or a log can hold (test only).
struct Random(u64);

impl SealRandom for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), SealError> {
        for chunk in out.chunks_mut(32) {
            self.0 += 1;
            chunk.copy_from_slice(&sha3_256(&[b"journal anchor test random", &self.0.to_be_bytes()])[..chunk.len()]);
        }
        Ok(())
    }
}

/// How a test makes a link misbehave.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Honest,
    /// Answers every head request with the first head answer it gave.
    ReplayHeads,
    /// Changes one byte of the first record of every fetch answer.
    TamperFetch,
}

/// What the test controls on the way to one region, and what crossed it.
struct Control {
    silent: AtomicBool,
    mode: Mutex<Mode>,
    first_head: Mutex<Option<Vec<u8>>>,
    /// Every request and answer that crossed the link.
    seen: Mutex<Vec<Vec<u8>>>,
}

impl Control {
    fn new() -> Arc<Control> {
        Arc::new(Control {
            silent: AtomicBool::new(false),
            mode: Mutex::new(Mode::Honest),
            first_head: Mutex::new(None),
            seen: Mutex::new(Vec::new()),
        })
    }
}

/// Where a link leads: a region's enclave, as long as it runs.
type Slot = Arc<Mutex<Option<Arc<PeerLogs>>>>;

/// The way to a peer's enclave: straight to its answers, as the test has
/// the link behave.
struct Link {
    target: Slot,
    control: Arc<Control>,
}

/// Where the body of an answer starts, past its envelope.
fn body_start(answer: &[u8]) -> usize {
    let responder = usize::from(answer[0]);
    let document = usize::from(u16::from_be_bytes([answer[1 + responder], answer[2 + responder]]));
    1 + responder + 2 + document + 32
}

impl PeerLink for Link {
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        if self.control.silent.load(Ordering::SeqCst) {
            return Err("unreachable".into());
        }
        self.control.seen.lock().unwrap().push(request.to_vec());
        let logs = self.target.lock().unwrap().clone().ok_or("unreachable")?;
        let mut answer = logs.answer(&support::master(), request)?;
        let mode = *self.control.mode.lock().unwrap();
        if mode == Mode::ReplayHeads && request[0] == OP_HEAD {
            let mut first = self.control.first_head.lock().unwrap();
            match first.as_ref() {
                Some(old) => answer = old.clone(),
                None => *first = Some(answer.clone()),
            }
        }
        let at = body_start(&answer) + 12 + 20;
        if mode == Mode::TamperFetch && request[0] == OP_FETCH && answer.len() > at {
            answer[at] ^= 0x01;
        }
        self.control.seen.lock().unwrap().push(answer.clone());
        Ok(answer)
    }
}

/// A peer region in this process whose copies are taken as they are (it
/// has no one to ask): its logs of the other regions, each over an
/// in-memory store of its host.
struct Region {
    logs: Arc<PeerLogs>,
    stores: BTreeMap<String, MemoryLogStore>,
    slot: Slot,
    control: Arc<Control>,
}

impl Region {
    /// Region `name`'s enclave on its own instance, its copies empty.
    fn new(name: &str) -> Region {
        Region::on(name, attester(name, instance(name, 0)), &[])
    }

    /// Region `name`'s enclave attesting with `attester`, its copy of each
    /// origin in `held` holding those records (the others empty).
    fn on(name: &str, attester: Arc<FakeAttester>, held: &[(&str, Vec<(u64, Vec<u8>)>)]) -> Region {
        let stores: BTreeMap<String, MemoryLogStore> =
            RELEASE_REGIONS.iter().filter(|r| **r != name).map(|r| (r.to_string(), MemoryLogStore::new())).collect();
        for (origin, records) in held {
            stores[*origin].set_records(records.clone());
        }
        let boxed = stores.iter().map(|(r, s)| (r.clone(), Box::new(s.clone()) as Box<dyn LogStore>)).collect();
        let peers = Arc::new(Peers::new(name, Vec::new()).with_attester(attester));
        let logs = Arc::new(PeerLogs::new(peers, boxed));
        logs.restore(&support::master()).expect("with no holder to ask, each copy is kept as it is");
        Region { slot: Arc::new(Mutex::new(Some(Arc::clone(&logs)))), logs, stores, control: Control::new() }
    }

    /// Its log of `origin`.
    fn log_of(&self, origin: &str) -> &MemoryLogStore {
        &self.stores[origin]
    }

    fn silence(&self, silent: bool) {
        self.control.silent.store(silent, Ordering::SeqCst);
    }

    fn set_mode(&self, mode: Mode) {
        *self.control.mode.lock().unwrap() = mode;
    }

    fn link(&self) -> Arc<dyn PeerLink> {
        Arc::new(Link { target: Arc::clone(&self.slot), control: Arc::clone(&self.control) })
    }
}

/// An anchor that keeps nothing (test only): a log written for `origin`
/// without any peer, as a host could replay or forge one.
struct Detached(&'static str);

impl HeadAnchor for Detached {
    fn origin(&self) -> &str {
        self.0
    }

    fn restore(&mut self, _: &MasterKey, _: &[(u64, Vec<u8>)]) -> Result<Vec<(u64, Vec<u8>)>, SealError> {
        Ok(Vec::new())
    }

    fn anchor(&mut self, _: u64, _: &[u8], _: &mut dyn LogStore) -> Result<(), SealError> {
        Ok(())
    }
}

/// Region `origin`'s log over `store` under `master`, anchored nowhere.
fn detached_log(master: &MasterKey, origin: &'static str, store: &MemoryLogStore, seed: u64) -> JournalLog {
    JournalLog::open_anchored(master, Box::new(store.clone()), Box::new(Random(seed)), Box::new(Detached(origin)))
        .expect("the log verifies")
}

/// A service request kind 3 body: op, origin, nonce and the rest.
fn request(op: u8, origin: &str, nonce: u8, rest: &[u8]) -> Vec<u8> {
    let mut body = vec![op, origin.len() as u8];
    body.extend_from_slice(origin.as_bytes());
    body.extend_from_slice(&[nonce; 32]);
    body.extend_from_slice(rest);
    body
}

/// An append request: record `counter` of `origin`'s log.
fn append(origin: &str, counter: u64, record: &[u8]) -> Vec<u8> {
    request(OP_APPEND, origin, 0x42, &[&counter.to_be_bytes()[..], record].concat())
}

/// The body of an answer.
fn body_of(answer: &[u8]) -> &[u8] {
    &answer[body_start(answer)..]
}

/// The counter of a head answer (0 for no copy).
fn head_counter(answer: &[u8]) -> u64 {
    let body = body_of(answer);
    match body[0] {
        1 => u64::from_be_bytes(body[1..9].try_into().unwrap()),
        _ => 0,
    }
}

/// us-east-1's two peers.
struct World {
    eu: Region,
    ap: Region,
    us: Arc<FakeAttester>,
}

impl World {
    fn new() -> World {
        World { eu: Region::new(EU), ap: Region::new(AP), us: attester(US, instance(US, 0)) }
    }

    /// us-east-1's peers over `links` (eu-central-1's port, then
    /// ap-southeast-1's).
    fn peers_on(&self, links: [Arc<dyn PeerLink>; 2], seed: u64) -> Arc<Peers> {
        let [eu, ap] = links;
        let peers = vec![Peer { region: EU.into(), link: eu }, Peer { region: AP.into(), link: ap }];
        Arc::new(Peers::new(US, peers).with_random(Box::new(Random(seed << 40))).with_attester(self.us.clone()))
    }

    fn anchor(&self, seed: u64) -> Anchor {
        Anchor::new(self.peers_on([self.eu.link(), self.ap.link()], seed))
    }

    /// us-east-1's log over `store`, anchored in both peers.
    fn open(&self, store: &MemoryLogStore, seed: u64) -> Result<JournalLog, SealError> {
        self.open_on(store, seed, [self.eu.link(), self.ap.link()])
    }

    /// The same, its peer ports leading over `links`.
    fn open_on(&self, store: &MemoryLogStore, seed: u64, links: [Arc<dyn PeerLink>; 2]) -> Result<JournalLog, SealError> {
        JournalLog::open_anchored(
            &support::master(),
            Box::new(store.clone()),
            Box::new(Random(seed << 20)),
            Box::new(Anchor::new(self.peers_on(links, seed))),
        )
    }
}

fn seal_on(log: &JournalLog, clock: &TestClock, label: u64) -> Seal {
    Seal::new(
        support::master(),
        SealConfig { measurement: MEASUREMENT, answer_lifetime_secs: 120 },
        Box::new(TestRandom::new(label)),
        Box::new(clock.clone()),
        Box::new(log.clone()),
        Box::new(SettledCheck),
        Box::new(support::registered(&[UID])),
    )
}

/// Four saves: two cards, both kinds, one entry replaced.
fn save_four(log: &mut JournalLog) -> Vec<(CardUid, EntryKind, Vec<u8>)> {
    let saves = vec![
        (UID, EntryKind::Fill, b"first fill entry".to_vec()),
        (UID, EntryKind::Open, b"an open entry".to_vec()),
        (OTHER, EntryKind::Fill, b"another card's fill".to_vec()),
        (UID, EntryKind::Fill, b"the fill entry replaced".to_vec()),
    ];
    for (uid, kind, sealed) in &saves {
        log.save(uid, *kind, sealed.clone()).expect("the save is anchored");
    }
    saves
}

/// Fills `card` and seals it on `seal`; the commit data.
fn fill_and_seal(seal: &mut Seal, card: &mut SimCard, maker: &mut StubMaker) -> Vec<u8> {
    let request = FillRequest { uid: UID, challenge: [0x0f; 32], amount_wei: AMOUNT, pin: None };
    let filled = seal.fill(card, &request, maker).expect("fill");
    let chain = StubChain::default();
    chain.pay(&filled.commit_data, AMOUNT);
    let sealed = seal.confirm_fill(card, &CheckRequest { uid: UID, challenge: [3; 32] }, &chain).expect("confirm");
    assert_eq!(sealed.body.state, CardState::Sealed);
    filled.commit_data
}

#[test]
fn every_save_reaches_every_peer_before_it_is_ok() {
    let world = World::new();
    let store = MemoryLogStore::new();
    let mut log = world.open(&store, 1).expect("an empty log, both peers answering no copy of an empty log");
    save_four(&mut log);
    assert_eq!(store.records().len(), 4);
    // Each peer holds exactly the host's records, in a log of its own for
    // us-east-1, and nothing in its log of the third region.
    assert_eq!(world.eu.log_of(US).records(), store.records());
    assert_eq!(world.ap.log_of(US).records(), store.records());
    assert!(world.eu.log_of(AP).records().is_empty());
    assert!(world.ap.log_of(EU).records().is_empty());
}

#[test]
fn a_tail_cut_while_the_enclave_is_stopped_is_restored_and_with_a_peer_unreachable_it_is_refused() {
    let world = World::new();
    let store = MemoryLogStore::new();
    let saves = {
        let mut log = world.open(&store, 2).unwrap();
        save_four(&mut log)
        // The enclave stops.
    };
    let whole = store.records();
    // The host drops the last two records while the enclave is stopped.
    store.set_records(whole[..2].to_vec());
    // The store alone cannot see it: the shorter log still verifies.
    let unanchored = detached_log(&support::master(), US, &store, 1);
    assert_eq!(unanchored.counter(), 2);

    // No peer reachable: refused, and nothing appended.
    world.eu.silence(true);
    world.ap.silence(true);
    assert_eq!(world.open(&store, 3).err(), Some(NO_PEER));
    assert_eq!(store.records(), whole[..2].to_vec());
    // One peer back is not enough: a restart needs every peer.
    world.ap.silence(false);
    assert_eq!(world.open(&store, 4).err(), Some(NO_PEER));
    assert_eq!(store.records(), whole[..2].to_vec());

    // Both back: the cut is caught and the records restored.
    world.eu.silence(false);
    let log = world.open(&store, 5).expect("restored from the peers");
    assert_eq!(log.counter(), 4);
    assert_eq!(store.records(), whole, "the host's store holds the whole log again");
    assert_eq!(log.load(&UID, EntryKind::Fill), Some(saves[3].2.clone()));
    assert_eq!(log.load(&OTHER, EntryKind::Fill), Some(saves[2].2.clone()));
}

#[test]
fn the_shared_log_refuses_with_a_peer_silent_and_opens_on_a_later_try() {
    let world = World::new();
    let store = MemoryLogStore::new();
    {
        let mut log = world.open(&store, 6).unwrap();
        save_four(&mut log);
    }
    store.set_records(store.records()[..1].to_vec());
    world.eu.silence(true);
    let shared = SharedLog::anchored_with_random(Box::new(store.clone()), Box::new(Random(6)), Box::new(world.anchor(6)));
    let refused = shared.journal(&support::master()).err().expect("eu-central-1 did not answer");
    assert!(is_anchor_error(&refused), "{refused}");
    assert!(!shared.is_open());
    assert_eq!(shared.head(), None, "no head before the log is open");
    world.eu.silence(false);
    let log = shared.journal(&support::master()).expect("tried again, restored");
    assert_eq!(log.counter(), 4);
    assert!(shared.is_open());
    assert_eq!(shared.head().map(|(counter, _)| counter), Some(4));
}

/// Fills, seals and begins an Open of `card` on `log`, cut off at the first
/// card command after the Open was journaled; the commit data and the request.
fn begin_open_cut_off(log: &JournalLog, card: &mut SimCard, maker: &mut StubMaker, phone_seed: u8) -> (Vec<u8>, OpenRequest) {
    let clock = TestClock::new();
    let mut seal = seal_on(log, &clock, 1);
    let commit_data = fill_and_seal(&mut seal, card, maker);
    let phone = support::phone(phone_seed);
    let request = OpenRequest { uid: UID, challenge: [5; 32], phone_key: phone.public_key(), pin: None };
    let mut step = 0;
    loop {
        card.drop_from(step, support::DropStyle::AfterCard);
        let cut = seal.open(card, &request);
        card.reconnect();
        assert_eq!(cut.err(), Some(SealError::Dropped), "step {step}");
        if log.load(&UID, EntryKind::Open).is_some() {
            break;
        }
        step += 1;
        assert!(step < 64, "the Open was never journaled");
    }
    (commit_data, request)
}

#[test]
fn a_replaced_host_restores_the_whole_log_from_its_peers_and_finishes_an_open_it_never_saw() {
    let world = World::new();
    let first_store = MemoryLogStore::new();
    let mut card = SimCard::set_up(UID);
    let mut maker = StubMaker::default();
    let (commit_data, request) = {
        let log = world.open(&first_store, 7).unwrap();
        begin_open_cut_off(&log, &mut card, &mut maker, 0x61)
        // The host instance is lost here, with its store.
    };

    // A new host on a new instance: its store is empty.
    let new_store = MemoryLogStore::new();
    world.us.set_pcr4(instance(US, 1));
    let log = world.open(&new_store, 8).expect("restored from the peers");
    assert_eq!(new_store.records(), first_store.records(), "the whole log, ciphertext as it was");
    assert!(log.load(&UID, EntryKind::Open).is_some(), "the Open the new host never saw");

    // The Open is finished on the new host, with the same key.
    let clock = TestClock::new();
    let mut seal = seal_on(&log, &clock, 2);
    let opened = seal.open(&mut card, &request).expect("finished on the new host");
    let phone = support::phone(0x61);
    assert_eq!(phone.open(&opened.release, &UID, 1).unwrap().expose_secret(), &maker.key_for(&commit_data)[..]);
    assert_eq!(world.ap.log_of(US).records(), new_store.records());
    assert_eq!(world.eu.log_of(US).records(), new_store.records());

    // Another phone cannot take it over.
    let other = OpenRequest { phone_key: support::phone(0x62).public_key(), ..request };
    assert!(seal.open(&mut card, &other).is_err());
}

/// One region's enclave and host, every log on it, its peer ports leading
/// to the other regions' enclaves of a [`Net`].
struct Node {
    own: MemoryLogStore,
    copies: BTreeMap<String, MemoryLogStore>,
    logs: Arc<PeerLogs>,
    journal: Arc<SharedLog>,
}

/// Three regions in this process, each a [`Node`] that can be replaced.
struct Net {
    slots: BTreeMap<String, Slot>,
    controls: BTreeMap<String, Arc<Control>>,
}

impl Net {
    fn new() -> Net {
        Net {
            slots: RELEASE_REGIONS.iter().map(|r| (r.to_string(), Arc::new(Mutex::new(None)))).collect(),
            controls: RELEASE_REGIONS.iter().map(|r| (r.to_string(), Control::new())).collect(),
        }
    }

    fn link(&self, to: &str) -> Arc<dyn PeerLink> {
        Arc::new(Link { target: Arc::clone(&self.slots[to]), control: Arc::clone(&self.controls[to]) })
    }

    /// Region `name`'s enclave on a new host (its `generation`-th, every
    /// store empty), reachable from the others at once; not started yet.
    fn boot(&self, name: &str, generation: u8) -> Node {
        let links = RELEASE_REGIONS
            .iter()
            .filter(|r| **r != name)
            .map(|r| Peer { region: r.to_string(), link: self.link(r) })
            .collect();
        let peers = Peers::new(name, links)
            .with_random(Box::new(Random(u64::from(generation) << 48 | u64::from(name.as_bytes()[0]) << 40)))
            .with_attester(attester(name, instance(name, generation)));
        let peers = Arc::new(peers);
        let own = MemoryLogStore::new();
        let journal = Arc::new(SharedLog::anchored_with_random(
            Box::new(own.clone()),
            Box::new(Random(u64::from(generation) << 32)),
            Box::new(Anchor::new(Arc::clone(&peers))),
        ));
        let copies: BTreeMap<String, MemoryLogStore> =
            RELEASE_REGIONS.iter().filter(|r| **r != name).map(|r| (r.to_string(), MemoryLogStore::new())).collect();
        let stores = copies.iter().map(|(r, s)| (r.clone(), Box::new(s.clone()) as Box<dyn LogStore>)).collect();
        let logs = Arc::new(PeerLogs::new(peers, stores).with_own_log(Arc::clone(&journal), Box::new(own.clone())));
        *self.slots[name].lock().unwrap() = Some(Arc::clone(&logs));
        Node { own, copies, logs, journal }
    }

    /// Takes region `name`'s enclave and host away.
    fn lose(&self, name: &str) {
        *self.slots[name].lock().unwrap() = None;
    }
}

/// What an enclave does once it holds M, before it serves: every peer log
/// restored, then its own log opened.
fn start(node: &Node) -> Result<JournalLog, SealError> {
    node.logs.restore(&support::master())?;
    node.journal.journal(&support::master())
}

/// Starts every node, each tried again in turn (as the enclaves retry every
/// minute) until all are open.
fn start_in_turns(nodes: &[&Node]) -> Vec<JournalLog> {
    let mut open: Vec<Option<JournalLog>> = nodes.iter().map(|_| None).collect();
    for _ in 0..6 {
        for (node, slot) in nodes.iter().zip(open.iter_mut()) {
            if slot.is_none() {
                *slot = start(node).ok();
            }
        }
    }
    open.into_iter().map(|log| log.expect("every region starts")).collect()
}

#[test]
fn regions_replaced_one_after_another_keep_the_last_regions_journal() {
    let net = Net::new();
    // A fresh deployment: every store empty, every region started.
    let (us, eu, ap) = (net.boot(US, 0), net.boot(EU, 0), net.boot(AP, 0));
    let mut logs = start_in_turns(&[&us, &eu, &ap]);
    let mut ap_log = logs.pop().unwrap();
    let mut us_log = logs.remove(0);
    // ap-southeast-1 journals a Fill and an Open, us-east-1 one Fill.
    ap_log.save(&UID, EntryKind::Fill, b"ap's fill".to_vec()).unwrap();
    ap_log.save(&UID, EntryKind::Open, b"ap's open".to_vec()).unwrap();
    us_log.save(&OTHER, EntryKind::Fill, b"us's fill".to_vec()).unwrap();
    let ap_records = ap.own.records();
    let us_records = us.own.records();
    assert_eq!(ap_records.len(), 2);
    assert_eq!(us.copies[AP].records(), ap_records);
    assert_eq!(eu.copies[AP].records(), ap_records);
    drop((us_log, ap_log));

    // us-east-1 is replaced. Before its start its copies answer no copy,
    // never a zero head.
    net.lose(US);
    drop(us);
    let us = net.boot(US, 1);
    for origin in [AP, EU] {
        let answer = us.logs.answer(&support::master(), &request(OP_HEAD, origin, 0x31, &[])).unwrap();
        assert_eq!(body_of(&answer), [0, NO_COPY_NOT_RESTORED], "{origin}");
    }
    let us_log = start(&us).expect("the replaced us-east-1 restores every log it keeps");
    assert_eq!(us_log.counter(), 1);
    assert_eq!(us.own.records(), us_records);
    assert_eq!(us.copies[AP].records(), ap_records, "us-east-1's copy of ap-southeast-1's log");
    assert!(us.copies[EU].records().is_empty());
    assert!(us.logs.all_restored());
    drop(us_log);

    // eu-central-1 is replaced next, with no write in between.
    net.lose(EU);
    drop(eu);
    let eu = net.boot(EU, 1);
    start(&eu).expect("the replaced eu-central-1 restores every log it keeps");
    assert_eq!(eu.copies[AP].records(), ap_records, "eu-central-1's copy of ap-southeast-1's log");
    assert_eq!(eu.copies[US].records(), us_records);

    // ap-southeast-1 last: both its copies were restored by replaced hosts,
    // and its journal survives.
    net.lose(AP);
    drop(ap);
    let ap = net.boot(AP, 1);
    let ap_log = start(&ap).expect("the replaced ap-southeast-1 restores its own log");
    assert_eq!(ap.own.records(), ap_records);
    assert_eq!(ap_log.counter(), 2);
    assert_eq!(ap_log.load(&UID, EntryKind::Open), Some(b"ap's open".to_vec()));
    assert_eq!(ap.copies[US].records(), us_records);
}

#[test]
fn every_region_restarting_at_once_starts_again_and_a_replaced_host_among_them_restores() {
    let net = Net::new();
    let (us, eu, ap) = (net.boot(US, 0), net.boot(EU, 0), net.boot(AP, 0));
    let mut logs = start_in_turns(&[&us, &eu, &ap]);
    logs[2].save(&UID, EntryKind::Open, b"ap's open".to_vec()).unwrap();
    let ap_records = ap.own.records();
    drop(logs);
    // Every enclave restarts on its host (the stores stay); ap-southeast-1's
    // host is replaced at the same time.
    let reboot = |old: Node, name: &str, generation: u8, keep: bool| {
        let node = net.boot(name, generation);
        if keep {
            node.own.set_records(old.own.records());
            for (origin, store) in &node.copies {
                store.set_records(old.copies[origin].records());
            }
        }
        node
    };
    let (us, eu, ap) = (reboot(us, US, 1, true), reboot(eu, EU, 1, true), reboot(ap, AP, 1, false));
    let logs = start_in_turns(&[&us, &eu, &ap]);
    assert_eq!(ap.own.records(), ap_records);
    assert_eq!(logs[2].load(&UID, EntryKind::Open), Some(b"ap's open".to_vec()));
}

#[test]
fn an_empty_or_unrestored_peer_log_answers_no_copy_and_no_copy_never_counts_as_a_head() {
    let master = support::master();
    // A copy not restored yet answers no copy, empty or with records.
    let peers = Arc::new(Peers::new(AP, Vec::new()).with_attester(attester(AP, instance(AP, 0))));
    let unrestored_store = MemoryLogStore::new();
    let unrestored = PeerLogs::new(Arc::clone(&peers), vec![(US.to_string(), Box::new(unrestored_store.clone()))]);
    let answer = unrestored.answer(&master, &request(OP_HEAD, US, 1, &[])).unwrap();
    assert_eq!(body_of(&answer), [0, NO_COPY_NOT_RESTORED]);
    assert!(unrestored.answer(&master, &append(US, 1, &[0u8; 64])).is_err(), "it takes no append before its restore");
    assert!(unrestored.answer(&master, &request(OP_FETCH, US, 1, &1u64.to_be_bytes())).is_err());
    let world = World::new();
    let us_store = MemoryLogStore::new();
    save_four(&mut world.open(&us_store, 50).unwrap());
    unrestored_store.set_records(us_store.records());
    let answer = unrestored.answer(&master, &request(OP_HEAD, US, 2, &[])).unwrap();
    assert_eq!(body_of(&answer), [0, NO_COPY_UNCONFIRMED]);
    // A copy restored and empty answers no copy too, never a zero head.
    let answer = Region::new(EU).logs.answer(&master, &request(OP_HEAD, US, 3, &[])).unwrap();
    assert_eq!(body_of(&answer), [0, NO_COPY_EMPTY]);

    // us-east-1 has records, and no peer holds them: refused, not opened.
    let lost = World::new();
    assert_eq!(lost.open(&us_store, 51).err(), Some(NO_COPY));
    assert_eq!(us_store.records().len(), 4, "nothing dropped");
    // One peer holds them, the other answers no copy: still refused, with
    // the store full or empty (a no copy never agrees).
    let half = Region::on(AP, attester(AP, instance(AP, 0)), &[(US, us_store.records())]);
    let links = [lost.eu.link(), half.link()];
    assert_eq!(lost.open_on(&us_store, 52, links.clone()).err(), Some(NO_COPY));
    let empty = MemoryLogStore::new();
    assert_eq!(lost.open_on(&empty, 53, links).err(), Some(NO_COPY));
    assert!(empty.records().is_empty());
    // Both hold them: restored.
    let full = Region::on(EU, attester(EU, instance(EU, 0)), &[(US, us_store.records())]);
    assert_eq!(lost.open_on(&empty, 54, [full.link(), half.link()]).unwrap().counter(), 4);

    // A copy with records whose holders say the log is empty is refused, and
    // an empty copy while a holder has records not confirmed waits.
    let asker = |links: Vec<Peer>, store: &MemoryLogStore| {
        let peers = Arc::new(Peers::new(EU, links).with_attester(attester(EU, instance(EU, 0))));
        PeerLogs::new(peers, vec![(US.to_string(), Box::new(store.clone()) as Box<dyn LogStore>)])
    };
    let says_empty = Region::new(AP);
    let copy = MemoryLogStore::new();
    copy.set_records(us_store.records());
    let refused = asker(vec![Peer { region: AP.into(), link: says_empty.link() }], &copy);
    assert_eq!(refused.restore(&master).err(), Some(NO_COPY));
    assert!(!refused.is_restored(US));
    let waiting = PeerLogs::new(Arc::clone(&peers), vec![(US.to_string(), Box::new(us_store.clone()))]);
    let waiting = Arc::new(waiting);
    let to_waiting = Arc::new(Link { target: Arc::new(Mutex::new(Some(waiting))), control: Control::new() });
    let fresh = MemoryLogStore::new();
    let waits = asker(vec![Peer { region: AP.into(), link: to_waiting }], &fresh);
    assert_eq!(waits.restore(&master).err(), Some(NO_COPY));
    assert!(fresh.records().is_empty());
}

#[test]
fn a_peer_answering_an_old_head_with_an_old_nonce_is_not_taken() {
    let world = World::new();
    world.eu.set_mode(Mode::ReplayHeads);
    let store = MemoryLogStore::new();
    {
        // eu-central-1 answers no copy here, and keeps that answer.
        let mut log = world.open(&store, 9).unwrap();
        save_four(&mut log);
    }
    assert_eq!(world.eu.log_of(US).records().len(), 4, "the appends reached it");
    // The host empties its store; eu-central-1's link replays its old answer
    // (no copy, a MAC and a document over an old nonce).
    store.set_records(Vec::new());
    assert_eq!(world.open(&store, 10).err(), Some(UNATTESTED), "an old answer is never taken");
    assert!(store.records().is_empty());
    // An honest answer with this start's own nonce restores the log.
    world.eu.set_mode(Mode::Honest);
    assert_eq!(world.open(&store, 11).unwrap().counter(), 4);
}

#[test]
fn a_forked_head_is_refused() {
    let world = World::new();
    let store = MemoryLogStore::new();
    {
        let mut log = world.open(&store, 12).unwrap();
        save_four(&mut log);
    }
    // Another log of us-east-1 with the same entries under the same M (other
    // IVs): the same counters, other tags.
    let fork_store = MemoryLogStore::new();
    let mut fork = detached_log(&support::master(), US, &fork_store, 99);
    for (uid, kind, sealed) in [
        (UID, EntryKind::Fill, b"first fill entry".to_vec()),
        (UID, EntryKind::Open, b"an open entry".to_vec()),
        (OTHER, EntryKind::Fill, b"another card's fill".to_vec()),
        (UID, EntryKind::Fill, b"the fill entry replaced".to_vec()),
    ] {
        fork.save(&uid, kind, sealed).unwrap();
    }
    // The host shows the fork: the same counter as the peers, another tag.
    store.set_records(fork_store.records());
    assert_eq!(world.open(&store, 13).err(), Some(FORKED));
    // A shorter fork: the peers' next record does not chain onto it.
    store.set_records(fork_store.records()[..2].to_vec());
    let refused = world.open(&store, 14).err().expect("refused");
    assert!(refused == BAD_RESTORE || refused == FORKED, "{refused}");
    assert_eq!(store.records(), fork_store.records()[..2].to_vec(), "nothing appended");
}

#[test]
fn a_restored_record_changed_in_transit_or_on_a_peers_host_is_refused() {
    let world = World::new();
    let store = MemoryLogStore::new();
    {
        let mut log = world.open(&store, 15).unwrap();
        save_four(&mut log);
    }
    let whole = store.records();
    store.set_records(whole[..1].to_vec());
    // Changed on the way: the answer's MAC no longer verifies.
    world.eu.set_mode(Mode::TamperFetch);
    assert_eq!(world.open(&store, 16).err(), Some(UNATTESTED));
    assert_eq!(store.records(), whole[..1].to_vec(), "no changed record reached the host's store");
    world.eu.set_mode(Mode::Honest);
    // Changed on eu-central-1's host after its restore: the peer answers it
    // as it is, and it fails its check on us-east-1's chain.
    let mut changed = whole.clone();
    changed[2].1[20] ^= 0x01;
    world.eu.log_of(US).set_records(changed);
    assert_eq!(world.open(&store, 17).err(), Some(BAD_RESTORE));
    assert_eq!(store.records(), whole[..1].to_vec());
    world.eu.log_of(US).set_records(whole.clone());
    assert_eq!(world.open(&store, 18).unwrap().counter(), 4);
}

#[test]
fn an_approved_enclave_on_the_askers_host_or_one_instance_for_two_peers_is_never_taken() {
    let master = support::master();
    let world = World::new();
    let store = MemoryLogStore::new();
    let mut card = SimCard::set_up(UID);
    let mut maker = StubMaker::default();
    {
        let log = world.open(&store, 60).unwrap();
        begin_open_cut_off(&log, &mut card, &mut maker, 0x65);
    }
    // The Open is the last record journaled.
    let whole = store.records();
    let prefix = whole[..whole.len() - 1].to_vec();
    // us-east-1's host controller cuts the Open off its store and starts an
    // approved eu-central-1 enclave on that same host (us-east-1's PCR4),
    // which joined M; it seeds that enclave's copy with the prefix and
    // leads both of us-east-1's peer ports to it.
    let on_own_host = Region::on(EU, attester(EU, world.us.pcr4()), &[(US, prefix.clone())]);
    store.set_records(prefix.clone());
    let both = [on_own_host.link(), on_own_host.link()];
    assert_eq!(world.open_on(&store, 61, both).err(), Some(UNATTESTED));
    // One port only: still refused (every peer must be taken).
    assert_eq!(world.open_on(&store, 62, [on_own_host.link(), world.ap.link()]).err(), Some(UNATTESTED));
    // An eu-central-1 and an ap-southeast-1 enclave, both on one other
    // instance: the two answers share a PCR4.
    let elsewhere = instance("sa-east-1", 9);
    let eu_there = Region::on(EU, attester(EU, elsewhere), &[(US, prefix.clone())]);
    let ap_there = Region::on(AP, attester(AP, elsewhere), &[(US, prefix.clone())]);
    assert_eq!(world.open_on(&store, 63, [eu_there.link(), ap_there.link()]).err(), Some(UNATTESTED));
    // An eu-central-1 enclave answering on ap-southeast-1's port, and an
    // enclave of us-east-1's own image: not the port's region.
    let eu_other = Region::on(EU, attester(EU, instance(EU, 7)), &[(US, prefix.clone())]);
    assert_eq!(world.open_on(&store, 64, [world.eu.link(), eu_other.link()]).err(), Some(UNATTESTED));
    let us_image = {
        let own = MemoryLogStore::new();
        own.set_records(prefix.clone());
        let shared = Arc::new(SharedLog::anchored(Box::new(own.clone()), Box::new(Detached(US))));
        shared.journal(&master).unwrap();
        let peers = Arc::new(Peers::new(US, Vec::new()).with_attester(attester(US, instance(US, 7))));
        let logs = Arc::new(PeerLogs::new(peers, Vec::new()).with_own_log(shared, Box::new(own)));
        Arc::new(Link { target: Arc::new(Mutex::new(Some(logs))), control: Control::new() }) as Arc<dyn PeerLink>
    };
    assert_eq!(world.open_on(&store, 65, [us_image, world.ap.link()]).err(), Some(UNATTESTED));
    // A build not on the approved list.
    let unapproved = Arc::new(FakeAttester::new(KEY, [0xee; 48], instance(EU, 8), vec![[0xee; 48]]));
    let rogue = Region::on(EU, unapproved, &[(US, prefix.clone())]);
    assert_eq!(world.open_on(&store, 66, [rogue.link(), world.ap.link()]).err(), Some(UNATTESTED));
    assert_eq!(store.records(), prefix, "nothing taken from any of them");

    // The established peers, each on its own instance: the Open is restored.
    let log = world.open(&store, 67).unwrap();
    assert_eq!(store.records(), whole);
    assert!(log.load(&UID, EntryKind::Open).is_some());
    // And a save is never acknowledged by an enclave on this host either.
    let mut log = world.open_on(&store, 68, [world.eu.link(), world.ap.link()]).unwrap();
    world.ap.logs.peers().install_attester(attester(AP, world.us.pcr4()));
    assert_eq!(log.save(&OTHER, EntryKind::Fill, b"after".to_vec()).err(), Some(UNATTESTED));
    assert_eq!(log.load(&OTHER, EntryKind::Fill), None);
    world.ap.logs.peers().install_attester(attester(AP, instance(AP, 0)));
    log.save(&OTHER, EntryKind::Fill, b"after".to_vec()).expect("both peers on instances of their own");
    // The document in an answer: the asker's nonce, the responder's PCR4;
    // changed or cut short, it is not taken.
    let answer = world.eu.logs.answer(&master, &request(OP_HEAD, US, 4, &[])).unwrap();
    let document = &answer[3 + EU.len()..body_start(&answer) - 32];
    let checked = world.us.check(document).expect("eu-central-1's document");
    assert_eq!((checked.pcr4, checked.nonce), (instance(EU, 0), vec![4u8; 32]));
    let mut changed = document.to_vec();
    changed[60] ^= 0x01;
    assert!(world.us.check(&changed).is_err());
    assert!(world.us.check(&document[..document.len() - 1]).is_err());
}

#[test]
fn a_save_with_one_peer_silent_fails_and_the_card_is_unchanged() {
    let world = World::new();
    let store = MemoryLogStore::new();
    let log = world.open(&store, 18).unwrap();
    let clock = TestClock::new();
    let mut seal = seal_on(&log, &clock, 3);
    let mut card = SimCard::set_up(UID);
    let mut maker = StubMaker::default();
    let commit_data = fill_and_seal(&mut seal, &mut card, &mut maker);
    let written = store.records().len();

    world.ap.silence(true);
    let (file, keys) = (card.file.clone(), card.keys);
    let phone = support::phone(0x63);
    let request = OpenRequest { uid: UID, challenge: [6; 32], phone_key: phone.public_key(), pin: None };
    assert_eq!(seal.open(&mut card, &request).err(), Some(NOT_ACKNOWLEDGED));
    assert_eq!((card.file.clone(), card.keys), (file, keys), "the card is unchanged");
    assert_eq!(log.load(&UID, EntryKind::Open), None, "the Open is not taken as journaled");
    assert!(log.has_unsettled());
    // The host keeps the record; eu-central-1 took it, ap-southeast-1 did not.
    assert_eq!(store.records().len(), written + 1);
    assert_eq!(world.eu.log_of(US).records().len(), written + 1);
    assert_eq!(world.ap.log_of(US).records().len(), written);

    // ap-southeast-1 back: the Open goes on, and it is sent what it missed.
    world.ap.silence(false);
    let opened = seal.open(&mut card, &request).expect("the Open with both peers");
    assert_eq!(phone.open(&opened.release, &UID, 1).unwrap().expose_secret(), &maker.key_for(&commit_data)[..]);
    assert_eq!(world.ap.log_of(US).records(), store.records());
    assert_eq!(world.eu.log_of(US).records(), store.records());
}

#[test]
fn a_record_no_peer_acknowledged_is_held_back_and_a_host_that_drops_it_is_refused() {
    let world = World::new();
    let store = MemoryLogStore::new();
    let mut log = world.open(&store, 19).unwrap();
    log.save(&UID, EntryKind::Fill, b"acknowledged".to_vec()).unwrap();
    world.eu.silence(true);
    world.ap.silence(true);
    assert_eq!(log.save(&UID, EntryKind::Fill, b"held back".to_vec()).err(), Some(NOT_ACKNOWLEDGED));
    assert_eq!(log.load(&UID, EntryKind::Fill), Some(b"acknowledged".to_vec()));
    // Each session's check of the store asks no peer and holds it back still.
    log.check_store().expect("the store holds what was written");
    assert_eq!(log.load(&UID, EntryKind::Fill), Some(b"acknowledged".to_vec()));
    // The host drops the record it said was durable: a rollback.
    let records = store.records();
    store.set_records(records[..1].to_vec());
    assert!(log.check_store().is_err());
    assert!(log.refused());
    world.eu.silence(false);
    world.ap.silence(false);
    store.set_records(records);
    assert!(log.save(&OTHER, EntryKind::Fill, b"after".to_vec()).is_err(), "refused for good");
}

#[test]
fn peers_see_ciphertext_only() {
    let world = World::new();
    let store = MemoryLogStore::new();
    let log = world.open(&store, 20).unwrap();
    let clock = TestClock::new();
    let mut seal = seal_on(&log, &clock, 4);
    let mut card = SimCard::set_up(UID);
    let mut maker = StubMaker::default();
    let commit_data = fill_and_seal(&mut seal, &mut card, &mut maker);
    let phone = support::phone(0x64);
    let request = OpenRequest { uid: UID, challenge: [7; 32], phone_key: phone.public_key(), pin: None };
    seal.open(&mut card, &request).expect("open");
    // A restore crosses the links too.
    let fresh = MemoryLogStore::new();
    world.open(&fresh, 21).unwrap();

    // What the peers' hosts keep is exactly the host's ciphertext records.
    assert_eq!(world.eu.log_of(US).records(), store.records());
    assert_eq!(world.ap.log_of(US).records(), store.records());
    let key = maker.key_for(&commit_data);
    let coin = sha3_256(&[&commit_data]);
    let mut texts = vec![world.eu.log_of(US).bytes(), world.ap.log_of(US).bytes()];
    texts.extend(world.eu.control.seen.lock().unwrap().iter().cloned());
    texts.extend(world.ap.control.seen.lock().unwrap().iter().cloned());
    assert!(texts.len() > 4);
    for text in &texts {
        assert!(!contains(text, &UID.0), "a UID crossed to a peer");
        assert!(!contains(text, &key), "a Phantom Key crossed to a peer");
        assert!(!contains(text, &commit_data[..32]), "commit data crossed to a peer");
        assert!(!contains(text, &coin), "a coin crossed to a peer");
        assert!(!contains(text, &AMOUNT.to_be_bytes()), "an amount crossed to a peer");
        assert!(!contains(text, &phone.public_key()[..64]), "a phone key crossed to a peer");
    }
}

#[test]
fn a_peer_takes_only_records_chained_under_m_and_only_for_the_other_regions() {
    let peer = Region::new(EU);
    let master = support::master();
    // A record of us-east-1's log under another M.
    let foreign_store = MemoryLogStore::new();
    let mut other = [0x77u8; 32];
    let mut foreign = detached_log(&MasterKey::take(&mut other), US, &foreign_store, 30);
    foreign.save(&UID, EntryKind::Fill, b"entry".to_vec()).unwrap();
    let record = foreign_store.records()[0].1.clone();
    assert!(peer.logs.answer(&master, &append(US, 1, &record)).is_err(), "another M's record");
    // A log anchored nowhere (no origin) is no region's either.
    let unanchored_store = MemoryLogStore::new();
    let mut unanchored = JournalLog::open_with(&master, Box::new(unanchored_store.clone()), Box::new(Random(31))).unwrap();
    unanchored.save(&UID, EntryKind::Fill, b"entry".to_vec()).unwrap();
    assert!(peer.logs.answer(&master, &append(US, 1, &unanchored_store.records()[0].1)).is_err(), "no origin");
    assert!(peer.log_of(US).records().is_empty());
    // The same entry written for us-east-1 under this M is taken.
    let own_store = MemoryLogStore::new();
    let mut own = detached_log(&master, US, &own_store, 32);
    own.save(&UID, EntryKind::Fill, b"entry".to_vec()).unwrap();
    let taken = peer.logs.answer(&master, &append(US, 1, &own_store.records()[0].1)).expect("us-east-1's record 1");
    assert_eq!(head_counter(&taken), 1);
    assert_eq!(&taken[1..1 + EU.len()], EU.as_bytes(), "the answer names the responder's region");
    assert_eq!(peer.log_of(US).records(), own_store.records());
    assert!(peer.logs.answer(&master, &append(EU, 1, &record)).is_err(), "its own region");
    assert!(peer.logs.answer(&master, &append("sa-east-1", 1, &record)).is_err(), "a region it keeps no log of");
    assert!(peer.logs.answer(&master, &[2u8, 200, 1, 2]).is_err(), "malformed");
    assert!(peer.logs.answer(&master, &[9u8, 2, b'u', b's']).is_err(), "malformed");
    assert_eq!(peer.logs.origins(), vec![AP.to_string(), US.to_string()]);
    // An enclave with no attester answers nothing.
    let mute = PeerLogs::new(Arc::new(Peers::new(EU, Vec::new())), Vec::new());
    assert!(mute.answer(&master, &request(OP_HEAD, US, 1, &[])).is_err());
}

#[test]
fn a_record_of_one_region_is_never_taken_as_another_regions() {
    let master = support::master();
    let world = World::new();
    let us_store = MemoryLogStore::new();
    let mut us_log = world.open(&us_store, 40).unwrap();
    save_four(&mut us_log);
    let us_records = us_store.records();

    // Anyone can fetch us-east-1's records from a peer: the service port
    // takes the request without knowing who asks.
    let fetched = world.eu.logs.answer(&master, &request(OP_FETCH, US, 0x01, &1u64.to_be_bytes())).unwrap();
    assert!(contains(&fetched, &us_records[0].1), "the fetch carries us-east-1's record 1");

    // us-east-1's record 1, appended as ap-southeast-1's counter 1 to
    // eu-central-1's (empty) log of ap-southeast-1: refused, nothing kept.
    assert!(world.eu.log_of(AP).records().is_empty());
    let refused = world.eu.logs.answer(&master, &append(AP, 1, &us_records[0].1));
    assert!(refused.is_err(), "a record of us-east-1 taken as ap-southeast-1's");
    assert!(world.eu.log_of(AP).records().is_empty(), "the peer log is unchanged");
    let head = world.eu.logs.answer(&master, &request(OP_HEAD, AP, 0x02, &[])).unwrap();
    assert_eq!(head_counter(&head), 0, "the peer's copy of ap-southeast-1 is still empty");
    // And us-east-1's own log there is as it was.
    assert_eq!(world.eu.log_of(US).records(), us_records);

    // Nor onto a log of ap-southeast-1 that has records: its record 1
    // written (and anchored in eu-central-1), us-east-1's record 2 is not
    // taken as its counter 2.
    let ap_store = MemoryLogStore::new();
    let ap_peers = || {
        let peers = Peers::new(AP, vec![Peer { region: EU.into(), link: world.eu.link() }]);
        Arc::new(peers.with_random(Box::new(Random(41))).with_attester(attester(AP, instance(AP, 0))))
    };
    let mut ap_log =
        JournalLog::open_anchored(&master, Box::new(ap_store.clone()), Box::new(Random(42)), Box::new(Anchor::new(ap_peers())))
            .unwrap();
    ap_log.save(&OTHER, EntryKind::Fill, b"ap-southeast-1's own entry".to_vec()).unwrap();
    assert_eq!(world.eu.log_of(AP).records(), ap_store.records());
    let held = world.eu.log_of(AP).records();
    assert!(world.eu.logs.answer(&master, &append(AP, 2, &us_records[1].1)).is_err());
    assert_eq!(world.eu.log_of(AP).records(), held, "the peer log is unchanged");

    // The check itself: us-east-1's record 1 opens only on us-east-1's chain.
    assert!(Chain::new(&master, AP).push(1, &us_records[0].1).is_err());
    assert!(Chain::new(&master, "").push(1, &us_records[0].1).is_err());
    Chain::new(&master, US).push(1, &us_records[0].1).expect("us-east-1's own chain");

    // A host that shows ap-southeast-1's enclave us-east-1's log is refused
    // before any peer is asked.
    let planted = MemoryLogStore::new();
    planted.set_records(us_records.clone());
    let opened = JournalLog::open_anchored(&master, Box::new(planted.clone()), Box::new(Random(44)), Box::new(Anchor::new(ap_peers())));
    assert!(opened.is_err());
    assert_eq!(planted.records(), us_records);
}

/// The vectors file, read without a JSON crate (the default build has
/// none): its label, its regions and its cards.
fn vectors() -> (String, Vec<String>, Vec<(CardUid, String)>) {
    let quoted = |text: &str| -> Vec<String> { text.split('"').skip(1).step_by(2).map(str::to_owned).collect() };
    let label = quoted(VECTORS.split("\"label\":").nth(1).unwrap())[0].clone();
    let regions_text = VECTORS.split("\"regions\":").nth(1).unwrap().split(']').next().unwrap();
    let regions = quoted(regions_text);
    let cards = VECTORS
        .split("\"uid\":")
        .skip(1)
        .map(|entry| {
            let fields = quoted(entry);
            let uid = CardUid(support::unhex(&fields[0]).try_into().expect("a 7-byte UID"));
            assert_eq!(fields[1], "home");
            (uid, fields[2].clone())
        })
        .collect();
    (label, regions, cards)
}

#[test]
fn the_home_rule_matches_its_fixed_vectors_and_every_region_agrees() {
    let (label, regions, cards) = vectors();
    assert_eq!(label.as_bytes(), HOME_REGION_LABEL);
    assert_eq!(regions, RELEASE_REGIONS.to_vec(), "the vectors use the release's ordered list");
    assert!(cards.len() >= 5);
    for region in &regions {
        assert!(cards.iter().any(|(_, home)| home == region), "no vector card is homed in {region}");
    }
    for (uid, home) in &cards {
        // The rule written out: the greatest SHA3-256(label || region || UID).
        let by_hand = regions
            .iter()
            .max_by_key(|region| sha3_256(&[HOME_REGION_LABEL, region.as_bytes(), &uid.0]))
            .unwrap();
        assert_eq!(by_hand, home, "{}", support::hex(&uid.0));
        assert_eq!(home_region(&regions, uid), Some(home.as_str()));
        // Every region computes the same home, and exactly one is it.
        let mine: Vec<&str> = RELEASE_REGIONS
            .iter()
            .filter(|own| {
                let regions = Regions::release(own).unwrap();
                assert_eq!(regions.home(uid), home);
                regions.is_home(uid)
            })
            .copied()
            .collect();
        assert_eq!(mine, vec![home.as_str()]);
        // Stable: asked again, the same answer.
        assert_eq!(home_region(&RELEASE_REGIONS, uid), Some(home.as_str()));
    }
    // The tests' card is among them.
    assert!(cards.iter().any(|(uid, _)| *uid == UID));
}

#[test]
fn a_region_list_must_be_well_formed_and_name_this_region() {
    assert_eq!(Regions::new(&[US], US).err(), Some(RegionsRefused::TooFew));
    assert_eq!(Regions::new(&[US, "EU-central-1"], US).err(), Some(RegionsRefused::BadName));
    assert_eq!(Regions::new(&[US, "eu/../x"], US).err(), Some(RegionsRefused::BadName));
    assert_eq!(Regions::new(&[US, US], US).err(), Some(RegionsRefused::Twice));
    assert_eq!(Regions::new(&[US, EU], AP).err(), Some(RegionsRefused::NotListed));
    let regions = Regions::release(EU).unwrap();
    assert_eq!(regions.own(), EU);
    assert_eq!(regions.peers(), vec![US, AP]);
    assert_eq!(regions.peers().len(), PEER_PORTS.len(), "one peer port per other region");
    assert!(valid_region("ap-southeast-1") && !valid_region("") && !valid_region("-a") && !valid_region(&"a".repeat(33)));
}
