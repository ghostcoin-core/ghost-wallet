//! The journal log's head anchored in the peer regions, with in-memory
//! stores and peers in this process: every save reaches every peer before it
//! is `Ok`; a tail the host cut while the enclave was stopped is caught and
//! restored from a peer, and with no peer reachable the log is refused; a
//! replaced host (an empty log) restores the whole log from a peer and then
//! finishes an Open it never saw; a peer answering an old head with an old
//! nonce is not taken; a forked head is refused; a restored record changed
//! in transit is refused; a save with one peer silent fails and leaves the
//! card unchanged; peers see ciphertext only; and the home rule agrees across
//! regions and matches its fixed vectors (`tests/vectors/home-region.json`).

mod support;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ghost_seal::journal_anchor::{
    Anchor, BAD_RESTORE, FORKED, HOME_REGION_LABEL, NO_PEER, NOT_ACKNOWLEDGED, OP_APPEND, OP_FETCH, OP_HEAD, PEER_PORTS,
    Peer, PeerLink, PeerLogs, RELEASE_REGIONS, Regions, RegionsRefused, home_region, is_anchor_error, valid_region,
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

/// How a test makes a peer misbehave.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Honest,
    /// Answers every head request with the first head answer it gave.
    ReplayHeads,
    /// Changes one byte of the first record of every fetch answer.
    TamperFetch,
}

/// A peer region in this process: its logs of the other regions, each over
/// an in-memory store of its host.
struct Region {
    logs: Arc<PeerLogs>,
    stores: BTreeMap<String, MemoryLogStore>,
    silent: Arc<AtomicBool>,
    mode: Arc<Mutex<Mode>>,
    first_head: Arc<Mutex<Option<Vec<u8>>>>,
    /// Every request and answer that crossed the link.
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Region {
    fn new(name: &str) -> Region {
        let stores: BTreeMap<String, MemoryLogStore> =
            RELEASE_REGIONS.iter().filter(|r| **r != name).map(|r| (r.to_string(), MemoryLogStore::new())).collect();
        let boxed = stores.iter().map(|(r, s)| (r.clone(), Box::new(s.clone()) as Box<dyn LogStore>)).collect();
        Region {
            logs: Arc::new(PeerLogs::new(name, boxed)),
            stores,
            silent: Arc::new(AtomicBool::new(false)),
            mode: Arc::new(Mutex::new(Mode::Honest)),
            first_head: Arc::new(Mutex::new(None)),
            seen: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Its log of `origin`.
    fn log_of(&self, origin: &str) -> &MemoryLogStore {
        &self.stores[origin]
    }

    fn silence(&self, silent: bool) {
        self.silent.store(silent, Ordering::SeqCst);
    }

    fn set_mode(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }

    fn link(&self) -> Arc<dyn PeerLink> {
        Arc::new(Link {
            logs: Arc::clone(&self.logs),
            silent: Arc::clone(&self.silent),
            mode: Arc::clone(&self.mode),
            first_head: Arc::clone(&self.first_head),
            seen: Arc::clone(&self.seen),
        })
    }
}

/// The origin's way to a peer: straight to its answers, as the test has the
/// peer behave.
struct Link {
    logs: Arc<PeerLogs>,
    silent: Arc<AtomicBool>,
    mode: Arc<Mutex<Mode>>,
    first_head: Arc<Mutex<Option<Vec<u8>>>>,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl PeerLink for Link {
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        if self.silent.load(Ordering::SeqCst) {
            return Err("unreachable".into());
        }
        self.seen.lock().unwrap().push(request.to_vec());
        let mut answer = self.logs.answer(&support::master(), request)?;
        let mode = *self.mode.lock().unwrap();
        if mode == Mode::ReplayHeads && request[0] == OP_HEAD {
            let mut first = self.first_head.lock().unwrap();
            match first.as_ref() {
                Some(old) => answer = old.clone(),
                None => *first = Some(answer.clone()),
            }
        }
        if mode == Mode::TamperFetch && request[0] == OP_FETCH && answer.len() > 40 {
            answer[40] ^= 0x01;
        }
        self.seen.lock().unwrap().push(answer.clone());
        Ok(answer)
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

/// The counter of a head answer.
fn head_counter(answer: &[u8]) -> u64 {
    u64::from_be_bytes(answer[..8].try_into().unwrap())
}

/// The two peers of us-east-1.
struct World {
    eu: Region,
    ap: Region,
}

impl World {
    fn new() -> World {
        World { eu: Region::new(EU), ap: Region::new(AP) }
    }

    fn anchor(&self, seed: u64) -> Anchor {
        let peers = vec![
            Peer { region: EU.into(), link: self.eu.link() },
            Peer { region: AP.into(), link: self.ap.link() },
        ];
        Anchor::with_random(US, peers, Box::new(Random(seed << 40)))
    }

    /// us-east-1's log over `store`, anchored in both peers.
    fn open(&self, store: &MemoryLogStore, seed: u64) -> Result<JournalLog, SealError> {
        JournalLog::open_anchored(
            &support::master(),
            Box::new(store.clone()),
            Box::new(Random(seed << 20)),
            Box::new(self.anchor(seed)),
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
    let mut log = world.open(&store, 1).expect("an empty log with both peers answering");
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
fn a_tail_cut_while_the_enclave_is_stopped_is_restored_from_a_peer_and_with_no_peer_it_is_refused() {
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

    // One peer back: the cut is caught and the records restored.
    world.ap.silence(false);
    let log = world.open(&store, 4).expect("restored from ap-southeast-1");
    assert_eq!(log.counter(), 4);
    assert_eq!(store.records(), whole, "the host's store holds the whole log again");
    assert_eq!(log.load(&UID, EntryKind::Fill), Some(saves[3].2.clone()));
    assert_eq!(log.load(&OTHER, EntryKind::Fill), Some(saves[2].2.clone()));
}

#[test]
fn the_shared_log_refuses_with_no_peer_and_opens_on_a_later_try() {
    let world = World::new();
    let store = MemoryLogStore::new();
    {
        let mut log = world.open(&store, 5).unwrap();
        save_four(&mut log);
    }
    store.set_records(store.records()[..1].to_vec());
    world.eu.silence(true);
    world.ap.silence(true);
    let shared = SharedLog::anchored_with_random(Box::new(store.clone()), Box::new(Random(6)), Box::new(world.anchor(6)));
    let refused = shared.journal(&support::master()).err().expect("no peer answered");
    assert!(is_anchor_error(&refused), "{refused}");
    assert!(!shared.is_open());
    world.eu.silence(false);
    let log = shared.journal(&support::master()).expect("tried again, restored from eu-central-1");
    assert_eq!(log.counter(), 4);
    assert!(shared.is_open());
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
fn a_replaced_host_restores_the_whole_log_from_a_peer_and_finishes_an_open_it_never_saw() {
    let world = World::new();
    let first_store = MemoryLogStore::new();
    let mut card = SimCard::set_up(UID);
    let mut maker = StubMaker::default();
    let (commit_data, request) = {
        let log = world.open(&first_store, 7).unwrap();
        begin_open_cut_off(&log, &mut card, &mut maker, 0x61)
        // The host instance is lost here, with its store.
    };

    // A new host: its store is empty. Only eu-central-1 answers at the start.
    let new_store = MemoryLogStore::new();
    world.ap.silence(true);
    let log = world.open(&new_store, 8).expect("restored from eu-central-1");
    assert_eq!(new_store.records(), first_store.records(), "the whole log, ciphertext as it was");
    assert!(log.load(&UID, EntryKind::Open).is_some(), "the Open the new host never saw");

    // The Open is finished on the new host, with the same key, once both
    // peers answer again (each of its saves needs both).
    world.ap.silence(false);
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

#[test]
fn a_peer_answering_an_old_head_with_an_old_nonce_is_not_taken() {
    let world = World::new();
    world.eu.set_mode(Mode::ReplayHeads);
    let store = MemoryLogStore::new();
    {
        // eu-central-1 answers head 0 here, and keeps that answer.
        let mut log = world.open(&store, 9).unwrap();
        save_four(&mut log);
    }
    assert_eq!(world.eu.log_of(US).records().len(), 4, "the appends reached it");
    // The host empties its store; the only peer it lets through replays its
    // old answer (counter 0, a MAC over an old nonce).
    store.set_records(Vec::new());
    world.ap.silence(true);
    assert_eq!(world.open(&store, 10).err(), Some(NO_PEER), "an old head is never taken");
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
fn a_restored_record_changed_in_transit_is_refused() {
    let world = World::new();
    let store = MemoryLogStore::new();
    {
        let mut log = world.open(&store, 15).unwrap();
        save_four(&mut log);
    }
    let whole = store.records();
    store.set_records(whole[..1].to_vec());
    world.ap.silence(true);
    world.eu.set_mode(Mode::TamperFetch);
    assert_eq!(world.open(&store, 16).err(), Some(BAD_RESTORE));
    assert_eq!(store.records(), whole[..1].to_vec(), "no changed record reached the host's store");
    world.eu.set_mode(Mode::Honest);
    assert_eq!(world.open(&store, 17).unwrap().counter(), 4);
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
    texts.extend(world.eu.seen.lock().unwrap().iter().cloned());
    texts.extend(world.ap.seen.lock().unwrap().iter().cloned());
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
    assert_eq!(peer.log_of(US).records(), own_store.records());
    assert!(peer.logs.answer(&master, &append(EU, 1, &record)).is_err(), "its own region");
    assert!(peer.logs.answer(&master, &append("sa-east-1", 1, &record)).is_err(), "a region it keeps no log of");
    assert!(peer.logs.answer(&master, &[2u8, 200, 1, 2]).is_err(), "malformed");
    assert!(peer.logs.answer(&master, &[9u8, 2, b'u', b's']).is_err(), "malformed");
    assert_eq!(peer.logs.origins(), vec![AP.to_string(), US.to_string()]);
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
    assert_eq!(head_counter(&head), 0, "the peer's head of ap-southeast-1 is still empty");
    // And us-east-1's own log there is as it was.
    assert_eq!(world.eu.log_of(US).records(), us_records);

    // Nor onto a log of ap-southeast-1 that has records: its record 1
    // written (and anchored in eu-central-1), us-east-1's record 2 is not
    // taken as its counter 2.
    let ap_store = MemoryLogStore::new();
    let ap_anchor = Anchor::with_random(AP, vec![Peer { region: EU.into(), link: world.eu.link() }], Box::new(Random(41)));
    let mut ap_log =
        JournalLog::open_anchored(&master, Box::new(ap_store.clone()), Box::new(Random(42)), Box::new(ap_anchor)).unwrap();
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
    let ap_anchor = Anchor::with_random(AP, vec![Peer { region: EU.into(), link: world.eu.link() }], Box::new(Random(43)));
    assert!(JournalLog::open_anchored(&master, Box::new(planted.clone()), Box::new(Random(44)), Box::new(ap_anchor)).is_err());
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
