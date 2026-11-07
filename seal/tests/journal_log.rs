//! The journal's append-only sealed log over a store the test can corrupt
//! (a dishonest host): a restart gives back the same entries, a Fill whose
//! answer was lost hands back the same coin after a reopen, every kind of
//! tampering is refused at open, a store that rolls back while the log runs
//! is refused for good, a failed append fails the save and leaves the card
//! unchanged, and the store never holds a UID, an entry kind, commit data,
//! a coin, a key or an amount in clear.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ghost_seal::journal_log::{HOST_JOURNAL_LABEL, JournalLog, LogStore, MAX_RECORD_BYTES, MemoryLogStore, SharedLog};
use ghost_seal::primitives::sha3_256;
use ghost_seal::{
    CardState, CardUid, CheckRequest, EntryKind, FillRequest, Journal, MasterKey, OpenRequest, Seal, SealConfig,
    SealError, SealRandom,
};
use support::{AMOUNT, MEASUREMENT, SettledCheck, SimCard, StubChain, StubMaker, TestClock, TestRandom, UID, contains};

const OTHER: CardUid = CardUid([0x04, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);

/// A deterministic random source a log can hold (test only).
struct LogRandom(u64);

impl SealRandom for LogRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), SealError> {
        for chunk in out.chunks_mut(32) {
            self.0 += 1;
            chunk.copy_from_slice(&sha3_256(&[b"journal log test random", &self.0.to_be_bytes()])[..chunk.len()]);
        }
        Ok(())
    }
}

fn other_master() -> MasterKey {
    let mut bytes = [0x77u8; 32];
    MasterKey::take(&mut bytes)
}

fn open_with(master: &MasterKey, store: &MemoryLogStore) -> Result<JournalLog, SealError> {
    JournalLog::open_with(master, Box::new(store.clone()), Box::new(LogRandom(1000)))
}

fn open(store: &MemoryLogStore) -> Result<JournalLog, SealError> {
    open_with(&support::master(), store)
}

fn refused(result: Result<JournalLog, SealError>) -> bool {
    matches!(result, Err(SealError::Journal(_)))
}

/// A store holding four saves: two cards, both kinds, one entry replaced.
fn four_records() -> (MemoryLogStore, Vec<(CardUid, EntryKind, Vec<u8>)>) {
    four_records_with(1)
}

/// [`four_records`], its IVs from random source `seed`: another seed is
/// another log of the same entries under the same M.
fn four_records_with(seed: u64) -> (MemoryLogStore, Vec<(CardUid, EntryKind, Vec<u8>)>) {
    let store = MemoryLogStore::new();
    let mut log =
        JournalLog::open_with(&support::master(), Box::new(store.clone()), Box::new(LogRandom(seed << 32))).unwrap();
    let saves = vec![
        (UID, EntryKind::Fill, b"first fill entry".to_vec()),
        (UID, EntryKind::Open, b"an open entry".to_vec()),
        (OTHER, EntryKind::Fill, b"another card's fill".to_vec()),
        (UID, EntryKind::Fill, b"the fill entry replaced".to_vec()),
    ];
    for (uid, kind, sealed) in &saves {
        log.save(uid, *kind, sealed.clone()).unwrap();
    }
    (store, saves)
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

fn fill_request() -> FillRequest {
    FillRequest { uid: UID, challenge: [0x0f; 32], amount_wei: AMOUNT, pin: None }
}

#[test]
fn save_then_reopen_gives_the_same_entries() {
    let (store, _) = four_records();
    // Counters 1 to 4, one per save, nothing else.
    assert_eq!(store.records().iter().map(|(counter, _)| *counter).collect::<Vec<_>>(), vec![1, 2, 3, 4]);
    for (_, record) in store.records() {
        assert!(record.len() <= MAX_RECORD_BYTES);
    }

    // A restart: the log read back from the store alone.
    let log = open(&store).expect("the log verifies");
    assert_eq!(log.counter(), 4);
    assert_eq!(log.load(&UID, EntryKind::Fill), Some(b"the fill entry replaced".to_vec()));
    assert_eq!(log.load(&UID, EntryKind::Open), Some(b"an open entry".to_vec()));
    assert_eq!(log.load(&OTHER, EntryKind::Fill), Some(b"another card's fill".to_vec()));
    assert_eq!(log.load(&OTHER, EntryKind::Open), None);

    // A save after the restart goes on at counter 5, and the next restart
    // sees it.
    let mut log = log;
    log.save(&OTHER, EntryKind::Open, b"opened after the restart".to_vec()).unwrap();
    assert_eq!(store.records().last().unwrap().0, 5);
    let again = open(&store).unwrap();
    assert_eq!(again.load(&OTHER, EntryKind::Open), Some(b"opened after the restart".to_vec()));
    assert_eq!(again.counter(), 5);
}

#[test]
fn an_empty_store_opens_empty_and_numbers_from_one() {
    let store = MemoryLogStore::new();
    let mut log = open(&store).unwrap();
    assert_eq!((log.counter(), log.load(&UID, EntryKind::Fill)), (0, None));
    log.save(&UID, EntryKind::Fill, b"entry".to_vec()).unwrap();
    assert_eq!(store.records()[0].0, 1);
}

#[test]
fn load_answers_from_the_verified_log_never_from_the_store() {
    let (store, _) = four_records();
    let log = open(&store).unwrap();
    // The host empties its store: the running log still answers what it
    // verified and wrote.
    store.set_records(Vec::new());
    assert_eq!(log.load(&UID, EntryKind::Open), Some(b"an open entry".to_vec()));
}

#[test]
fn a_fill_whose_answer_was_lost_hands_back_the_same_coin_after_a_reopen() {
    let store = MemoryLogStore::new();
    let clock = TestClock::new();
    let mut maker = StubMaker::default();
    let mut card = SimCard::set_up(UID);
    let first = {
        let log = open(&store).unwrap();
        let mut seal = seal_on(&log, &clock, 1);
        seal.fill(&mut card, &fill_request(), &mut maker).expect("fill")
        // The answer never reached the phone; the Seal stops here.
    };

    // A restart: a new log from the store, a new Seal.
    let log = open(&store).unwrap();
    let mut seal = seal_on(&log, &clock, 2);
    let again = seal.fill(&mut card, &fill_request(), &mut maker).expect("the Fill asked again");
    assert_eq!(again.commit_data, first.commit_data, "the same coin");
    assert_eq!(maker.made.borrow().len(), 1, "no new key was made");

    // Paid, it is Sealed; after one more restart the Check finds its Fill
    // entry and answers Sealed.
    let chain = StubChain::default();
    chain.pay(&first.commit_data, AMOUNT);
    let sealed = seal.confirm_fill(&mut card, &CheckRequest { uid: UID, challenge: [3; 32] }, &chain).unwrap();
    assert_eq!(sealed.body.state, CardState::Sealed);
    let log = open(&store).unwrap();
    let mut seal = seal_on(&log, &clock, 3);
    let checked = seal.check(&mut card, &CheckRequest { uid: UID, challenge: [4; 32] }).unwrap();
    assert_eq!((checked.body.state, checked.body.amount_wei), (CardState::Sealed, AMOUNT));
}

#[test]
fn an_open_begun_before_a_restart_is_finished_after_it_with_the_same_key() {
    let store = MemoryLogStore::new();
    let clock = TestClock::new();
    let mut maker = StubMaker::default();
    let mut card = SimCard::set_up(UID);
    let log = open(&store).unwrap();
    let mut seal = seal_on(&log, &clock, 1);
    let filled = seal.fill(&mut card, &fill_request(), &mut maker).unwrap();
    let chain = StubChain::default();
    chain.pay(&filled.commit_data, AMOUNT);
    seal.confirm_fill(&mut card, &CheckRequest { uid: UID, challenge: [3; 32] }, &chain).unwrap();

    // The Open is cut off at the first command after it was journaled.
    let phone = support::phone(0x61);
    let request = OpenRequest { uid: UID, challenge: [5; 32], phone_key: phone.public_key(), pin: None };
    let mut step = 0;
    loop {
        card.drop_from(step, support::DropStyle::AfterCard);
        let cut = seal.open(&mut card, &request);
        card.reconnect();
        assert_eq!(cut.err(), Some(SealError::Dropped), "step {step}");
        if log.load(&UID, EntryKind::Open).is_some() {
            break;
        }
        step += 1;
        assert!(step < 64, "the Open was never journaled");
    }
    drop((seal, log));

    let log = open(&store).unwrap();
    assert!(log.load(&UID, EntryKind::Open).is_some(), "the Open survived the restart");
    let mut seal = seal_on(&log, &clock, 2);
    let opened = seal.open(&mut card, &request).expect("finished after the restart");
    assert_eq!(phone.open(&opened.release, &UID, 1).unwrap().expose_secret(), &maker.key_for(&filled.commit_data)[..]);
}

#[test]
fn every_kind_of_tampering_is_refused_at_open() {
    let (store, _) = four_records();
    let good = store.records();
    assert!(open(&store).is_ok());
    let with = |records: Vec<(u64, Vec<u8>)>| {
        let tampered = MemoryLogStore::new();
        tampered.set_records(records);
        open(&tampered)
    };

    // A repeated record.
    let mut repeated = good.clone();
    repeated.insert(2, good[1].clone());
    assert!(refused(with(repeated)), "a repeat");
    // A dropped record, in the middle.
    let mut dropped = good.clone();
    dropped.remove(1);
    assert!(refused(with(dropped.clone())), "a gap");
    // The same, renumbered so the counters run on.
    let renumbered: Vec<_> = dropped.iter().enumerate().map(|(i, (_, r))| (i as u64 + 1, r.clone())).collect();
    assert!(refused(with(renumbered)), "a drop hidden by renumbering");
    // Two records swapped, with their counters and without.
    let mut swapped = good.clone();
    swapped.swap(1, 2);
    assert!(refused(with(swapped)), "a reorder");
    let mut swapped_bytes = good.clone();
    let (a, b) = (good[1].1.clone(), good[2].1.clone());
    swapped_bytes[1].1 = b;
    swapped_bytes[2].1 = a;
    assert!(refused(with(swapped_bytes)), "a reorder under the same counters");
    // A changed counter.
    let mut counter = good.clone();
    counter[3].0 = 9;
    assert!(refused(with(counter)), "a changed counter");
    // A changed ciphertext byte, in the middle and in the last record.
    for at in [1, 3] {
        let mut ciphertext = good.clone();
        ciphertext[at].1[20] ^= 0x01;
        assert!(refused(with(ciphertext)), "a changed ciphertext in record {}", at + 1);
    }
    // A changed IV.
    let mut iv = good.clone();
    iv[2].1[0] ^= 0x80;
    assert!(refused(with(iv)), "a changed IV");
    // A changed tag, in the middle and at the end.
    for at in [1, 3] {
        let mut tag = good.clone();
        let last = tag[at].1.len() - 1;
        tag[at].1[last] ^= 0x01;
        assert!(refused(with(tag)), "a changed tag in record {}", at + 1);
    }
    // A record cut short, or not whole blocks.
    let mut short = good.clone();
    short[2].1.truncate(40);
    assert!(refused(with(short)), "a record too short");
    let mut ragged = good.clone();
    ragged[2].1.pop();
    assert!(refused(with(ragged)), "a record of the wrong length");

    // A record from another log under the same M, at the same counter.
    let (other_store, _) = four_records_with(2);
    let other = other_store.records();
    assert_ne!(other[1].1, good[1].1, "fresh IVs make another log");
    let mut foreign = good.clone();
    foreign[1] = other[1].clone();
    assert!(refused(with(foreign)), "a record from another log");
    // Another log's first record in front of this one's.
    let mut spliced = vec![other[0].clone()];
    spliced.extend(good[1..].iter().cloned());
    assert!(refused(with(spliced)), "a first record from another log");

    // Another M.
    assert!(refused(open_with(&other_master(), &store)), "another M");
}

#[test]
fn a_record_that_does_not_decode_is_refused_even_with_a_good_tag() {
    // A record sealed under the right keys but holding no entry kind it knows:
    // made with the log's own layout (the test knows the label).
    use ghost_seal::primitives::{aes256_cbc_encrypt, hkdf_sha3_256, hmac_sha3_256, pad};
    // The test M's bytes (its fixed pattern).
    let master_bytes: Vec<u8> = (0..32u8).map(|i| 0x40 + i).collect();
    let mut okm = [0u8; 64];
    hkdf_sha3_256(HOST_JOURNAL_LABEL, &master_bytes, &[HOST_JOURNAL_LABEL], &mut okm);
    let enc: [u8; 32] = okm[..32].try_into().unwrap();
    let mac = &okm[32..];
    let make = |plain: &[u8]| {
        let iv = [0x24u8; 16];
        let mut record = iv.to_vec();
        record.extend(aes256_cbc_encrypt(&enc, &iv, &pad(plain)).unwrap());
        // A log anchored nowhere: its origin is empty (length 0).
        let tag = hmac_sha3_256(mac, &[HOST_JOURNAL_LABEL, &[0u8], &1u64.to_be_bytes(), &[0u8; 32], &record]);
        record.extend_from_slice(&tag);
        record
    };
    let store = MemoryLogStore::new();
    // A good one opens: the test's layout is the log's.
    let good = make(&[&[2u8][..], &UID.0, b"entry"].concat());
    store.set_records(vec![(1, good)]);
    assert_eq!(open(&store).unwrap().load(&UID, EntryKind::Fill), Some(b"entry".to_vec()));
    // An unknown kind, and no entry after the UID.
    for plain in [[&[9u8][..], &UID.0, b"entry"].concat(), [&[1u8][..], &UID.0].concat()] {
        store.set_records(vec![(1, make(&plain))]);
        assert!(refused(open(&store)));
    }
}

#[test]
fn a_store_that_later_returns_a_shorter_or_different_log_is_refused() {
    // Shorter: the host cuts the tail while the log runs.
    let (store, _) = four_records();
    let mut log = open(&store).unwrap();
    log.save(&OTHER, EntryKind::Open, b"fifth".to_vec()).unwrap();
    assert!(log.check_store().is_ok());
    let full = store.records();
    store.set_records(full[..4].to_vec());
    assert!(matches!(log.check_store(), Err(SealError::Journal(_))));
    assert!(log.refused());
    assert!(matches!(log.save(&UID, EntryKind::Fill, b"sixth".to_vec()), Err(SealError::Journal(_))));
    // Refused for good, even once the host puts the records back.
    store.set_records(full.clone());
    assert!(log.check_store().is_err());
    assert!(log.save(&UID, EntryKind::Fill, b"sixth".to_vec()).is_err());
    assert_eq!(store.records().len(), 5, "nothing more was appended");

    // Different: the last record swapped for another log's (same M, same
    // counter).
    let (store, _) = four_records();
    let log = open(&store).unwrap();
    let (other, _) = four_records_with(2);
    let mut changed = store.records();
    changed[3] = other.records()[3].clone();
    store.set_records(changed);
    assert!(log.check_store().is_err());

    // Longer: a record the log never wrote.
    let (store, _) = four_records();
    let log = open(&store).unwrap();
    let mut longer = store.records();
    longer.push((5, other.records()[0].1.clone()));
    store.set_records(longer);
    assert!(log.check_store().is_err());

    // The whole store replaced by another valid log of the same length.
    let (store, _) = four_records();
    let log = open(&store).unwrap();
    store.set_records(other.records());
    assert!(log.check_store().is_err());
}

#[test]
fn a_store_that_fails_the_append_fails_the_save_and_an_open_leaves_the_card_unchanged() {
    let store = MemoryLogStore::new();
    let clock = TestClock::new();
    let mut maker = StubMaker::default();
    let mut card = SimCard::set_up(UID);
    let log = open(&store).unwrap();
    let mut seal = seal_on(&log, &clock, 1);
    let filled = seal.fill(&mut card, &fill_request(), &mut maker).unwrap();
    let chain = StubChain::default();
    chain.pay(&filled.commit_data, AMOUNT);
    seal.confirm_fill(&mut card, &CheckRequest { uid: UID, challenge: [3; 32] }, &chain).unwrap();
    let records = store.records().len();

    // The store stops taking records: a save fails, and the map is not
    // changed.
    store.fail_appends(true);
    let mut direct = log.clone();
    assert!(matches!(direct.save(&OTHER, EntryKind::Fill, b"x".to_vec()), Err(SealError::Journal(_))));
    assert_eq!(log.load(&OTHER, EntryKind::Fill), None);

    // A full Open: refused before the card changes.
    let (file, keys, versions) = (card.file.clone(), card.keys, card.versions);
    let phone = support::phone(0x62);
    let request = OpenRequest { uid: UID, challenge: [6; 32], phone_key: phone.public_key(), pin: None };
    assert!(matches!(seal.open(&mut card, &request), Err(SealError::Journal(_))));
    assert_eq!((card.file.clone(), card.keys, card.versions), (file, keys, versions), "the card is unchanged");
    assert_eq!(log.load(&UID, EntryKind::Open), None);
    assert_eq!(store.records().len(), records);
    let checked = seal.check(&mut card, &CheckRequest { uid: UID, challenge: [7; 32] }).unwrap();
    assert_eq!(checked.body.state, CardState::Sealed);

    // The store recovers: the Open goes through on the next counter.
    store.fail_appends(false);
    let opened = seal.open(&mut card, &request).expect("the Open after the store recovered");
    assert_eq!(phone.open(&opened.release, &UID, 1).unwrap().expose_secret(), &maker.key_for(&filled.commit_data)[..]);
    let counters: Vec<u64> = store.records().iter().map(|(c, _)| *c).collect();
    assert_eq!(counters, (1..=counters.len() as u64).collect::<Vec<_>>());
    assert!(open(&store).is_ok());
}

/// A store that keeps each append but loses its answer while `lose` is set.
struct LosesAnswers {
    inner: MemoryLogStore,
    lose: Arc<AtomicBool>,
}

impl LogStore for LosesAnswers {
    fn append(&mut self, counter: u64, record: &[u8]) -> Result<(), SealError> {
        self.inner.append(counter, record)?;
        if self.lose.load(Ordering::SeqCst) { Err(SealError::Journal("no answer")) } else { Ok(()) }
    }

    fn read_all(&mut self) -> Result<Vec<(u64, Vec<u8>)>, SealError> {
        self.inner.read_all()
    }
}

#[test]
fn an_append_kept_whose_answer_was_lost_is_taken_at_the_next_save() {
    let store = MemoryLogStore::new();
    let lose = Arc::new(AtomicBool::new(true));
    let backing = LosesAnswers { inner: store.clone(), lose: Arc::clone(&lose) };
    let mut log = JournalLog::open_with(&support::master(), Box::new(backing), Box::new(LogRandom(5))).unwrap();
    assert!(log.save(&UID, EntryKind::Fill, b"kept, answer lost".to_vec()).is_err());
    assert_eq!(log.load(&UID, EntryKind::Fill), None, "not taken while unanswered");
    lose.store(false, Ordering::SeqCst);
    log.save(&OTHER, EntryKind::Fill, b"next".to_vec()).expect("the next save settles the first");
    assert_eq!(log.load(&UID, EntryKind::Fill), Some(b"kept, answer lost".to_vec()));
    assert_eq!(store.records().iter().map(|(c, _)| *c).collect::<Vec<_>>(), vec![1, 2]);
    let reopened = open(&store).unwrap();
    assert_eq!(reopened.load(&OTHER, EntryKind::Fill), Some(b"next".to_vec()));
}

#[test]
fn an_entry_too_large_for_a_record_is_refused_and_nothing_is_appended() {
    let store = MemoryLogStore::new();
    let mut log = open(&store).unwrap();
    assert!(matches!(log.save(&UID, EntryKind::Open, vec![0x55; MAX_RECORD_BYTES]), Err(SealError::Journal(_))));
    assert!(store.records().is_empty());
    log.save(&UID, EntryKind::Open, vec![0x55; 3000]).unwrap();
    assert_eq!(store.records().len(), 1);
}

#[test]
fn the_shared_log_opens_once_hands_out_one_log_and_refuses_another_m() {
    let (store, _) = four_records();
    let shared = SharedLog::with_random(Box::new(store.clone()), Box::new(LogRandom(9)));
    assert!(!shared.is_open());
    let mut first = shared.journal(&support::master()).unwrap();
    assert!(shared.is_open());
    let second = shared.journal(&support::master()).unwrap();
    first.save(&OTHER, EntryKind::Open, b"through the first handle".to_vec()).unwrap();
    assert_eq!(second.load(&OTHER, EntryKind::Open), Some(b"through the first handle".to_vec()));
    assert_eq!(second.counter(), 5, "one log, one counter");
    assert!(matches!(shared.journal(&other_master()), Err(SealError::Journal(_))));

    // A later handout reads the store again and refuses a rollback.
    store.set_records(store.records()[..4].to_vec());
    assert!(shared.journal(&support::master()).is_err());
    assert!(first.refused());
}

#[test]
fn a_shared_log_that_fails_to_open_is_tried_again() {
    let (store, _) = four_records();
    let good = store.records();
    let mut bad = good.clone();
    bad[2].1[30] ^= 0x04;
    store.set_records(bad);
    let shared = SharedLog::new(Box::new(store.clone()));
    assert!(shared.journal(&support::master()).is_err());
    assert!(!shared.is_open());
    // A store that cannot be read is refused too, and tried again.
    store.fail_reads(true);
    assert!(shared.journal(&support::master()).is_err(), "a store that cannot be read");
    store.fail_reads(false);
    store.set_records(good);
    let log = shared.journal(&support::master()).expect("opens once the store is sound");
    assert_eq!(log.counter(), 4);
}

#[test]
fn the_store_holds_no_uid_kind_commit_data_coin_key_or_amount() {
    let store = MemoryLogStore::new();
    let clock = TestClock::new();
    let mut maker = StubMaker::default();
    let mut card = SimCard::set_up(UID);
    let log = open(&store).unwrap();
    let mut seal = seal_on(&log, &clock, 1);
    let filled = seal.fill(&mut card, &FillRequest { pin: Some(ghost_seal::Pin::new("4831").unwrap()), ..fill_request() }, &mut maker).unwrap();
    let chain = StubChain::default();
    chain.pay(&filled.commit_data, AMOUNT);
    seal.confirm_fill(&mut card, &CheckRequest { uid: UID, challenge: [3; 32] }, &chain).unwrap();
    let phone = support::phone(0x63);
    let opened = seal
        .open(
            &mut card,
            &OpenRequest {
                uid: UID,
                challenge: [8; 32],
                phone_key: phone.public_key(),
                pin: Some(ghost_seal::Pin::new("4831").unwrap()),
            },
        )
        .unwrap();
    let key = maker.key_for(&filled.commit_data);
    assert_eq!(phone.open(&opened.release, &UID, 1).unwrap().expose_secret(), &key[..]);
    assert!(store.records().len() >= 3);

    let bytes = store.bytes();
    let coin = sha3_256(&[&filled.commit_data]);
    let master_bytes: Vec<u8> = (0..32u8).map(|i| 0x40 + i).collect();
    let mut secrets: Vec<(&str, Vec<u8>)> = vec![
        ("the UID", UID.0.to_vec()),
        ("the Open kind next to the UID", [&[EntryKind::Open as u8][..], &UID.0].concat()),
        ("the Fill kind next to the UID", [&[EntryKind::Fill as u8][..], &UID.0].concat()),
        ("the commit data", filled.commit_data[..32].to_vec()),
        ("the coin", coin.to_vec()),
        ("the Phantom Key", key.clone()),
        ("the amount", AMOUNT.to_be_bytes().to_vec()),
        ("the phone key", phone.public_key()[..32].to_vec()),
        ("M", master_bytes),
        ("the PIN", b"4831".to_vec()),
    ];
    // Nor the Seal's own sealed entries: each is sealed again for the store.
    for kind in [EntryKind::Fill, EntryKind::Open] {
        let sealed = log.load(&UID, kind).expect("an entry");
        secrets.push(("a sealed entry", sealed[..32].to_vec()));
    }
    for (what, secret) in &secrets {
        assert!(!contains(&bytes, secret), "the store holds {what}");
    }
}
