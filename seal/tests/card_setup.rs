//! The card setup against the simulated NTAG 424 DNA: a factory card ends
//! with the Seal's keys and settings and in the registry; every permission
//! is as intended; a card with the wrong keys is refused untouched; a setup
//! cut off at any command is finished by the next run; a second run on a
//! finished card changes nothing.

mod card_support;
mod support;

use ghost_seal::apdu::command;
use ghost_seal::card_keys::{CardUid, card_keys, card_keys_at, key_version};
use ghost_seal::flows::record_file_settings;
use ghost_seal::link::CardLink;
use ghost_seal::record::{KEY_SLOT_BYTES, KEY_SLOT_OFFSET, KeySlot};
use ghost_seal::setup::{FACTORY_KEY, set_up_card};
use ghost_seal::{
    CardRegistry, CardState, CheckRequest, MasterKey, MemoryJournal, MemoryRegistry, PhantomKey, SealError,
};
use card_support::{
    BATCH, DATE, assert_set_up, commands, expected_set_up, request, run_setup, sent_command, snapshot,
};
use support::{DropStyle, SettledCheck, SimCard, TestClock, TestRandom, UID, contains, master, seal_with, sealed_card};

const OTHER_UID: CardUid = CardUid([0x04, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);

fn other_master() -> MasterKey {
    let mut bytes = [0x99u8; 32];
    MasterKey::take(&mut bytes)
}

/// A card set up under another master key.
fn foreign_card() -> SimCard {
    let mut card = SimCard::factory(UID.0);
    let keys = card_keys(&other_master(), &UID);
    for key_no in 0..5u8 {
        card.keys[usize::from(key_no)] = *keys.key(key_no);
        card.versions[usize::from(key_no)] = key_version(0);
    }
    card.settings = record_file_settings();
    card
}

#[test]
fn a_factory_card_ends_with_the_seal_keys_settings_and_a_registry_entry() {
    let mut card = SimCard::factory(UID.0);
    let registry = MemoryRegistry::new();
    let report = run_setup(&mut card, &mut registry.clone(), 1).expect("setup");

    assert!(!report.already_registered);
    assert!(!report.resumed);
    assert_eq!(report.keys_changed, 5);
    assert!(report.settings_changed);
    assert_set_up(&card);
    // The record was zeroed as two 128-byte frames.
    assert_eq!(card.write_lengths, vec![128, 128]);

    let entries = registry.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].uid(), UID);
    assert_eq!(entries[0].set_up_on(), DATE);
    assert_eq!(entries[0].batch(), BATCH);

    // No new key ever crossed the relay in the clear.
    let keys = card_keys(&master(), &UID);
    for key_no in 0..5u8 {
        assert!(!card.transcript.iter().any(|apdu| contains(apdu, keys.key(key_no))));
    }
    // Key 0 is changed last: every other ChangeKey comes before it.
    let changes: Vec<u8> = commands(&card)
        .iter()
        .filter(|apdu| apdu.len() > 5 && apdu[0] == 0x90 && apdu[1] == command::CHANGE_KEY)
        .map(|apdu| apdu[5])
        .collect();
    assert_eq!(changes, vec![1, 2, 3, 4, 0]);
}

#[test]
fn each_new_key_authenticates_and_no_factory_key_does() {
    let mut card = SimCard::factory(UID.0);
    run_setup(&mut card, &mut MemoryRegistry::new(), 2).unwrap();
    let keys = card_keys(&master(), &UID);
    let mut random = TestRandom::new(3);
    let mut link = CardLink::new(&mut card);
    for key_no in 0..5u8 {
        link.select().unwrap();
        let mut session = link.authenticate(key_no, keys.key(key_no), &mut random).expect("the new key");
        assert_eq!(link.card_uid(&mut session).unwrap(), UID.0);
        link.select().unwrap();
        assert_eq!(link.authenticate(key_no, &FACTORY_KEY, &mut random).err(), Some(SealError::UnknownKeys));
        link.select().unwrap();
        assert_eq!(link.key_version(key_no).unwrap(), key_version(0));
    }
}

#[test]
fn every_permission_of_the_record_file_is_as_intended() {
    let mut card = SimCard::factory(UID.0);
    run_setup(&mut card, &mut MemoryRegistry::new(), 4).unwrap();
    let keys = card_keys(&master(), &UID);
    let mut random = TestRandom::new(5);
    let denied = |command: u8| Some(SealError::Chip { command, sw1: 0x91, sw2: 0x9d });

    let mut link = CardLink::new(&mut card);
    let mut session_for = |link: &mut CardLink<'_>, key_no: u8| {
        link.select().unwrap();
        link.authenticate(key_no, keys.key(key_no), &mut random).unwrap()
    };

    // GetFileSettings: Full, Read&Write 2, Change 0, Read 1, Write 2, 256 bytes, no SDM.
    let mut session = session_for(&mut link, 0);
    assert_eq!(link.file_settings(&mut session, 2).unwrap(), vec![0x00, 0x03, 0x20, 0x12, 0x00, 0x01, 0x00]);

    // Key 1 reads, never writes.
    let mut session = session_for(&mut link, 1);
    assert_eq!(link.read_frame(&mut session, 0, 16).unwrap().to_vec(), vec![0u8; 16]);
    let mut session = session_for(&mut link, 1);
    assert_eq!(link.write_frame(&mut session, 0, &[1u8; 16]).err(), denied(command::WRITE_DATA));

    // Key 2 reads and writes.
    let mut session = session_for(&mut link, 2);
    link.write_verified(&mut session, 0, &[0u8; 16]).expect("key 2 writes");

    // Keys 0, 3 and 4 neither read nor write.
    for key_no in [0u8, 3, 4] {
        let mut session = session_for(&mut link, key_no);
        assert_eq!(link.read_frame(&mut session, 0, 16).err(), denied(command::READ_DATA));
        let mut session = session_for(&mut link, key_no);
        assert_eq!(link.write_frame(&mut session, 0, &[1u8; 16]).err(), denied(command::WRITE_DATA));
    }

    // Only key 0 changes the settings.
    for key_no in [1u8, 2, 3, 4] {
        let mut session = session_for(&mut link, key_no);
        assert_eq!(
            link.change_file_settings(&mut session, 2, &[0x00, 0xe0, 0xee]).err(),
            denied(command::CHANGE_FILE_SETTINGS)
        );
    }
    drop(link);
    assert_set_up(&card);
}

#[test]
fn a_set_up_card_checks_empty_with_the_registry_installed() {
    let mut card = SimCard::factory(UID.0);
    let registry = MemoryRegistry::new();
    run_setup(&mut card, &mut registry.clone(), 6).unwrap();
    let journal = MemoryJournal::new();
    let clock = TestClock::new();
    let mut seal = seal_with(&journal, &clock, 7, Box::new(SettledCheck), Box::new(registry));
    let answer = seal.check(&mut card, &CheckRequest { uid: UID, challenge: [3u8; 32] }).expect("check");
    assert_eq!((answer.body.state, answer.body.generation, answer.body.amount_wei), (CardState::Empty, 0, 0));
}

#[test]
fn a_card_with_the_wrong_keys_is_refused_untouched() {
    let mut weird_key0 = SimCard::factory(UID.0);
    weird_key0.keys[0] = [0x11; 16];
    let mut weird_key3 = SimCard::factory(UID.0);
    weird_key3.keys[3] = [0x33; 16];
    let mut opened = SimCard::set_up(UID);
    opened.versions = [key_version(1); 5];
    let mut mixed = SimCard::factory(UID.0);
    mixed.versions[2] = 7;
    let mut half_foreign = SimCard::factory(UID.0);
    half_foreign.keys[1] = *card_keys(&other_master(), &UID).key(1);
    half_foreign.versions[1] = key_version(0);
    let mut next_generation = SimCard::factory(UID.0);
    let next = card_keys_at(&master(), &UID, 1);
    for key_no in 0..5u8 {
        next_generation.keys[usize::from(key_no)] = *next.key(key_no);
        next_generation.versions[usize::from(key_no)] = key_version(1);
    }

    for (name, mut card) in [
        ("factory version, key 0 not the factory key", weird_key0),
        ("factory version, key 3 not the factory key", weird_key3),
        ("another master key", foreign_card()),
        ("keys of a later generation", next_generation),
        ("version 2 under generation 0 keys", opened),
        ("an unknown key version", mixed),
        ("one key the Seal's under another master", half_foreign),
    ] {
        let before = snapshot(&card);
        let registry = MemoryRegistry::new();
        let result = run_setup(&mut card, &mut registry.clone(), 8);
        assert_eq!(result.err(), Some(SealError::UnknownKeys), "{name}");
        assert_eq!(snapshot(&card), before, "{name}: the card changed");
        assert!(card.write_lengths.is_empty(), "{name}");
        assert!(!sent_command(&commands(&card), command::CHANGE_KEY), "{name}");
        assert!(!sent_command(&commands(&card), command::CHANGE_FILE_SETTINGS), "{name}");
        assert!(registry.entries().is_empty(), "{name}: registered");
    }
}

#[test]
fn a_card_answering_for_another_uid_is_refused() {
    let mut card = SimCard::factory(OTHER_UID.0);
    let before = snapshot(&card);
    let registry = MemoryRegistry::new();
    let result = set_up_card(&mut card, &master(), &request(UID), &mut TestRandom::new(9), &mut registry.clone());
    assert_eq!(result.err(), Some(SealError::UnknownKeys));
    assert_eq!(snapshot(&card), before);
    assert!(registry.entries().is_empty());
}

#[test]
fn a_card_holding_a_ghost_record_is_never_wiped() {
    // A Sealed card the registry does not know (a lost registry line).
    let mut sealed = sealed_card(None);
    let before = snapshot(&sealed.card);
    let registry = MemoryRegistry::new();
    let result = run_setup(&mut sealed.card, &mut registry.clone(), 10);
    assert_eq!(result.err(), Some(SealError::WrongState(CardState::Sealed)));
    assert_eq!(snapshot(&sealed.card), before);
    assert!(registry.entries().is_empty());

    // A Fill cut off after its key slot and before its header.
    let mut card = SimCard::set_up(UID);
    let slot = KeySlot { generation: 0, coin: [0x42; 32], key: Some(PhantomKey::new(vec![7u8; 32]).unwrap()) };
    let start = KEY_SLOT_OFFSET as usize;
    card.file[start..start + KEY_SLOT_BYTES].copy_from_slice(&slot.encode(&UID));
    let before = snapshot(&card);
    let result = run_setup(&mut card, &mut registry.clone(), 11);
    assert_eq!(result.err(), Some(SealError::FillPending));
    assert_eq!(snapshot(&card), before);
    assert!(registry.entries().is_empty());
}

#[test]
fn a_card_left_half_set_up_is_finished() {
    // Keys 1 and 2 already the Seal's, the rest and the settings factory.
    let mut card = SimCard::factory(UID.0);
    let keys = card_keys(&master(), &UID);
    for key_no in [1u8, 2] {
        card.keys[usize::from(key_no)] = *keys.key(key_no);
        card.versions[usize::from(key_no)] = key_version(0);
    }
    card.file[..4].copy_from_slice(b"junk");
    let registry = MemoryRegistry::new();
    let report = run_setup(&mut card, &mut registry.clone(), 12).expect("finished");
    assert!(report.resumed);
    assert_eq!(report.keys_changed, 3);
    assert!(report.settings_changed);
    assert_set_up(&card);
    assert_eq!(registry.entries().len(), 1);

    // All keys changed and the settings set, cut before the record was zeroed.
    let mut card = SimCard::set_up(UID);
    card.file[200] = 0x55;
    let registry = MemoryRegistry::new();
    let report = run_setup(&mut card, &mut registry.clone(), 13).expect("finished");
    assert!(report.resumed);
    assert_eq!((report.keys_changed, report.settings_changed), (0, false));
    assert_set_up(&card);
    assert_eq!(registry.entries().len(), 1);
}

#[test]
fn a_setup_cut_at_every_command_is_finished_by_the_next_run() {
    let mut whole = SimCard::factory(UID.0);
    run_setup(&mut whole, &mut MemoryRegistry::new(), 20).unwrap();
    let total = whole.sent;
    assert!(total > 40, "the setup sends {total} commands");

    for style in [DropStyle::BeforeCard, DropStyle::AfterCard] {
        for cut in 0..total {
            let mut card = SimCard::factory(UID.0);
            let registry = MemoryRegistry::new();
            card.drop_from(cut, style);
            let first = run_setup(&mut card, &mut registry.clone(), 21);
            assert_eq!(first.err(), Some(SealError::Dropped), "cut at {cut} {style:?}");
            assert!(registry.entries().is_empty(), "registered before the setup finished (cut at {cut} {style:?})");

            card.reconnect();
            let partly_changed = card.versions.contains(&key_version(0));
            let report = run_setup(&mut card, &mut registry.clone(), 22)
                .unwrap_or_else(|error| panic!("cut at {cut} {style:?}: the second run failed: {error}"));
            assert_eq!(report.resumed, partly_changed, "cut at {cut} {style:?}");
            assert!(!report.already_registered);
            assert_set_up(&card);
            assert_eq!(registry.entries().len(), 1, "cut at {cut} {style:?}");
            assert_eq!(registry.entries()[0].uid(), UID);
        }
    }
}

#[test]
fn a_second_run_on_a_finished_card_changes_nothing() {
    let mut card = SimCard::factory(UID.0);
    let registry = MemoryRegistry::new();
    run_setup(&mut card, &mut registry.clone(), 30).unwrap();
    let before = snapshot(&card);
    let entries = registry.entries();
    card.transcript.clear();
    card.write_lengths.clear();

    let mut later = request(UID);
    later.set_up_on = "2027-01-01".to_owned();
    later.batch = "another-batch".to_owned();
    let report = set_up_card(&mut card, &master(), &later, &mut TestRandom::new(31), &mut registry.clone())
        .expect("verified");
    assert!(report.already_registered);
    assert!(!report.resumed);
    assert_eq!((report.keys_changed, report.settings_changed), (0, false));
    assert_eq!(snapshot(&card), before);
    assert_eq!(registry.entries(), entries);
    let sent = commands(&card);
    for ins in [command::CHANGE_KEY, command::CHANGE_FILE_SETTINGS, command::WRITE_DATA, command::READ_DATA] {
        assert!(!sent_command(&sent, ins), "the second run sent {ins:02X}");
    }
    // It still authenticated with every key.
    let authentications = sent.iter().filter(|apdu| apdu[0] == 0x90 && apdu[1] == command::AUTHENTICATE_EV2_FIRST);
    assert_eq!(authentications.count(), 5);
}

#[test]
fn a_registered_card_in_use_is_verified_and_left_alone() {
    let mut sealed = sealed_card(None);
    let mut registry = MemoryRegistry::new();
    registry.record(&ghost_seal::RegistryEntry::new(UID, DATE, BATCH).unwrap()).unwrap();
    let before = snapshot(&sealed.card);
    let report = run_setup(&mut sealed.card, &mut registry.clone(), 40).expect("verified");
    assert!(report.already_registered);
    assert_eq!(snapshot(&sealed.card), before);

    // A registered card whose keys are not the generation 0 keys any more is
    // refused, and still not touched.
    let mut moved = SimCard::factory(UID.0);
    let next = card_keys_at(&master(), &UID, 1);
    for key_no in 0..5u8 {
        moved.keys[usize::from(key_no)] = *next.key(key_no);
        moved.versions[usize::from(key_no)] = key_version(1);
    }
    let before = snapshot(&moved);
    assert_eq!(run_setup(&mut moved, &mut registry.clone(), 41).err(), Some(SealError::UnknownKeys));
    assert_eq!(snapshot(&moved), before);
}

#[test]
fn a_bad_batch_or_date_is_refused_before_the_card_is_touched() {
    for (date, batch) in [(DATE, ""), (DATE, "two words"), (DATE, "x/../y"), ("2026-13-01", BATCH), ("06-11-2026", BATCH)] {
        let mut card = SimCard::factory(UID.0);
        let mut bad = request(UID);
        bad.set_up_on = date.to_owned();
        bad.batch = batch.to_owned();
        let registry = MemoryRegistry::new();
        let result = set_up_card(&mut card, &master(), &bad, &mut TestRandom::new(50), &mut registry.clone());
        assert!(matches!(result, Err(SealError::Registry(_))), "{date} {batch:?}");
        assert_eq!(card.sent, 0);
        assert_eq!(snapshot(&card), expected_factory());
    }
}

fn expected_factory() -> card_support::CardSnapshot {
    snapshot(&SimCard::factory(UID.0))
}

#[test]
fn the_expected_state_is_not_the_factory_state() {
    // Guards the helpers: a factory card is not what a setup leaves.
    assert_ne!(expected_set_up(UID, &master()), expected_factory());
}
