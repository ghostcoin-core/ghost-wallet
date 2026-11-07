//! The card registry: every Seal is built with one and refuses an
//! unregistered UID ("Not a Ghost card") before it sends the card anything,
//! and lets a registered card through; the file registry reads back what it
//! wrote and ignores torn lines.

mod card_support;
mod support;

use ghost_seal::card_keys::CardUid;
use ghost_seal::registry::date_of_unix;
use ghost_seal::{
    CardRegistry, CardState, CheckRequest, FileRegistry, FillRequest, MemoryJournal, MemoryRegistry, OpenRequest,
    RegistryEntry, SealError,
};
use card_support::{BATCH, DATE, assert_set_up, run_setup, temp_registry};
use support::{AMOUNT, SettledCheck, SimCard, StubChain, StubMaker, TestClock, UID, phone, seal, seal_with, sealed_card};

const OTHER_UID: CardUid = CardUid([0x04, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);

fn registered(uids: &[CardUid]) -> MemoryRegistry {
    let mut registry = MemoryRegistry::new();
    for uid in uids {
        registry.record(&RegistryEntry::new(*uid, DATE, BATCH).unwrap()).unwrap();
    }
    registry
}

#[test]
fn check_refuses_an_unregistered_uid_before_sending_the_card_anything() {
    let mut card = SimCard::set_up(UID);
    let journal = MemoryJournal::new();
    let clock = TestClock::new();
    let mut s = seal_with(&journal, &clock, 1, Box::new(SettledCheck), Box::new(registered(&[OTHER_UID])));
    let error = s.check(&mut card, &CheckRequest { uid: UID, challenge: [1u8; 32] }).unwrap_err();
    assert_eq!(error, SealError::NotAGhostCard);
    assert_eq!(error.to_string(), "Not a Ghost card");
    assert_eq!(card.sent, 0);
    assert!(card.transcript.is_empty());
}

#[test]
fn fill_confirm_and_open_refuse_an_unregistered_uid_before_sending_anything() {
    let mut sealed = sealed_card(None);
    let sent_before = sealed.card.sent;
    let mut s =
        seal_with(&sealed.journal, &sealed.clock, 2, Box::new(SettledCheck), Box::new(MemoryRegistry::new()));

    let mut blank = SimCard::set_up(UID);
    let fill = FillRequest { uid: UID, challenge: [2u8; 32], amount_wei: AMOUNT, pin: None };
    assert_eq!(s.fill(&mut blank, &fill, &mut StubMaker::default()).err(), Some(SealError::NotAGhostCard));
    assert_eq!(blank.sent, 0);

    let confirm = CheckRequest { uid: UID, challenge: [3u8; 32] };
    assert_eq!(
        s.confirm_fill(&mut sealed.card, &confirm, &StubChain::default()).err(),
        Some(SealError::NotAGhostCard)
    );
    let open = OpenRequest { uid: UID, challenge: [4u8; 32], phone_key: phone(9).public_key(), pin: None };
    assert_eq!(s.open(&mut sealed.card, &open).err().map(|e| e.to_string()), Some("Not a Ghost card".to_owned()));
    assert_eq!(sealed.card.sent, sent_before);
    assert!(sealed.card.transcript.is_empty());
    assert!(!sealed.journal.has_open(&UID));
}

#[test]
fn a_registered_card_passes() {
    let sealed = sealed_card(None);
    let mut card = sealed.card;
    let mut s = seal_with(&sealed.journal, &sealed.clock, 3, Box::new(SettledCheck), Box::new(registered(&[UID])));
    let answer = s.check(&mut card, &CheckRequest { uid: UID, challenge: [5u8; 32] }).expect("check");
    assert_eq!(answer.body.state, CardState::Sealed);
    assert_eq!(answer.body.amount_wei, AMOUNT);
}

#[test]
fn an_empty_registry_refuses_every_card_and_the_test_seal_holds_only_its_card() {
    // There is no Seal without a registry: an empty one serves no card.
    let mut card = SimCard::set_up(UID);
    let journal = MemoryJournal::new();
    let clock = TestClock::new();
    let mut empty = seal_with(&journal, &clock, 4, Box::new(SettledCheck), Box::new(MemoryRegistry::new()));
    assert_eq!(empty.check(&mut card, &CheckRequest { uid: UID, challenge: [6u8; 32] }).err(), Some(SealError::NotAGhostCard));
    assert_eq!(card.sent, 0);

    // The tests' Seal registers its one card and no other.
    let answer = seal(&journal, &clock, 4).check(&mut card, &CheckRequest { uid: UID, challenge: [6u8; 32] });
    assert_eq!(answer.expect("check").body.state, CardState::Empty);
    let mut other = SimCard::set_up(OTHER_UID);
    let refused = seal(&journal, &clock, 4).check(&mut other, &CheckRequest { uid: OTHER_UID, challenge: [6u8; 32] });
    assert_eq!(refused.err(), Some(SealError::NotAGhostCard));
    assert_eq!(other.sent, 0);
}

#[test]
fn a_card_set_up_into_a_file_registry_checks_after_the_seal_reopens_it() {
    let path = temp_registry("setup-then-check");
    let mut card = SimCard::factory(UID.0);
    {
        let mut registry = FileRegistry::open(&path).unwrap();
        run_setup(&mut card, &mut registry, 5).expect("setup");
    }
    assert_set_up(&card);

    let journal = MemoryJournal::new();
    let clock = TestClock::new();
    let mut s =
        seal_with(&journal, &clock, 6, Box::new(SettledCheck), Box::new(FileRegistry::open(&path).unwrap()));
    let answer = s.check(&mut card, &CheckRequest { uid: UID, challenge: [7u8; 32] }).expect("check");
    assert_eq!(answer.body.state, CardState::Empty);

    let mut other = SimCard::set_up(OTHER_UID);
    let error = s.check(&mut other, &CheckRequest { uid: OTHER_UID, challenge: [8u8; 32] }).unwrap_err();
    assert_eq!(error, SealError::NotAGhostCard);
    assert_eq!(other.sent, 0);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_file_registry_reads_back_what_it_wrote() {
    let path = temp_registry("round-trip");
    let entries = [
        RegistryEntry::new(UID, "2026-11-06", "mac-studio-1").unwrap(),
        RegistryEntry::new(OTHER_UID, "2026-11-07", "maker_lot.7").unwrap(),
    ];
    {
        let mut registry = FileRegistry::open(&path).unwrap();
        assert!(registry.entries().is_empty());
        for entry in &entries {
            registry.record(entry).unwrap();
        }
        // A UID already registered keeps its first entry and is not appended again.
        registry.record(&RegistryEntry::new(UID, "2027-01-01", "later").unwrap()).unwrap();
    }
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().count(), 2);
    assert!(text.ends_with('\n'));
    assert!(text.starts_with("04518dfaa96180 2026-11-06 mac-studio-1 "));

    let registry = FileRegistry::open(&path).unwrap();
    assert_eq!(registry.lookup(&UID), Some(entries[0].clone()));
    assert_eq!(registry.lookup(&OTHER_UID), Some(entries[1].clone()));
    assert!(!registry.contains(&CardUid([0u8; 7])));
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|e| e.uid());
    assert_eq!(registry.entries(), sorted);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_file_registry_ignores_torn_and_damaged_lines() {
    let path = temp_registry("torn");
    let first = RegistryEntry::new(UID, DATE, BATCH).unwrap();
    let torn = RegistryEntry::new(OTHER_UID, DATE, BATCH).unwrap().to_line();
    let damaged = RegistryEntry::new(CardUid([0x04, 1, 2, 3, 4, 5, 6]), DATE, BATCH).unwrap().to_line().replace(BATCH, "test-batch-2");
    let text = format!("{}{}\n{}", first.to_line(), damaged.trim_end(), &torn[..torn.len() - 3]);
    std::fs::write(&path, &text).unwrap();

    let mut registry = FileRegistry::open(&path).unwrap();
    assert_eq!(registry.entries(), vec![first.clone()]);
    assert!(!registry.contains(&OTHER_UID));

    // The next entry starts a line of its own after the torn one, and reads back.
    let next = RegistryEntry::new(CardUid([0x04, 9, 9, 9, 9, 9, 9]), "2026-11-08", "next").unwrap();
    registry.record(&next).unwrap();
    let reopened = FileRegistry::open(&path).unwrap();
    assert_eq!(reopened.lookup(&next.uid()), Some(next.clone()));
    assert_eq!(reopened.lookup(&UID), Some(first));
    assert!(!reopened.contains(&OTHER_UID));
    assert_eq!(reopened.entries().len(), 2);

    // A torn tail alone (no newline at all) is an empty registry.
    let lone = temp_registry("lone");
    std::fs::write(&lone, &torn[..torn.len() - 1]).unwrap();
    assert!(FileRegistry::open(&lone).unwrap().entries().is_empty());
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&lone);
}

#[test]
fn a_missing_registry_file_is_empty_and_created_by_the_first_record() {
    let path = temp_registry("missing");
    let mut registry = FileRegistry::open(&path).unwrap();
    assert!(registry.entries().is_empty());
    assert!(!path.exists());
    registry.record(&RegistryEntry::new(UID, DATE, BATCH).unwrap()).unwrap();
    assert!(path.exists());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn entries_hold_a_valid_date_and_batch_only() {
    assert!(RegistryEntry::new(UID, "2026-02-30x", BATCH).is_err());
    assert!(RegistryEntry::new(UID, "2026-00-10", BATCH).is_err());
    assert!(RegistryEntry::new(UID, DATE, "a b").is_err());
    assert!(RegistryEntry::new(UID, DATE, &"b".repeat(33)).is_err());
    assert!(RegistryEntry::new(UID, DATE, &"b".repeat(32)).is_ok());
    assert_eq!(RegistryEntry::from_line(""), None);
    let line = RegistryEntry::new(UID, DATE, BATCH).unwrap().to_line();
    assert_eq!(RegistryEntry::from_line(line.trim_end()), Some(RegistryEntry::new(UID, DATE, BATCH).unwrap()));
}

#[test]
fn set_up_dates_are_utc_calendar_dates() {
    assert_eq!(date_of_unix(0), "1970-01-01");
    assert_eq!(date_of_unix(951_782_400), "2000-02-29");
    assert_eq!(date_of_unix(1_800_000_000), "2027-01-15");
    assert_eq!(date_of_unix(1_798_761_599), "2026-12-31");
}
