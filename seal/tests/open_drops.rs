//! An Open cut off at every step: by a connection that drops before the card
//! runs a command, and by one that drops after the card ran it but before its
//! answer came back. After each cut the Seal restarts (a new Seal on the
//! same journal), a Check never answers Sealed once the Open began, and the
//! Open run again releases the very key that was filled: no money is lost.

mod support;

use ghost_seal::card_keys::{card_keys_at, key_version};
use ghost_seal::{CardState, CheckRequest, OpenRequest, Pin, SealError};
use support::{DropStyle, SealedCard, UID, contains, phone, seal, sealed_card};

fn open_request(phone_key: Vec<u8>, pin: Option<&str>) -> OpenRequest {
    OpenRequest { uid: UID, challenge: [0x51; 32], phone_key, pin: pin.map(|p| Pin::new(p).unwrap()) }
}

/// Runs an Open on a fresh sealed card, cut at command `step`; returns
/// whether that first try finished (the cut came after its last command).
fn cut_at(step: usize, style: DropStyle, pin: Option<&str>) -> bool {
    let SealedCard { mut card, journal, clock, maker, commit_data, amount_wei } = sealed_card(pin);
    let key = maker.key_for(&commit_data);
    let phone = phone(0x61);

    card.drop_from(step, style);
    let first = seal(&journal, &clock, 100).open(&mut card, &open_request(phone.public_key(), pin));
    card.reconnect();
    let finished = match &first {
        Ok(_) => true,
        Err(SealError::Dropped) => false,
        Err(other) => panic!("step {step} {style:?}: {other:?}"),
    };
    let began = journal.has_open(&UID);

    // After the cut, a restarted Seal checks the card.
    let checked = seal(&journal, &clock, 101)
        .check(&mut card, &CheckRequest { uid: UID, challenge: [0x52; 32] })
        .unwrap_or_else(|e| panic!("check after step {step} {style:?}: {e:?}"));
    if began {
        assert_ne!(checked.body.state, CardState::Sealed, "Sealed after the Open began (step {step} {style:?})");
        assert!(matches!(checked.body.state, CardState::Opening | CardState::Opened));
        assert_eq!(checked.body.amount_wei, amount_wei);
    } else {
        assert_eq!(checked.body.state, CardState::Sealed, "step {step} {style:?}");
    }

    // A Fill can never start on a card whose Open began.
    if began {
        let fill = seal(&journal, &clock, 102).fill(
            &mut card,
            &ghost_seal::FillRequest { uid: UID, challenge: [0x53; 32], amount_wei: 1, pin: None },
            &mut support::StubMaker::default(),
        );
        assert!(fill.is_err());
        // Nor does it go on for another phone key.
        let other = support::phone(0x62);
        assert_eq!(
            seal(&journal, &clock, 103).open(&mut card, &open_request(other.public_key(), pin)).err(),
            Some(SealError::PhoneKeyMismatch),
            "step {step} {style:?}"
        );
    }

    // Run again after a restart: the same key, to the bound phone key.
    let opened = seal(&journal, &clock, 104)
        .open(&mut card, &open_request(phone.public_key(), pin))
        .unwrap_or_else(|e| panic!("resume after step {step} {style:?}: {e:?}"));
    let released = phone.open(&opened.release, &UID, 1).unwrap();
    assert_eq!(released.expose_secret(), &key[..], "step {step} {style:?}");
    assert_eq!(opened.answer.body.state, CardState::Opened);
    assert_eq!(opened.answer.body.amount_wei, amount_wei);

    // The card ends Opened at generation 1: keys rotated, slot wiped.
    let checked = seal(&journal, &clock, 105).check(&mut card, &CheckRequest { uid: UID, challenge: [0x54; 32] }).unwrap();
    assert_eq!((checked.body.state, checked.body.generation), (CardState::Opened, 1));
    let new_keys = card_keys_at(&support::master(), &UID, 1);
    for key_no in 0..5u8 {
        assert_eq!(&card.keys[usize::from(key_no)], new_keys.key(key_no), "step {step} {style:?}");
        assert_eq!(card.versions[usize::from(key_no)], key_version(1));
    }
    assert!(!contains(&card.file, &key));
    finished
}

fn every_step(style: DropStyle, pin: Option<&str>) {
    let mut step = 0;
    while !cut_at(step, style, pin) {
        step += 1;
        assert!(step < 400, "the Open never finished");
    }
    // An Open is dozens of commands: select, authenticate, read, journal,
    // mark, wipe, five key changes and five fresh authentications.
    assert!(step > 40, "the Open took only {step} commands");
}

#[test]
fn dropped_before_the_card_runs_each_command() {
    every_step(DropStyle::BeforeCard, None);
}

#[test]
fn dropped_after_the_card_runs_each_command() {
    every_step(DropStyle::AfterCard, None);
}

#[test]
fn dropped_at_each_step_of_an_open_with_a_pin() {
    every_step(DropStyle::AfterCard, Some("2580"));
}
