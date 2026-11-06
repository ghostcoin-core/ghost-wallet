//! Fill, Check and Open end to end against the simulated NTAG 424 DNA.

mod support;

use ghost_seal::apdu::command;
use ghost_seal::card_keys::{KEY_APPLICATION_MASTER, card_keys, card_keys_at, key_version};
use ghost_seal::flows::record_file_settings;
use ghost_seal::link::CardLink;
use ghost_seal::primitives::sha3_256;
use ghost_seal::record::FRAME_BYTES;
use ghost_seal::{
    AnswerKind, AnswerVerifier, CardState, CardTransport, CheckRequest, FillRequest, MemoryJournal, OpenRequest, Pin,
    SealError, SignedAnswer,
};
use support::{
    AMOUNT, DropStyle, MEASUREMENT, SimCard, StubChain, StubMaker, TestClock, TestRandom, UID, contains, phone, seal,
    sealed_card,
};

fn verify(answer: &SignedAnswer, verifying_key: &[u8], challenge: &[u8; 32], now: u64) {
    let verifier = AnswerVerifier::new(verifying_key, MEASUREMENT).unwrap();
    let body = verifier.verify(&answer.bytes, &answer.signature, challenge, &UID, now).expect("a valid answer");
    assert_eq!(&body, &answer.body);
}

fn check(card: &mut SimCard, journal: &MemoryJournal, clock: &TestClock, challenge: u8) -> SignedAnswer {
    let mut seal = seal(journal, clock, 50 + u64::from(challenge));
    let answer = seal.check(card, &CheckRequest { uid: UID, challenge: [challenge; 32] }).expect("check");
    verify(&answer, &seal.answer_verifying_key(), &[challenge; 32], clock.0.get());
    answer
}

fn fill_request(pin: Option<&str>) -> FillRequest {
    FillRequest { uid: UID, challenge: [0x0f; 32], amount_wei: AMOUNT, pin: pin.map(|p| Pin::new(p).unwrap()) }
}

#[test]
fn fill_confirm_check_open_end_to_end() {
    let journal = MemoryJournal::new();
    let clock = TestClock::new();
    let mut maker = StubMaker::default();
    let mut card = SimCard::set_up(UID);

    // A card fresh from setup checks as Empty.
    let blank = check(&mut card, &journal, &clock, 0x10);
    assert_eq!((blank.body.state, blank.body.amount_wei, blank.body.generation), (CardState::Empty, 0, 0));
    assert_eq!(blank.body.kind, AnswerKind::Check);

    // Fill: only the public commit data and the amount come back.
    let mut s = seal(&journal, &clock, 1);
    let filled = s.fill(&mut card, &fill_request(None), &mut maker).unwrap();
    assert_eq!(filled.commit_data.len(), 430);
    assert_eq!(filled.amount_wei, AMOUNT);
    let coin = sha3_256(&[&filled.commit_data]);
    assert_eq!(filled.answer.body.kind, AnswerKind::Fill);
    assert_eq!(filled.answer.body.state, CardState::Empty);
    assert_eq!(filled.answer.body.coin, coin);
    assert_eq!(filled.answer.body.binding, coin);
    assert_eq!(filled.answer.body.amount_wei, AMOUNT);
    verify(&filled.answer, &s.answer_verifying_key(), &[0x0f; 32], clock.0.get());
    let key = maker.key_for(&filled.commit_data);

    // Until the chain check confirms the payment the card is not Sealed.
    assert_eq!(check(&mut card, &journal, &clock, 0x11).body.state, CardState::Empty);
    let chain = StubChain::default();
    let confirm = CheckRequest { uid: UID, challenge: [0x12; 32] };
    assert_eq!(s.confirm_fill(&mut card, &confirm, &chain), Err(SealError::NotPaid));
    chain.mismatch.set(true);
    assert_eq!(s.confirm_fill(&mut card, &confirm, &chain), Err(SealError::PaymentMismatch));
    chain.mismatch.set(false);
    // A payment of another amount is not this coin.
    chain.pay(&filled.commit_data, AMOUNT - 1);
    assert_eq!(s.confirm_fill(&mut card, &confirm, &chain), Err(SealError::NotPaid));
    assert_eq!(check(&mut card, &journal, &clock, 0x13).body.state, CardState::Empty);

    chain.pay(&filled.commit_data, AMOUNT);
    let sealed = s.confirm_fill(&mut card, &confirm, &chain).unwrap();
    assert_eq!((sealed.body.state, sealed.body.amount_wei, sealed.body.coin), (CardState::Sealed, AMOUNT, coin));
    verify(&sealed, &s.answer_verifying_key(), &[0x12; 32], clock.0.get());
    // Confirming again answers Sealed without asking the chain again.
    let asked = chain.asked.get();
    assert_eq!(s.confirm_fill(&mut card, &confirm, &chain).unwrap().body.state, CardState::Sealed);
    assert_eq!(chain.asked.get(), asked);

    // Check: Sealed, its amount and its coin.
    let checked = check(&mut card, &journal, &clock, 0x14);
    assert_eq!((checked.body.state, checked.body.amount_wei, checked.body.coin), (CardState::Sealed, AMOUNT, coin));
    assert_eq!(checked.body.binding, [0u8; 32]);

    // Open: the key comes back encrypted to the phone key, the card is Opened
    // at the next generation, every key moved.
    let phone = phone(0x33);
    let opened = s
        .open(&mut card, &OpenRequest { uid: UID, challenge: [0x15; 32], phone_key: phone.public_key(), pin: None })
        .unwrap();
    assert!(!contains(&opened.release, &key));
    assert_eq!(phone.open(&opened.release, &UID, 1).unwrap().expose_secret(), &key[..]);
    assert!(phone.open(&opened.release, &UID, 0).is_err());
    assert!(support::phone(0x34).open(&opened.release, &UID, 1).is_err());
    assert_eq!(opened.answer.body.kind, AnswerKind::Open);
    assert_eq!((opened.answer.body.state, opened.answer.body.generation), (CardState::Opened, 1));
    assert_eq!(opened.answer.body.binding, sha3_256(&[&opened.release]));
    assert_eq!((opened.answer.body.amount_wei, opened.answer.body.coin), (AMOUNT, coin));
    verify(&opened.answer, &s.answer_verifying_key(), &[0x15; 32], clock.0.get());

    let new_keys = card_keys_at(&support::master(), &UID, 1);
    for key_no in 0..5u8 {
        assert_eq!(&card.keys[usize::from(key_no)], new_keys.key(key_no));
        assert_eq!(card.versions[usize::from(key_no)], key_version(1));
    }
    // The key slot is wiped on the card.
    assert!(!contains(&card.file, &key));

    let after = check(&mut card, &journal, &clock, 0x16);
    assert_eq!((after.body.state, after.body.generation), (CardState::Opened, 1));

    // A filled card never fills again; an Open asked again hands the same key
    // to the same phone only.
    assert_eq!(s.fill(&mut card, &fill_request(None), &mut maker).err(), Some(SealError::WrongState(CardState::Opening)));
    let again = s
        .open(&mut card, &OpenRequest { uid: UID, challenge: [0x17; 32], phone_key: phone.public_key(), pin: None })
        .unwrap();
    assert_eq!(phone.open(&again.release, &UID, 1).unwrap().expose_secret(), &key[..]);
    let other = support::phone(0x35);
    assert_eq!(
        s.open(&mut card, &OpenRequest { uid: UID, challenge: [0x18; 32], phone_key: other.public_key(), pin: None })
            .err(),
        Some(SealError::PhoneKeyMismatch)
    );
}

#[test]
fn every_write_is_a_frame_of_128_bytes_or_less_and_is_read_back() {
    let journal = MemoryJournal::new();
    let clock = TestClock::new();
    let mut card = SimCard::set_up(UID);
    let mut s = seal(&journal, &clock, 1);
    let filled = s.fill(&mut card, &fill_request(Some("4831")), &mut StubMaker::default()).unwrap();
    let chain = StubChain::default();
    chain.pay(&filled.commit_data, AMOUNT);
    s.confirm_fill(&mut card, &CheckRequest { uid: UID, challenge: [1; 32] }, &chain).unwrap();
    s.open(
        &mut card,
        &OpenRequest { uid: UID, challenge: [2; 32], phone_key: phone(1).public_key(), pin: Some(Pin::new("4831").unwrap()) },
    )
    .unwrap();
    assert!(card.write_lengths.len() >= 6, "{:?}", card.write_lengths);
    assert!(card.write_lengths.iter().all(|length| *length > 0 && *length <= FRAME_BYTES), "{:?}", card.write_lengths);
    // Every WriteData is followed by a ReadData of the same frame.
    let commands: Vec<u8> = card.transcript.iter().filter(|apdu| apdu.len() > 1 && apdu[0] == 0x90).map(|apdu| apdu[1]).collect();
    let writes = commands.iter().filter(|c| **c == command::WRITE_DATA).count();
    let reads = commands.iter().filter(|c| **c == command::READ_DATA).count();
    assert_eq!(writes, card.write_lengths.len());
    assert!(reads >= writes);
    for (i, c) in commands.iter().enumerate() {
        if *c == command::WRITE_DATA {
            assert!(commands[i + 1..].contains(&command::READ_DATA));
        }
    }
}

#[test]
fn the_key_never_crosses_the_relay_and_check_never_reads_it() {
    let mut sealed = sealed_card(None);
    let key = sealed.maker.key_for(&sealed.commit_data);
    let mut transcript = Vec::new();

    let before = sealed.card.transcript.len();
    check(&mut sealed.card, &sealed.journal, &sealed.clock, 0x20);
    let check_apdus: Vec<Vec<u8>> = sealed.card.transcript[before..].to_vec();
    // Check reads the header frame only: no ReadData at the key slot's offset (0x80).
    for apdu in &check_apdus {
        if apdu.len() > 12 && apdu[0] == 0x90 && apdu[1] == command::READ_DATA {
            assert_eq!(&apdu[5..9], &[0x02, 0x00, 0x00, 0x00], "Check read past the header");
        }
    }
    transcript.extend(check_apdus);

    let phone = phone(0x21);
    let mut s = seal(&sealed.journal, &sealed.clock, 3);
    let opened = s
        .open(&mut sealed.card, &OpenRequest { uid: UID, challenge: [0x22; 32], phone_key: phone.public_key(), pin: None })
        .unwrap();
    transcript.extend(sealed.card.transcript.iter().cloned());
    transcript.push(opened.release.clone());
    transcript.push(opened.answer.bytes.clone());
    for message in &transcript {
        assert!(!contains(message, &key), "the key crossed the relay in clear");
    }
    // Nor does the journal store hold it in clear.
    for entry in sealed.journal.sealed_entries() {
        assert!(!contains(&entry, &key));
    }
}

#[test]
fn fill_refuses_cards_it_cannot_trust() {
    let journal = MemoryJournal::new();
    let clock = TestClock::new();
    let mut maker = StubMaker::default();
    let mut s = seal(&journal, &clock, 1);

    // Factory keys (version 0): never set up.
    let mut factory = SimCard::factory(UID.0);
    assert_eq!(s.fill(&mut factory, &fill_request(None), &mut maker).err(), Some(SealError::NotSetUp));

    // The record file left plain and free.
    let mut open_file = SimCard::set_up(UID);
    open_file.settings = [0x00, 0xe0, 0xee];
    assert_eq!(s.fill(&mut open_file, &fill_request(None), &mut maker).err(), Some(SealError::NotSetUp));

    // Keys of another Seal.
    let mut foreign = SimCard::set_up(UID);
    foreign.keys[2] = [0x99; 16];
    assert_eq!(s.fill(&mut foreign, &fill_request(None), &mut maker).err(), Some(SealError::UnknownKeys));

    // A card whose chip reports another UID than the one asked about.
    let mut other_uid = SimCard::set_up(UID);
    other_uid.uid = [0x04, 0, 0, 0, 0, 0, 1];
    assert_eq!(s.fill(&mut other_uid, &fill_request(None), &mut maker).err(), Some(SealError::UnknownKeys));

    // Zero is no amount.
    let mut card = SimCard::set_up(UID);
    let zero = FillRequest { amount_wei: 0, ..fill_request(None) };
    assert_eq!(s.fill(&mut card, &zero, &mut maker).err(), Some(SealError::BadAmount));
    assert!(maker.made.borrow().is_empty(), "no key is made for a card that is refused");
}

#[test]
fn a_waiting_fill_hands_back_its_coin_and_a_sealed_card_is_never_refilled() {
    let journal = MemoryJournal::new();
    let clock = TestClock::new();
    let mut maker = StubMaker::default();
    let mut card = SimCard::set_up(UID);
    let mut s = seal(&journal, &clock, 1);
    let first = s.fill(&mut card, &fill_request(None), &mut maker).unwrap();
    // Asked again (its answer was lost): the same coin, no new key.
    let second = s.fill(&mut card, &fill_request(None), &mut maker).unwrap();
    assert_eq!(second.commit_data, first.commit_data);
    assert_eq!(maker.made.borrow().len(), 1);
    // Another amount or a PIN is another Fill: refused while this one waits.
    let more = FillRequest { amount_wei: AMOUNT + 1, ..fill_request(None) };
    assert_eq!(s.fill(&mut card, &more, &mut maker).err(), Some(SealError::FillPending));
    assert_eq!(s.fill(&mut card, &fill_request(Some("1111")), &mut maker).err(), Some(SealError::FillPending));

    let chain = StubChain::default();
    chain.pay(&first.commit_data, AMOUNT);
    s.confirm_fill(&mut card, &CheckRequest { uid: UID, challenge: [3; 32] }, &chain).unwrap();
    assert_eq!(
        s.fill(&mut card, &fill_request(None), &mut maker).err(),
        Some(SealError::WrongState(CardState::Sealed))
    );
    // An Open on a card that is not Sealed is refused.
    let mut empty = SimCard::set_up(UID);
    let fresh = MemoryJournal::new();
    let mut other = seal(&fresh, &clock, 2);
    assert_eq!(
        other
            .open(&mut empty, &OpenRequest { uid: UID, challenge: [4; 32], phone_key: phone(1).public_key(), pin: None })
            .err(),
        Some(SealError::WrongState(CardState::Empty))
    );
    // A phone key that is not an ML-KEM-768 key is refused before the card is touched.
    let sent = card.sent;
    assert_eq!(
        s.open(&mut card, &OpenRequest { uid: UID, challenge: [5; 32], phone_key: vec![0u8; 10], pin: None }).err(),
        Some(SealError::BadPhoneKey)
    );
    assert_eq!(card.sent, sent);
}

#[test]
fn a_fill_cut_off_at_any_step_never_seals_and_never_strands_a_coin() {
    for style in [DropStyle::BeforeCard, DropStyle::AfterCard] {
        let mut step = 0;
        loop {
            let journal = MemoryJournal::new();
            let clock = TestClock::new();
            let mut maker = StubMaker::default();
            let mut card = SimCard::set_up(UID);
            card.drop_from(step, style);
            let mut s = seal(&journal, &clock, 7);
            let first = s.fill(&mut card, &fill_request(None), &mut maker);
            card.reconnect();
            let finished = first.is_ok();
            if !finished {
                assert_eq!(first.err(), Some(SealError::Dropped));
                assert_ne!(check(&mut card, &journal, &clock, 0x30).body.state, CardState::Sealed);
            }
            // Run again after a restart: a Fill that can be paid and opened.
            let mut s = seal(&journal, &clock, 8);
            let filled = s.fill(&mut card, &fill_request(None), &mut maker).unwrap();
            let chain = StubChain::default();
            chain.pay(&filled.commit_data, AMOUNT);
            s.confirm_fill(&mut card, &CheckRequest { uid: UID, challenge: [6; 32] }, &chain).unwrap();
            let phone = phone(0x40);
            let opened = s
                .open(&mut card, &OpenRequest { uid: UID, challenge: [7; 32], phone_key: phone.public_key(), pin: None })
                .unwrap();
            assert_eq!(
                phone.open(&opened.release, &UID, 1).unwrap().expose_secret(),
                &maker.key_for(&filled.commit_data)[..],
                "step {step} {style:?}"
            );
            if finished {
                break;
            }
            step += 1;
        }
        assert!(step > 10, "the Fill took {step} commands");
    }
}

#[test]
fn file_settings_commands_round_trip() {
    let mut card = SimCard::set_up(UID);
    let keys = card_keys(&support::master(), &UID);
    let mut random = TestRandom::new(5);
    let mut link = CardLink::new(&mut card);
    link.select().unwrap();
    let mut session = link.authenticate(KEY_APPLICATION_MASTER, keys.key(KEY_APPLICATION_MASTER), &mut random).unwrap();
    let settings = link.file_settings(&mut session, 0x02).unwrap();
    assert_eq!(settings[0], 0x00);
    assert_eq!(&settings[1..4], &record_file_settings());
    assert_eq!(&settings[4..7], &[0x00, 0x01, 0x00]);
    link.change_file_settings(&mut session, 0x02, &[0x03, 0x30, 0x33]).unwrap();
    assert_eq!(&link.file_settings(&mut session, 0x02).unwrap()[1..4], &[0x03, 0x30, 0x33]);
    link.change_file_settings(&mut session, 0x02, &record_file_settings()).unwrap();
    drop(link);
    assert_eq!(card.settings, record_file_settings());
    // A key that may not change the settings is refused by the chip.
    let mut link = CardLink::new(&mut card);
    link.select().unwrap();
    let mut session = link.authenticate(1, keys.key(1), &mut random).unwrap();
    assert!(matches!(
        link.change_file_settings(&mut session, 0x02, &[0x00, 0xe0, 0xee]),
        Err(SealError::Chip { sw2: 0x9d, .. })
    ));
    assert_eq!(card.transceive(&[0x90, 0x60, 0x00, 0x00, 0x00]).unwrap(), vec![0x91, 0x1c]);
}
