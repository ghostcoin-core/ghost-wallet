//! A replayed old answer is rejected, and a wrong Open PIN runs into the
//! retry limit.

mod support;

use ghost_seal::record::PIN_TRIES;
use ghost_seal::{AnswerRejected, AnswerVerifier, CardState, CheckRequest, CardUid, OpenRequest, Pin, SealError};
use support::{DropStyle, MEASUREMENT, UID, phone, seal, sealed_card};

fn open_with(pin: Option<&str>, phone_key: Vec<u8>) -> OpenRequest {
    OpenRequest { uid: UID, challenge: [0x71; 32], phone_key, pin: pin.map(|p| Pin::new(p).unwrap()) }
}

#[test]
fn a_replayed_old_answer_is_rejected() {
    let mut sealed = sealed_card(None);
    let mut s = seal(&sealed.journal, &sealed.clock, 1);
    let verifier = AnswerVerifier::new(&s.answer_verifying_key(), MEASUREMENT).unwrap();
    let now = sealed.clock.0.get();

    // A receiver's Check with its own fresh challenge: Sealed.
    let first_challenge = [0xa1; 32];
    let old = s.check(&mut sealed.card, &CheckRequest { uid: UID, challenge: first_challenge }).unwrap();
    assert_eq!(old.body.state, CardState::Sealed);
    assert!(verifier.verify(&old.bytes, &old.signature, &first_challenge, &UID, now).is_ok());

    // The card is opened.
    let phone = phone(0x72);
    s.open(&mut sealed.card, &open_with(None, phone.public_key())).unwrap();

    // The next receiver asks with a new challenge. The old Sealed answer,
    // replayed by a relay, is rejected; the fresh answer says Opened.
    let second_challenge = [0xa2; 32];
    assert_eq!(
        verifier.verify(&old.bytes, &old.signature, &second_challenge, &UID, now),
        Err(AnswerRejected::WrongChallenge)
    );
    let fresh = s.check(&mut sealed.card, &CheckRequest { uid: UID, challenge: second_challenge }).unwrap();
    assert_eq!(verifier.verify(&fresh.bytes, &fresh.signature, &second_challenge, &UID, now).unwrap().state, CardState::Opened);

    // Replayed to a receiver who reused its challenge, it is still refused once expired.
    let later = old.body.expires_at;
    assert_eq!(
        verifier.verify(&old.bytes, &old.signature, &first_challenge, &UID, later),
        Err(AnswerRejected::Expired)
    );
    assert!(verifier.verify(&old.bytes, &old.signature, &first_challenge, &UID, later - 1).is_ok());

    // Edited to say Sealed, or moved to another card: the signature fails.
    let mut edited = fresh.bytes.clone();
    edited[144] = CardState::Sealed as u8;
    assert_eq!(
        verifier.verify(&edited, &fresh.signature, &second_challenge, &UID, now),
        Err(AnswerRejected::BadSignature)
    );
    let other_card = CardUid([0x04, 1, 2, 3, 4, 5, 6]);
    assert_eq!(
        verifier.verify(&fresh.bytes, &fresh.signature, &second_challenge, &other_card, now),
        Err(AnswerRejected::WrongCard)
    );
    assert_eq!(
        verifier.verify(&fresh.bytes, &fresh.signature[..100], &second_challenge, &UID, now),
        Err(AnswerRejected::Malformed)
    );

    // Signed by Seal code with another measurement: refused by a phone pinning this one.
    let pinned_elsewhere = AnswerVerifier::new(&s.answer_verifying_key(), [0u8; 48]).unwrap();
    assert_eq!(
        pinned_elsewhere.verify(&fresh.bytes, &fresh.signature, &second_challenge, &UID, now),
        Err(AnswerRejected::WrongMeasurement)
    );

    // Another Seal key (another M) does not verify.
    let mut other_master = [0x77u8; 32];
    let other = ghost_seal::Seal::new(
        ghost_seal::MasterKey::take(&mut other_master),
        ghost_seal::SealConfig { measurement: MEASUREMENT, answer_lifetime_secs: 120 },
        Box::new(support::TestRandom::new(3)),
        Box::new(sealed.clock.clone()),
        Box::new(ghost_seal::MemoryJournal::new()),
    );
    let stranger = AnswerVerifier::new(&other.answer_verifying_key(), MEASUREMENT).unwrap();
    assert_eq!(
        stranger.verify(&fresh.bytes, &fresh.signature, &second_challenge, &UID, now),
        Err(AnswerRejected::BadSignature)
    );
}

#[test]
fn answers_expire_after_their_lifetime() {
    let mut sealed = sealed_card(None);
    let mut s = seal(&sealed.journal, &sealed.clock, 1);
    let verifier = AnswerVerifier::new(&s.answer_verifying_key(), MEASUREMENT).unwrap();
    let challenge = [0xb1; 32];
    let answer = s.check(&mut sealed.card, &CheckRequest { uid: UID, challenge }).unwrap();
    assert_eq!(answer.body.expires_at, sealed.clock.0.get() + 120);
    sealed.clock.advance(119);
    assert!(verifier.verify(&answer.bytes, &answer.signature, &challenge, &UID, sealed.clock.0.get()).is_ok());
    sealed.clock.advance(1);
    assert_eq!(
        verifier.verify(&answer.bytes, &answer.signature, &challenge, &UID, sealed.clock.0.get()),
        Err(AnswerRejected::Expired)
    );
}

#[test]
fn a_wrong_pin_hits_the_retry_limit() {
    let mut sealed = sealed_card(Some("4831"));
    let phone = phone(0x73);
    let mut s = seal(&sealed.journal, &sealed.clock, 1);

    // No PIN given: refused, and no try is used.
    assert_eq!(s.open(&mut sealed.card, &open_with(None, phone.public_key())).err(), Some(SealError::PinRequired));

    for tries_left in (0..PIN_TRIES).rev() {
        assert_eq!(
            s.open(&mut sealed.card, &open_with(Some("0000"), phone.public_key())).err(),
            Some(SealError::WrongPin { tries_left })
        );
        assert!(!sealed.journal.has_open(&UID));
    }
    // The limit is reached: even the right PIN is refused, the key stays sealed.
    assert_eq!(s.open(&mut sealed.card, &open_with(Some("4831"), phone.public_key())).err(), Some(SealError::PinLocked));
    let checked = s.check(&mut sealed.card, &CheckRequest { uid: UID, challenge: [0xc1; 32] }).unwrap();
    assert_eq!(checked.body.state, CardState::Sealed);
    assert!(!sealed.journal.has_open(&UID));
    // A restarted Seal remembers nothing; the card itself counts the tries.
    let mut restarted = seal(&sealed.journal, &sealed.clock, 2);
    assert_eq!(
        restarted.open(&mut sealed.card, &open_with(Some("4831"), phone.public_key())).err(),
        Some(SealError::PinLocked)
    );
}

#[test]
fn the_right_pin_opens_and_a_cut_connection_buys_no_free_guess() {
    let mut sealed = sealed_card(Some("4831"));
    let phone = phone(0x74);
    let mut s = seal(&sealed.journal, &sealed.clock, 1);
    assert_eq!(
        s.open(&mut sealed.card, &open_with(Some("1234"), phone.public_key())).err(),
        Some(SealError::WrongPin { tries_left: PIN_TRIES - 1 })
    );

    // Cut the connection right after the card ran each command of a wrong
    // guess: the try is counted before the PIN is compared, so dropping the
    // answer never gives the guess back.
    let mut after_cut = Vec::new();
    for step in 0.. {
        let mut card = sealed.card.clone();
        card.drop_from(step, DropStyle::AfterCard);
        let result = s.open(&mut card, &open_with(Some("1234"), phone.public_key()));
        card.reconnect();
        if !matches!(result, Err(SealError::Dropped)) {
            assert_eq!(result.err(), Some(SealError::WrongPin { tries_left: PIN_TRIES - 2 }));
            break;
        }
        let next = s.open(&mut card, &open_with(Some("1234"), phone.public_key())).err();
        let Some(SealError::WrongPin { tries_left }) = next else { panic!("step {step}: expected a wrong PIN") };
        after_cut.push(tries_left);
        assert!(step < 40);
    }
    // Cut before the counter's frame was written, the guess was never made;
    // cut any time after, the try is gone.
    let first_counted = after_cut.iter().position(|t| *t == PIN_TRIES - 3).expect("a cut after the count");
    assert!(after_cut[..first_counted].iter().all(|t| *t == PIN_TRIES - 2), "{after_cut:?}");
    assert!(after_cut[first_counted..].iter().all(|t| *t == PIN_TRIES - 3), "{after_cut:?}");

    // The right PIN still opens (one try used on this card), and the key is released.
    let opened = s.open(&mut sealed.card, &open_with(Some("4831"), phone.public_key())).unwrap();
    let key = sealed.maker.key_for(&sealed.commit_data);
    assert_eq!(phone.open(&opened.release, &UID, 1).unwrap().expose_secret(), &key[..]);
}
