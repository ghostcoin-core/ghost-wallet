//! The relay carrying a Fill, its confirmation and an Open, round trip by
//! round trip, against the simulated card: the phone's side of the relay is
//! played by the test, which hands each APDU to the card and each raw answer
//! back. Every signed answer is checked as the phone checks it. Default
//! features: no networking.

mod support;

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ghost_seal::primitives::sha3_256;
use ghost_seal::record::PIN_TRIES;
use ghost_seal::{
    AnswerKind, AnswerVerifier, CardState, CardTransport, FlowStep, KeyMakerFactory, MemoryJournal, PaymentCheckFactory,
    Pin, Relay, RelayError, RelayLimits, SealError, SessionId, SignedAnswer, Step,
};
use support::{
    AMOUNT, MEASUREMENT, START_TIME, SharedJournal, SimCard, SyncChain, SyncMaker, TestClock, UID, carry,
    contains, phone,
};

/// A relay whose sessions each run a Seal with the test M over `journal`.
fn relay_with(journal: &SharedJournal, limits: RelayLimits) -> Relay {
    let journal = journal.clone();
    Relay::new(Arc::new(move || support::thread_seal(&journal)), limits)
}

fn maker_factory(maker: &SyncMaker) -> KeyMakerFactory {
    let maker = maker.clone();
    Arc::new(move || Box::new(maker.clone()))
}

fn payment_factory(chain: &SyncChain) -> PaymentCheckFactory {
    let chain = chain.clone();
    Arc::new(move || Box::new(chain.clone()))
}

/// The phone's check of an answer: the test Seal's pinned key and measurement.
fn verifier() -> AnswerVerifier {
    let key = support::seal(&MemoryJournal::new(), &TestClock::new(), 0).answer_verifying_key();
    AnswerVerifier::new(&key, MEASUREMENT).unwrap()
}

fn pin(digits: &str) -> Option<Pin> {
    Some(Pin::new(digits).unwrap())
}

/// A Check through the unchanged `start_check` and `step`.
fn check(relay: &Relay, card: &mut SimCard, challenge: [u8; 32]) -> (Result<SignedAnswer, RelayError>, usize) {
    let mut step = relay.start_check(UID, challenge);
    let mut round_trips = 1;
    loop {
        match step {
            Ok(Step::Done(answer)) => return (Ok(answer), round_trips),
            Err(error) => return (Err(error), round_trips),
            Ok(Step::Apdu { session, apdu }) => {
                let answer = card.transceive(&apdu).expect("the card stays in the field");
                round_trips += 1;
                step = relay.step(&session, &answer);
            }
        }
    }
}

#[test]
fn the_relay_carries_a_fill_its_confirmation_and_an_open_round_trip_by_round_trip() {
    let journal = SharedJournal::default();
    let relay = relay_with(&journal, RelayLimits::default());
    let (maker, chain, verifier) = (SyncMaker::default(), SyncChain::default(), verifier());
    let mut card = SimCard::set_up(UID);

    // Fill, with an Open PIN: the Seal writes the key and hands back only the commit data.
    let challenge = [0x31; 32];
    let first = relay.start_fill(UID, challenge, AMOUNT, pin("2468"), maker_factory(&maker));
    assert!(matches!(first, Ok(FlowStep::Apdu { .. })), "a Fill begins with a command for the card");
    let (filled, round_trips) = carry(&mut card, &relay, first);
    let filled = filled.expect("the Fill");
    assert!(round_trips > 8, "a Fill takes many card round trips, took {round_trips}");
    let commit_data = filled.commit_data.clone().expect("a Fill hands back its commit data");
    assert_eq!(commit_data.len(), 430);
    assert_eq!(filled.release, None);
    let body = verifier.verify(&filled.answer.bytes, &filled.answer.signature, &challenge, &UID, START_TIME).unwrap();
    let coin = sha3_256(&[&commit_data]);
    assert_eq!(
        (body.kind, body.state, body.coin, body.binding, body.amount_wei),
        (AnswerKind::Fill, CardState::Empty, coin, coin, AMOUNT)
    );
    assert_eq!((body.pin_required, body.pin_tries_left), (true, PIN_TRIES));
    assert_eq!(relay.session_count(), 0, "a finished session is not held");

    // Its confirmation, before the payment: refused as not paid.
    let first = relay.start_confirm_fill(UID, [0x32; 32], payment_factory(&chain));
    assert_eq!(carry(&mut card, &relay, first).0, Err(RelayError::Seal(SealError::NotPaid)));

    // Paid exactly: the card is written Sealed and the answer (kind Fill) says so.
    chain.pay(&commit_data, AMOUNT);
    let challenge = [0x33; 32];
    let (sealed, _) = carry(&mut card, &relay, relay.start_confirm_fill(UID, challenge, payment_factory(&chain)));
    let sealed = sealed.expect("the confirmation");
    assert_eq!((sealed.commit_data.as_ref(), sealed.release.as_ref()), (None, None));
    let body = verifier.verify(&sealed.answer.bytes, &sealed.answer.signature, &challenge, &UID, START_TIME).unwrap();
    assert_eq!((body.kind, body.state, body.amount_wei, body.coin), (AnswerKind::Fill, CardState::Sealed, AMOUNT, coin));

    // A Check through the unchanged path says Sealed.
    let challenge = [0x34; 32];
    let (checked, _) = check(&relay, &mut card, challenge);
    let checked = checked.expect("the Check");
    let body = verifier.verify(&checked.bytes, &checked.signature, &challenge, &UID, START_TIME).unwrap();
    assert_eq!((body.kind, body.state, body.amount_wei), (AnswerKind::Check, CardState::Sealed, AMOUNT));

    // Open: without the PIN, then with a wrong one, then with the right one.
    let phone = phone(0x47);
    let first = relay.start_open(UID, [0x35; 32], phone.public_key(), None);
    assert_eq!(carry(&mut card, &relay, first).0, Err(RelayError::Seal(SealError::PinRequired)));
    let first = relay.start_open(UID, [0x36; 32], phone.public_key(), pin("1357"));
    assert_eq!(
        carry(&mut card, &relay, first).0,
        Err(RelayError::Seal(SealError::WrongPin { tries_left: PIN_TRIES - 1 }))
    );
    let challenge = [0x37; 32];
    let (opened, round_trips) = carry(&mut card, &relay, relay.start_open(UID, challenge, phone.public_key(), pin("2468")));
    let opened = opened.expect("the Open");
    assert!(round_trips > 20, "an Open rotates five keys, took {round_trips} round trips");
    let release = opened.release.clone().expect("an Open hands back its release package");
    assert_eq!(opened.commit_data, None);
    let body = verifier.verify(&opened.answer.bytes, &opened.answer.signature, &challenge, &UID, START_TIME).unwrap();
    assert_eq!((body.kind, body.state, body.binding), (AnswerKind::Open, CardState::Opened, sha3_256(&[&release])));
    // The release opens only for the phone key the Open was bound to, to the key the Fill wrote.
    assert_eq!(phone.open(&release, &UID, 1).unwrap().expose_secret(), &maker.key_for(&commit_data)[..]);
    assert!(support::phone(0x48).open(&release, &UID, 1).is_err());
    assert!(journal.has_open(&UID));

    // The PIN went to the Seal only: nothing the phone relayed carries it.
    for digits in [&b"2468"[..], b"1357"] {
        assert!(!card.transcript.iter().any(|bytes| contains(bytes, digits)));
    }

    // A Check now says Opened.
    let challenge = [0x38; 32];
    let checked = check(&relay, &mut card, challenge).0.expect("the Check");
    let body = verifier.verify(&checked.bytes, &checked.signature, &challenge, &UID, START_TIME).unwrap();
    assert_eq!(body.state, CardState::Opened);
}

#[test]
fn an_unknown_finished_aborted_or_expired_session_is_refused() {
    let journal = SharedJournal::default();
    let limits = RelayLimits { idle_timeout: Duration::from_millis(300), total_limit: Duration::from_secs(5), max_sessions: 4 };
    let relay = relay_with(&journal, limits);
    let maker = SyncMaker::default();

    let unknown = SessionId([0x99; 16]);
    assert_eq!(relay.step_flow(&unknown, &[0x91, 0x00]), Err(RelayError::UnknownSession));
    assert_eq!(relay.abort(&unknown), Err(RelayError::UnknownSession));

    // The card's answer comes after the idle timeout: expired once, then unknown.
    let mut card = SimCard::set_up(UID);
    let Ok(FlowStep::Apdu { session, apdu }) = relay.start_fill(UID, [0x41; 32], AMOUNT, None, maker_factory(&maker))
    else {
        panic!("a Fill begins with a command for the card");
    };
    let answer = card.transceive(&apdu).unwrap();
    thread::sleep(Duration::from_millis(450));
    assert_eq!(relay.step_flow(&session, &answer), Err(RelayError::Expired));
    assert_eq!(relay.step_flow(&session, &answer), Err(RelayError::UnknownSession));

    // A malformed card answer is refused and the session goes on.
    let mut card = SimCard::set_up(UID);
    let first = relay.start_confirm_fill(UID, [0x42; 32], payment_factory(&SyncChain::default()));
    let Ok(FlowStep::Apdu { session, apdu }) = first else { panic!("a confirmation begins with a command") };
    assert_eq!(relay.step_flow(&session, &[0x91]), Err(RelayError::BadRequest("a card answer is 2 to 258 bytes")));
    // Aborted (the card left the field): unknown from then on.
    let answer = card.transceive(&apdu).unwrap();
    assert_eq!(relay.abort(&session), Ok(()));
    assert_eq!(relay.step_flow(&session, &answer), Err(RelayError::UnknownSession));

    // Finished: unknown from then on.
    let mut card = SimCard::set_up(UID);
    let Ok(FlowStep::Apdu { mut session, mut apdu }) = relay.start_open(UID, [0x43; 32], phone(3).public_key(), None)
    else {
        panic!("an Open begins with a command");
    };
    let last_answer = loop {
        let answer = card.transceive(&apdu).unwrap();
        match relay.step_flow(&session, &answer) {
            Ok(FlowStep::Apdu { session: next, apdu: command }) => {
                assert_eq!(next, session, "a session keeps its id");
                (session, apdu) = (next, command);
            }
            // An empty card is not opened: the flow ends refused.
            Err(RelayError::Seal(SealError::WrongState(CardState::Empty))) => break answer,
            other => panic!("unexpected {other:?}"),
        }
    };
    assert_eq!(relay.step_flow(&session, &last_answer), Err(RelayError::UnknownSession));

    // A Fill of nothing is refused before any card traffic and holds no session.
    assert_eq!(
        relay.start_fill(UID, [0x44; 32], 0, None, maker_factory(&maker)),
        Err(RelayError::Seal(SealError::BadAmount))
    );
    assert_eq!(relay.session_count(), 0);
    assert!(maker.made.lock().unwrap().is_empty(), "no key was made for the cut-off or refused Fills");
}

#[test]
fn start_check_is_unchanged_and_step_flow_carries_a_check_too() {
    let journal = SharedJournal::default();
    let relay = relay_with(&journal, RelayLimits::default());
    let verifier = verifier();

    // A Check of a blank card through start_check and step, about eight Seal round trips.
    let mut card = SimCard::set_up(UID);
    let challenge = [0x51; 32];
    let (answer, round_trips) = check(&relay, &mut card, challenge);
    let answer = answer.expect("the Check");
    assert!((6..=10).contains(&round_trips), "a Check took {round_trips} Seal round trips");
    let body = verifier.verify(&answer.bytes, &answer.signature, &challenge, &UID, START_TIME).unwrap();
    assert_eq!((body.kind, body.state, body.amount_wei, body.coin), (AnswerKind::Check, CardState::Empty, 0, [0u8; 32]));
    assert_eq!(
        verifier.verify(&answer.bytes, &answer.signature, &[0x52; 32], &UID, START_TIME),
        Err(ghost_seal::AnswerRejected::WrongChallenge)
    );

    // The same Check through step_flow ends with no extras.
    let mut card = SimCard::set_up(UID);
    let first = relay.start_check(UID, [0x53; 32]).map(|step| match step {
        Step::Apdu { session, apdu } => FlowStep::Apdu { session, apdu },
        Step::Done(_) => panic!("a Check begins with a command"),
    });
    let finished = carry(&mut card, &relay, first).0.expect("the Check");
    assert_eq!((finished.commit_data, finished.release), (None, None));

    // A card that does not hold the Seal's keys is refused.
    let mut stranger = SimCard::factory(UID.0);
    assert!(matches!(check(&relay, &mut stranger, [0x54; 32]).0, Err(RelayError::Seal(_))));
    assert_eq!(relay.session_count(), 0);
}
