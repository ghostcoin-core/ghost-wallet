//! The chain status check and the card registry are mandatory: `Seal::new`
//! is the only way to build a Seal and takes both; the old optional hooks
//! are gone from the public API; every Seal the crate's own sources build
//! passes both; an unregistered card is refused before any card traffic;
//! and a coin not paid exactly is never answered Sealed. Default features.

mod support;

use std::path::{Path, PathBuf};

use ghost_seal::chain_check::safe_depth;
use ghost_seal::journal::Journal;
use ghost_seal::{
    CardRegistry, CardState, CardUid, CheckRequest, Clock, CoinQuery, CoinStatusCheck, FillRequest, MasterKey,
    MemoryJournal, MemoryRegistry, OpenRequest, Seal, SealConfig, SealError, SealRandom, SignedAnswer,
};
use support::nodes::{FakeChain, node_check, two_nodes};
use support::{AMOUNT, SettledCheck, SimCard, StubChain, StubMaker, TestClock, UID, phone, registered, seal_with};

const OTHER_UID: CardUid = CardUid([0x04, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68]);

#[test]
fn seal_new_takes_the_status_check_and_the_registry() {
    // Fails to compile if `Seal::new` loses either argument.
    let build: fn(
        MasterKey,
        SealConfig,
        Box<dyn SealRandom>,
        Box<dyn Clock>,
        Box<dyn Journal>,
        Box<dyn CoinStatusCheck>,
        Box<dyn CardRegistry>,
    ) -> Seal = Seal::new;
    let seal = build(
        support::master(),
        SealConfig { measurement: support::MEASUREMENT, answer_lifetime_secs: 120 },
        Box::new(support::TestRandom::new(1)),
        Box::new(TestClock::new()),
        Box::new(MemoryJournal::new()),
        Box::new(SettledCheck),
        Box::new(MemoryRegistry::new()),
    );
    assert!(!seal.answer_verifying_key().is_empty());
}

/// Every `.rs` file under `dir`.
fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(rust_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
    files
}

/// The crate's own sources (not its tests), with their text.
fn sources() -> Vec<(PathBuf, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    rust_files(&src).into_iter().map(|path| (path.clone(), std::fs::read_to_string(&path).unwrap())).collect()
}

/// The text between the parentheses that open at `open`, and its
/// top-level arguments.
fn arguments(text: &str, open: usize) -> Vec<String> {
    let bytes = text.as_bytes();
    assert_eq!(bytes[open], b'(');
    let mut depth = 0;
    let mut args = Vec::new();
    let mut start = open + 1;
    for (i, b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    args.push(text[start..i].trim().to_owned());
                    break;
                }
            }
            b',' if depth == 1 => {
                args.push(text[start..i].trim().to_owned());
                start = i + 1;
            }
            _ => {}
        }
    }
    args.retain(|a| !a.is_empty());
    args
}

#[test]
fn no_source_builds_a_seal_without_the_check_and_the_registry() {
    let sources = sources();
    let flows = &sources.iter().find(|(path, _)| path.ends_with("flows.rs")).expect("flows.rs").1;

    // The old optional hooks are not public (they are gone).
    for hook in ["chain_status", "registry"] {
        let name = format!("fn with_{hook}");
        for (path, text) in &sources {
            for (at, _) in text.match_indices(&name) {
                let before = &text[..at];
                let line_start = before.rfind('\n').map_or(0, |n| n + 1);
                let prefix = before[line_start..].trim();
                assert!(!prefix.starts_with("pub"), "{} makes with_{hook} public", path.display());
            }
        }
    }
    // Nor are the Seal's fields: no struct literal outside `Seal::new`.
    let declaration = flows.find("pub struct Seal {").expect("the Seal");
    let body_end = declaration + flows[declaration..].find('}').unwrap();
    for line in flows[declaration..body_end].lines().skip(1) {
        assert!(!line.trim_start().starts_with("pub"), "a public field of the Seal: {line}");
    }
    let mut literals = Vec::new();
    for (path, text) in &sources {
        for (at, _) in text.match_indices("Seal {") {
            let before = &text[..at];
            let boundary = before.chars().last().is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
            let declared = before.trim_end().ends_with("struct") || before.trim_end().ends_with("impl");
            let returned = before.trim_end().ends_with("->");
            if boundary && !declared && !returned {
                literals.push(path.clone());
            }
        }
    }
    assert_eq!(literals.len(), 1, "the Seal is built by a struct literal only in Seal::new: {literals:?}");
    assert!(literals[0].ends_with("flows.rs"));

    // Every call of `Seal::new` outside the tests passes all seven
    // arguments, the check and the registry among them.
    let mut calls = 0;
    for (path, text) in &sources {
        for (at, _) in text.match_indices("Seal::new(") {
            let args = arguments(text, at + "Seal::new".len());
            assert_eq!(args.len(), 7, "{} builds a Seal with {} arguments: {args:?}", path.display(), args.len());
            calls += 1;
        }
    }
    assert!(calls >= 2, "the enclave and the test server build their Seals with Seal::new");
}

#[test]
fn an_unregistered_card_is_refused_before_any_card_traffic() {
    // The tests' Seal holds UID only; OTHER_UID is set up with the same M.
    let journal = MemoryJournal::new();
    let clock = TestClock::new();
    let mut seal = support::seal(&journal, &clock, 1);
    let mut card = SimCard::set_up(OTHER_UID);

    let check = seal.check(&mut card, &CheckRequest { uid: OTHER_UID, challenge: [1; 32] });
    assert_eq!(check.err(), Some(SealError::NotAGhostCard));
    let fill = FillRequest { uid: OTHER_UID, challenge: [2; 32], amount_wei: AMOUNT, pin: None };
    assert_eq!(seal.fill(&mut card, &fill, &mut StubMaker::default()).err(), Some(SealError::NotAGhostCard));
    let confirm = CheckRequest { uid: OTHER_UID, challenge: [3; 32] };
    assert_eq!(seal.confirm_fill(&mut card, &confirm, &StubChain::default()).err(), Some(SealError::NotAGhostCard));
    let open = OpenRequest { uid: OTHER_UID, challenge: [4; 32], phone_key: phone(3).public_key(), pin: None };
    assert_eq!(seal.open(&mut card, &open).err(), Some(SealError::NotAGhostCard));
    assert_eq!(card.sent, 0, "no command reached the card");
    assert!(card.transcript.is_empty());
    assert!(!journal.has_open(&OTHER_UID));

    // Registered, the same card is served.
    let mut seal = seal_with(&journal, &clock, 2, Box::new(SettledCheck), Box::new(registered(&[OTHER_UID])));
    let answer = seal.check(&mut card, &CheckRequest { uid: OTHER_UID, challenge: [5; 32] }).expect("check");
    assert_eq!(answer.body.state, CardState::Empty);
}

fn state(answer: Result<SignedAnswer, SealError>) -> Option<CardState> {
    answer.ok().map(|a| a.body.state)
}

#[test]
fn a_coin_not_paid_exactly_is_not_sealed() {
    for paid in [AMOUNT - 1, AMOUNT + 1] {
        let journal = MemoryJournal::new();
        let clock = TestClock::new();
        let mut maker = StubMaker::default();
        let mut card = SimCard::set_up(UID);
        let chain = FakeChain::new().shared();
        let (a, b) = two_nodes(&chain);
        let mut seal =
            seal_with(&journal, &clock, 3, Box::new(node_check(&[&a, &b])), Box::new(registered(&[UID])));
        let filled = seal
            .fill(&mut card, &FillRequest { uid: UID, challenge: [6; 32], amount_wei: AMOUNT, pin: None }, &mut maker)
            .expect("fill");

        // Another amount, settled: whatever the payment check says, the
        // Seal's own check refuses.
        chain.borrow_mut().vanish(&filled.commit_data, paid);
        chain.borrow_mut().mine(safe_depth(AMOUNT) + 5);
        let lax = StubChain::default();
        lax.pay(&filled.commit_data, AMOUNT);
        let confirm = CheckRequest { uid: UID, challenge: [7; 32] };
        assert_eq!(seal.confirm_fill(&mut card, &confirm, &lax).err(), Some(SealError::PaymentMismatch), "paid {paid}");
        assert_eq!(state(seal.check(&mut card, &CheckRequest { uid: UID, challenge: [8; 32] })), Some(CardState::Empty));

        // A card a lax Seal wrote Sealed is still never answered Sealed.
        let mut lax_seal = support::seal(&journal, &clock, 4);
        assert_eq!(state(lax_seal.confirm_fill(&mut card, &confirm, &lax)), Some(CardState::Sealed));
        let checked = seal.check(&mut card, &CheckRequest { uid: UID, challenge: [9; 32] });
        assert_eq!(checked.err(), Some(SealError::PaymentMismatch), "paid {paid}");
    }

    // Paid exactly but not settled yet: not Sealed either.
    let journal = MemoryJournal::new();
    let clock = TestClock::new();
    let mut maker = StubMaker::default();
    let mut card = SimCard::set_up(UID);
    let chain = FakeChain::new().shared();
    let (a, b) = two_nodes(&chain);
    let mut seal = seal_with(&journal, &clock, 5, Box::new(node_check(&[&a, &b])), Box::new(registered(&[UID])));
    let filled = seal
        .fill(&mut card, &FillRequest { uid: UID, challenge: [10; 32], amount_wei: AMOUNT, pin: None }, &mut maker)
        .expect("fill");
    let coin = CoinQuery {
        commit_data: filled.commit_data.clone(),
        amount_wei: AMOUNT,
        spend_marker: maker.marker_for(&filled.commit_data),
    };
    chain.borrow_mut().pay(&coin, 1);
    let lax = StubChain::default();
    lax.pay(&filled.commit_data, AMOUNT);
    let confirm = CheckRequest { uid: UID, challenge: [11; 32] };
    assert_eq!(seal.confirm_fill(&mut card, &confirm, &lax).err(), Some(SealError::NotSettled));
    // Settled: Sealed.
    chain.borrow_mut().mine(safe_depth(AMOUNT));
    assert_eq!(state(seal.confirm_fill(&mut card, &confirm, &lax)), Some(CardState::Sealed));
}
