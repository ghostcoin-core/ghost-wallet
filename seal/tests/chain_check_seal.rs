//! The Seal with the chain check, on the simulated card: Fill's confirmation
//! and Check answer Sealed only for a coin paid exactly, settled and unspent,
//! and refuse otherwise; a journaled Open still answers first.

mod support;

use std::cell::RefCell;
use std::rc::Rc;

use ghost_seal::chain_check::safe_depth;
use ghost_seal::{
    CardState, CheckRequest, CoinQuery, FillOutcome, FillRequest, MemoryJournal, OpenRequest, Seal, SealError,
    SignedAnswer,
};
use support::nodes::{FakeChain, FakeNode, node_check, two_nodes};
use support::{AMOUNT, SimCard, StubChain, StubMaker, TestClock, UID};

/// A filled card, its Seal's journal and the chain its two nodes read.
struct Rig {
    card: SimCard,
    journal: MemoryJournal,
    clock: TestClock,
    maker: StubMaker,
    chain: Rc<RefCell<FakeChain>>,
    a: FakeNode,
    b: FakeNode,
    filled: FillOutcome,
}

impl Rig {
    /// A card filled by a Seal (no chain status check needed to fill).
    fn filled() -> Rig {
        let journal = MemoryJournal::new();
        let clock = TestClock::new();
        let mut maker = StubMaker::default();
        let mut card = SimCard::set_up(UID);
        let filled = support::seal(&journal, &clock, 1)
            .fill(&mut card, &FillRequest { uid: UID, challenge: [1; 32], amount_wei: AMOUNT, pin: None }, &mut maker)
            .expect("fill");
        let chain = FakeChain::new().shared();
        let (a, b) = two_nodes(&chain);
        Rig { card, journal, clock, maker, chain, a, b, filled }
    }

    fn coin(&self) -> CoinQuery {
        CoinQuery {
            commit_data: self.filled.commit_data.clone(),
            amount_wei: AMOUNT,
            spend_marker: self.maker.marker_for(&self.filled.commit_data),
        }
    }

    /// A Seal over the rig's journal with the chain status check installed.
    fn seal(&self) -> Seal {
        support::seal(&self.journal, &self.clock, 2).with_chain_status(Box::new(node_check(&[&self.a, &self.b])))
    }

    /// A Seal over the rig's journal without it.
    fn plain_seal(&self) -> Seal {
        support::seal(&self.journal, &self.clock, 3)
    }

    fn pay(&self, depth: u64) {
        let coin = self.coin();
        self.chain.borrow_mut().pay(&coin, depth);
    }

    fn check(&mut self, seal: &mut Seal) -> Result<SignedAnswer, SealError> {
        seal.check(&mut self.card, &CheckRequest { uid: UID, challenge: [0x0c; 32] })
    }

    /// Fill's confirmation with the node chain check as its chain check.
    fn confirm(&mut self, seal: &mut Seal) -> Result<SignedAnswer, SealError> {
        let chain = node_check(&[&self.a, &self.b]).with_coin(self.coin());
        seal.confirm_fill(&mut self.card, &CheckRequest { uid: UID, challenge: [0x0f; 32] }, &chain)
    }

    /// Fill's confirmation with a chain check that calls every coin paid.
    fn confirm_with_lax_chain(&mut self, seal: &mut Seal) -> Result<SignedAnswer, SealError> {
        let lax = StubChain::default();
        lax.pay(&self.filled.commit_data, AMOUNT);
        seal.confirm_fill(&mut self.card, &CheckRequest { uid: UID, challenge: [0x0e; 32] }, &lax)
    }

    /// A rig whose card is Sealed through the node chain check.
    fn sealed() -> Rig {
        let mut rig = Rig::filled();
        rig.pay(safe_depth(AMOUNT));
        let mut seal = rig.seal();
        assert_eq!(rig.confirm(&mut seal).expect("sealed").body.state, CardState::Sealed);
        rig
    }
}

fn state(answer: Result<SignedAnswer, SealError>) -> CardState {
    answer.expect("an answer").body.state
}

#[test]
fn fill_confirmation_seals_only_an_exact_settled_unspent_coin() {
    let mut rig = Rig::filled();
    let mut seal = rig.seal();

    assert_eq!(rig.confirm(&mut seal).err(), Some(SealError::NotPaid), "nothing paid");
    assert_eq!(state(rig.check(&mut seal)), CardState::Empty);

    rig.chain.borrow_mut().vanish(&rig.filled.commit_data, AMOUNT);
    for _ in 1..safe_depth(AMOUNT) {
        assert_eq!(rig.confirm(&mut seal).err(), Some(SealError::NotPaid), "paid but not settled");
        assert_eq!(state(rig.check(&mut seal)), CardState::Empty, "the card stays Empty while it fills");
        rig.chain.borrow_mut().mine(1);
    }

    let sealed = rig.confirm(&mut seal).expect("settled");
    assert_eq!(sealed.body.state, CardState::Sealed);
    assert_eq!(sealed.body.amount_wei, AMOUNT);
    let checked = rig.check(&mut seal).expect("check");
    assert_eq!(checked.body.state, CardState::Sealed);
    assert_eq!(checked.body.coin, rig.coin().coin());
}

#[test]
fn fill_confirmation_refuses_a_wrong_payment() {
    for paid in [AMOUNT - 1, AMOUNT + 1] {
        let mut rig = Rig::filled();
        rig.chain.borrow_mut().vanish(&rig.filled.commit_data, paid);
        rig.chain.borrow_mut().mine(10);
        let mut seal = rig.seal();
        assert_eq!(rig.confirm(&mut seal).err(), Some(SealError::PaymentMismatch), "paid {paid}");
        assert_eq!(rig.confirm_with_lax_chain(&mut seal).err(), Some(SealError::PaymentMismatch), "paid {paid}");
        assert_eq!(state(rig.check(&mut seal)), CardState::Empty);
    }
}

#[test]
fn the_installed_check_gates_fill_confirmation_whatever_chain_check_is_passed() {
    // Paid, not yet settled.
    let mut rig = Rig::filled();
    rig.chain.borrow_mut().vanish(&rig.filled.commit_data, AMOUNT);
    let mut seal = rig.seal();
    assert_eq!(rig.confirm_with_lax_chain(&mut seal).err(), Some(SealError::NotSettled));
    assert_eq!(state(rig.check(&mut seal)), CardState::Empty, "nothing was written");

    // Settled but spent.
    rig.chain.borrow_mut().mine(safe_depth(AMOUNT));
    let marker = rig.coin().spend_marker;
    rig.chain.borrow_mut().spend(marker);
    assert_eq!(rig.confirm_with_lax_chain(&mut seal).err(), Some(SealError::CoinSpent));

    // A node down.
    let mut rig = Rig::filled();
    rig.pay(safe_depth(AMOUNT));
    let mut seal = rig.seal();
    rig.b.down.set(true);
    assert_eq!(rig.confirm_with_lax_chain(&mut seal).err(), Some(SealError::CantCheckNow));
    assert_eq!(rig.confirm(&mut seal).err(), Some(SealError::NotPaid));
    rig.b.down.set(false);
    assert_eq!(state(rig.confirm_with_lax_chain(&mut seal)), CardState::Sealed);
}

#[test]
fn check_refuses_sealed_once_the_coin_is_spent() {
    let mut rig = Rig::sealed();
    // A restarted Seal: the commit data and spend marker come from its journal.
    let mut seal = rig.seal();
    assert_eq!(state(rig.check(&mut seal)), CardState::Sealed);

    let marker = rig.coin().spend_marker;
    rig.chain.borrow_mut().spend(marker);
    assert_eq!(rig.check(&mut seal).err(), Some(SealError::CoinSpent));
    assert_eq!(rig.confirm(&mut seal).err(), Some(SealError::CoinSpent), "nor a confirmation again");
}

#[test]
fn check_cannot_check_with_a_node_down_or_the_nodes_apart() {
    let mut rig = Rig::sealed();
    let mut seal = rig.seal();
    rig.a.down.set(true);
    assert_eq!(rig.check(&mut seal).err(), Some(SealError::CantCheckNow));
    rig.b.down.set(true);
    assert_eq!(rig.check(&mut seal).err(), Some(SealError::CantCheckNow));
    rig.a.down.set(false);
    rig.b.down.set(false);
    assert_eq!(state(rig.check(&mut seal)), CardState::Sealed);

    // Node b now follows its own copy of the chain, a block ahead.
    let ahead = rig.chain.borrow().clone().shared();
    ahead.borrow_mut().mine(1);
    rig.b = FakeNode::new("node-b", &ahead);
    let mut seal = rig.seal();
    assert_eq!(rig.check(&mut seal).err(), Some(SealError::CantCheckNow));
}

#[test]
fn check_refuses_a_card_sealed_on_a_payment_that_is_not_settled_or_exact() {
    // Sealed by a Seal without the status check, on a lax chain check.
    let mut rig = Rig::filled();
    let mut plain = rig.plain_seal();
    assert_eq!(state(rig.confirm_with_lax_chain(&mut plain)), CardState::Sealed);
    assert_eq!(state(rig.check(&mut plain)), CardState::Sealed, "without the status check, Check is unchanged");

    let mut seal = rig.seal();
    assert_eq!(rig.check(&mut seal).err(), Some(SealError::NotSettled), "nothing paid");
    rig.chain.borrow_mut().vanish(&rig.filled.commit_data, AMOUNT);
    assert_eq!(rig.check(&mut seal).err(), Some(SealError::NotSettled), "one block deep");

    let mut underpaid = Rig::filled();
    let mut plain = underpaid.plain_seal();
    assert_eq!(state(underpaid.confirm_with_lax_chain(&mut plain)), CardState::Sealed);
    underpaid.chain.borrow_mut().vanish(&underpaid.filled.commit_data, AMOUNT - 1);
    underpaid.chain.borrow_mut().mine(10);
    let mut seal = underpaid.seal();
    assert_eq!(underpaid.check(&mut seal).err(), Some(SealError::PaymentMismatch));
}

#[test]
fn without_the_status_check_check_is_unchanged() {
    let mut rig = Rig::sealed();
    rig.a.down.set(true);
    rig.b.down.set(true);
    let mut plain = rig.plain_seal();
    assert_eq!(state(rig.check(&mut plain)), CardState::Sealed);
}

#[test]
fn a_seal_with_no_fill_entry_for_the_coin_never_answers_sealed() {
    let mut rig = Rig::sealed();
    let lost = MemoryJournal::new();
    let mut seal = support::seal(&lost, &rig.clock, 4).with_chain_status(Box::new(node_check(&[&rig.a, &rig.b])));
    assert!(matches!(rig.check(&mut seal), Err(SealError::Journal(_))));
}

#[test]
fn a_journaled_open_still_answers_first() {
    let mut rig = Rig::sealed();
    let mut seal = rig.seal();
    let phone = support::phone(0x51);
    let opened = seal
        .open(&mut rig.card, &OpenRequest { uid: UID, challenge: [0x52; 32], phone_key: phone.public_key(), pin: None })
        .expect("open");
    assert_eq!(opened.answer.body.state, CardState::Opened);

    // The receiver spends the coin and the nodes go away: Check still answers
    // Opened, from the journal.
    let marker = rig.coin().spend_marker;
    rig.chain.borrow_mut().spend(marker);
    assert_eq!(state(rig.check(&mut seal)), CardState::Opened);
    rig.a.down.set(true);
    assert_eq!(state(rig.check(&mut seal)), CardState::Opened);
}

#[test]
fn the_fill_journal_keeps_the_makers_spend_marker() {
    let mut rig = Rig::sealed();
    // A marker other than the coin's being spent changes nothing.
    rig.chain.borrow_mut().spend(support::stub_spend_marker(b"another key"));
    let mut seal = rig.seal();
    assert_eq!(state(rig.check(&mut seal)), CardState::Sealed);
    assert_eq!(rig.coin().spend_marker, support::stub_spend_marker(&rig.maker.key_for(&rig.filled.commit_data)));
}
