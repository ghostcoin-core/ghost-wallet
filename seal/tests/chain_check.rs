//! The chain check against fake nodes: exact payment, wrong payments, the
//! settlement depth, spent coins, and the agreement of two or more nodes.

mod support;

use ghost_seal::chain_check::{MIN_NODES, safe_depth};
use ghost_seal::primitives::sha3_256;
use ghost_seal::{
    ChainCheck, ChainNode, CoinClaim, CoinStatus, CoinStatusCheck, NodeChainCheck, NodeListError, PaymentVerdict,
    TxOutcome,
};
use support::UID;
use support::nodes::{
    FakeChain, FakeNode, NETWORK, OTHER_CHAIN, OTHER_GENESIS, node_check, test_coin, test_commit_data, two_nodes,
};

const AMOUNT: u128 = 1_500_000_000_000_000_000;

fn depth() -> u64 {
    safe_depth(AMOUNT)
}

fn filling(confirmations: u64) -> CoinStatus {
    CoinStatus::Filling { confirmations, needed: depth() }
}

fn claim(coin: &ghost_seal::CoinQuery) -> CoinClaim {
    CoinClaim { uid: UID, coin: coin.coin(), amount_wei: coin.amount_wei }
}

#[test]
fn the_settlement_depth_is_the_wallets() {
    assert_eq!(depth(), ghost_wallet_core::settle_confirmations());
    assert_eq!(safe_depth(1), ghost_wallet_core::settle_confirmations());
    assert!(depth() >= 2, "these tests need a depth with a step below it");
}

#[test]
fn an_exact_settled_unspent_payment_is_the_only_paid_one() {
    let coin = test_coin(1, AMOUNT);
    let chain = FakeChain::new().shared();
    chain.borrow_mut().pay(&coin, depth());
    let (a, b) = two_nodes(&chain);
    let check = node_check(&[&a, &b]).with_coin(coin.clone());
    assert_eq!(check.coin_status(&coin), CoinStatus::ExactSettledUnspent);
    assert_eq!(check.confirm_payment(&claim(&coin)), PaymentVerdict::Paid);
    assert!(a.calls.get() > 0 && b.calls.get() > 0, "both nodes are asked");
}

#[test]
fn underpaid_and_overpaid_are_the_wrong_amount() {
    for paid in [AMOUNT - 1, AMOUNT / 2, AMOUNT + 1, AMOUNT * 2] {
        let coin = test_coin(2, AMOUNT);
        let chain = FakeChain::new().shared();
        chain.borrow_mut().vanish(&coin.commit_data, paid);
        chain.borrow_mut().mine(depth() + 5);
        let (a, b) = two_nodes(&chain);
        let check = node_check(&[&a, &b]).with_coin(coin.clone());
        assert_eq!(check.coin_status(&coin), CoinStatus::WrongAmount, "paid {paid}");
        assert_eq!(check.confirm_payment(&claim(&coin)), PaymentVerdict::Mismatch);
    }
}

#[test]
fn an_exact_payment_next_to_a_wrong_one_still_counts() {
    let coin = test_coin(3, AMOUNT);
    let chain = FakeChain::new().shared();
    chain.borrow_mut().vanish(&coin.commit_data, AMOUNT - 1);
    chain.borrow_mut().pay(&coin, depth());
    let (a, b) = two_nodes(&chain);
    assert_eq!(node_check(&[&a, &b]).coin_status(&coin), CoinStatus::ExactSettledUnspent);
}

#[test]
fn other_commit_data_with_the_coins_fingerprint_is_wrong_commit_data() {
    let coin = test_coin(4, AMOUNT);
    let mut other = coin.commit_data.clone();
    let last = other.len() - 1;
    other[last] ^= 0x01;
    assert_eq!(other[2..34], coin.commit_data[2..34], "the same fingerprint");
    let chain = FakeChain::new().shared();
    chain.borrow_mut().vanish(&other, AMOUNT);
    chain.borrow_mut().mine(depth() + 5);
    let (a, b) = two_nodes(&chain);
    let check = node_check(&[&a, &b]).with_coin(coin.clone());
    assert_eq!(check.coin_status(&coin), CoinStatus::WrongCommitData);
    assert_eq!(check.confirm_payment(&claim(&coin)), PaymentVerdict::Mismatch);
}

#[test]
fn commit_data_the_core_refuses_is_wrong_commit_data() {
    let mut coin = test_coin(5, AMOUNT);
    coin.commit_data[1] = 0x02;
    let chain = FakeChain::new().shared();
    let (a, b) = two_nodes(&chain);
    assert_eq!(node_check(&[&a, &b]).coin_status(&coin), CoinStatus::WrongCommitData);
}

#[test]
fn nodes_on_another_chain_id_or_genesis_are_the_wrong_chain() {
    for network in [OTHER_CHAIN, OTHER_GENESIS] {
        let coin = test_coin(6, AMOUNT);
        let mut fake = FakeChain::new();
        fake.network = network;
        let chain = fake.shared();
        chain.borrow_mut().pay(&coin, depth());
        let (a, b) = two_nodes(&chain);
        let check = node_check(&[&a, &b]).with_coin(coin.clone());
        assert_eq!(check.network(), NETWORK);
        assert_eq!(check.coin_status(&coin), CoinStatus::WrongChain, "{network:?}");
        assert_eq!(check.confirm_payment(&claim(&coin)), PaymentVerdict::Mismatch);
    }
}

#[test]
fn a_vanish_signed_for_another_chain_is_the_wrong_chain() {
    let coin = test_coin(7, AMOUNT);
    let chain = FakeChain::new().shared();
    chain.borrow_mut().send(&coin.commit_data, AMOUNT, OTHER_CHAIN.chain_id, TxOutcome::Succeeded);
    chain.borrow_mut().mine(depth() + 5);
    let (a, b) = two_nodes(&chain);
    assert_eq!(node_check(&[&a, &b]).coin_status(&coin), CoinStatus::WrongChain);
}

#[test]
fn a_payment_below_the_safe_depth_is_filling_never_paid() {
    let coin = test_coin(8, AMOUNT);
    let chain = FakeChain::new().shared();
    let (a, b) = two_nodes(&chain);
    let check = node_check(&[&a, &b]).with_coin(coin.clone());

    assert_eq!(check.coin_status(&coin), filling(0), "nothing paid yet");
    assert_eq!(check.confirm_payment(&claim(&coin)), PaymentVerdict::NotYet);

    chain.borrow_mut().vanish(&coin.commit_data, AMOUNT);
    for confirmations in 1..depth() {
        assert_eq!(check.coin_status(&coin), filling(confirmations));
        assert_eq!(check.confirm_payment(&claim(&coin)), PaymentVerdict::NotYet);
        chain.borrow_mut().mine(1);
    }
    assert_eq!(check.coin_status(&coin), CoinStatus::ExactSettledUnspent);
    assert_eq!(check.confirm_payment(&claim(&coin)), PaymentVerdict::Paid);
}

#[test]
fn a_failed_vanish_pays_nothing() {
    let coin = test_coin(9, AMOUNT);
    let chain = FakeChain::new().shared();
    chain.borrow_mut().send(&coin.commit_data, AMOUNT, NETWORK.chain_id, TxOutcome::Failed);
    chain.borrow_mut().mine(depth() + 5);
    let (a, b) = two_nodes(&chain);
    assert_eq!(node_check(&[&a, &b]).coin_status(&coin), filling(0));
}

#[test]
fn a_spent_coin_is_spent() {
    let coin = test_coin(10, AMOUNT);
    let chain = FakeChain::new().shared();
    chain.borrow_mut().pay(&coin, depth());
    chain.borrow_mut().spend(sha3_256(&[b"another coin's marker"]));
    let (a, b) = two_nodes(&chain);
    let check = node_check(&[&a, &b]).with_coin(coin.clone());
    assert_eq!(check.coin_status(&coin), CoinStatus::ExactSettledUnspent, "another marker is not this coin's");

    chain.borrow_mut().spend(coin.spend_marker);
    assert_eq!(check.coin_status(&coin), CoinStatus::Spent);
    assert_eq!(check.confirm_payment(&claim(&coin)), PaymentVerdict::Mismatch);
}

#[test]
fn a_spend_before_the_safe_depth_is_still_spent() {
    let coin = test_coin(11, AMOUNT);
    let chain = FakeChain::new().shared();
    chain.borrow_mut().vanish(&coin.commit_data, AMOUNT);
    chain.borrow_mut().spent.insert(coin.spend_marker);
    let (a, b) = two_nodes(&chain);
    assert_eq!(node_check(&[&a, &b]).coin_status(&coin), CoinStatus::Spent);
}

#[test]
fn nodes_that_disagree_on_the_tip_cannot_check() {
    let coin = test_coin(12, AMOUNT);
    let first = FakeChain::new().shared();
    first.borrow_mut().pay(&coin, depth() + 1);

    // One block ahead, with the same result.
    let ahead = first.borrow().clone().shared();
    ahead.borrow_mut().mine(1);
    let (a, _) = two_nodes(&first);
    let b = FakeNode::new("node-b", &ahead);
    assert_eq!(node_check(&[&a, &b]).coin_status(&coin), CoinStatus::CantCheckNow);

    // The same height on another fork.
    let fork = first.borrow().clone().shared();
    fork.borrow_mut().fork = 1;
    let c = FakeNode::new("node-c", &fork);
    assert_eq!(node_check(&[&a, &c]).coin_status(&coin), CoinStatus::CantCheckNow);

    // The same tip again agrees.
    let same = first.borrow().clone().shared();
    let d = FakeNode::new("node-d", &same);
    assert_eq!(node_check(&[&a, &d]).coin_status(&coin), CoinStatus::ExactSettledUnspent);
}

#[test]
fn nodes_that_agree_on_the_tip_but_not_the_result_cannot_check() {
    let coin = test_coin(13, AMOUNT);
    let honest = FakeChain::new().shared();
    honest.borrow_mut().pay(&coin, depth());
    honest.borrow_mut().spend(coin.spend_marker);

    // A node that hides the spend, at the same tip.
    let hiding = honest.borrow().clone().shared();
    hiding.borrow_mut().spent.clear();
    let a = FakeNode::new("node-a", &honest);
    let b = FakeNode::new("node-b", &hiding);
    assert_eq!(a.tip(), b.tip());
    let check = node_check(&[&a, &b]).with_coin(coin.clone());
    assert_eq!(check.coin_status(&coin), CoinStatus::CantCheckNow);
    assert_eq!(check.confirm_payment(&claim(&coin)), PaymentVerdict::NotYet);

    // Three nodes, one of them out of line: still no answer.
    let c = FakeNode::new("node-c", &honest);
    assert_eq!(node_check(&[&a, &c, &b]).coin_status(&coin), CoinStatus::CantCheckNow);
    assert_eq!(node_check(&[&a, &c]).coin_status(&coin), CoinStatus::Spent);
}

#[test]
fn one_node_down_cannot_check() {
    let coin = test_coin(14, AMOUNT);
    let chain = FakeChain::new().shared();
    chain.borrow_mut().pay(&coin, depth());
    let (a, b) = two_nodes(&chain);
    let check = node_check(&[&a, &b]).with_coin(coin.clone());
    for down in [&a, &b] {
        down.down.set(true);
        assert_eq!(check.coin_status(&coin), CoinStatus::CantCheckNow);
        assert_eq!(check.confirm_payment(&claim(&coin)), PaymentVerdict::NotYet);
        down.down.set(false);
        assert_eq!(check.coin_status(&coin), CoinStatus::ExactSettledUnspent);
    }
}

#[test]
fn both_nodes_down_cannot_check() {
    let coin = test_coin(15, AMOUNT);
    let chain = FakeChain::new().shared();
    chain.borrow_mut().pay(&coin, depth());
    let (a, b) = two_nodes(&chain);
    a.down.set(true);
    b.down.set(true);
    let check = node_check(&[&a, &b]).with_coin(coin.clone());
    assert_eq!(check.coin_status(&coin), CoinStatus::CantCheckNow);
    assert_eq!(check.confirm_payment(&claim(&coin)), PaymentVerdict::NotYet);
}

#[test]
fn a_receipt_whose_leaf_is_not_in_the_tree_cannot_check() {
    let coin = test_coin(16, AMOUNT);
    let mut fake = FakeChain::new();
    fake.drop_leaves = true;
    let chain = fake.shared();
    chain.borrow_mut().pay(&coin, depth());
    let (a, b) = two_nodes(&chain);
    assert_eq!(node_check(&[&a, &b]).coin_status(&coin), CoinStatus::CantCheckNow);
}

#[test]
fn a_receipt_whose_leaf_is_another_coins_cannot_check() {
    let coin = test_coin(17, AMOUNT);
    let chain = FakeChain::new().shared();
    chain.borrow_mut().pay(&coin, depth());
    // Another coin's leaf where the paid one should be, as if the node made
    // up the receipt.
    let position = chain.borrow().receipts[0].leaf_position as usize;
    chain.borrow_mut().leaves[position] = sha3_256(&[b"not this coin"]);
    let (a, b) = two_nodes(&chain);
    assert_eq!(node_check(&[&a, &b]).coin_status(&coin), CoinStatus::CantCheckNow);
}

#[test]
fn a_tree_that_does_not_hash_to_the_header_root_cannot_check() {
    let coin = test_coin(21, AMOUNT);
    let chain = FakeChain::new().shared();
    chain.borrow_mut().pay(&coin, depth());
    let (a, b) = two_nodes(&chain);
    assert_eq!(node_check(&[&a, &b]).coin_status(&coin), CoinStatus::ExactSettledUnspent);
    chain.borrow_mut().wrong_root = true;
    assert_eq!(node_check(&[&a, &b]).coin_status(&coin), CoinStatus::CantCheckNow);
}

#[test]
fn a_coin_in_a_later_page_is_found_there() {
    let coin = test_coin(22, AMOUNT);
    let mut fake = FakeChain::new();
    fake.leaves = (0..5000u32).map(|i| sha3_256(&[b"other coin", &i.to_be_bytes()])).collect();
    let chain = fake.shared();
    chain.borrow_mut().pay(&coin, depth());
    assert_eq!(chain.borrow().receipts[0].leaf_position, 5000);
    let (a, b) = two_nodes(&chain);
    assert_eq!(node_check(&[&a, &b]).coin_status(&coin), CoinStatus::ExactSettledUnspent);
}

#[test]
fn a_claim_for_a_coin_never_handed_over_is_not_yet() {
    let coin = test_coin(18, AMOUNT);
    let chain = FakeChain::new().shared();
    chain.borrow_mut().pay(&coin, depth());
    let (a, b) = two_nodes(&chain);
    let check = node_check(&[&a, &b]);
    assert_eq!(check.confirm_payment(&claim(&coin)), PaymentVerdict::NotYet);
    let other = node_check(&[&a, &b]).with_coin(test_coin(19, AMOUNT));
    assert_eq!(other.confirm_payment(&claim(&coin)), PaymentVerdict::NotYet);
    // The claim's amount is the one checked: the card's.
    let known = node_check(&[&a, &b]).with_coin(coin.clone());
    let mut more = claim(&coin);
    more.amount_wei += 1;
    assert_eq!(known.confirm_payment(&more), PaymentVerdict::Mismatch);
}

#[test]
fn a_check_needs_two_distinct_nodes() {
    assert_eq!(MIN_NODES, 2);
    let chain = FakeChain::new().shared();
    let (a, b) = two_nodes(&chain);
    let boxed = |nodes: &[&FakeNode]| -> Vec<Box<dyn ChainNode>> {
        nodes.iter().map(|node| Box::new((*node).clone()) as Box<dyn ChainNode>).collect()
    };
    assert_eq!(NodeChainCheck::new(NETWORK, boxed(&[])).err(), Some(NodeListError::TooFewNodes));
    assert_eq!(NodeChainCheck::new(NETWORK, boxed(&[&a])).err(), Some(NodeListError::TooFewNodes));
    assert_eq!(NodeChainCheck::new(NETWORK, boxed(&[&a, &a])).err(), Some(NodeListError::SameNodeTwice));
    assert!(NodeChainCheck::new(NETWORK, boxed(&[&a, &b])).is_ok());
}

#[test]
fn the_query_debug_output_leaves_the_spend_marker_out() {
    let coin = test_coin(20, AMOUNT);
    let shown = format!("{coin:?}");
    let marker_hex: String = coin.spend_marker.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!shown.contains(&marker_hex));
    assert!(!shown.contains(&format!("{:?}", coin.spend_marker)));
    assert_eq!(test_commit_data(20), coin.commit_data);
}
