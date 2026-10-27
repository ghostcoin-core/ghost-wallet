//! The Summon benchmark: one reveal of a salted coin on the test chain,
//! proved by Ghost's reveal builder and checked by Ghost's verifier.
//!
//! Proving is slow, so one proof is built once and shared by the checks that
//! only read it.

use std::sync::OnceLock;

use ghost_client::RevealError;
use ghost_client::reveal::ProofError;
use ghost_proofs::verify_salted_coin_reveal;
use ghost_wallet_core::summon::{TestSummon, build_test_summon, test_chain_params};
use ghost_wallet_core::{SummonError, prove_test_summon};

/// The example key digits the benchmark proves with. Example only.
const TEST_DIGITS: &str = "0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812";

fn summon() -> &'static TestSummon {
    static SUMMON: OnceLock<TestSummon> = OnceLock::new();
    SUMMON.get_or_init(|| build_test_summon().unwrap_or_else(|error| panic!("{error}")))
}

/// Fails if `text` holds the key digits, whole or any run of four groups.
fn assert_no_key_digits(text: &str) {
    let squashed: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let groups: Vec<&str> = TEST_DIGITS.split(' ').collect();
    for window in groups.windows(4) {
        assert!(!text.contains(&window.join(" ")), "the text holds the key digits");
        assert!(!squashed.contains(&window.concat()), "the text holds the key digits");
    }
}

#[test]
fn summon_proof_verifies() {
    let s = summon();
    assert_eq!(verify_salted_coin_reveal(&s.params, &s.reveal, &s.proof), Ok(()));
    assert!(!s.proof.as_bytes().is_empty());
    // It pays the test recipient on the test chain.
    assert_eq!(s.reveal.recipient, [5; 20]);
    assert_eq!(s.params, test_chain_params());
}

#[test]
fn summon_proof_refused_for_a_changed_amount() {
    let s = summon();
    let mut changed = s.reveal.clone();
    changed.out[31] ^= 1;
    assert!(verify_salted_coin_reveal(&s.params, &changed, &s.proof).is_err());
}

#[test]
fn summon_proof_refused_for_a_changed_recipient() {
    let s = summon();
    let mut changed = s.reveal.clone();
    changed.recipient[0] ^= 1;
    assert!(verify_salted_coin_reveal(&s.params, &changed, &s.proof).is_err());
}

#[test]
fn summon_proof_refused_on_another_chain() {
    let s = summon();
    let mut other = s.params.clone();
    other.chain_id[7] ^= 1;
    assert!(verify_salted_coin_reveal(&other, &s.reveal, &s.proof).is_err());
}

#[test]
fn summon_report_says_verified() {
    let report = prove_test_summon().unwrap_or_else(|error| panic!("{error}"));
    assert!(report.verified);
    assert_eq!(report.proof_bytes, summon().proof.as_bytes().len() as u64);
    assert!(report.proof_bytes > 0);
    assert_no_key_digits(&format!("{report:?}"));
}

#[test]
fn summon_error_text_never_holds_the_key() {
    let errors = [
        SummonError::from(RevealError::Proof(ProofError::ConservationFails)),
        SummonError::from(RevealError::Proof(ProofError::NotInTree)),
        SummonError::from(RevealError::NumbersExhausted),
        SummonError::from(ProofError::Rejected),
    ];
    for error in errors {
        let SummonError::Failed { reason } = &error;
        assert!(!reason.is_empty());
        assert_no_key_digits(&error.to_string());
        assert_no_key_digits(&format!("{error:?}"));
    }
}

#[test]
fn key_digit_check_catches_the_digits() {
    // The check above would catch the key if it leaked.
    let leaked = format!("summon failed: {TEST_DIGITS}");
    assert!(std::panic::catch_unwind(|| assert_no_key_digits(&leaked)).is_err());
    let squashed = TEST_DIGITS.replace(' ', "");
    assert!(std::panic::catch_unwind(|| assert_no_key_digits(&squashed)).is_err());
}
