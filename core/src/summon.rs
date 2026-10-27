//! The Summon benchmark: one reveal of a salted coin, proved by Ghost's own
//! reveal builder and checked by Ghost's own verifier.
//!
//! Everything is fixed and built here, as Ghost's `client/tests/second_slice.rs`
//! does: the example Phantom Key of spec 01, a small coin tree built by hand
//! on a test chain, and a generator seeded with a constant. Nothing is
//! downloaded, read from a file or touches real funds. Nothing here logs or
//! formats the key.

use core::fmt;
use std::time::Instant;

use ghost_client::reveal::{ChainParams, CoinReveal, ProofError, Proof, TREE_DEPTH};
use ghost_client::{
    Amount, KeyFormat, OwnedCoin, PhantomKey, RevealError, RevealTerms, Rule, partial_reveal,
};
use ghost_proofs::{PROTOCOL_VERSION_1, Tree, empty_leaf, tree_node, verify_salted_coin_reveal};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// The example words key of spec 01, section 5, as its digit view. Example
/// only: it has never held anything.
const TEST_DIGITS: &str = "0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812";
/// The example chain identifier of spec 01, section 14: a test chain.
const TEST_CHAIN_ID: u64 = 1234;
/// The seed of the test chain's generator.
const TEST_SEED: u64 = 0x5eed;
/// What the test key's coin holds, what the reveal pays out and its fee.
const COMMITTED: u128 = 1_000_000_000;
const PAID: u128 = 100_000_000;
const FEE: u128 = 21_000;
/// The test recipient.
const RECIPIENT: [u8; 20] = [5; 20];

/// What one Summon proof reports to the harness. No secret is in it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SummonReport {
    /// The size of the proof, in bytes.
    pub proof_bytes: u64,
    /// Whether Ghost's verifier accepted the proof.
    pub verified: bool,
    /// How long the reveal builder took to prove, in milliseconds.
    pub prove_millis: u64,
}

/// Why the Summon benchmark could not prove.
///
/// The messages never contain the key.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum SummonError {
    /// The test key or the reveal builder refused.
    Failed { reason: String },
}

impl fmt::Display for SummonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SummonError::Failed { reason } => write!(f, "summon failed: {reason}"),
        }
    }
}

impl std::error::Error for SummonError {}

impl From<RevealError> for SummonError {
    fn from(error: RevealError) -> Self {
        SummonError::Failed { reason: error.to_string() }
    }
}

impl From<ProofError> for SummonError {
    fn from(error: ProofError) -> Self {
        SummonError::Failed { reason: error.to_string() }
    }
}

/// One proved Summon: the public fields, the proof, and how long proving took.
pub struct TestSummon {
    /// The test chain's constants.
    pub params: ChainParams,
    /// The public fields of the reveal.
    pub reveal: CoinReveal,
    /// The proof.
    pub proof: Proof,
    /// How long the reveal builder took, in milliseconds.
    pub prove_millis: u64,
}

/// The constants of the test chain.
pub fn test_chain_params() -> ChainParams {
    ChainParams {
        chain_id: TEST_CHAIN_ID.to_be_bytes(),
        version: PROTOCOL_VERSION_1,
        domain: [7; 32],
    }
}

/// Builds the test chain and proves one partial reveal of the test key's
/// coin, with Ghost's `partial_reveal`. Only the proving call is timed.
pub fn build_test_summon() -> Result<TestSummon, SummonError> {
    let params = test_chain_params();
    let mut rng = StdRng::seed_from_u64(TEST_SEED);
    let key = PhantomKey::parse(TEST_DIGITS)
        .map_err(|_| SummonError::Failed { reason: "the test key does not parse".to_owned() })?;
    let other = PhantomKey::generate(KeyFormat::Words, &mut rng);

    // A small coin tree: another key's commit, then the test key's number 0.
    let committed = amount(COMMITTED)?;
    let other_commit = other
        .salted_coin_commit(0, amount(5_000)?, Rule::EMPTY, &mut rng)
        .map_err(|_| SummonError::Failed { reason: "the test commit was refused".to_owned() })?;
    let commit = key
        .salted_coin_commit(0, committed, Rule::EMPTY, &mut rng)
        .map_err(|_| SummonError::Failed { reason: "the test commit was refused".to_owned() })?;
    let leaves = [*other_commit.commitment.as_bytes(), *commit.commitment.as_bytes()];
    let position = 1;
    let (root, path) = root_and_path(&leaves, position);

    let coin = OwnedCoin {
        number: 0,
        amount: committed,
        rule: Rule::EMPTY,
        salt: commit.salt,
        position,
        path,
    };
    let terms = RevealTerms { root, recipient: RECIPIENT, fee: amount(FEE)? };
    let mut zk_randomness = [0u8; 32];
    rng.fill_bytes(&mut zk_randomness);

    let start = Instant::now();
    let built = partial_reveal(&params, &key, &coin, &terms, amount(PAID)?, &mut rng, zk_randomness)?;
    let prove_millis = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

    Ok(TestSummon { params, reveal: built.reveal, proof: built.proof, prove_millis })
}

/// Proves one Summon on the test chain and checks the proof with Ghost's
/// verifier, `ghost_proofs::verify_salted_coin_reveal`.
#[uniffi::export]
pub fn prove_test_summon() -> Result<SummonReport, SummonError> {
    let summon = build_test_summon()?;
    let verified = verify_salted_coin_reveal(&summon.params, &summon.reveal, &summon.proof).is_ok();
    Ok(SummonReport {
        proof_bytes: summon.proof.as_bytes().len() as u64,
        verified,
        prove_millis: summon.prove_millis,
    })
}

fn amount(wei: u128) -> Result<Amount, SummonError> {
    Amount::new(wei).map_err(|_| SummonError::Failed { reason: "a test amount is out of range".to_owned() })
}

/// The root over `leaves` (position order, the rest empty) and the path of
/// the leaf at `position`. Each path is 32 siblings; empty subtrees are zero
/// hashes.
fn root_and_path(leaves: &[[u8; 32]], position: u32) -> ([u8; 32], [[u8; 32]; TREE_DEPTH]) {
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut zero = empty_leaf();
    let mut path = [[0u8; 32]; TREE_DEPTH];
    let mut index = position as usize;
    for (depth, sibling) in path.iter_mut().enumerate() {
        *sibling = level.get(index ^ 1).copied().unwrap_or(zero);
        level = level
            .chunks(2)
            .map(|pair| tree_node(Tree::Coin, depth as u8, &pair[0], pair.get(1).unwrap_or(&zero)))
            .collect();
        zero = tree_node(Tree::Coin, depth as u8, &zero, &zero);
        index >>= 1;
    }
    (level[0], path)
}
