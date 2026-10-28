//! A plain send on the local test chain, signed here in the native core.
//!
//! The kill-recovery benchmark pays real GHOST on the test chain of
//! `scripts/test-chain.sh` from an account of the app's public test words
//! (Ghost's counting-bytes test seed, test data that guards nothing). The
//! transaction is an account transaction (`0x52`) of the rescue-key scheme
//! `0x0003`, signed by `ghost_client` with hedged ML-DSA-44; this module only
//! builds it, checks its inputs and hands back the hash, the sender and the
//! envelope to broadcast with `eth_sendRawTransaction`.
//!
//! It is test-only by name and by rule: it takes the public test words and
//! signs for the test chain's identifier only. A real wallet's seed never
//! crosses into the app; its send path stays inside native code.
//!
//! The randomness of the hedged signature comes from the operating system on
//! every signing ([`sign_test_send`]); only the tests pass their own
//! generator ([`sign_test_send_with`]). Nothing here logs or formats the
//! words, the seed, the key or the signature: [`SignedTestSend`]'s `Debug`
//! shows the envelope's length only, and errors hold reasons only.

use core::convert::Infallible;
use core::fmt;

use ghost_client::account::{
    AccountTx, RESCUE_PUBLIC_KEY_BYTES, SIG_BYTE_GAS, SIGNATURE_BYTES, VERIFY_GAS_ML_DSA_44, WalletSeed,
};
use rand::rngs::SysRng;
use rand::{CryptoRng, TryCryptoRng, TryRng};

use crate::to_hex_address;

/// The chain identifier of the local test chain (`scripts/test-chain.sh`).
pub const TEST_CHAIN_ID: u64 = 6_777_971;

/// The gas of a plain transfer from a rescue-key account (`0x0003`): 21,000,
/// plus 16 for each byte of the scheme, the 1,344-byte public key and the
/// 2,420-byte signature, plus 3,000 for the ML-DSA-44 check. The node's
/// `eth_estimateGas` leaves the scheme gas out, so this is set, not asked.
pub const RESCUE_TRANSFER_GAS: u64 =
    21_000 + SIG_BYTE_GAS * (2 + RESCUE_PUBLIC_KEY_BYTES as u64 + SIGNATURE_BYTES as u64) + VERIFY_GAS_ML_DSA_44;

/// What a test send pays and the chain data it is signed against. Nothing
/// here is secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TestSend {
    /// Must be [`TEST_CHAIN_ID`], checked against the node's `eth_chainId`.
    pub chain_id: u64,
    /// The hash of block 0, 32 bytes.
    pub genesis_hash: Vec<u8>,
    /// The sender's nonce: the payment's identity.
    pub nonce: u64,
    /// The recipient's 20-byte address.
    pub recipient: Vec<u8>,
    /// The amount in wei.
    pub value: u64,
    pub max_priority_fee_per_gas: u64,
    pub max_fee_per_gas: u64,
    /// At least [`RESCUE_TRANSFER_GAS`].
    pub gas_limit: u64,
}

/// A signed test send: what the payment saves and broadcasts. No key
/// material is in here.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct SignedTestSend {
    /// `keccak256(envelope)`.
    pub transaction_hash: Vec<u8>,
    /// The sender's 20-byte address.
    pub sender: Vec<u8>,
    /// `0x52 || rlp([...])`, the bytes sent with `eth_sendRawTransaction`.
    pub envelope: Vec<u8>,
}

impl fmt::Debug for SignedTestSend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The envelope holds the signature: only its length is shown.
        f.debug_struct("SignedTestSend")
            .field("transaction_hash", &hex(&self.transaction_hash))
            .field("sender", &hex(&self.sender))
            .field("envelope_len", &self.envelope.len())
            .finish()
    }
}

/// Why a test send was not signed. Never holds the words, a key or a
/// signature.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum SendError {
    /// The chain identifier is not the test chain's.
    WrongChain { expected: u64, found: u64 },
    /// The words are not a valid account phrase.
    Words { reason: String },
    /// An input is malformed.
    Malformed { reason: String },
    /// The operating system gave no randomness for the signature.
    Randomness,
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongChain { expected, found } => {
                write!(f, "a test send is signed for chain {expected} only, not {found}")
            }
            Self::Words { reason } => write!(f, "invalid account words: {reason}"),
            Self::Malformed { reason } => write!(f, "the test send is malformed: {reason}"),
            Self::Randomness => f.write_str("the operating system gave no randomness for the signature"),
        }
    }
}

impl std::error::Error for SendError {}

/// Signs a test send from account `account_index` of the public test words,
/// with fresh randomness from the operating system for the hedged signature.
/// Returns the hash, the sender and the envelope only.
#[uniffi::export]
pub fn sign_test_send(test_words: String, account_index: u32, send: TestSend) -> Result<SignedTestSend, SendError> {
    let mut rng = OsRandom { failed: false };
    let signed = sign_test_send_with(&test_words, account_index, &send, &mut rng)?;
    if rng.failed {
        // Signed with missing randomness: never hand it out.
        return Err(SendError::Randomness);
    }
    Ok(signed)
}

/// [`sign_test_send`] with the caller's generator. The app never calls this:
/// it is for the tests, which pass a seeded one.
pub fn sign_test_send_with<R: CryptoRng + ?Sized>(
    test_words: &str,
    account_index: u32,
    send: &TestSend,
    rng: &mut R,
) -> Result<SignedTestSend, SendError> {
    if send.chain_id != TEST_CHAIN_ID {
        return Err(SendError::WrongChain { expected: TEST_CHAIN_ID, found: send.chain_id });
    }
    let malformed = |reason: &str| SendError::Malformed { reason: reason.to_owned() };
    let genesis: [u8; 32] =
        send.genesis_hash.as_slice().try_into().map_err(|_| malformed("the genesis hash is not 32 bytes"))?;
    let recipient: [u8; 20] =
        send.recipient.as_slice().try_into().map_err(|_| malformed("the recipient is not 20 bytes"))?;
    if send.gas_limit < RESCUE_TRANSFER_GAS {
        return Err(malformed("the gas limit is below the gas of a plain transfer"));
    }
    if send.max_fee_per_gas < send.max_priority_fee_per_gas {
        return Err(malformed("the fee cap is below the priority fee"));
    }
    let seed = WalletSeed::from_words(test_words).map_err(|error| SendError::Words { reason: error.to_string() })?;
    let account = seed.rescue_account(account_index);
    drop(seed);
    let tx = AccountTx {
        chain_id: send.chain_id,
        nonce: send.nonce,
        max_priority_fee_per_gas: u128::from(send.max_priority_fee_per_gas),
        max_fee_per_gas: u128::from(send.max_fee_per_gas),
        gas_limit: send.gas_limit,
        to: Some(recipient),
        value: u128::from(send.value),
        data: Vec::new(),
        access_list: Vec::new(),
    };
    let signed = account.sign(&tx, &genesis, rng);
    Ok(SignedTestSend {
        transaction_hash: signed.hash.to_vec(),
        sender: signed.sender.to_vec(),
        envelope: signed.envelope,
    })
}

/// The address of account `account_index` of the public test words, as `0x`
/// and 40 lowercase hex digits: the sender of a test send.
#[uniffi::export]
pub fn test_send_sender(test_words: String, account_index: u32) -> Result<String, SendError> {
    let seed = WalletSeed::from_words(&test_words).map_err(|error| SendError::Words { reason: error.to_string() })?;
    Ok(to_hex_address(seed.rescue_account(account_index).address()))
}

/// The gas limit of a plain test send, [`RESCUE_TRANSFER_GAS`].
#[uniffi::export]
pub fn test_send_gas_limit() -> u64 {
    RESCUE_TRANSFER_GAS
}

/// The test chain's identifier, [`TEST_CHAIN_ID`].
#[uniffi::export]
pub fn test_chain_id() -> u64 {
    TEST_CHAIN_ID
}

/// The operating system's random source, read on every draw. A failed read
/// is remembered (and the bytes zeroed) rather than a panic across the
/// UniFFI boundary; [`sign_test_send`] then throws the signature away, and
/// `crate::accounts` the new words.
pub(crate) struct OsRandom {
    pub(crate) failed: bool,
}

impl TryRng for OsRandom {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        if SysRng.try_fill_bytes(dst).is_err() {
            dst.fill(0);
            self.failed = true;
        }
        Ok(())
    }
}

impl TryCryptoRng for OsRandom {}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
