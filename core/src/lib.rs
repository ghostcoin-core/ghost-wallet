//! Native core of Ghost Wallet.
//!
//! A thin layer over Ghost's `client` crate, exported to the app through
//! UniFFI. It holds no derivation code of its own: every key and address comes
//! from `ghost_client`. Nothing here logs, prints or formats secret material.

use core::fmt;

use ghost_client::account::{SeedError, WalletSeed};

pub mod accounts;
pub mod header_sync;
#[cfg(target_os = "ios")]
pub mod keychain;
pub mod restore_scan;
pub mod send;
pub mod spot_check;
pub mod step_sequence;
pub mod summon;
pub mod vanish;

pub use accounts::{
    AccountError, AccountVault, CHECKED_WORDS, MemoryStore, SeedStore, check_new_account_word, discard_new_account,
    has_account, import_account_words, is_account_word, is_listed_word, new_account_words, save_new_account,
    saved_account_words, saved_account_zero_address,
};
pub use header_sync::{
    ChainState, DeviceConditions, HeaderChainConstants, HeaderProgress, HeaderRun, HeaderStore, HeaderSync,
    HeaderSyncError, PinnedKeyBlock, RECENT_HEADERS, ReorgEvent, RunBudget, RunProgress, RunSpent,
    SAVED_STATE_VERSION, StopReason, ThermalState,
};
pub use restore_scan::{
    AccountLookup, AccountState, DerivedAccount, GAP_LIMIT, RestoreError, RestoreLookup, RestoreResult,
    RestoredAccount, UNVERIFIED_NOTE,
};
pub use send::{
    RESCUE_TRANSFER_GAS, SendError, SignedTestSend, TEST_CHAIN_ID, TestSend, sign_test_send, sign_test_send_with,
    test_chain_id, test_send_gas_limit, test_send_sender,
};
pub use spot_check::{SpotCheckError, SpotCheckKey, SpotCheckReport, spot_check_header, spot_check_seed_height};
pub use step_sequence::{
    Attempt, ChainView, Identity, Inclusion, MAX_ATTEMPTS, PaymentIntent, PaymentKind, PaymentRecord, PaymentSequence,
    PaymentStore, RECORD_VERSION, Receipt, ReceiptStatus, Recovery, SETTLE_CONFIRMATIONS, Step, StepError,
    decode_payment_record, encode_payment_record, settle_confirmations, transaction_hash,
};
pub use summon::{SummonError, SummonReport, prove_test_summon};
pub use vanish::{
    BuiltPrivateTx, CHECKED_KEY_WORDS, COMMIT_DATA_BYTES, COMMIT_ENTRY, CoinLeaf, ENVELOPE_BYTES, FEE_WINDOW,
    FeeWindow, KeyCoins, KeyVault, MIN_VANISH_FEES, PRIVATE_TX_GAS, PRIVATE_TX_TYPE, ProvedReveal, RevealRequest,
    RevealedLeaf, SignedVanish, VANISH_GAS_LIMIT, VANISH_MIN_GAS, VanishCommit, VanishError, VanishSend, WordsCheck,
    check_key_words, check_phantom_key_word, classify_words, commit_leaf, confirm_phantom_key_saved, fee_window,
    find_coins, find_key_coins, forget_phantom_key, min_vanish_wei, parse_wei, prepare_vanish, private_envelope,
    prove_key_reveal, prove_reveal_with, reveal_fee, reveal_fee_wei, reveal_leaf, sign_vanish, sign_vanish_with,
    take_phantom_key_words, vanish_commit_with,
};

uniffi::setup_scaffolding!();

/// Why a set of words could not be turned into an account.
///
/// The messages never contain the words themselves.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum WordsError {
    /// The words are not a valid Ghost account phrase.
    Invalid { reason: String },
}

impl fmt::Display for WordsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WordsError::Invalid { reason } => write!(f, "invalid account words: {reason}"),
        }
    }
}

impl std::error::Error for WordsError {}

impl From<SeedError> for WordsError {
    fn from(error: SeedError) -> Self {
        WordsError::Invalid { reason: error.to_string() }
    }
}

/// Returns the address of account 0 for the given 24 account words, as `0x`
/// followed by 40 lowercase hex digits.
///
/// The account uses the rescue-key scheme `0x0003`, the default of Ghost's
/// wallet. The seed is wiped by `ghost_client` when it goes out of scope.
#[uniffi::export]
pub fn account_zero_address(words: String) -> Result<String, WordsError> {
    let seed = WalletSeed::from_words(&words)?;
    let account = seed.rescue_account(0);
    Ok(to_hex_address(account.address()))
}

pub(crate) fn to_hex_address(address: &[u8; 20]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + 2 * address.len());
    out.push_str("0x");
    for byte in address {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}
