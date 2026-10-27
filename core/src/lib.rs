//! Native core of Ghost Wallet.
//!
//! A thin layer over Ghost's `client` crate, exported to the app through
//! UniFFI. It holds no derivation code of its own: every key and address comes
//! from `ghost_client`. Nothing here logs, prints or formats secret material.

use core::fmt;

use ghost_client::account::{SeedError, WalletSeed};

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

fn to_hex_address(address: &[u8; 20]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + 2 * address.len());
    out.push_str("0x");
    for byte in address {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}
