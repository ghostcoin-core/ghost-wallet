//! A Phantom Key on an NTAG 424 DNA card, as far as the native core goes.
//!
//! The card module (`modules/ghost-nfc/ios`) seals the Phantom Key under the
//! card's own keys and writes it; it reads it back and opens it. The key
//! crosses between this core and that module through two C functions, which
//! the UniFFI bindings do not carry, so JavaScript can neither ask for a key
//! nor see one:
//!
//! - [`ghost_wallet_card_copy_new_key`] copies the words of the key Vanish
//!   holds, once they were shown and three of them typed back (the card is
//!   never the only copy), for the card module to seal;
//! - [`ghost_wallet_card_hold_key`] takes the words a card held, checks they
//!   are a Phantom Key and holds them here.
//!
//! [`find_card_key_coins`] and [`prove_card_key_reveal`] then Summon or Claim
//! with the held card key exactly as the typed-key calls do, and
//! [`forget_card_key`] wipes it. Nothing here logs or formats a key.

use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::accounts::wipe_string;
use crate::vanish::{
    CoinLeaf, KeyCoins, ProvedReveal, RevealRequest, VanishError, classify_words, find_key_coins, new_key,
    prove_key_reveal,
};

/// The key a card handed over: its words, wiped when replaced or forgotten.
static CARD_KEY: Mutex<Option<String>> = Mutex::new(None);

/// No key is held, or its words were not checked yet.
pub const CARD_NO_KEY: isize = -1;
/// The buffer is too small for the words.
pub const CARD_TOO_SMALL: isize = -2;
/// A null pointer was passed.
pub const CARD_NULL: isize = -3;

fn card_key() -> MutexGuard<'static, Option<String>> {
    CARD_KEY.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Copies the words of the Phantom Key Vanish holds (UTF-8, no terminator)
/// into `out`, and returns how many bytes were written, or [`CARD_NO_KEY`],
/// [`CARD_TOO_SMALL`] or [`CARD_NULL`]. The key stays held for the Vanish.
///
/// # Safety
///
/// `out` must be valid for writes of `capacity` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_wallet_card_copy_new_key(out: *mut u8, capacity: usize) -> isize {
    if out.is_null() {
        return CARD_NULL;
    }
    let copied = new_key().with_checked_words(|words| {
        let bytes = words.as_bytes();
        if bytes.len() > capacity {
            return CARD_TOO_SMALL;
        }
        // SAFETY: the caller guarantees `out` holds `capacity` bytes, and
        // `bytes.len() <= capacity`.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
        bytes.len() as isize
    });
    copied.unwrap_or(CARD_NO_KEY)
}

/// Holds the Phantom Key a card handed over (`length` bytes of UTF-8 words
/// at `words`). Returns 0, [`CARD_NO_KEY`] when the bytes are not a Phantom
/// Key (account words never are), or [`CARD_NULL`]. A key held before is
/// wiped.
///
/// # Safety
///
/// `words` must be valid for reads of `length` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_wallet_card_hold_key(words: *const u8, length: usize) -> isize {
    if words.is_null() {
        return CARD_NULL;
    }
    // SAFETY: the caller guarantees `words` holds `length` bytes.
    let bytes = unsafe { core::slice::from_raw_parts(words, length) };
    let Ok(text) = core::str::from_utf8(bytes) else {
        return CARD_NO_KEY;
    };
    let text = text.to_owned();
    if !hold_card_words(text) {
        return CARD_NO_KEY;
    }
    0
}

/// Holds `text` as the card key when it is a Phantom Key; wipes it otherwise.
pub fn hold_card_words(text: String) -> bool {
    if classify_words(&text).verdict != "phantom-key" {
        wipe_string(text);
        return false;
    }
    if let Some(old) = card_key().replace(text) {
        wipe_string(old);
    }
    true
}

/// A copy of the held card key, for one lookup or proof (which wipes it).
fn card_key_text() -> Result<String, VanishError> {
    card_key().as_ref().cloned().ok_or(VanishError::NoKeyHeld)
}

/// Whether a card's Phantom Key is held.
#[uniffi::export]
pub fn has_card_key() -> bool {
    card_key().is_some()
}

/// Wipes the card's Phantom Key.
#[uniffi::export]
pub fn forget_card_key() {
    if let Some(old) = card_key().take() {
        wipe_string(old);
    }
}

/// [`find_key_coins`] with the key the card handed over.
#[uniffi::export]
pub fn find_card_key_coins(chain_id: u64, leaves: Vec<CoinLeaf>, spent: Vec<Vec<u8>>) -> Result<KeyCoins, VanishError> {
    find_key_coins(card_key_text()?, chain_id, leaves, spent)
}

/// [`prove_key_reveal`] with the key the card handed over.
#[uniffi::export]
pub fn prove_card_key_reveal(
    request: RevealRequest,
    leaves: Vec<CoinLeaf>,
    spent: Vec<Vec<u8>>,
) -> Result<ProvedReveal, VanishError> {
    prove_key_reveal(card_key_text()?, request, leaves, spent)
}
