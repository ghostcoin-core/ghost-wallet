//! The account words: made, checked and saved here, in the native core.
//!
//! Create: [`new_account_words`] draws a new seed from the operating system's
//! random source and holds it in native memory; its 24 words go to the backup
//! screen, the only screen that shows them. [`check_new_account_word`] answers
//! whether the word at a position is the one typed from paper, and
//! [`save_new_account`] saves the seed to the Keychain once
//! [`CHECKED_WORDS`] different words have been typed right. Until then
//! [`discard_new_account`] forgets it.
//!
//! Import: [`import_account_words`] checks 24 typed words (the word list and
//! the checksum, by `ghost_client`) and saves them. [`is_account_word`] tells
//! the import screen whether one typed word is in the list.
//!
//! The seed is saved as its 32 bytes, in the Keychain of this device only
//! (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, never synchronised), and a
//! saved account is never overwritten. Off iOS (the Rust tests) the store is
//! [`MemoryStore`].
//!
//! Nothing here logs, prints or formats words or seeds: no type holding one
//! implements `Debug`, and errors hold positions and reasons only. Seeds are
//! wiped by `ghost_client` when dropped, the held words by `SeedWords`, and the
//! words the app passes in are wiped here once read. The copies UniFFI makes
//! to carry words across to JavaScript belong to the binding and are freed by
//! it.

use core::fmt;
use core::sync::atomic::{Ordering, compiler_fence};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

use ghost_client::account::{SEED_BYTES, SEED_WORDS, SeedError, WalletSeed};
use ghost_client::wordlist::WORDLIST;
use rand::CryptoRng;

use crate::send::OsRandom;
use crate::to_hex_address;

/// How many different words of a new account must be typed right before it
/// can be saved.
pub const CHECKED_WORDS: u32 = 3;

/// Why the account words could not be made, checked or saved. The messages
/// never hold a word.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum AccountError {
    /// The words are not a Ghost account.
    Words { reason: String },
    /// No new account is held: none was made, or it was saved or discarded.
    NoNewAccount,
    /// A word position is not 1 to 24.
    BadPosition { position: u32 },
    /// Too few words of the new account have been typed right to save it.
    NotChecked { checked: u32, needed: u32 },
    /// An account is saved already, and it is never overwritten.
    AccountExists,
    /// No account is saved.
    NoAccount,
    /// The operating system gave no randomness for the new words.
    Randomness,
    /// The saved account is not a 32-byte seed.
    BadSavedAccount,
    /// The Keychain refused, with this `OSStatus`.
    Keychain { status: i32 },
}

impl fmt::Display for AccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Words { reason } => write!(f, "invalid account words: {reason}"),
            Self::NoNewAccount => f.write_str("no new account is held"),
            Self::BadPosition { position } => write!(f, "word {position} is not 1 to {SEED_WORDS}"),
            Self::NotChecked { checked, needed } => {
                write!(f, "{checked} of the {needed} words to check have been typed right")
            }
            Self::AccountExists => f.write_str("an account is saved already"),
            Self::NoAccount => f.write_str("no account is saved"),
            Self::Randomness => f.write_str("the operating system gave no randomness for the new words"),
            Self::BadSavedAccount => f.write_str("the saved account is not a 32-byte seed"),
            Self::Keychain { status } => write!(f, "the Keychain refused (status {status})"),
        }
    }
}

impl std::error::Error for AccountError {}

impl From<SeedError> for AccountError {
    fn from(error: SeedError) -> Self {
        AccountError::Words { reason: error.to_string() }
    }
}

/// Where a saved account's seed lives: the Keychain on the phone.
pub trait SeedStore: Send + Sync {
    /// Whether a seed is saved.
    fn contains(&self) -> Result<bool, AccountError>;
    /// The saved seed, if any.
    fn load(&self) -> Result<Option<WalletSeed>, AccountError>;
    /// Saves `seed`; [`AccountError::AccountExists`] if one is saved already.
    fn save(&self, seed: &WalletSeed) -> Result<(), AccountError>;
}

/// A store in memory, wiped when dropped or overwritten: the store off iOS.
#[derive(Default)]
pub struct MemoryStore {
    seed: Mutex<Option<[u8; SEED_BYTES]>>,
}

impl MemoryStore {
    fn slot(&self) -> MutexGuard<'_, Option<[u8; SEED_BYTES]>> {
        self.seed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Overwrites the saved seed with zeros, as dropping the store does.
    fn wipe_seed(&self) {
        if let Some(bytes) = self.slot().as_mut() {
            wipe(bytes);
        }
    }
}

impl SeedStore for MemoryStore {
    fn contains(&self) -> Result<bool, AccountError> {
        Ok(self.slot().is_some())
    }

    fn load(&self) -> Result<Option<WalletSeed>, AccountError> {
        Ok(self.slot().as_ref().map(|bytes| WalletSeed::from_bytes(*bytes)))
    }

    fn save(&self, seed: &WalletSeed) -> Result<(), AccountError> {
        let mut slot = self.slot();
        if slot.is_some() {
            return Err(AccountError::AccountExists);
        }
        *slot = Some(*seed.as_bytes());
        Ok(())
    }
}

impl Drop for MemoryStore {
    fn drop(&mut self) {
        self.wipe_seed();
    }
}

/// A new account, held until it is saved or discarded.
struct NewAccount {
    seed: WalletSeed,
    /// Which positions have been typed right.
    checked: [bool; SEED_WORDS],
}

/// The accounts of one store: the saved one, and a new one being backed up.
pub struct AccountVault<S: SeedStore> {
    store: S,
    new_account: Mutex<Option<NewAccount>>,
}

impl<S: SeedStore> AccountVault<S> {
    pub fn new(store: S) -> Self {
        Self { store, new_account: Mutex::new(None) }
    }

    /// The store the accounts are saved in.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Makes a new account from the operating system's random source, holds
    /// it, and returns its 24 words. A new account held before is forgotten.
    pub fn new_account_words(&self) -> Result<Vec<String>, AccountError> {
        self.refuse_if_saved()?;
        let mut rng = OsRandom { failed: false };
        let seed = WalletSeed::generate(&mut rng);
        if rng.failed {
            // Made with missing randomness: dropped (and wiped), never shown.
            return Err(AccountError::Randomness);
        }
        Ok(self.hold(seed))
    }

    /// [`AccountVault::new_account_words`] with the caller's generator. The
    /// app never calls this: it is for the tests, which pass a seeded one.
    pub fn new_account_words_with<R: CryptoRng + ?Sized>(&self, rng: &mut R) -> Result<Vec<String>, AccountError> {
        self.refuse_if_saved()?;
        Ok(self.hold(WalletSeed::generate(rng)))
    }

    /// Whether the held new account's word at `position` (1 to 24) is `word`,
    /// ignoring surrounding spaces and case.
    pub fn check_new_account_word(&self, position: u32, word: &str) -> Result<bool, AccountError> {
        let index = position
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
            .filter(|index| *index < SEED_WORDS)
            .ok_or(AccountError::BadPosition { position })?;
        let mut held = self.held();
        let account = held.as_mut().ok_or(AccountError::NoNewAccount)?;
        let words = account.seed.to_words();
        let matches = words.as_str().split_whitespace().nth(index).is_some_and(|held| same_word(held, word.trim()));
        drop(words);
        if matches {
            account.checked[index] = true;
        }
        Ok(matches)
    }

    /// Saves the held new account and forgets it, once [`CHECKED_WORDS`]
    /// different words have been typed right. If the store refuses, the
    /// account stays held, so saving can be tried again.
    pub fn save_new_account(&self) -> Result<(), AccountError> {
        let mut held = self.held();
        let account = held.as_ref().ok_or(AccountError::NoNewAccount)?;
        let checked = account.checked.iter().filter(|checked| **checked).count() as u32;
        if checked < CHECKED_WORDS {
            return Err(AccountError::NotChecked { checked, needed: CHECKED_WORDS });
        }
        self.store.save(&account.seed)?;
        *held = None;
        Ok(())
    }

    /// Forgets the held new account without saving it.
    pub fn discard_new_account(&self) {
        *self.held() = None;
    }

    /// Checks 24 typed words (the word list and the checksum) and saves them.
    /// Any new account held is forgotten.
    pub fn import_account_words(&self, words: &str) -> Result<(), AccountError> {
        let seed = WalletSeed::from_words(words)?;
        self.store.save(&seed)?;
        self.discard_new_account();
        Ok(())
    }

    /// Whether an account is saved.
    pub fn has_account(&self) -> Result<bool, AccountError> {
        self.store.contains()
    }

    /// The account 0 address (rescue-key scheme `0x0003`) of the saved
    /// account, as `0x` and 40 lowercase hex digits.
    pub fn saved_account_zero_address(&self) -> Result<String, AccountError> {
        let seed = self.store.load()?.ok_or(AccountError::NoAccount)?;
        Ok(to_hex_address(seed.rescue_account(0).address()))
    }

    /// Whether a new account is held.
    pub fn holds_new_account(&self) -> bool {
        self.held().is_some()
    }

    fn refuse_if_saved(&self) -> Result<(), AccountError> {
        if self.store.contains()? { Err(AccountError::AccountExists) } else { Ok(()) }
    }

    fn hold(&self, seed: WalletSeed) -> Vec<String> {
        let words = seed.to_words();
        let list = words.as_str().split_whitespace().map(str::to_owned).collect();
        drop(words);
        // The account held before, if any, is dropped (and wiped) here.
        *self.held() = Some(NewAccount { seed, checked: [false; SEED_WORDS] });
        list
    }

    fn held(&self) -> MutexGuard<'_, Option<NewAccount>> {
        self.new_account.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Whether `word`, ignoring surrounding spaces and case, is in the account
/// word list: [`is_account_word`] without the wiping of an owned string.
pub fn is_listed_word(word: &str) -> bool {
    // Lowercased on the stack, and wiped there: every word of the list is
    // shorter than this.
    let word = word.trim().as_bytes();
    let mut lower = [0u8; 16];
    if word.is_empty() || word.len() > lower.len() {
        return false;
    }
    for (to, from) in lower.iter_mut().zip(word) {
        *to = from.to_ascii_lowercase();
    }
    let found = core::str::from_utf8(&lower[..word.len()]).is_ok_and(|lower| WORDLIST.binary_search(&lower).is_ok());
    wipe(&mut lower);
    found
}

/// Compares two words ignoring ASCII case, looking at every byte whatever the
/// first difference.
fn same_word(held: &str, typed: &str) -> bool {
    let (held, typed) = (held.as_bytes(), typed.as_bytes());
    if held.len() != typed.len() {
        return false;
    }
    held.iter().zip(typed).fold(0u8, |diff, (a, b)| diff | (a.to_ascii_lowercase() ^ b.to_ascii_lowercase())) == 0
}

/// Overwrites `bytes` with zeros in a way the compiler keeps.
pub(crate) fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, exclusive reference.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Wipes a string the app passed in, all of its buffer, then frees it.
pub(crate) fn wipe_string(text: String) {
    let mut bytes = text.into_bytes();
    let capacity = bytes.capacity();
    bytes.resize(capacity, 0);
    wipe(&mut bytes);
}

#[cfg(target_os = "ios")]
type PlatformStore = crate::keychain::KeychainStore;
#[cfg(not(target_os = "ios"))]
type PlatformStore = MemoryStore;

/// The app's accounts: the Keychain on the phone.
static ACCOUNTS: LazyLock<AccountVault<PlatformStore>> = LazyLock::new(|| AccountVault::new(PlatformStore::default()));

/// Makes a new account, holds it in native memory, and returns its 24 words
/// for the backup screen.
#[uniffi::export]
pub fn new_account_words() -> Result<Vec<String>, AccountError> {
    ACCOUNTS.new_account_words()
}

/// Whether the held new account's word at `position` (1 to 24) is `word`.
#[uniffi::export]
pub fn check_new_account_word(position: u32, word: String) -> Result<bool, AccountError> {
    let result = ACCOUNTS.check_new_account_word(position, &word);
    wipe_string(word);
    result
}

/// Saves the held new account to the Keychain, this device only, and forgets
/// it; [`CHECKED_WORDS`] of its words must have been typed right.
#[uniffi::export]
pub fn save_new_account() -> Result<(), AccountError> {
    ACCOUNTS.save_new_account()
}

/// Forgets the held new account without saving it.
#[uniffi::export]
pub fn discard_new_account() {
    ACCOUNTS.discard_new_account();
}

/// Whether `word` is in the account word list.
#[uniffi::export]
pub fn is_account_word(word: String) -> bool {
    let found = is_listed_word(&word);
    wipe_string(word);
    found
}

/// Checks 24 typed words and saves them to the Keychain, this device only.
#[uniffi::export]
pub fn import_account_words(words: String) -> Result<(), AccountError> {
    let result = ACCOUNTS.import_account_words(&words);
    wipe_string(words);
    result
}

/// Whether an account is saved.
#[uniffi::export]
pub fn has_account() -> Result<bool, AccountError> {
    ACCOUNTS.has_account()
}

/// The account 0 address of the saved account.
#[uniffi::export]
pub fn saved_account_zero_address() -> Result<String, AccountError> {
    ACCOUNTS.saved_account_zero_address()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_zeroes_every_byte() {
        let mut bytes = *b"abandon amount liar";
        wipe(&mut bytes);
        assert_eq!(bytes, [0u8; 19]);
    }

    #[test]
    fn memory_store_wipes_a_seed_when_dropped() {
        let store = MemoryStore::default();
        store.save(&WalletSeed::from_bytes([9u8; SEED_BYTES])).unwrap();
        store.wipe_seed();
        assert_eq!(*store.slot(), Some([0u8; SEED_BYTES]));
    }

    #[test]
    fn same_word_ignores_case_only() {
        assert!(same_word("abandon", "ABANDON"));
        assert!(!same_word("abandon", "abandom"));
        assert!(!same_word("abandon", "abando"));
    }
}
