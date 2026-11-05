//! Vanish, Summon and Claim by a typed Phantom Key, in the native core.
//!
//! Vanish: [`prepare_vanish`] draws a fresh Phantom Key from the operating
//! system's random source and makes its coin commit number 0 with Ghost's own
//! client: the 430-byte commit data (version `0x0003`, the fingerprint `F`,
//! the per-coin salt and the 380-byte version-3 note sealed under the key's
//! note key, with the empty policy capsule), the same bytes Ghost's web app
//! sends and the only commit data Ghost's node accepts. As in Ghost's web app, the key is
//! written down before anything is sent: it is held in native memory only
//! while [`take_phantom_key_words`] hands its 24 words to the screen that
//! shows them (once) and [`check_phantom_key_word`] checks three of them typed
//! back; [`confirm_phantom_key_saved`] then drops it. A person who ticks
//! "Skip the check" has it dropped by [`confirm_phantom_key_saved_unchecked`].
//! A words key never goes on a card. A card Vanish, [`prepare_card_vanish`],
//! holds a card-only key instead: its words never leave the core except onto
//! the card, which is its only copy, and it is dropped once it is on the
//! card. A key is never saved, so a
//! kill before then leaves nothing signed and nothing lost. [`sign_vanish`] signs the
//! account transaction (`0x52`, rescue-key scheme `0x0003`, hedged ML-DSA-44)
//! that pays the amount to the coin commit entry with that data. It needs no
//! key, so a Vanish whose fee moved is signed again from its saved details.
//!
//! Summon and Claim: the person types the key. [`check_key_words`] tells the
//! key field and the wallet field apart: account words are never a key and a
//! key is never account words (Ghost's `WalletSeed::from_words` refuses a
//! Phantom Key). The coin tree is rebuilt from public chain data:
//! [`commit_leaf`] for each Vanish, [`reveal_leaf`] for each reveal.
//! [`find_key_coins`] looks the key up in it with Ghost's `restore_coins`, and
//! [`prove_key_reveal`] proves the reveal here, on the phone, and lays out the
//! private transaction (`0x50`) of spec 07. A reveal still carries a 156-byte
//! (version-2) remainder note; the coin tree holds it zero-padded to the 380
//! bytes of every tree note, so [`reveal_leaf`] pads it as the node does.
//!
//! Nothing here logs, prints or formats a key, its words or a signature: no
//! type holding one implements `Debug`, errors hold reasons and positions
//! only, and the key text the app passes in is wiped once read.

use core::fmt;
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use ghost_client::account::{AccountTx, WalletSeed};
use ghost_client::commit::salted_coin_commitment;
use ghost_client::reveal::{ChainParams, CoinReveal, Proof};
use ghost_client::{
    Amount, Capsule, Commitment, Current, Fingerprint, KeyError, KeyFormat, Marker, NOTE_BYTES, NoteContents,
    PhantomKey, REVEAL_NOTE_BYTES, RevealTerms, Rule, SALT_BYTES, SALTED_COMMIT_DATA_BYTES,
    SALTED_COMMIT_FORMAT_VERSION, Salt, TreeLeaf, encrypt_note, full_reveal, pad_reveal_note, partial_reveal,
    restore_coins, salted_commit_data,
};
use ghost_proofs::PROTOCOL_VERSION_1;
use rand::CryptoRng;

use crate::accounts::{saved_seed, wipe_string};
use crate::send::{OsRandom, RESCUE_TRANSFER_GAS, TEST_CHAIN_ID, is_wallet_chain};
use crate::summon::root_and_path;

/// The coin commit entry a Vanish pays: `ghost` then zeros then `0x05`, the
/// default of Ghost's web app.
pub const COMMIT_ENTRY: [u8; 20] = [
    0x67, 0x68, 0x6f, 0x73, 0x74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05,
];
/// The commit data's layout version, Ghost's: version 3 (`0x0003`).
pub const COMMIT_VERSION: [u8; 2] = SALTED_COMMIT_FORMAT_VERSION;
/// Version, `F`, the salt and the 380-byte note: 430 bytes.
pub const COMMIT_DATA_BYTES: usize = SALTED_COMMIT_DATA_BYTES;
/// Where the note starts in the commit data.
const COMMIT_NOTE_AT: usize = 2 + 32 + SALT_BYTES;
const _: () = assert!(COMMIT_DATA_BYTES == COMMIT_NOTE_AT + NOTE_BYTES);
/// The gas limit of a Vanish: the cap of Ghost's web app. Unused gas is not
/// paid.
pub const VANISH_GAS_LIMIT: u64 = 500_000;
/// The type byte of a private transaction (spec 07).
pub const PRIVATE_TX_TYPE: u8 = 0x50;
/// The private transaction layout version.
pub const PRIVATE_TX_VERSION: [u8; 2] = [0x00, 0x01];
/// The proof field, zero-padded.
pub const PROOF_FIELD_BYTES: usize = 1_310_720;
/// The payload: version, chain, marker, root, remainder, recipient, out, fee,
/// proof and the 156-byte remainder note.
pub const PAYLOAD_BYTES: usize = 2 + 8 + 32 + 32 + 32 + 20 + 32 + 32 + PROOF_FIELD_BYTES + REVEAL_NOTE_BYTES;
/// The type byte and the payload.
pub const ENVELOPE_BYTES: usize = 1 + PAYLOAD_BYTES;
/// The gas every private transaction uses, `G_PRIV`.
pub const PRIVATE_TX_GAS: u64 = 21_090_372;
/// Blocks per fee window.
pub const FEE_WINDOW: u64 = 4;
/// The smallest Vanish is this many Summon fees (a wallet rule of spec 07).
pub const MIN_VANISH_FEES: u128 = 4;

const MARKER_AT: usize = 1 + 2 + 8;
const REMAINDER_AT: usize = MARKER_AT + 32 + 32;
const NOTE_AT: usize = ENVELOPE_BYTES - REVEAL_NOTE_BYTES;

/// Why a Vanish, a lookup or a reveal could not be made. Never holds a key,
/// its words or a signature.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum VanishError {
    /// The chain identifier is neither the local test chain's (`expected`)
    /// nor the public test network's.
    WrongChain { expected: u64, found: u64 },
    /// The text is not a Phantom Key.
    NotAKey { reason: String },
    /// An amount is malformed or out of range.
    Amount { reason: String },
    /// An input is malformed.
    Malformed { reason: String },
    /// No new Phantom Key is held: none was made, or it was dropped.
    NoKeyHeld,
    /// The new key's words were handed out already: they are shown once.
    AlreadyShown,
    /// Too few of the new key's words have been typed back.
    NotChecked { checked: u32, needed: u32 },
    /// The new key is for a card only: its words never leave the core, and
    /// it is dropped only once it is on a card.
    CardOnly,
    /// The new key is a words key: its words were shown, or could be, so it
    /// never goes on a card. Only a card-only key does.
    NotCardOnly,
    /// The key's coin is not in the coin tree this phone rebuilt.
    NotFound,
    /// The key's coin is spent.
    Spent,
    /// The account could not be read.
    Account { reason: String },
    /// The reveal could not be proved.
    Proof { reason: String },
    /// The operating system gave no randomness.
    Randomness,
}

impl fmt::Display for VanishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongChain { found, .. } => write!(f, "Vanish is for the Ghost test chains only, not {found}"),
            Self::NotAKey { reason } => write!(f, "not a Phantom Key: {reason}"),
            Self::Amount { reason } => write!(f, "the amount is refused: {reason}"),
            Self::Malformed { reason } => write!(f, "malformed input: {reason}"),
            Self::NoKeyHeld => f.write_str("no new Phantom Key is held"),
            Self::AlreadyShown => f.write_str("the new Phantom Key's words were shown already"),
            Self::NotChecked { checked, needed } => {
                write!(f, "{checked} of the {needed} key words to check have been typed back")
            }
            Self::CardOnly => f.write_str("the new Phantom Key is for a card only: its words are never shown"),
            Self::NotCardOnly => f.write_str("the new Phantom Key is a words key: it never goes on a card"),
            Self::NotFound => f.write_str("the key's coin is not in the coin tree"),
            Self::Spent => f.write_str("the key's coin is spent"),
            Self::Account { reason } => write!(f, "the account cannot be read: {reason}"),
            Self::Proof { reason } => write!(f, "the reveal could not be proved: {reason}"),
            Self::Randomness => f.write_str("the operating system gave no randomness"),
        }
    }
}

impl std::error::Error for VanishError {}

fn malformed(reason: &str) -> VanishError {
    VanishError::Malformed { reason: reason.to_owned() }
}

// ---------------------------------------------------------------------------
// Fees

/// The Summon fee of a fee window whose reference base fee is `b_ref`:
/// `G_PRIV × U_1` plus a tenth (rounded up), with
/// `U_1 = b_ref + ⌊b_ref/8⌋ + ⌊b_ref/20000⌋ + 1`.
pub fn reveal_fee(b_ref: u128) -> Option<u128> {
    let price = b_ref.checked_add(b_ref / 8)?.checked_add(b_ref / 20_000)?.checked_add(1)?;
    let base = u128::from(PRIVATE_TX_GAS).checked_mul(price)?;
    base.checked_add(base.div_ceil(10))
}

/// The fee of a reveal, in wei as decimal digits, for the reference base fee
/// `b_ref_wei` (decimal digits).
#[uniffi::export]
pub fn reveal_fee_wei(b_ref_wei: String) -> Result<String, VanishError> {
    let b_ref = parse_wei(&b_ref_wei)?;
    reveal_fee(b_ref)
        .map(|fee| fee.to_string())
        .ok_or_else(|| VanishError::Amount { reason: "the base fee is too large".to_owned() })
}

/// The smallest Vanish, [`MIN_VANISH_FEES`] Summon fees, in wei as decimal
/// digits.
#[uniffi::export]
pub fn min_vanish_wei(b_ref_wei: String) -> Result<String, VanishError> {
    let b_ref = parse_wei(&b_ref_wei)?;
    reveal_fee(b_ref)
        .and_then(|fee| fee.checked_mul(MIN_VANISH_FEES))
        .map(|wei| wei.to_string())
        .ok_or_else(|| VanishError::Amount { reason: "the base fee is too large".to_owned() })
}

/// Where a reveal proved after block `tip` stands: the block whose base fee
/// sets its fee, and the last block that may include it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FeeWindow {
    /// The first block of the tip's window: its base fee is `b_ref`.
    pub reference_height: u64,
    /// The last block of the window after it. A block after this one does
    /// not take the fee, so the reveal is proved again.
    pub valid_until: u64,
}

/// The fee window of a reveal proved when the chain's tip is `tip`.
#[uniffi::export]
pub fn fee_window(tip: u64) -> FeeWindow {
    let window = tip / FEE_WINDOW;
    FeeWindow { reference_height: window * FEE_WINDOW, valid_until: (window + 2) * FEE_WINDOW - 1 }
}

// ---------------------------------------------------------------------------
// The key field and the wallet field

/// What typed words are. `verdict` is one of:
///
/// - `empty`: nothing typed;
/// - `account-words`: a wallet's 24 recovery words, never a key;
/// - `phantom-key`: a Phantom Key, never a wallet;
/// - `wrong-format`: neither 24 words nor 84 digits;
/// - `unknown-word`: word `position` (from 1) is not in the word list;
/// - `word-check`: 24 listed words that fail the key's check;
/// - `digit-check`: digits that fail their check.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WordsCheck {
    pub verdict: String,
    /// The word an `unknown-word` names, from 1; 0 otherwise.
    pub position: u32,
}

impl WordsCheck {
    fn new(verdict: &str, position: u32) -> Self {
        Self { verdict: verdict.to_owned(), position }
    }
}

/// [`check_key_words`] without the wiping of an owned string.
pub fn classify_words(text: &str) -> WordsCheck {
    if text.trim().is_empty() {
        return WordsCheck::new("empty", 0);
    }
    // Ghost's seed parser refuses a Phantom Key, so the two never overlap.
    if WalletSeed::from_words(text).is_ok() {
        return WordsCheck::new("account-words", 0);
    }
    match PhantomKey::parse(text) {
        Ok(_) => WordsCheck::new("phantom-key", 0),
        Err(KeyError::UnknownWord { word, .. }) => {
            WordsCheck::new("unknown-word", u32::try_from(word).unwrap_or(u32::MAX))
        }
        Err(KeyError::WordCheckMismatch) => WordsCheck::new("word-check", 0),
        Err(KeyError::ChecksumMismatch { .. } | KeyError::SecretOutOfRange) => WordsCheck::new("digit-check", 0),
        Err(_) => WordsCheck::new("wrong-format", 0),
    }
}

/// What the typed text is: a Phantom Key, account words, or why neither.
/// The key field takes only `phantom-key`; the wallet field refuses it.
#[uniffi::export]
pub fn check_key_words(text: String) -> WordsCheck {
    let check = classify_words(&text);
    wipe_string(text);
    check
}

// ---------------------------------------------------------------------------
// Vanish

/// A Vanish as decided: what to pay and the commit data to send. Public: the
/// chain shows all of it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VanishCommit {
    /// The [`COMMIT_DATA_BYTES`] of the transaction's data.
    pub commit_data: Vec<u8>,
    /// The amount, in wei as decimal digits.
    pub amount_wei: String,
    /// The coin's leaf, `C`.
    pub commitment: Vec<u8>,
}

/// How many different words of a new key must be typed back before its
/// Vanish is sent, as in Ghost's web app.
pub const CHECKED_KEY_WORDS: u32 = 3;

/// A new Phantom Key, held until three of its words are typed back or the
/// person skips the check, or (a card-only key) until it is on a card.
struct HeldKey {
    key: PhantomKey,
    shown: bool,
    checked: [bool; 24],
    /// Its words were copied out for a card: a card-only key only.
    on_card: bool,
    /// Made for a card only: its words are never handed out or checked, and
    /// the card is its only copy.
    card_only: bool,
}

impl HeldKey {
    fn checked_count(&self) -> u32 {
        self.checked.iter().filter(|checked| **checked).count() as u32
    }
}

/// A new Phantom Key: its words handed out once, then three of them typed
/// back, then dropped. Never saved.
pub struct KeyVault {
    held: Mutex<Option<HeldKey>>,
}

impl Default for KeyVault {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyVault {
    pub const fn new() -> Self {
        Self { held: Mutex::new(None) }
    }

    /// Makes a new key with `rng`, holds it, and returns its coin commit
    /// number 0 of `amount_wei` on `chain_id`. A key held before is dropped.
    pub fn prepare_with<R: CryptoRng + ?Sized>(
        &self,
        chain_id: u64,
        amount_wei: u128,
        rng: &mut R,
    ) -> Result<VanishCommit, VanishError> {
        self.prepare_held(chain_id, amount_wei, false, rng)
    }

    /// [`Self::prepare_with`] for a card-only key: its words are never handed
    /// out or checked, the card export needs no showing, and it is dropped
    /// only once it is on a card. Whoever holds the card holds the coin.
    pub fn prepare_card_with<R: CryptoRng + ?Sized>(
        &self,
        chain_id: u64,
        amount_wei: u128,
        rng: &mut R,
    ) -> Result<VanishCommit, VanishError> {
        self.prepare_held(chain_id, amount_wei, true, rng)
    }

    fn prepare_held<R: CryptoRng + ?Sized>(
        &self,
        chain_id: u64,
        amount_wei: u128,
        card_only: bool,
        rng: &mut R,
    ) -> Result<VanishCommit, VanishError> {
        let key = PhantomKey::generate(KeyFormat::Words, rng);
        let commit = vanish_commit_with(&key, chain_id, amount_wei, rng)?;
        *self.lock() = Some(HeldKey { key, shown: false, checked: [false; 24], on_card: false, card_only });
        Ok(commit)
    }

    /// The held key's 24 words, once: asking again is refused, and a
    /// card-only key never hands them out.
    pub fn take_words(&self) -> Result<Vec<String>, VanishError> {
        let mut held = self.lock();
        let held = held.as_mut().ok_or(VanishError::NoKeyHeld)?;
        if held.card_only {
            return Err(VanishError::CardOnly);
        }
        if held.shown {
            return Err(VanishError::AlreadyShown);
        }
        let words = held.key.format_words().ok_or_else(|| malformed("the key has no words view"))?;
        held.shown = true;
        Ok(words.as_str().split_whitespace().map(str::to_owned).collect())
    }

    /// Whether the held key's word at `position` (1 to 24) is `word`,
    /// ignoring surrounding spaces and case. A card-only key is refused: no
    /// guess at its words is ever answered.
    pub fn check_word(&self, position: u32, word: &str) -> Result<bool, VanishError> {
        let index = position
            .checked_sub(1)
            .map(|index| index as usize)
            .filter(|index| *index < 24)
            .ok_or_else(|| malformed("a key word position is 1 to 24"))?;
        let mut held = self.lock();
        let held = held.as_mut().ok_or(VanishError::NoKeyHeld)?;
        if held.card_only {
            return Err(VanishError::CardOnly);
        }
        let words = held.key.format_words().ok_or_else(|| malformed("the key has no words view"))?;
        let matches = words.as_str().split_whitespace().nth(index).is_some_and(|held| held.eq_ignore_ascii_case(word.trim()));
        if matches {
            held.checked[index] = true;
        }
        Ok(matches)
    }

    /// Once [`CHECKED_KEY_WORDS`] different words were typed back, drops a
    /// words key: the person has it, and the phone keeps nothing. A card-only
    /// key is dropped once it is on a card, and refused before; a words key
    /// never goes on a card, so it always needs the check (or the skip).
    pub fn confirm_saved(&self) -> Result<(), VanishError> {
        let mut held = self.lock();
        let key = held.as_ref().ok_or(VanishError::NoKeyHeld)?;
        if key.card_only {
            if !key.on_card {
                return Err(VanishError::CardOnly);
            }
        } else {
            let checked = key.checked_count();
            if !key.shown || checked < CHECKED_KEY_WORDS {
                return Err(VanishError::NotChecked { checked, needed: CHECKED_KEY_WORDS });
            }
        }
        *held = None;
        Ok(())
    }

    /// Drops the key once its words were shown, with none typed back: only
    /// for a person who ticked "Skip the check" and accepted that a mistake
    /// in what they wrote down loses the coins. Words never shown are still
    /// refused, so a key is never dropped unseen, and a card-only key is
    /// always refused: it is dropped only by [`Self::confirm_saved`] once on
    /// a card.
    pub fn confirm_saved_unchecked(&self) -> Result<(), VanishError> {
        let mut held = self.lock();
        let key = held.as_ref().ok_or(VanishError::NoKeyHeld)?;
        if key.card_only {
            return Err(VanishError::CardOnly);
        }
        if !key.shown {
            return Err(VanishError::NotChecked { checked: key.checked_count(), needed: CHECKED_KEY_WORDS });
        }
        *held = None;
        Ok(())
    }

    /// Drops the held key.
    pub fn forget(&self) {
        *self.lock() = None;
    }

    /// Whether a key is held.
    pub fn holds_key(&self) -> bool {
        self.lock().is_some()
    }

    /// Runs `use_words` on the held key's words for a card. Only a card-only
    /// key goes on a card: its words were never shown and never can be, so
    /// the card is its only copy, like cash. A words key is always refused,
    /// shown or not, so no one can keep its words and pass its card off as
    /// the only copy. The key stays held, and is marked as on a card when
    /// `use_words` took the words (returned `Some`).
    pub fn with_card_words<T>(&self, use_words: impl FnOnce(&str) -> Option<T>) -> Result<Option<T>, VanishError> {
        let mut guard = self.lock();
        let held = guard.as_mut().ok_or(VanishError::NoKeyHeld)?;
        if !held.card_only {
            return Err(VanishError::NotCardOnly);
        }
        let words = held.key.format_words().ok_or_else(|| malformed("the key has no words view"))?;
        let result = use_words(words.as_str());
        if result.is_some() {
            held.on_card = true;
        }
        Ok(result)
    }

    fn lock(&self) -> MutexGuard<'_, Option<HeldKey>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The coin commit number 0 of `key` for `amount_wei` on `chain_id`: the
/// commit, its note sealed under the key's note key, and the commit data.
pub fn vanish_commit_with<R: CryptoRng + ?Sized>(
    key: &PhantomKey,
    chain_id: u64,
    amount_wei: u128,
    rng: &mut R,
) -> Result<VanishCommit, VanishError> {
    let amount = amount(amount_wei)?;
    if amount_wei == 0 {
        return Err(VanishError::Amount { reason: "a Vanish moves more than nothing".to_owned() });
    }
    let commit = key
        .salted_coin_commit(0, amount, Rule::EMPTY, rng)
        .map_err(|error| VanishError::Amount { reason: error.to_string() })?;
    let salt = Salt::from_bytes(*commit.salt.as_bytes());
    let contents = NoteContents::salted_coin(0, amount, Rule::EMPTY, salt);
    // A version-3 note: the coin's fields and the empty policy capsule.
    let note = encrypt_note(&key.note_key(), chain_id, &commit.commitment, &contents, &Capsule::empty(), rng);
    let data = salted_commit_data(&commit.fingerprint, &commit.salt, &note);
    Ok(VanishCommit {
        commit_data: data.to_vec(),
        amount_wei: amount_wei.to_string(),
        commitment: commit.commitment.as_bytes().to_vec(),
    })
}

static NEW_KEY: LazyLock<KeyVault> = LazyLock::new(KeyVault::new);

/// The new Phantom Key Vanish holds, for the card bridge.
pub(crate) fn new_key() -> &'static KeyVault {
    &NEW_KEY
}

/// Makes a fresh Phantom Key from the operating system's random source,
/// holds it in native memory, and returns its Vanish commit for
/// `amount_wei` (decimal digits) on `chain_id`, the build's test chain.
#[uniffi::export]
pub fn prepare_vanish(chain_id: u64, amount_wei: String) -> Result<VanishCommit, VanishError> {
    check_chain(chain_id)?;
    let wei = parse_wei(&amount_wei)?;
    let mut rng = OsRandom { failed: false };
    let commit = NEW_KEY.prepare_with(chain_id, wei, &mut rng)?;
    if rng.failed {
        // Made with missing randomness: dropped, never shown or sent.
        NEW_KEY.forget();
        return Err(VanishError::Randomness);
    }
    Ok(commit)
}

/// [`prepare_vanish`] for a card only: the held key's words are never handed
/// out or checked ([`take_phantom_key_words`] and [`check_phantom_key_word`]
/// refuse it), the card export takes it without showing, and
/// [`confirm_phantom_key_saved`] drops it only once it is on a card. The card
/// is its only copy.
#[uniffi::export]
pub fn prepare_card_vanish(chain_id: u64, amount_wei: String) -> Result<VanishCommit, VanishError> {
    check_chain(chain_id)?;
    let wei = parse_wei(&amount_wei)?;
    let mut rng = OsRandom { failed: false };
    let commit = NEW_KEY.prepare_card_with(chain_id, wei, &mut rng)?;
    if rng.failed {
        // Made with missing randomness: dropped, never put on a card or sent.
        NEW_KEY.forget();
        return Err(VanishError::Randomness);
    }
    Ok(commit)
}

/// The held Phantom Key's 24 words, for the one screen that shows them.
/// Asking again is refused.
#[uniffi::export]
pub fn take_phantom_key_words() -> Result<Vec<String>, VanishError> {
    NEW_KEY.take_words()
}

/// Whether the held key's word at `position` (1 to 24) is `word`.
#[uniffi::export]
pub fn check_phantom_key_word(position: u32, word: String) -> Result<bool, VanishError> {
    let result = NEW_KEY.check_word(position, &word);
    wipe_string(word);
    result
}

/// Drops the held key once three of its words were typed back (or, a
/// card-only key, once it was put on a card); the Vanish is then backed up
/// and may be signed.
#[uniffi::export]
pub fn confirm_phantom_key_saved() -> Result<(), VanishError> {
    NEW_KEY.confirm_saved()
}

/// Drops the held key once its words were shown, with none typed back. The
/// app calls this only when the person ticked "Skip the check".
#[uniffi::export]
pub fn confirm_phantom_key_saved_unchecked() -> Result<(), VanishError> {
    NEW_KEY.confirm_saved_unchecked()
}

/// Forgets the held Phantom Key without showing it.
#[uniffi::export]
pub fn forget_phantom_key() {
    NEW_KEY.forget();
}

/// What a Vanish pays and the chain data it is signed against. Nothing here
/// is secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VanishSend {
    /// Must be a Ghost test chain's: the local one or the public test network.
    pub chain_id: u64,
    /// The hash of block 0, 32 bytes.
    pub genesis_hash: Vec<u8>,
    /// The account's nonce: the payment's identity.
    pub nonce: u64,
    /// The [`COMMIT_DATA_BYTES`] of [`VanishCommit::commit_data`].
    pub commit_data: Vec<u8>,
    /// In wei, as decimal digits.
    pub amount_wei: String,
    pub max_priority_fee_per_gas: u64,
    pub max_fee_per_gas: u64,
    /// At least a plain transfer's gas and the data's.
    pub gas_limit: u64,
}

/// A signed Vanish. No key material is in here.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct SignedVanish {
    pub transaction_hash: Vec<u8>,
    pub sender: Vec<u8>,
    /// `0x52 || rlp([...])`, for `eth_sendRawTransaction`.
    pub envelope: Vec<u8>,
}

impl fmt::Debug for SignedVanish {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The envelope holds the signature: only its length is shown.
        f.debug_struct("SignedVanish")
            .field("transaction_hash", &self.transaction_hash.len())
            .field("sender", &self.sender.len())
            .field("envelope_len", &self.envelope.len())
            .finish()
    }
}

/// The least gas a Vanish may be given: a plain transfer's and 16 per data
/// byte.
pub const VANISH_MIN_GAS: u64 = RESCUE_TRANSFER_GAS + 16 * COMMIT_DATA_BYTES as u64;

/// Signs a Vanish from account `account_index` of `seed` with `rng`. The app
/// calls [`sign_vanish`]; this is for the tests.
pub fn sign_vanish_with<R: CryptoRng + ?Sized>(
    seed: &WalletSeed,
    account_index: u32,
    send: &VanishSend,
    rng: &mut R,
) -> Result<SignedVanish, VanishError> {
    check_chain(send.chain_id)?;
    let genesis: [u8; 32] =
        send.genesis_hash.as_slice().try_into().map_err(|_| malformed("the genesis hash is not 32 bytes"))?;
    check_commit_data(&send.commit_data)?;
    let value = parse_wei(&send.amount_wei)?;
    if value == 0 {
        return Err(VanishError::Amount { reason: "a Vanish moves more than nothing".to_owned() });
    }
    if send.gas_limit < VANISH_MIN_GAS {
        return Err(malformed("the gas limit is below the gas of a Vanish"));
    }
    if send.max_fee_per_gas < send.max_priority_fee_per_gas {
        return Err(malformed("the fee cap is below the priority fee"));
    }
    let account = seed.rescue_account(account_index);
    let tx = AccountTx {
        chain_id: send.chain_id,
        nonce: send.nonce,
        max_priority_fee_per_gas: u128::from(send.max_priority_fee_per_gas),
        max_fee_per_gas: u128::from(send.max_fee_per_gas),
        gas_limit: send.gas_limit,
        to: Some(COMMIT_ENTRY),
        value,
        data: send.commit_data.clone(),
        access_list: Vec::new(),
    };
    let signed = account.sign(&tx, &genesis, rng);
    Ok(SignedVanish { transaction_hash: signed.hash.to_vec(), sender: signed.sender.to_vec(), envelope: signed.envelope })
}

/// Signs a Vanish from account 0 of the account saved on this phone, with
/// fresh randomness from the operating system. The words stay in native code.
#[uniffi::export]
pub fn sign_vanish(send: VanishSend) -> Result<SignedVanish, VanishError> {
    let seed = saved_seed().map_err(|error| VanishError::Account { reason: error.to_string() })?;
    let mut rng = OsRandom { failed: false };
    let signed = sign_vanish_with(&seed, 0, &send, &mut rng)?;
    if rng.failed {
        return Err(VanishError::Randomness);
    }
    Ok(signed)
}

/// The coin commit entry, `0x` and 40 hex digits.
#[uniffi::export]
pub fn commit_entry_address() -> String {
    crate::to_hex_address(&COMMIT_ENTRY)
}

/// The gas limit of a Vanish, [`VANISH_GAS_LIMIT`].
#[uniffi::export]
pub fn vanish_gas_limit() -> u64 {
    VANISH_GAS_LIMIT
}

// ---------------------------------------------------------------------------
// The coin tree, from public chain data

/// One leaf of the coin tree: its commitment, its note, and its salt when the
/// chain shows it beside the leaf (a Vanish; a reveal's remainder keeps its
/// salt in the note).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CoinLeaf {
    pub commitment: Vec<u8>,
    pub note: Vec<u8>,
    pub salt: Option<Vec<u8>>,
}

/// What one reveal shows: the marker it spent and the remainder leaf it adds.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RevealedLeaf {
    pub marker: Vec<u8>,
    pub leaf: CoinLeaf,
}

fn check_commit_data(data: &[u8]) -> Result<(), VanishError> {
    if data.len() != COMMIT_DATA_BYTES {
        return Err(malformed("the commit data is not 430 bytes"));
    }
    if data[..2] != COMMIT_VERSION {
        return Err(malformed("the commit data is not version 3"));
    }
    Ok(())
}

/// The leaf a successful Vanish adds: `C` from its `F` and the amount it paid.
#[uniffi::export]
pub fn commit_leaf(commit_data: Vec<u8>, amount_wei: String) -> Result<CoinLeaf, VanishError> {
    check_commit_data(&commit_data)?;
    let amount = amount(parse_wei(&amount_wei)?)?;
    let fingerprint: [u8; 32] = commit_data[2..34].try_into().map_err(|_| malformed("no fingerprint"))?;
    let commitment = salted_coin_commitment(&Fingerprint::from_bytes(fingerprint), amount);
    Ok(CoinLeaf {
        commitment: commitment.as_bytes().to_vec(),
        note: commit_data[COMMIT_NOTE_AT..].to_vec(),
        salt: Some(commit_data[34..COMMIT_NOTE_AT].to_vec()),
    })
}

/// The marker and remainder leaf of a private transaction's envelope. The
/// envelope's 156-byte remainder note is zero-padded to the tree's 380 bytes,
/// as the node stores it.
#[uniffi::export]
pub fn reveal_leaf(envelope: Vec<u8>) -> Result<RevealedLeaf, VanishError> {
    if envelope.len() != ENVELOPE_BYTES || envelope[0] != PRIVATE_TX_TYPE {
        return Err(malformed("not a private transaction"));
    }
    if envelope[1..3] != PRIVATE_TX_VERSION {
        return Err(malformed("not a version 1 private transaction"));
    }
    let note: &[u8; REVEAL_NOTE_BYTES] =
        envelope[NOTE_AT..].try_into().map_err(|_| malformed("the remainder note is not 156 bytes"))?;
    Ok(RevealedLeaf {
        marker: envelope[MARKER_AT..MARKER_AT + 32].to_vec(),
        leaf: CoinLeaf {
            commitment: envelope[REMAINDER_AT..REMAINDER_AT + 32].to_vec(),
            note: pad_reveal_note(note).to_vec(),
            salt: None,
        },
    })
}

fn tree_leaves(leaves: &[CoinLeaf]) -> Result<Vec<TreeLeaf>, VanishError> {
    leaves
        .iter()
        .map(|leaf| {
            let commitment: [u8; 32] =
                leaf.commitment.as_slice().try_into().map_err(|_| malformed("a leaf is not 32 bytes"))?;
            let note: [u8; NOTE_BYTES] =
                leaf.note.as_slice().try_into().map_err(|_| malformed("a note is not 380 bytes"))?;
            let salt = match &leaf.salt {
                None => None,
                Some(salt) => Some(Salt::from_bytes(
                    salt.as_slice().try_into().map_err(|_| malformed("a salt is not 16 bytes"))?,
                )),
            };
            Ok(TreeLeaf { commitment: Commitment::from_bytes(commitment), note, salt })
        })
        .collect()
}

fn spent_markers(spent: &[Vec<u8>]) -> Result<Vec<Marker>, VanishError> {
    spent
        .iter()
        .map(|marker| {
            let bytes: [u8; 32] = marker.as_slice().try_into().map_err(|_| malformed("a marker is not 32 bytes"))?;
            Ok(Marker::from_bytes(bytes))
        })
        .collect()
}

/// What the coin tree shows of a key. `status` is `found` (an unspent coin
/// of `amount_wei`), `spent` (its coins are all spent) or `not-found` (this
/// phone cannot find its coins yet: not "zero").
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct KeyCoins {
    pub status: String,
    /// The unspent coin's amount, in wei as decimal digits; `0` otherwise.
    pub amount_wei: String,
}

/// The key's unspent coin: the first one if several are unspent.
fn unspent_coin(
    key: &PhantomKey,
    chain_id: u64,
    leaves: &[TreeLeaf],
    spent: &[Marker],
) -> Result<ghost_client::FoundCoin, VanishError> {
    let restored = restore_coins(key, chain_id, 0, leaves, spent).map_err(|error| malformed(&error.to_string()))?;
    let unspent = match restored.current {
        Current::One(coin) => vec![coin],
        Current::Several(coins) => coins,
        Current::None => Vec::new(),
    };
    // A full Summon leaves an empty remainder: it holds nothing to reveal.
    match unspent.into_iter().find(|coin| coin.amount.wei() > 0) {
        Some(coin) => Ok(coin),
        None if restored.found.is_empty() => Err(VanishError::NotFound),
        None => Err(VanishError::Spent),
    }
}

/// Looks `key` up in the coin tree `leaves`, with the spent markers `spent`.
pub fn find_coins(key: &PhantomKey, chain_id: u64, leaves: &[CoinLeaf], spent: &[Vec<u8>]) -> Result<KeyCoins, VanishError> {
    let leaves = tree_leaves(leaves)?;
    let spent = spent_markers(spent)?;
    match unspent_coin(key, chain_id, &leaves, &spent) {
        Ok(coin) => Ok(KeyCoins { status: "found".to_owned(), amount_wei: coin.amount.wei().to_string() }),
        Err(VanishError::NotFound) => Ok(KeyCoins { status: "not-found".to_owned(), amount_wei: "0".to_owned() }),
        Err(VanishError::Spent) => Ok(KeyCoins { status: "spent".to_owned(), amount_wei: "0".to_owned() }),
        Err(error) => Err(error),
    }
}

/// Looks the typed key up in the coin tree this phone rebuilt.
#[uniffi::export]
pub fn find_key_coins(
    key_text: String,
    chain_id: u64,
    leaves: Vec<CoinLeaf>,
    spent: Vec<Vec<u8>>,
) -> Result<KeyCoins, VanishError> {
    let key = parse_key(key_text)?;
    find_coins(&key, chain_id, &leaves, &spent)
}

// ---------------------------------------------------------------------------
// Summon and Claim

/// What a reveal pays and the chain data it is proved against.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RevealRequest {
    /// Must be a Ghost test chain's: the local one or the public test network.
    pub chain_id: u64,
    /// The hash of block 0: the proof's domain.
    pub genesis_hash: Vec<u8>,
    /// The account the coins go to, 20 bytes.
    pub recipient: Vec<u8>,
    /// The base fee of the fee window's first block, in wei as decimal digits.
    pub base_fee_ref_wei: String,
    /// What goes out, in wei as decimal digits: none for a Summon of the
    /// whole coin, some for a Claim of part of it (the rest stays with the
    /// key).
    pub out_wei: Option<String>,
}

/// A proved reveal, laid out as a private transaction. Public: the chain
/// shows all of it.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct ProvedReveal {
    /// `keccak256(envelope)`.
    pub transaction_hash: Vec<u8>,
    /// The coin's marker: the payment's identity.
    pub marker: Vec<u8>,
    /// `0x50 || payload`, for `eth_sendRawTransaction`.
    pub envelope: Vec<u8>,
    /// In wei, as decimal digits.
    pub fee_wei: String,
    pub out_wei: String,
    /// What stays with the key.
    pub remainder_wei: String,
    pub prove_millis: u64,
}

impl fmt::Debug for ProvedReveal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProvedReveal")
            .field("envelope_len", &self.envelope.len())
            .field("fee_wei", &self.fee_wei)
            .field("out_wei", &self.out_wei)
            .finish()
    }
}

/// A proved reveal with the parts a verifier checks.
pub struct BuiltPrivateTx {
    pub proved: ProvedReveal,
    pub params: ChainParams,
    pub reveal: CoinReveal,
    pub proof: Proof,
}

/// Proves a reveal of `key`'s unspent coin with `rng`. The app calls
/// [`prove_key_reveal`]; this is for the tests.
pub fn prove_reveal_with<R: CryptoRng + ?Sized>(
    key: &PhantomKey,
    request: &RevealRequest,
    leaves: &[CoinLeaf],
    spent: &[Vec<u8>],
    rng: &mut R,
) -> Result<BuiltPrivateTx, VanishError> {
    check_chain(request.chain_id)?;
    let domain: [u8; 32] =
        request.genesis_hash.as_slice().try_into().map_err(|_| malformed("the genesis hash is not 32 bytes"))?;
    let recipient: [u8; 20] =
        request.recipient.as_slice().try_into().map_err(|_| malformed("the recipient is not 20 bytes"))?;
    if recipient == [0u8; 20] {
        return Err(malformed("the zero address cannot receive a reveal"));
    }
    let fee_wei = reveal_fee(parse_wei(&request.base_fee_ref_wei)?)
        .ok_or_else(|| VanishError::Amount { reason: "the base fee is too large".to_owned() })?;
    let fee = amount(fee_wei)?;

    let tree = tree_leaves(leaves)?;
    let markers = spent_markers(spent)?;
    let found = unspent_coin(key, request.chain_id, &tree, &markers)?;
    let held = found.amount.wei();
    let most = held.checked_sub(fee_wei);
    let out_wei = match &request.out_wei {
        None => most,
        Some(out) => {
            let out = parse_wei(out)?;
            most.filter(|most| out <= *most).map(|_| out)
        }
    }
    .filter(|out| *out > 0)
    .ok_or_else(|| VanishError::Amount { reason: "the coin does not hold that much and the fee".to_owned() })?;

    let commitments: Vec<[u8; 32]> = tree.iter().map(|leaf| *leaf.commitment.as_bytes()).collect();
    let (root, path) = root_and_path(&commitments, found.position);
    let marker = found.marker.as_bytes().to_vec();
    let coin = found.owned(path);
    let params = ChainParams { chain_id: request.chain_id.to_be_bytes(), version: PROTOCOL_VERSION_1, domain };
    let terms = RevealTerms { root, recipient, fee };
    let mut zk_randomness = [0u8; 32];
    rng.fill_bytes(&mut zk_randomness);

    let start = Instant::now();
    let built = match &request.out_wei {
        None => full_reveal(&params, key, &coin, &terms, rng, zk_randomness),
        Some(_) => partial_reveal(&params, key, &coin, &terms, amount(out_wei)?, rng, zk_randomness),
    }
    .map_err(|error| VanishError::Proof { reason: error.to_string() })?;
    let prove_millis = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

    let envelope = private_envelope(request.chain_id, &built.reveal, built.proof.as_bytes())?;
    let proved = ProvedReveal {
        transaction_hash: crate::step_sequence::transaction_hash(envelope.clone()),
        marker,
        envelope,
        fee_wei: fee_wei.to_string(),
        out_wei: out_wei.to_string(),
        remainder_wei: (held - fee_wei - out_wei).to_string(),
        prove_millis,
    };
    Ok(BuiltPrivateTx { proved, params, reveal: built.reveal, proof: built.proof })
}

/// Lays a reveal out as spec 07's private transaction: `0x50`, then version,
/// chain, marker, root, remainder, recipient, out, fee, the proof padded with
/// zeros, and the remainder's note.
pub fn private_envelope(chain_id: u64, reveal: &CoinReveal, proof: &[u8]) -> Result<Vec<u8>, VanishError> {
    if proof.len() > PROOF_FIELD_BYTES {
        return Err(VanishError::Proof { reason: "the proof does not fit the transaction".to_owned() });
    }
    let mut out = Vec::with_capacity(ENVELOPE_BYTES);
    out.push(PRIVATE_TX_TYPE);
    out.extend_from_slice(&PRIVATE_TX_VERSION);
    out.extend_from_slice(&chain_id.to_be_bytes());
    out.extend_from_slice(&reveal.marker);
    out.extend_from_slice(&reveal.root);
    out.extend_from_slice(&reveal.remainder);
    out.extend_from_slice(&reveal.recipient);
    out.extend_from_slice(&reveal.out);
    out.extend_from_slice(&reveal.fee);
    out.extend_from_slice(proof);
    out.resize(NOTE_AT, 0);
    out.extend_from_slice(&reveal.remainder_note);
    debug_assert_eq!(out.len(), ENVELOPE_BYTES);
    Ok(out)
}

/// Proves, here on the phone, a Summon (the whole coin, less the fee) or a
/// Claim (`out_wei` of it) of the typed key's coin to `recipient`, and lays
/// it out as a private transaction. The key is read, used and wiped.
#[uniffi::export]
pub fn prove_key_reveal(
    key_text: String,
    request: RevealRequest,
    leaves: Vec<CoinLeaf>,
    spent: Vec<Vec<u8>>,
) -> Result<ProvedReveal, VanishError> {
    let key = parse_key(key_text)?;
    let mut rng = OsRandom { failed: false };
    let built = prove_reveal_with(&key, &request, &leaves, &spent, &mut rng)?;
    if rng.failed {
        return Err(VanishError::Randomness);
    }
    Ok(built.proved)
}

// ---------------------------------------------------------------------------

/// The app passes its build's chain: the local test chain or the public test
/// network. Any other chain is refused.
fn check_chain(chain_id: u64) -> Result<(), VanishError> {
    if is_wallet_chain(chain_id) {
        Ok(())
    } else {
        Err(VanishError::WrongChain { expected: TEST_CHAIN_ID, found: chain_id })
    }
}

/// Parses the typed key and wipes the text. Account words are refused by
/// name, never parsed as a key.
fn parse_key(text: String) -> Result<PhantomKey, VanishError> {
    let result = if WalletSeed::from_words(&text).is_ok() {
        Err(VanishError::NotAKey { reason: "these are account words, not a Phantom Key".to_owned() })
    } else {
        PhantomKey::parse(&text).map_err(|error| VanishError::NotAKey { reason: error.to_string() })
    };
    wipe_string(text);
    result
}

/// Decimal digits of wei.
pub fn parse_wei(text: &str) -> Result<u128, VanishError> {
    let bad = || VanishError::Amount { reason: "not a whole number of wei".to_owned() };
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(bad());
    }
    text.parse::<u128>().map_err(|_| bad())
}

fn amount(wei: u128) -> Result<Amount, VanishError> {
    Amount::new(wei).map_err(|error| VanishError::Amount { reason: error.to_string() })
}
