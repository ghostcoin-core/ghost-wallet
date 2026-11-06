//! The phone's side of a Sealed card's Open (`docs/sealed-card.md`, "Open
//! release"; the Seal's own reference is `PhoneSecret` in
//! `seal/src/release.rs`).
//!
//! 1. [`seal_open_phone_key`] makes an ML-KEM-768 key pair here, from a
//!    64-byte seed drawn from the operating system, and hands JavaScript only
//!    its public encapsulation key, to send with the Open. A key already held
//!    is handed out again, so an Open cut off by a lost connection is asked
//!    again with the same phone key, and the Seal releases the card's key to
//!    it (it releases to the phone key bound when the Open started, and to no
//!    other).
//! 2. The card module's relay hands the Seal's release package straight to
//!    [`ghost_wallet_seal_open_take_release`], a C function the JavaScript
//!    bindings do not carry.
//! 3. [`finish_seal_open`] checks the Seal's signed Open answer (it must bind
//!    exactly the held package), opens the package with the held key, and
//!    puts the Phantom Key in the core's card-key slot (`crate::card`). The
//!    existing Claim then runs on it unchanged; JavaScript gets only a
//!    verdict.
//! 4. [`forget_seal_open_key`] wipes the key once that Claim settled.
//!
//! The seed may also be copied to the card module for the Keychain (this
//! device only, [`ghost_wallet_seal_open_copy_seed`]) and given back after a
//! restart ([`ghost_wallet_seal_open_restore_seed`]), so an Open whose app was
//! closed can still be asked again with the same key.
//!
//! The released key is the wallet core's key bytes: the format code `0x20`
//! then the key's 32 secret bytes. Nothing here logs, prints or formats the
//! seed, the shared secret or a key. No cryptography is written here:
//! ML-KEM is `ml-kem`, HKDF and HMAC (over SHA3-256) are `hkdf` and `hmac`,
//! AES-256-CBC is `aes` and `cbc`, at the versions `seal/` pins.

use core::convert::Infallible;
use std::sync::{Mutex, MutexGuard, PoisonError};

use aes::Aes256;
use aes::cipher::{BlockModeDecrypt, KeyInit, KeyIvInit};
use ghost_client::{KeyFormat, PhantomKey};
use hkdf::SimpleHkdf;
use hmac::{Mac, SimpleHmac};
use ml_kem::{Decapsulate, DecapsulationKey, KeyExport, MlKem768};
use rand::rngs::SysRng;
use rand::{TryCryptoRng, TryRng};
use sha3::Sha3_256;
use zeroize::{Zeroize, Zeroizing};

use crate::card::hold_card_words;
use crate::seal_answer::{Refusal, SealAnswerCheck, SealAnswerVerdict, check_answer, sha3_256, verdict};

/// The HKDF salt and MAC label of a release package.
pub const RELEASE_LABEL: &[u8] = b"ghost-seal/v1/open-release";
/// The label of a phone key's hash.
pub const PHONE_KEY_LABEL: &[u8] = b"ghost-seal/v1/phone-key";
/// An ML-KEM-768 encapsulation key's length.
pub const PHONE_KEY_BYTES: usize = 1184;
/// An ML-KEM-768 ciphertext's length.
pub const KEM_CIPHERTEXT_BYTES: usize = 1088;
/// The seed of a phone key: ML-KEM's d || z.
pub const PHONE_SEED_BYTES: usize = 64;
/// The wallet core's key format code, the first byte of released key bytes.
pub const KEY_FORMAT_CODE: u8 = 0x20;
/// A Phantom Key's secret bytes.
pub const KEY_SECRET_BYTES: usize = 32;
/// The longest release package: a key slot holds at most 64 key bytes.
pub const MAX_RELEASE_BYTES: usize = 4 + KEM_CIPHERTEXT_BYTES + 16 + 80 + TAG_BYTES;

const MAGIC: &[u8; 4] = b"GSR1";
const TAG_BYTES: usize = 32;

/// No phone key is held, or no release is held.
pub const OPEN_NOTHING_HELD: isize = -1;
/// The buffer is too small, or the bytes are the wrong length.
pub const OPEN_WRONG_LENGTH: isize = -2;
/// A null pointer was passed.
pub const OPEN_NULL: isize = -3;

/// The phone key of an Open, and the release the relay handed over for it.
struct PendingOpen {
    seed: Zeroizing<[u8; PHONE_SEED_BYTES]>,
    release: Option<Vec<u8>>,
}

static OPEN: Mutex<Option<PendingOpen>> = Mutex::new(None);

fn pending() -> MutexGuard<'static, Option<PendingOpen>> {
    OPEN.lock().unwrap_or_else(PoisonError::into_inner)
}

fn decapsulation_key(seed: &[u8; PHONE_SEED_BYTES]) -> DecapsulationKey<MlKem768> {
    DecapsulationKey::<MlKem768>::from_seed(ml_kem::Seed::from(*seed))
}

/// The public encapsulation key of a seed.
pub fn phone_key_of(seed: &[u8; PHONE_SEED_BYTES]) -> Vec<u8> {
    decapsulation_key(seed).encapsulation_key().to_bytes().to_vec()
}

/// SHA3-256 of a phone key, as the card record and the Seal's journal bind it.
pub fn phone_key_hash(phone_key: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(PHONE_KEY_LABEL.len() + phone_key.len());
    bytes.extend_from_slice(PHONE_KEY_LABEL);
    bytes.extend_from_slice(phone_key);
    sha3_256(&bytes)
}

/// Why an Open could not be finished. Never holds a key or a seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// No phone key is held: none was made, or it was wiped.
    NoPhoneKey,
    /// No release package is held.
    NoRelease,
    /// The package does not open with this phone key for this card.
    BadRelease,
    /// What the package holds is not the wallet core's key bytes.
    NotAKey,
    /// The operating system gave no randomness.
    Randomness,
}

impl OpenError {
    /// The error's code, as JavaScript sees it.
    pub fn code(self) -> &'static str {
        match self {
            OpenError::NoPhoneKey => "no-phone-key",
            OpenError::NoRelease => "no-release",
            OpenError::BadRelease => "bad-release",
            OpenError::NotAKey => "not-a-key",
            OpenError::Randomness => "randomness",
        }
    }
}

/// Makes the phone key of an Open from `seed` and holds it, unless one is
/// held already. Returns the held key's public encapsulation key.
pub fn hold_phone_key(seed: &mut [u8; PHONE_SEED_BYTES]) -> Vec<u8> {
    let mut held = pending();
    let open = held.get_or_insert_with(|| PendingOpen { seed: Zeroizing::new(*seed), release: None });
    seed.zeroize();
    phone_key_of(&open.seed)
}

/// The held phone key's public encapsulation key, made from the operating
/// system's random source when none is held. The private key never leaves
/// native code.
#[uniffi::export]
pub fn seal_open_phone_key() -> Result<Vec<u8>, SealOpenError> {
    if let Some(open) = pending().as_ref() {
        return Ok(phone_key_of(&open.seed));
    }
    let mut seed = Zeroizing::new([0u8; PHONE_SEED_BYTES]);
    if SysRng.try_fill_bytes(&mut seed[..]).is_err() {
        return Err(SealOpenError::Failed { code: OpenError::Randomness.code().to_owned() });
    }
    Ok(hold_phone_key(&mut *seed))
}

/// Whether a phone key of an Open is held.
#[uniffi::export]
pub fn has_seal_open_key() -> bool {
    pending().is_some()
}

/// Wipes the phone key of an Open and any release held for it. The app calls
/// this once the Claim of the opened card settled.
#[uniffi::export]
pub fn forget_seal_open_key() {
    if let Some(mut open) = pending().take() {
        if let Some(release) = open.release.as_mut() {
            release.zeroize();
        }
    }
}

/// Holds the release package the relay received for the held phone key.
pub fn hold_release(package: &[u8]) -> Result<(), OpenError> {
    if package.len() > MAX_RELEASE_BYTES {
        return Err(OpenError::BadRelease);
    }
    let mut held = pending();
    let open = held.as_mut().ok_or(OpenError::NoPhoneKey)?;
    open.release = Some(package.to_vec());
    Ok(())
}

/// Why [`seal_open_phone_key`] failed.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum SealOpenError {
    /// `code` is one of [`OpenError::code`]'s codes.
    Failed { code: String },
}

impl core::fmt::Display for SealOpenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SealOpenError::Failed { code } => write!(f, "the Open's phone key failed: {code}"),
        }
    }
}

impl std::error::Error for SealOpenError {}

/// Checks the Seal's Open answer against the held release package, opens the
/// package with the held phone key, and holds the Phantom Key in the core's
/// card-key slot for the Claim. `refusal` is empty when it did; it is one of
/// the answer refusals of `crate::seal_answer` or [`OpenError::code`]'s codes
/// otherwise. The release is dropped either way; the phone key stays until
/// [`forget_seal_open_key`], so the Open can be asked again.
#[uniffi::export]
pub fn finish_seal_open(check: SealAnswerCheck) -> SealAnswerVerdict {
    if check.kind != "open" {
        return verdict(Err(Refusal::WrongKind));
    }
    let (seed, release) = {
        let mut held = pending();
        let Some(open) = held.as_mut() else {
            return failed(OpenError::NoPhoneKey);
        };
        let Some(release) = open.release.take() else {
            return failed(OpenError::NoRelease);
        };
        (open.seed.clone(), Zeroizing::new(release))
    };
    let answer = match check_answer(&check, Some(release.as_slice())) {
        Ok(answer) => answer,
        Err(refusal) => return verdict(Err(refusal)),
    };
    if answer.state != "opened" {
        return verdict(Err(Refusal::WrongKind));
    }
    let key = match open_release(&seed, &release, &answer.uid, answer.generation) {
        Ok(key) => key,
        Err(error) => return failed(error),
    };
    let words = match phantom_key_from_bytes(&key) {
        Ok(phantom) => match phantom.format_words() {
            Some(words) => words.as_str().to_owned(),
            None => return failed(OpenError::NotAKey),
        },
        Err(error) => return failed(error),
    };
    if !hold_card_words(words) {
        return failed(OpenError::NotAKey);
    }
    verdict(Ok(answer))
}

fn failed(error: OpenError) -> SealAnswerVerdict {
    SealAnswerVerdict { refusal: error.code().to_owned(), answer: None }
}

fn release_keys(shared: &[u8], uid: &[u8], generation: u32) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mut okm = Zeroizing::new([0u8; 64]);
    SimpleHkdf::<Sha3_256>::new(Some(RELEASE_LABEL), shared)
        .expand_multi_info(&[uid, &generation.to_be_bytes()], &mut okm[..])
        .expect("64 bytes is well within HKDF's limit");
    let mut enc = Zeroizing::new([0u8; 32]);
    let mut mac = Zeroizing::new([0u8; 32]);
    enc.copy_from_slice(&okm[..32]);
    mac.copy_from_slice(&okm[32..]);
    (enc, mac)
}

/// Opens a release package for card `uid` at `generation` (the card's new
/// generation, as the Open answer gives it) with the phone key of `seed`.
/// Returns the released key bytes.
pub fn open_release(
    seed: &[u8; PHONE_SEED_BYTES],
    package: &[u8],
    uid: &[u8],
    generation: u32,
) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    let fixed = 4 + KEM_CIPHERTEXT_BYTES + 16;
    if package.len() < fixed + 16 + TAG_BYTES || (package.len() - fixed - TAG_BYTES) % 16 != 0 {
        return Err(OpenError::BadRelease);
    }
    if &package[..4] != MAGIC {
        return Err(OpenError::BadRelease);
    }
    let (signed, stored) = package.split_at(package.len() - TAG_BYTES);
    let key = decapsulation_key(seed);
    let shared = Zeroizing::new(
        key.decapsulate_slice(&package[4..4 + KEM_CIPHERTEXT_BYTES]).map_err(|_| OpenError::BadRelease)?,
    );
    let (enc, mac_key) = release_keys(&shared, uid, generation);
    let mut mac = <SimpleHmac<Sha3_256> as KeyInit>::new_from_slice(&mac_key[..]).map_err(|_| OpenError::BadRelease)?;
    mac.update(RELEASE_LABEL);
    mac.update(uid);
    mac.update(&generation.to_be_bytes());
    mac.update(signed);
    mac.verify_slice(stored).map_err(|_| OpenError::BadRelease)?;

    let iv: [u8; 16] = package[4 + KEM_CIPHERTEXT_BYTES..fixed].try_into().map_err(|_| OpenError::BadRelease)?;
    let mut mode = cbc::Decryptor::<Aes256>::new_from_slices(&enc[..], &iv).map_err(|_| OpenError::BadRelease)?;
    let mut plain = Zeroizing::new(signed[fixed..].to_vec());
    for chunk in plain.chunks_exact_mut(16) {
        let mut block = aes::Block::default();
        block.copy_from_slice(chunk);
        mode.decrypt_block(&mut block);
        chunk.copy_from_slice(&block);
        block.zeroize();
    }
    // ISO/IEC 9797-1 padding method 2: 0x80, then zeros to a whole block.
    let mut end = plain.len();
    while end > 0 && plain[end - 1] == 0x00 {
        end -= 1;
    }
    if end == 0 || plain[end - 1] != 0x80 || plain.len() - (end - 1) > 16 {
        return Err(OpenError::BadRelease);
    }
    Ok(Zeroizing::new(plain[..end - 1].to_vec()))
}

/// The Phantom Key of released key bytes: the format code
/// [`KEY_FORMAT_CODE`] then [`KEY_SECRET_BYTES`] secret bytes. Ghost's client
/// makes a key of a format from the first 32 bytes its source gives, so the
/// key is made from a source that gives exactly these; a secret the client
/// would not take (it asks for more) is refused.
pub fn phantom_key_from_bytes(bytes: &[u8]) -> Result<PhantomKey, OpenError> {
    if bytes.len() != 1 + KEY_SECRET_BYTES || bytes[0] != KEY_FORMAT_CODE {
        return Err(OpenError::NotAKey);
    }
    let mut source = GivenBytes { bytes: Zeroizing::new(bytes[1..].to_vec()), used: 0, overdrawn: false };
    let key = PhantomKey::generate(KeyFormat::Words, &mut source);
    if source.overdrawn || source.used != KEY_SECRET_BYTES {
        return Err(OpenError::NotAKey);
    }
    Ok(key)
}

/// A source that gives exactly the bytes it holds, then zeros (and says so).
struct GivenBytes {
    bytes: Zeroizing<Vec<u8>>,
    used: usize,
    overdrawn: bool,
}

impl TryRng for GivenBytes {
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
        let end = self.used + dst.len();
        if end > self.bytes.len() {
            dst.fill(0);
            self.overdrawn = true;
            return Ok(());
        }
        dst.copy_from_slice(&self.bytes[self.used..end]);
        self.used = end;
        Ok(())
    }
}

impl TryCryptoRng for GivenBytes {}

/// Holds the release package the card module's relay received (`length`
/// bytes at `package`) for the held phone key. Returns 0,
/// [`OPEN_NOTHING_HELD`] when no phone key is held, [`OPEN_WRONG_LENGTH`] for
/// a package too long to be a release, or [`OPEN_NULL`].
///
/// # Safety
///
/// `package` must be valid for reads of `length` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_wallet_seal_open_take_release(package: *const u8, length: usize) -> isize {
    if package.is_null() {
        return OPEN_NULL;
    }
    // SAFETY: the caller guarantees `package` holds `length` bytes.
    let bytes = unsafe { core::slice::from_raw_parts(package, length) };
    match hold_release(bytes) {
        Ok(()) => 0,
        Err(OpenError::NoPhoneKey) => OPEN_NOTHING_HELD,
        Err(_) => OPEN_WRONG_LENGTH,
    }
}

/// Copies the held phone key's 64-byte seed into `out` for the card module to
/// keep in the Keychain (this device only) until the Claim settles. Returns
/// 64, [`OPEN_NOTHING_HELD`], [`OPEN_WRONG_LENGTH`] (capacity under 64) or
/// [`OPEN_NULL`].
///
/// # Safety
///
/// `out` must be valid for writes of `capacity` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_wallet_seal_open_copy_seed(out: *mut u8, capacity: usize) -> isize {
    if out.is_null() {
        return OPEN_NULL;
    }
    if capacity < PHONE_SEED_BYTES {
        return OPEN_WRONG_LENGTH;
    }
    let held = pending();
    let Some(open) = held.as_ref() else {
        return OPEN_NOTHING_HELD;
    };
    // SAFETY: the caller guarantees `out` holds `capacity >= 64` bytes.
    unsafe { core::ptr::copy_nonoverlapping(open.seed.as_ptr(), out, PHONE_SEED_BYTES) };
    PHONE_SEED_BYTES as isize
}

/// Holds the phone key of a seed the card module kept in the Keychain, unless
/// a phone key is held already. Returns 0, [`OPEN_WRONG_LENGTH`] or
/// [`OPEN_NULL`].
///
/// # Safety
///
/// `seed` must be valid for reads of `length` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_wallet_seal_open_restore_seed(seed: *const u8, length: usize) -> isize {
    if seed.is_null() {
        return OPEN_NULL;
    }
    if length != PHONE_SEED_BYTES {
        return OPEN_WRONG_LENGTH;
    }
    // SAFETY: the caller guarantees `seed` holds `length == 64` bytes.
    let bytes = unsafe { core::slice::from_raw_parts(seed, length) };
    let mut copy = Zeroizing::new([0u8; PHONE_SEED_BYTES]);
    copy.copy_from_slice(bytes);
    hold_phone_key(&mut *copy);
    0
}
