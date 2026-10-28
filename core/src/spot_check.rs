//! Spot check: the proof of work of one header, checked on its own.
//!
//! The phone does not check the chain's headers one after another (a RandomX
//! hash costs seconds there, after minutes of cache setup). Instead it checks
//! one header now and then: it builds the RandomX cache of the header's key
//! block, hashes the header once with Ghost's own
//! `ghost_client::seal::verify_seal`, and checks that the header's difficulty
//! is at least a minimum the caller passes in (a release pins it). The cache
//! is freed before [`spot_check_header`] returns.
//!
//! [`SpotCheckKey`] holds one cache for longer, so the cache can be built
//! once and kept while something else runs (the worst-case benchmark holds it
//! through a proof); [`SpotCheckKey::release`] frees it.
//!
//! There is no network code here: the caller fetches the header and the hash
//! of its key block (the ancestor at [`spot_check_seed_height`]) and passes
//! the bytes in. No consensus or seal code lives here either.

use core::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use ghost_client::seal::{SealKey, header_fields, seed_height, verify_seal};

/// What one spot check found, and how long its two steps took.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct SpotCheckReport {
    /// The header's height.
    pub height: u64,
    /// The header's hash: Keccak-256 of its RLP.
    pub hash: Vec<u8>,
    /// The header's difficulty field, big-endian with no leading zero byte.
    pub difficulty: Vec<u8>,
    /// Whether the seal is valid at the header's own difficulty and that
    /// difficulty is at least the minimum.
    pub passed: bool,
    /// Why it did not pass; `None` when it passed.
    pub failure: Option<String>,
    /// How long building the RandomX cache took, in seconds.
    pub cache_seconds: f64,
    /// How long checking the seal (one RandomX hash) took, in seconds.
    pub hash_seconds: f64,
}

/// Why a spot check could not be made at all. A header that is checked and
/// fails is not an error: its report says why it did not pass.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum SpotCheckError {
    /// The header, the key block hash or the minimum is not usable.
    Input { reason: String },
    /// The cache was released before the check.
    Released,
}

impl fmt::Display for SpotCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpotCheckError::Input { reason } => write!(f, "spot check input refused: {reason}"),
            SpotCheckError::Released => f.write_str("the spot check's RandomX cache was released"),
        }
    }
}

impl std::error::Error for SpotCheckError {}

fn input(reason: &str) -> SpotCheckError {
    SpotCheckError::Input { reason: reason.to_string() }
}

/// The height of the key block whose hash keys the seal of the header at
/// `height` (Ghost's `seed_height`).
#[uniffi::export]
pub fn spot_check_seed_height(height: u64) -> u64 {
    seed_height(height)
}

/// Checks the proof of work of one header: builds the RandomX cache for
/// `key_block_hash`, hashes the header once, checks the hash against the
/// header's own difficulty and that difficulty against `min_difficulty`
/// (big-endian), and frees the cache before returning.
#[uniffi::export]
pub fn spot_check_header(
    header: Vec<u8>,
    key_block_hash: Vec<u8>,
    min_difficulty: Vec<u8>,
) -> Result<SpotCheckReport, SpotCheckError> {
    // Refuse what cannot be checked before spending a cache on it.
    header_fields(&header).map_err(|error| input(&format!("the header does not decode: {error:?}")))?;
    check_minimum(&min_difficulty)?;
    let key = SpotCheckKey::new(key_block_hash)?;
    let report = key.check(header, min_difficulty);
    key.release();
    report
}

/// One RandomX cache for spot checks, held until [`SpotCheckKey::release`]
/// or until the object goes.
#[derive(uniffi::Object)]
pub struct SpotCheckKey {
    key: Mutex<Option<SealKey>>,
    cache_seconds: f64,
}

#[uniffi::export]
impl SpotCheckKey {
    /// Builds the cache for the key block with hash `key_block_hash`.
    #[uniffi::constructor]
    pub fn new(key_block_hash: Vec<u8>) -> Result<Arc<Self>, SpotCheckError> {
        let hash: [u8; 32] =
            key_block_hash.as_slice().try_into().map_err(|_| input("the key block hash is not 32 bytes"))?;
        let start = Instant::now();
        let key = SealKey::new(&hash);
        let cache_seconds = start.elapsed().as_secs_f64();
        Ok(Arc::new(Self { key: Mutex::new(Some(key)), cache_seconds }))
    }

    /// How long building the cache took, in seconds.
    pub fn cache_seconds(&self) -> f64 {
        self.cache_seconds
    }

    /// Whether the cache is still held.
    pub fn is_held(&self) -> bool {
        self.lock().is_some()
    }

    /// Frees the cache. Returns whether it was still held.
    pub fn release(&self) -> bool {
        self.lock().take().is_some()
    }

    /// Checks one header under this cache, as [`spot_check_header`] does.
    pub fn check(&self, header: Vec<u8>, min_difficulty: Vec<u8>) -> Result<SpotCheckReport, SpotCheckError> {
        let fields =
            header_fields(&header).map_err(|error| input(&format!("the header does not decode: {error:?}")))?;
        check_minimum(&min_difficulty)?;
        let guard = self.lock();
        let key = guard.as_ref().ok_or(SpotCheckError::Released)?;

        let start = Instant::now();
        let seal = verify_seal(&header, &fields.difficulty, key);
        let hash_seconds = start.elapsed().as_secs_f64();
        drop(guard);

        let failure = match seal {
            Err(error) => Some(error.to_string()),
            Ok(()) if !at_least(&fields.difficulty, &min_difficulty) => {
                Some("the header's difficulty is below the minimum".to_string())
            }
            Ok(()) => None,
        };
        Ok(SpotCheckReport {
            height: fields.number,
            hash: fields.hash.to_vec(),
            difficulty: fields.difficulty,
            passed: failure.is_none(),
            failure,
            cache_seconds: self.cache_seconds,
            hash_seconds,
        })
    }
}

impl SpotCheckKey {
    fn lock(&self) -> MutexGuard<'_, Option<SealKey>> {
        self.key.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A minimum of zero would let any header through, and one wider than 256
/// bits no header can meet: both are refused.
fn check_minimum(min_difficulty: &[u8]) -> Result<(), SpotCheckError> {
    let digits = trimmed(min_difficulty);
    if digits.is_empty() {
        return Err(input("the minimum difficulty is zero"));
    }
    if digits.len() > 32 {
        return Err(input("the minimum difficulty is wider than 256 bits"));
    }
    Ok(())
}

/// The big-endian bytes without their leading zero bytes.
fn trimmed(be: &[u8]) -> &[u8] {
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    &be[first..]
}

/// Whether big-endian `value` is at least big-endian `minimum`.
fn at_least(value: &[u8], minimum: &[u8]) -> bool {
    let (value, minimum) = (trimmed(value), trimmed(minimum));
    (value.len(), value) >= (minimum.len(), minimum)
}
