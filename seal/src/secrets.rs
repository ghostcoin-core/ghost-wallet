//! The Seal's secrets: the master key M, Phantom Keys and Open PINs.
//!
//! None of these types implements `Debug`, `Display`, `Clone` or any
//! serialisation, and each is wiped from memory when dropped. There is no
//! function that hands M out: the Seal only derives keys from it.

use zeroize::{Zeroize, Zeroizing};

use crate::error::SealError;

/// The Seal's master key M (32 bytes). Every card's keys, the PIN hashes, the
/// journal keys and the answer-signing key are derived from it.
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl MasterKey {
    /// Takes M and wipes the caller's copy.
    pub fn take(bytes: &mut [u8; 32]) -> Self {
        let key = MasterKey(Zeroizing::new(*bytes));
        bytes.zeroize();
        key
    }

    /// For key derivation inside this crate only.
    pub(crate) fn derive_from(&self) -> &[u8; 32] {
        &self.0
    }

    /// For the key-share package only: the giving enclave encrypts M, under
    /// keys only an attested copy on the published list can derive, and
    /// nothing else reads M through this.
    #[cfg(feature = "nitro")]
    pub(crate) fn for_key_share_package(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The most bytes a Phantom Key may have: the card's key slot.
pub const PHANTOM_KEY_MAX_BYTES: usize = 64;

/// A Phantom Key's secret bytes, as the wallet core encodes them.
pub struct PhantomKey(Zeroizing<Vec<u8>>);

impl PhantomKey {
    /// Wraps a Phantom Key of 1 to [`PHANTOM_KEY_MAX_BYTES`] bytes. The vector
    /// is wiped when the key is dropped.
    pub fn new(bytes: Vec<u8>) -> Result<Self, SealError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() || bytes.len() > PHANTOM_KEY_MAX_BYTES {
            return Err(SealError::BadPhantomKey);
        }
        Ok(PhantomKey(bytes))
    }

    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Self, SealError> {
        Self::new(bytes.to_vec())
    }

    /// The key's bytes. The Seal calls this only to write the key slot, seal
    /// its journal and build the Open release; the phone calls it once the
    /// release is opened.
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    /// The key's length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Never true: a Phantom Key has at least one byte.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// An Open PIN: 4 to 12 ASCII digits.
pub struct Pin(Zeroizing<Vec<u8>>);

impl Pin {
    /// Checks and wraps a PIN.
    pub fn new(digits: &str) -> Result<Self, SealError> {
        let bytes = Zeroizing::new(digits.as_bytes().to_vec());
        if !(4..=12).contains(&bytes.len()) || !bytes.iter().all(u8::is_ascii_digit) {
            return Err(SealError::BadPin);
        }
        Ok(Pin(bytes))
    }

    pub(crate) fn digits(&self) -> &[u8] {
        &self.0
    }
}

/// An AES-128 card key, wiped when dropped.
pub type CardKey = Zeroizing<[u8; 16]>;
