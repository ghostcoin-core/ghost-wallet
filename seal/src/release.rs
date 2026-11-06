//! The Open release: the Phantom Key, encrypted to the phone key that was
//! bound when the Open started.
//!
//! The phone key is an ML-KEM-768 encapsulation key (FIPS 203). The Seal
//! encapsulates to it and derives two keys from the shared secret with HKDF
//! (HMAC-SHA3-256, salt [`RELEASE_LABEL`], info UID || generation): an
//! AES-256 key and an HMAC-SHA3-256 key. The key is padded (ISO/IEC 9797-1
//! method 2), encrypted with AES-256-CBC under a fresh IV, and the whole
//! package is MACed. The shared secret never leaves the Seal; only its
//! ML-KEM ciphertext does.
//!
//! Package: `GSR1` (4) || ML-KEM ciphertext (1088) || IV (16) ||
//! ciphertext (16 or more) || tag (32), the tag being HMAC-SHA3-256 over
//! [`RELEASE_LABEL`] || UID || generation || everything before the tag.

use ml_kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, KeyExport, MlKem768, TryKeyInit};
use zeroize::Zeroizing;

use crate::card_keys::CardUid;
use crate::error::SealError;
use crate::primitives::{aes256_cbc_decrypt, aes256_cbc_encrypt, ct_eq, hkdf_sha3_256, hmac_sha3_256, pad, sha3_256, unpad};
use crate::secrets::PhantomKey;
use crate::traits::{DrawnRandom, SealRandom};

/// The HKDF salt and MAC label of a release package.
pub const RELEASE_LABEL: &[u8] = b"ghost-seal/v1/open-release";
/// An ML-KEM-768 encapsulation key's length.
pub const PHONE_KEY_BYTES: usize = 1184;
/// An ML-KEM-768 ciphertext's length.
pub const KEM_CIPHERTEXT_BYTES: usize = 1088;

const MAGIC: &[u8; 4] = b"GSR1";
const TAG_BYTES: usize = 32;

/// SHA3-256 of a phone key: what the card record and the journal bind.
pub fn phone_key_hash(phone_key: &[u8]) -> [u8; 32] {
    sha3_256(&[b"ghost-seal/v1/phone-key", phone_key])
}

/// A phone's ML-KEM-768 encapsulation key.
pub struct PhoneKey {
    key: EncapsulationKey<MlKem768>,
}

impl PhoneKey {
    /// Reads and checks an encoded ML-KEM-768 encapsulation key.
    pub fn parse(bytes: &[u8]) -> Result<PhoneKey, SealError> {
        if bytes.len() != PHONE_KEY_BYTES {
            return Err(SealError::BadPhoneKey);
        }
        let key = <EncapsulationKey<MlKem768> as TryKeyInit>::new_from_slice(bytes).map_err(|_| SealError::BadPhoneKey)?;
        Ok(PhoneKey { key })
    }
}

fn release_keys(shared: &[u8], uid: &CardUid, generation: u32) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mut okm = Zeroizing::new([0u8; 64]);
    hkdf_sha3_256(RELEASE_LABEL, shared, &[&uid.0, &generation.to_be_bytes()], &mut okm[..]);
    let mut enc = Zeroizing::new([0u8; 32]);
    let mut mac = Zeroizing::new([0u8; 32]);
    enc.copy_from_slice(&okm[..32]);
    mac.copy_from_slice(&okm[32..]);
    (enc, mac)
}

fn tag(mac_key: &[u8; 32], uid: &CardUid, generation: u32, body: &[u8]) -> [u8; 32] {
    hmac_sha3_256(mac_key, &[RELEASE_LABEL, &uid.0, &generation.to_be_bytes(), body])
}

/// Encrypts `key` to `phone` for card `uid` at `generation`.
pub(crate) fn seal_release(
    phone: &PhoneKey,
    uid: &CardUid,
    generation: u32,
    key: &PhantomKey,
    random: &mut dyn SealRandom,
) -> Result<Vec<u8>, SealError> {
    let mut drawn = DrawnRandom::draw(random)?;
    let (ciphertext, shared) = phone.key.encapsulate_with_rng(&mut drawn);
    let shared = Zeroizing::new(shared);
    let (enc, mac) = release_keys(&shared, uid, generation);
    let mut iv = [0u8; 16];
    random.fill(&mut iv)?;
    let body = aes256_cbc_encrypt(&enc, &iv, &pad(key.expose_secret()))?;
    let mut package = Vec::with_capacity(4 + KEM_CIPHERTEXT_BYTES + 16 + body.len() + TAG_BYTES);
    package.extend_from_slice(MAGIC);
    package.extend_from_slice(&ciphertext);
    package.extend_from_slice(&iv);
    package.extend_from_slice(&body);
    let t = tag(&mac, uid, generation, &package);
    package.extend_from_slice(&t);
    Ok(package)
}

/// The phone's side of a release: its ML-KEM-768 decapsulation key. A
/// reference for the phone, and what the tests open releases with.
pub struct PhoneSecret {
    key: DecapsulationKey<MlKem768>,
}

impl PhoneSecret {
    /// A phone key from its 64-byte ML-KEM seed (d || z). The seed is wiped.
    pub fn from_seed(seed: &mut [u8; 64]) -> PhoneSecret {
        let key = DecapsulationKey::<MlKem768>::from_seed(ml_kem::Seed::from(*seed));
        zeroize::Zeroize::zeroize(seed);
        PhoneSecret { key }
    }

    /// The encoded encapsulation key the phone sends when it starts an Open.
    pub fn public_key(&self) -> Vec<u8> {
        self.key.encapsulation_key().to_bytes().to_vec()
    }

    /// Opens a release package for card `uid` at `generation`.
    pub fn open(&self, package: &[u8], uid: &CardUid, generation: u32) -> Result<PhantomKey, SealError> {
        let fixed = 4 + KEM_CIPHERTEXT_BYTES + 16;
        if package.len() < fixed + 16 + TAG_BYTES || (package.len() - fixed - TAG_BYTES) % 16 != 0 {
            return Err(SealError::BadRelease);
        }
        if &package[..4] != MAGIC {
            return Err(SealError::BadRelease);
        }
        let (signed, stored) = package.split_at(package.len() - TAG_BYTES);
        let shared = Zeroizing::new(
            self.key.decapsulate_slice(&package[4..4 + KEM_CIPHERTEXT_BYTES]).map_err(|_| SealError::BadRelease)?,
        );
        let (enc, mac) = release_keys(&shared, uid, generation);
        if !ct_eq(&tag(&mac, uid, generation, signed), stored) {
            return Err(SealError::BadRelease);
        }
        let iv: [u8; 16] = package[4 + KEM_CIPHERTEXT_BYTES..fixed].try_into().expect("16 bytes");
        let plain = aes256_cbc_decrypt(&enc, &iv, &signed[fixed..])?;
        let key = unpad(&plain).map_err(|_| SealError::BadRelease)?;
        PhantomKey::new(key.to_vec())
    }
}
