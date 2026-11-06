//! Each card's five AES-128 keys, derived from the Seal's master key M and
//! the card's UID. Nothing stores them: the Seal derives them again for every
//! tap.
//!
//! The KDF is HKDF (RFC 5869) with HMAC-SHA3-256:
//!
//! - salt: `ghost-seal/v1/card-keys`;
//! - input key material: M (32 bytes);
//! - info: the key's label, one zero byte, the 7-byte UID and the 4-byte key
//!   generation (big endian);
//! - output: 16 bytes.
//!
//! Each key has its own label ([`CARD_KEY_LABELS`]), so no two keys of a card
//! are ever equal by construction. Open moves a card to the next generation,
//! which gives it five new keys.

use crate::primitives::hkdf_sha3_256;
use crate::secrets::{CardKey, MasterKey};

/// A card's 7-byte UID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CardUid(pub [u8; 7]);

/// The HKDF salt of the card keys.
pub const CARD_KEYS_SALT: &[u8] = b"ghost-seal/v1/card-keys";

/// The label of each card key, by key number.
pub const CARD_KEY_LABELS: [&[u8]; 5] = [
    b"ghost-seal/v1/card-key/0/application-master",
    b"ghost-seal/v1/card-key/1/check-read",
    b"ghost-seal/v1/card-key/2/record-read-write",
    b"ghost-seal/v1/card-key/3/sdm-mac",
    b"ghost-seal/v1/card-key/4/reserve",
];

/// Key 0: changes keys and file settings.
pub const KEY_APPLICATION_MASTER: u8 = 0;
/// Key 1: reads the record (Check).
pub const KEY_CHECK_READ: u8 = 1;
/// Key 2: reads and writes the record (Fill, Open).
pub const KEY_RECORD_WRITE: u8 = 2;
/// Key 3: kept for SUN messages; no right uses it.
pub const KEY_SDM_MAC: u8 = 3;
/// Key 4: kept in reserve; no right uses it.
pub const KEY_RESERVE: u8 = 4;

/// A card's five keys of one generation. Wiped when dropped; no `Debug`.
pub struct CardKeys {
    generation: u32,
    keys: [CardKey; 5],
}

impl CardKeys {
    /// Key number `key_no` (0 to 4).
    pub fn key(&self, key_no: u8) -> &[u8; 16] {
        &self.keys[usize::from(key_no)]
    }

    /// The generation these keys belong to.
    pub fn generation(&self) -> u32 {
        self.generation
    }
}

/// The card's keys as the card setup gives them (generation 0).
pub fn card_keys(master: &MasterKey, uid: &CardUid) -> CardKeys {
    card_keys_at(master, uid, 0)
}

/// The card's keys of `generation`.
pub fn card_keys_at(master: &MasterKey, uid: &CardUid, generation: u32) -> CardKeys {
    let generation_bytes = generation.to_be_bytes();
    let keys = CARD_KEY_LABELS.map(|label| {
        let mut key = CardKey::default();
        hkdf_sha3_256(
            CARD_KEYS_SALT,
            master.derive_from(),
            &[label, &[0x00], &uid.0, &generation_bytes],
            &mut key[..],
        );
        key
    });
    CardKeys { generation, keys }
}

/// The key version a card's keys carry at `generation`: never 0, which is the
/// factory keys' version.
pub fn key_version(generation: u32) -> u8 {
    (generation % 255) as u8 + 1
}

/// The generation a key version stands for, or `None` for the factory version.
pub fn generation_of_version(version: u8) -> Option<u32> {
    version.checked_sub(1).map(u32::from)
}
