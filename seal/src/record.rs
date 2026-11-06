//! The card record: what a Ghost Sealed card keeps in its record file (file
//! 2, 256 bytes, CommMode.Full).
//!
//! The record is two frames, each written by one WriteData of at most
//! [`FRAME_BYTES`] bytes and each carrying its own check, so a write that the
//! card never finished is seen as a torn frame instead of being read as
//! something else. Every change of state rewrites exactly one frame.
//!
//! Header frame (offset 0, [`HEADER_BYTES`] bytes):
//!
//! | offset | bytes | field |
//! | --- | --- | --- |
//! | 0 | 4 | magic `GSH1` |
//! | 4 | 1 | layout version (1) |
//! | 5 | 1 | state: 0 Empty, 1 Sealed, 2 Opening, 3 Opened |
//! | 6 | 1 | flags: bit 0 a key is in the slot, bit 1 an Open PIN is set |
//! | 7 | 1 | Open PIN tries left |
//! | 8 | 4 | generation (big endian) |
//! | 12 | 16 | amount in wei (big endian) |
//! | 28 | 32 | the coin: SHA3-256 of its commit data |
//! | 60 | 16 | the Open PIN hash (zeros without a PIN) |
//! | 76 | 32 | SHA3-256 of the phone key an Open is bound to (zeros before) |
//! | 108 | 8 | check |
//!
//! Key slot frame (offset 128, [`KEY_SLOT_BYTES`] bytes):
//!
//! | offset | bytes | field |
//! | --- | --- | --- |
//! | 0 | 4 | magic `GSK1` |
//! | 4 | 4 | generation (big endian) |
//! | 8 | 32 | the coin the key belongs to (zeros when empty) |
//! | 40 | 1 | key length (0 when empty) |
//! | 41 | 64 | the Phantom Key, zero padded |
//! | 105 | 8 | check |
//!
//! The check is the first 8 bytes of SHA3-256(`ghost-seal/v1/record-check`
//! || the frame's magic || UID || the frame's other bytes). A frame of all
//! zeros is a blank file: a card that was set up and never filled.

use zeroize::Zeroizing;

use crate::card_keys::CardUid;
use crate::error::SealError;
use crate::primitives::{ct_eq, sha3_256};
use crate::secrets::{PHANTOM_KEY_MAX_BYTES, PhantomKey};

/// The record's file number (the NDEF file, 256 bytes).
pub const RECORD_FILE: u8 = 0x02;
/// The record file's size.
pub const RECORD_FILE_BYTES: u32 = 256;
/// The most bytes one WriteData or ReadData of the record carries.
pub const FRAME_BYTES: usize = 128;
/// Where the header frame starts.
pub const HEADER_OFFSET: u32 = 0;
/// Where the key slot frame starts.
pub const KEY_SLOT_OFFSET: u32 = 128;
/// The header frame's length.
pub const HEADER_BYTES: usize = 116;
/// The key slot frame's length.
pub const KEY_SLOT_BYTES: usize = 113;
/// Open PIN tries a card starts with.
pub const PIN_TRIES: u8 = 5;

const HEADER_MAGIC: &[u8; 4] = b"GSH1";
const KEY_SLOT_MAGIC: &[u8; 4] = b"GSK1";
const LAYOUT_VERSION: u8 = 1;
const CHECK_LABEL: &[u8] = b"ghost-seal/v1/record-check";
const CHECK_BYTES: usize = 8;
const FLAG_KEY: u8 = 0x01;
const FLAG_PIN: u8 = 0x02;

/// A card's state, as its record and every signed answer give it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardState {
    /// No coin: blank, or a Fill written and not yet paid.
    Empty = 0,
    /// Holds a paid coin; its key has never left the Seal and the card.
    Sealed = 1,
    /// An Open began: never safe to accept.
    Opening = 2,
    /// The key was released.
    Opened = 3,
}

impl CardState {
    /// The state of a byte.
    pub fn from_byte(byte: u8) -> Option<CardState> {
        match byte {
            0 => Some(CardState::Empty),
            1 => Some(CardState::Sealed),
            2 => Some(CardState::Opening),
            3 => Some(CardState::Opened),
            _ => None,
        }
    }
}

fn check(magic: &[u8; 4], uid: &CardUid, body: &[u8]) -> [u8; CHECK_BYTES] {
    let hash = sha3_256(&[CHECK_LABEL, magic, &uid.0, body]);
    let mut out = [0u8; CHECK_BYTES];
    out.copy_from_slice(&hash[..CHECK_BYTES]);
    out
}

/// The header frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The card's state.
    pub state: CardState,
    /// Whether the key slot holds a key.
    pub key_present: bool,
    /// The Open PIN hash, when the card has a PIN.
    pub pin_hash: Option<[u8; 16]>,
    /// Open PIN tries left.
    pub pin_tries_left: u8,
    /// The generation of the card's keys this record was written under.
    pub generation: u32,
    /// The coin's amount in wei.
    pub amount_wei: u128,
    /// SHA3-256 of the coin's commit data.
    pub coin: [u8; 32],
    /// SHA3-256 of the phone key an Open is bound to.
    pub phone_key_hash: [u8; 32],
}

impl Header {
    /// The header of a blank card of `generation`.
    pub fn blank(generation: u32) -> Header {
        Header {
            state: CardState::Empty,
            key_present: false,
            pin_hash: None,
            pin_tries_left: 0,
            generation,
            amount_wei: 0,
            coin: [0u8; 32],
            phone_key_hash: [0u8; 32],
        }
    }

    /// The frame's bytes for card `uid`.
    pub fn encode(&self, uid: &CardUid) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_BYTES);
        out.extend_from_slice(HEADER_MAGIC);
        out.push(LAYOUT_VERSION);
        out.push(self.state as u8);
        let mut flags = 0;
        if self.key_present {
            flags |= FLAG_KEY;
        }
        if self.pin_hash.is_some() {
            flags |= FLAG_PIN;
        }
        out.push(flags);
        out.push(self.pin_tries_left);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.amount_wei.to_be_bytes());
        out.extend_from_slice(&self.coin);
        out.extend_from_slice(&self.pin_hash.unwrap_or([0u8; 16]));
        out.extend_from_slice(&self.phone_key_hash);
        let c = check(HEADER_MAGIC, uid, &out[4..]);
        out.extend_from_slice(&c);
        debug_assert_eq!(out.len(), HEADER_BYTES);
        out
    }

    /// Reads a header frame; `None` for a blank file.
    pub fn decode(bytes: &[u8], uid: &CardUid) -> Result<Option<Header>, SealError> {
        if bytes.len() != HEADER_BYTES {
            return Err(SealError::TornRecord);
        }
        if bytes.iter().all(|b| *b == 0) {
            return Ok(None);
        }
        let (body, stored) = bytes.split_at(HEADER_BYTES - CHECK_BYTES);
        if &body[..4] != HEADER_MAGIC || !ct_eq(&check(HEADER_MAGIC, uid, &body[4..]), stored) {
            return Err(SealError::TornRecord);
        }
        if body[4] != LAYOUT_VERSION {
            return Err(SealError::TornRecord);
        }
        let state = CardState::from_byte(body[5]).ok_or(SealError::TornRecord)?;
        let flags = body[6];
        let mut pin = [0u8; 16];
        pin.copy_from_slice(&body[60..76]);
        let mut coin = [0u8; 32];
        coin.copy_from_slice(&body[28..60]);
        let mut phone_key_hash = [0u8; 32];
        phone_key_hash.copy_from_slice(&body[76..108]);
        Ok(Some(Header {
            state,
            key_present: flags & FLAG_KEY != 0,
            pin_hash: (flags & FLAG_PIN != 0).then_some(pin),
            pin_tries_left: body[7],
            generation: u32::from_be_bytes(body[8..12].try_into().expect("4 bytes")),
            amount_wei: u128::from_be_bytes(body[12..28].try_into().expect("16 bytes")),
            coin,
            phone_key_hash,
        }))
    }
}

/// The key slot frame.
pub struct KeySlot {
    /// The generation it was written under.
    pub generation: u32,
    /// The coin the key belongs to (zeros when empty).
    pub coin: [u8; 32],
    /// The Phantom Key, or `None` when the slot is empty.
    pub key: Option<PhantomKey>,
}

impl KeySlot {
    /// An empty (wiped) slot.
    pub fn empty(generation: u32) -> KeySlot {
        KeySlot { generation, coin: [0u8; 32], key: None }
    }

    /// The frame's bytes for card `uid`. Holds the key: wiped when dropped.
    pub fn encode(&self, uid: &CardUid) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(KEY_SLOT_BYTES));
        out.extend_from_slice(KEY_SLOT_MAGIC);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.coin);
        let mut slot = Zeroizing::new([0u8; PHANTOM_KEY_MAX_BYTES]);
        let length = match &self.key {
            Some(key) => {
                slot[..key.len()].copy_from_slice(key.expose_secret());
                key.len()
            }
            None => 0,
        };
        out.push(length as u8);
        out.extend_from_slice(&*slot);
        let c = check(KEY_SLOT_MAGIC, uid, &out[4..]);
        out.extend_from_slice(&c);
        debug_assert_eq!(out.len(), KEY_SLOT_BYTES);
        out
    }

    /// Reads a key slot frame; `None` for a blank file.
    pub fn decode(bytes: &[u8], uid: &CardUid) -> Result<Option<KeySlot>, SealError> {
        if bytes.len() != KEY_SLOT_BYTES {
            return Err(SealError::TornRecord);
        }
        if bytes.iter().all(|b| *b == 0) {
            return Ok(None);
        }
        let (body, stored) = bytes.split_at(KEY_SLOT_BYTES - CHECK_BYTES);
        if &body[..4] != KEY_SLOT_MAGIC || !ct_eq(&check(KEY_SLOT_MAGIC, uid, &body[4..]), stored) {
            return Err(SealError::TornRecord);
        }
        let length = usize::from(body[40]);
        if length > PHANTOM_KEY_MAX_BYTES {
            return Err(SealError::TornRecord);
        }
        let mut coin = [0u8; 32];
        coin.copy_from_slice(&body[8..40]);
        let key = if length == 0 { None } else { Some(PhantomKey::from_slice(&body[41..41 + length])?) };
        Ok(Some(KeySlot { generation: u32::from_be_bytes(body[4..8].try_into().expect("4 bytes")), coin, key }))
    }
}

/// Splits `data` into frames of at most [`FRAME_BYTES`] bytes, each with its
/// offset from `start`.
pub fn frames(start: u32, data: &[u8]) -> Vec<(u32, &[u8])> {
    data.chunks(FRAME_BYTES).enumerate().map(|(i, chunk)| (start + (i * FRAME_BYTES) as u32, chunk)).collect()
}
