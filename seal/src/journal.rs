//! The Seal's journal: what it writes before it changes a card, so a flow cut
//! off at any step is finished later, never lost.
//!
//! - An **Open** entry holds the phase the Open reached, the card's
//!   generation, the coin, its amount, the phone key the Open is bound to and
//!   the Phantom Key (which must survive the wipe of the card's key slot
//!   until it is released).
//! - A **Fill** entry holds the public commit data of a Fill and its coin's
//!   spend marker, so a Fill whose answer was lost hands back the same coin
//!   instead of a new key, and the chain check can test the coin at every
//!   Check.
//!
//! The store sees only sealed bytes: AES-256-CBC under a fresh IV, then
//! HMAC-SHA3-256 over the entry kind, the UID, the IV and the ciphertext,
//! with both keys derived from M ([`JOURNAL_LABEL`]).
//!
//! A real Seal's [`Journal`] is `journal_log::JournalLog`: each save appends
//! one record, sealed again under its own keys and chained by counter and
//! tag, to a log the parent host keeps; loads answer from the log as it was
//! verified in enclave memory, never from the host.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use zeroize::Zeroizing;

use crate::card_keys::CardUid;
use crate::error::SealError;
use crate::primitives::{aes256_cbc_decrypt, aes256_cbc_encrypt, ct_eq, hkdf_sha3_256, hmac_sha3_256, pad, unpad};
use crate::secrets::{MasterKey, PhantomKey};
use crate::traits::SealRandom;

/// The HKDF label of the journal keys.
pub const JOURNAL_LABEL: &[u8] = b"ghost-seal/v1/journal";

/// Which flow an entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntryKind {
    /// An Open in progress or finished.
    Open = 1,
    /// A Fill waiting for its payment.
    Fill = 2,
}

/// Where the Seal keeps its journal. Saving must be durable before it
/// returns: the Seal changes the card only after a save succeeded.
pub trait Journal {
    /// The sealed entry of `kind` for card `uid`, if any.
    fn load(&self, uid: &CardUid, kind: EntryKind) -> Option<Vec<u8>>;
    /// Replaces the sealed entry of `kind` for card `uid`.
    fn save(&mut self, uid: &CardUid, kind: EntryKind, sealed: Vec<u8>) -> Result<(), SealError>;
}

/// A journal in memory. Clones share the same entries, so a test can hand one
/// to a Seal, drop the Seal (a restart) and hand it to the next.
#[derive(Clone, Default)]
pub struct MemoryJournal {
    entries: Rc<RefCell<BTreeMap<(CardUid, EntryKind), Vec<u8>>>>,
}

impl MemoryJournal {
    /// An empty journal.
    pub fn new() -> MemoryJournal {
        MemoryJournal::default()
    }

    /// Whether an Open was journaled for card `uid`.
    pub fn has_open(&self, uid: &CardUid) -> bool {
        self.entries.borrow().contains_key(&(*uid, EntryKind::Open))
    }

    /// Every sealed entry, as the store holds them.
    pub fn sealed_entries(&self) -> Vec<Vec<u8>> {
        self.entries.borrow().values().cloned().collect()
    }
}

impl Journal for MemoryJournal {
    fn load(&self, uid: &CardUid, kind: EntryKind) -> Option<Vec<u8>> {
        self.entries.borrow().get(&(*uid, kind)).cloned()
    }

    fn save(&mut self, uid: &CardUid, kind: EntryKind, sealed: Vec<u8>) -> Result<(), SealError> {
        self.entries.borrow_mut().insert((*uid, kind), sealed);
        Ok(())
    }
}

fn journal_keys(master: &MasterKey) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mut okm = Zeroizing::new([0u8; 64]);
    hkdf_sha3_256(JOURNAL_LABEL, master.derive_from(), &[JOURNAL_LABEL], &mut okm[..]);
    let mut enc = Zeroizing::new([0u8; 32]);
    let mut mac = Zeroizing::new([0u8; 32]);
    enc.copy_from_slice(&okm[..32]);
    mac.copy_from_slice(&okm[32..]);
    (enc, mac)
}

fn seal_bytes(
    master: &MasterKey,
    uid: &CardUid,
    kind: EntryKind,
    plain: &[u8],
    random: &mut dyn SealRandom,
) -> Result<Vec<u8>, SealError> {
    let (enc, mac) = journal_keys(master);
    let mut iv = [0u8; 16];
    random.fill(&mut iv)?;
    let body = aes256_cbc_encrypt(&enc, &iv, &pad(plain))?;
    let mut out = Vec::with_capacity(16 + body.len() + 32);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&body);
    let tag = hmac_sha3_256(&mac[..], &[JOURNAL_LABEL, &[kind as u8], &uid.0, &out]);
    out.extend_from_slice(&tag);
    Ok(out)
}

fn unseal_bytes(master: &MasterKey, uid: &CardUid, kind: EntryKind, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
    if sealed.len() < 16 + 16 + 32 || (sealed.len() - 48) % 16 != 0 {
        return Err(SealError::Journal("an entry has the wrong length"));
    }
    let (enc, mac) = journal_keys(master);
    let (signed, stored) = sealed.split_at(sealed.len() - 32);
    if !ct_eq(&hmac_sha3_256(&mac[..], &[JOURNAL_LABEL, &[kind as u8], &uid.0, signed]), stored) {
        return Err(SealError::Journal("an entry fails its check"));
    }
    let iv: [u8; 16] = signed[..16].try_into().expect("16 bytes");
    let plain = aes256_cbc_decrypt(&enc, &iv, &signed[16..])?;
    unpad(&plain)
}

/// Reads fixed fields off the front of a byte string.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let part = self.bytes.get(self.at..self.at + n)?;
        self.at += n;
        Some(part)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn done(&self) -> bool {
        self.at == self.bytes.len()
    }
}

/// How far an Open got. Each phase is saved after the card step before it
/// was verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OpenPhase {
    /// Journaled; the card still says Sealed.
    Started = 1,
    /// The card says Opening, bound to the phone key.
    CardMarked = 2,
    /// The card's key slot is wiped.
    SlotWiped = 3,
    /// All five card keys are at the next generation.
    KeysRotated = 4,
    /// The card says Opened, checked by fresh authentication; the key is
    /// released to the bound phone key.
    Finished = 5,
}

impl OpenPhase {
    fn from_byte(byte: u8) -> Option<OpenPhase> {
        match byte {
            1 => Some(OpenPhase::Started),
            2 => Some(OpenPhase::CardMarked),
            3 => Some(OpenPhase::SlotWiped),
            4 => Some(OpenPhase::KeysRotated),
            5 => Some(OpenPhase::Finished),
            _ => None,
        }
    }
}

const ENTRY_VERSION: u8 = 1;

/// One card's Open, as journaled.
pub(crate) struct OpenEntry {
    pub(crate) phase: OpenPhase,
    pub(crate) generation: u32,
    pub(crate) coin: [u8; 32],
    pub(crate) amount_wei: u128,
    pub(crate) phone_key: Vec<u8>,
    pub(crate) key: PhantomKey,
}

impl OpenEntry {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(96 + self.phone_key.len()));
        out.push(ENTRY_VERSION);
        out.push(self.phase as u8);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.coin);
        out.extend_from_slice(&self.amount_wei.to_be_bytes());
        out.extend_from_slice(&(self.phone_key.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.phone_key);
        out.push(self.key.len() as u8);
        out.extend_from_slice(self.key.expose_secret());
        out
    }

    fn decode(bytes: &[u8]) -> Option<OpenEntry> {
        let mut r = Reader { bytes, at: 0 };
        if r.take(1)? != [ENTRY_VERSION] {
            return None;
        }
        let phase = OpenPhase::from_byte(r.take(1)?[0])?;
        let generation = u32::from_be_bytes(r.array()?);
        let coin = r.array()?;
        let amount_wei = u128::from_be_bytes(r.array()?);
        let phone_length = usize::from(u16::from_be_bytes(r.array()?));
        let phone_key = r.take(phone_length)?.to_vec();
        let key_length = usize::from(r.take(1)?[0]);
        let key = PhantomKey::from_slice(r.take(key_length)?).ok()?;
        r.done().then_some(OpenEntry { phase, generation, coin, amount_wei, phone_key, key })
    }

    /// The entry sealed for the store.
    pub(crate) fn seal(
        &self,
        master: &MasterKey,
        uid: &CardUid,
        random: &mut dyn SealRandom,
    ) -> Result<Vec<u8>, SealError> {
        seal_bytes(master, uid, EntryKind::Open, &self.encode(), random)
    }

    /// Opens a sealed entry for card `uid`.
    pub(crate) fn unseal(master: &MasterKey, uid: &CardUid, sealed: &[u8]) -> Result<OpenEntry, SealError> {
        let plain = unseal_bytes(master, uid, EntryKind::Open, sealed)?;
        OpenEntry::decode(&plain).ok_or(SealError::Journal("an entry does not decode"))
    }
}

/// The Fill entry's layout version: version 2 adds the spend marker.
const FILL_ENTRY_VERSION: u8 = 2;

/// A Fill, as journaled: the coin's commit data and its spend marker, which
/// the chain check needs at every Check (the card holds only the coin's
/// hash). Public values only: a spend marker is public once the coin is
/// spent and tells nothing before.
pub(crate) struct FillEntry {
    pub(crate) generation: u32,
    pub(crate) coin: [u8; 32],
    pub(crate) amount_wei: u128,
    pub(crate) commit_data: Vec<u8>,
    pub(crate) spend_marker: [u8; 32],
}

impl FillEntry {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(88 + self.commit_data.len());
        out.push(FILL_ENTRY_VERSION);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.coin);
        out.extend_from_slice(&self.amount_wei.to_be_bytes());
        out.extend_from_slice(&(self.commit_data.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.commit_data);
        out.extend_from_slice(&self.spend_marker);
        out
    }

    fn decode(bytes: &[u8]) -> Option<FillEntry> {
        let mut r = Reader { bytes, at: 0 };
        if r.take(1)? != [FILL_ENTRY_VERSION] {
            return None;
        }
        let generation = u32::from_be_bytes(r.array()?);
        let coin = r.array()?;
        let amount_wei = u128::from_be_bytes(r.array()?);
        let length = usize::from(u16::from_be_bytes(r.array()?));
        let commit_data = r.take(length)?.to_vec();
        let spend_marker = r.array()?;
        r.done().then_some(FillEntry { generation, coin, amount_wei, commit_data, spend_marker })
    }

    pub(crate) fn seal(
        &self,
        master: &MasterKey,
        uid: &CardUid,
        random: &mut dyn SealRandom,
    ) -> Result<Vec<u8>, SealError> {
        seal_bytes(master, uid, EntryKind::Fill, &self.encode(), random)
    }

    pub(crate) fn unseal(master: &MasterKey, uid: &CardUid, sealed: &[u8]) -> Result<FillEntry, SealError> {
        let plain = unseal_bytes(master, uid, EntryKind::Fill, sealed)?;
        FillEntry::decode(&plain).ok_or(SealError::Journal("an entry does not decode"))
    }
}
