//! The journal's durable layer: an append-only log of sealed records kept by
//! a store the Seal does not trust (the parent host), under the [`Journal`]
//! the flows use. Pure code: no socket, no file. The host's store is
//! `host_journal`; the tests use [`MemoryLogStore`].
//!
//! Each [`Journal::save`] appends one record, numbered by a counter that
//! starts at 1 and goes up by 1:
//!
//! ```text
//! record = IV (16) || AES-256-CBC(entry kind (1) || UID (7) || sealed entry, padded) || tag (32)
//! tag    = HMAC-SHA3-256(ghost-seal/v1/host-journal || origin length (1) || origin
//!                        || counter (u64, big endian) || the previous record's tag
//!                        || IV || ciphertext)
//! ```
//!
//! The origin is the id of the region whose log it is (the anchor's region,
//! [`HeadAnchor::origin`]; empty for a log anchored nowhere), so a record of
//! one region's log never verifies as another region's: not on its host,
//! not in a peer's log of another origin, not in a restore. The previous tag
//! of record 1 is 32 zero bytes. Both keys come from HKDF over M with the
//! label [`HOST_JOURNAL_LABEL`]. The store holds the counters and the
//! records only: it sees no UID, no entry kind, no card data and no key, and
//! it never holds M.
//!
//! **The previous format.** Before the log was anchored, a record's tag had
//! no origin field (`HMAC-SHA3-256(ghost-seal/v1/host-journal || counter ||
//! the previous record's tag || IV || ciphertext)`, same keys). A host's own
//! log that holds such records is upgraded when it is opened: every record
//! is checked once with that previous rule, then rewritten with the same
//! counter, IV and ciphertext (so the same entry) under the current tag, as
//! this region's record, and the store's whole log is replaced at once
//! ([`LogStore::replace_all`]: on the host, a new file renamed over the old
//! one) and read back before the log is used. A log mixing the two formats,
//! or a record of the previous format that fails the previous check, is
//! refused. An anchored log is upgraded only once its peers took the
//! upgraded records ([`HeadAnchor::restore_upgraded`]). Peer logs were never
//! written in the previous format and are never upgraded.
//!
//! Opening the log ([`JournalLog::open`]) reads every record in order and
//! refuses the whole log on a counter that is not the previous one plus 1
//! (a gap, a repeat or a reorder), a bad tag, a tag chained to another
//! previous record, a record that does not decode, or another M. It keeps
//! the latest entry per card and kind in memory, and [`Journal::load`]
//! answers from that verified map only, never from the store. A save
//! returns `Ok` only once the store has said the record is durable; only
//! then is the map changed.
//!
//! While it runs, the log remembers the last counter and tag it wrote. A
//! later read of the store ([`JournalLog::check_store`]) that shows fewer
//! records, more, or another tail is a rollback: the log refuses every
//! later save, for good.
//!
//! What the store alone cannot show, a cut made while the Seal is stopped
//! or a store replaced by an empty one, is caught by a [`HeadAnchor`]: the
//! log's head kept in the other regions (`journal_anchor`). An anchored log
//! asks the anchor, when it is opened, for the records the peers hold past
//! the store's end and appends them before it is used, and after each
//! append it asks the anchor to have every peer acknowledge the record. A
//! save is `Ok`, and the map changed, only after both. A record the store
//! took but the peers did not acknowledge is held back (not loaded) until a
//! later save has every peer acknowledge it; a store that then drops it is
//! a rollback.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use zeroize::Zeroizing;

use crate::card_keys::CardUid;
use crate::error::SealError;
use crate::journal::{EntryKind, Journal};
use crate::primitives::{aes256_cbc_decrypt, aes256_cbc_encrypt, ct_eq, hkdf_sha3_256, hmac_sha3_256, pad, unpad};
use crate::secrets::MasterKey;
use crate::traits::{SealRandom, SystemRandom};

/// The HKDF label of the log's keys, and the first part of every tag.
pub const HOST_JOURNAL_LABEL: &[u8] = b"ghost-seal/v1/host-journal";
/// The largest record the store takes.
pub const MAX_RECORD_BYTES: usize = 4096;
/// The bytes of a record's tag.
pub const TAG_BYTES: usize = 32;

const IV_BYTES: usize = 16;
/// The smallest record: an IV, one block and the tag.
const MIN_RECORD_BYTES: usize = IV_BYTES + 16 + TAG_BYTES;
const UID_BYTES: usize = 7;

/// Where the log's records are kept: the parent host's store in a real
/// Seal. Not trusted for integrity, only asked to keep what it is given.
pub trait LogStore: Send {
    /// Appends record number `counter`. Returns `Ok` only once the record is
    /// durable (flushed to disk); any failure is [`SealError::Journal`].
    fn append(&mut self, counter: u64, record: &[u8]) -> Result<(), SealError>;
    /// Every record the store holds, in order, with its counter.
    fn read_all(&mut self) -> Result<Vec<(u64, Vec<u8>)>, SealError>;
    /// Replaces every record the store holds with `records` (counters 1 on)
    /// at once: `Ok` only once the new records are durable; on a failure the
    /// store holds either the old records or the new ones, never a mix. What
    /// a log written in the previous format is upgraded with. A store that
    /// cannot do it refuses (the default).
    fn replace_all(&mut self, records: &[(u64, Vec<u8>)]) -> Result<(), SealError> {
        let _ = records;
        Err(SealError::Journal("the log store cannot replace its records"))
    }
}

#[derive(Default)]
struct MemoryStoreState {
    records: Vec<(u64, Vec<u8>)>,
    fail_appends: bool,
    fail_reads: bool,
}

/// A store in memory, for tests: clones share the same records, so a test
/// can read, change, drop or reorder them (a dishonest host), or make the
/// store fail. Like the host's store it takes only the next counter.
#[derive(Clone, Default)]
pub struct MemoryLogStore {
    state: Arc<Mutex<MemoryStoreState>>,
}

impl MemoryLogStore {
    /// An empty store.
    pub fn new() -> MemoryLogStore {
        MemoryLogStore::default()
    }

    fn lock(&self) -> MutexGuard<'_, MemoryStoreState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The records as the store holds them.
    pub fn records(&self) -> Vec<(u64, Vec<u8>)> {
        self.lock().records.clone()
    }

    /// Replaces the records (what a dishonest host would do).
    pub fn set_records(&self, records: Vec<(u64, Vec<u8>)>) {
        self.lock().records = records;
    }

    /// Makes every append fail (or succeed again).
    pub fn fail_appends(&self, fail: bool) {
        self.lock().fail_appends = fail;
    }

    /// Makes every read fail (or succeed again).
    pub fn fail_reads(&self, fail: bool) {
        self.lock().fail_reads = fail;
    }

    /// Every byte the store holds: each counter and record.
    pub fn bytes(&self) -> Vec<u8> {
        let state = self.lock();
        let mut out = Vec::new();
        for (counter, record) in &state.records {
            out.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(record);
        }
        out
    }
}

impl LogStore for MemoryLogStore {
    fn append(&mut self, counter: u64, record: &[u8]) -> Result<(), SealError> {
        let mut state = self.lock();
        if state.fail_appends {
            return Err(SealError::Journal("the log store did not take the record"));
        }
        if counter != state.records.len() as u64 + 1 || record.len() > MAX_RECORD_BYTES {
            return Err(SealError::Journal("the log store refused the record"));
        }
        state.records.push((counter, record.to_vec()));
        Ok(())
    }

    fn read_all(&mut self) -> Result<Vec<(u64, Vec<u8>)>, SealError> {
        let state = self.lock();
        if state.fail_reads {
            return Err(SealError::Journal("the log store could not be read"));
        }
        Ok(state.records.clone())
    }

    fn replace_all(&mut self, records: &[(u64, Vec<u8>)]) -> Result<(), SealError> {
        let mut state = self.lock();
        if state.fail_appends {
            return Err(SealError::Journal("the log store did not take the records"));
        }
        let numbered = records.iter().zip(1u64..).all(|((counter, record), expected)| {
            *counter == expected && !record.is_empty() && record.len() <= MAX_RECORD_BYTES
        });
        if !numbered {
            return Err(SealError::Journal("the log store refused the records"));
        }
        state.records = records.to_vec();
        Ok(())
    }
}

/// Keeps a log's head where its store's host cannot touch it (the other
/// regions, `journal_anchor::Anchor`).
pub trait HeadAnchor: Send {
    /// The region whose log this is: bound into every record's tag.
    fn origin(&self) -> &str;
    /// Called once, when the log is opened with `master`, with every record
    /// of the store, already checked: the records the anchor's peers hold
    /// past them, in order, which the log appends to the store before it is
    /// used. An error leaves the log unopened (and it is tried again).
    fn restore(&mut self, master: &MasterKey, records: &[(u64, Vec<u8>)]) -> Result<Vec<(u64, Vec<u8>)>, SealError>;
    /// [`HeadAnchor::restore`] of a log the store held in the previous
    /// format (written before the log was anchored): `records` are those
    /// records upgraded, not written to the store yet (it is upgraded only
    /// once this is `Ok`). No peer may hold a copy of a log never anchored,
    /// so the anchor may take them although no peer holds them, once it has
    /// had every peer take them. By default the same as `restore`.
    fn restore_upgraded(
        &mut self,
        master: &MasterKey,
        records: &[(u64, Vec<u8>)],
    ) -> Result<Vec<(u64, Vec<u8>)>, SealError> {
        self.restore(master, records)
    }
    /// Called after record `counter` is durable in `store`: `Ok` only once
    /// every peer holds it. `store` holds the earlier records a peer may
    /// lack.
    fn anchor(&mut self, counter: u64, record: &[u8], store: &mut dyn LogStore) -> Result<(), SealError>;
}

/// A log's chain checked one record at a time with the keys of an M, from
/// its start: what a peer region checks a record it keeps for another
/// region with, and a restored record is checked with.
#[derive(Clone)]
pub struct Chain {
    keys: LogKeys,
    counter: u64,
    tag: [u8; TAG_BYTES],
}

impl Chain {
    /// An empty chain of region `origin`'s log under the keys of `master`:
    /// it takes only records written for that origin.
    pub fn new(master: &MasterKey, origin: &str) -> Chain {
        Chain { keys: LogKeys::derive(master, origin), counter: 0, tag: [0u8; TAG_BYTES] }
    }

    /// The counter of the last record taken (0: none).
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// The tag of the last record taken (zeros: none).
    pub fn tag(&self) -> [u8; TAG_BYTES] {
        self.tag
    }

    /// Takes record `counter`: it must be the next counter, carry a good tag
    /// chained to the last record, and decode. Refused, the chain is left as
    /// it was.
    pub fn push(&mut self, counter: u64, record: &[u8]) -> Result<(), SealError> {
        if Some(counter) != self.counter.checked_add(1) {
            return Err(SealError::Journal("the log has a gap, a repeat or a reorder"));
        }
        self.keys.open(counter, &self.tag, record)?;
        self.counter = counter;
        self.tag = tag_of(record);
        Ok(())
    }
}

/// The tag a record ends with (`None`: too short to be a record).
pub fn record_tag(record: &[u8]) -> Option<[u8; TAG_BYTES]> {
    (record.len() >= MIN_RECORD_BYTES).then(|| tag_of(record))
}

/// The longest origin a tag binds (a region id).
const MAX_ORIGIN_BYTES: usize = 32;

/// The log's two keys, derived from M, and the origin region its tags bind.
#[derive(Clone)]
struct LogKeys {
    enc: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
    origin: Vec<u8>,
}

impl LogKeys {
    fn derive(master: &MasterKey, origin: &str) -> LogKeys {
        let mut okm = Zeroizing::new([0u8; 64]);
        hkdf_sha3_256(HOST_JOURNAL_LABEL, master.derive_from(), &[HOST_JOURNAL_LABEL], &mut okm[..]);
        let mut enc = Zeroizing::new([0u8; 32]);
        let mut mac = Zeroizing::new([0u8; 32]);
        enc.copy_from_slice(&okm[..32]);
        mac.copy_from_slice(&okm[32..]);
        // A region id is at most 32 bytes (`journal_anchor::valid_region`);
        // a longer one is cut, so its length always fits its one byte.
        let origin = origin.as_bytes()[..origin.len().min(MAX_ORIGIN_BYTES)].to_vec();
        LogKeys { enc, mac, origin }
    }

    fn tag(&self, counter: u64, previous: &[u8; TAG_BYTES], iv_and_body: &[u8]) -> [u8; TAG_BYTES] {
        self.tag_as(Format::Current, counter, previous, iv_and_body)
    }

    /// The tag of a record in `format`: the current one binds the origin,
    /// the previous one (before the log was anchored) has no origin field.
    fn tag_as(&self, format: Format, counter: u64, previous: &[u8; TAG_BYTES], iv_and_body: &[u8]) -> [u8; TAG_BYTES] {
        match format {
            Format::Current => {
                let length = [self.origin.len() as u8];
                hmac_sha3_256(
                    &self.mac[..],
                    &[HOST_JOURNAL_LABEL, &length, &self.origin, &counter.to_be_bytes(), previous, iv_and_body],
                )
            }
            Format::Previous => {
                hmac_sha3_256(&self.mac[..], &[HOST_JOURNAL_LABEL, &counter.to_be_bytes(), previous, iv_and_body])
            }
        }
    }

    /// Record `counter`, chained to `previous`, holding `sealed` for card
    /// `uid` and `kind`.
    fn seal(
        &self,
        random: &mut dyn SealRandom,
        counter: u64,
        previous: &[u8; TAG_BYTES],
        uid: &CardUid,
        kind: EntryKind,
        sealed: &[u8],
    ) -> Result<Vec<u8>, SealError> {
        let mut plain = Zeroizing::new(Vec::with_capacity(1 + UID_BYTES + sealed.len()));
        plain.push(kind as u8);
        plain.extend_from_slice(&uid.0);
        plain.extend_from_slice(sealed);
        let mut iv = [0u8; IV_BYTES];
        random.fill(&mut iv)?;
        let body = aes256_cbc_encrypt(&self.enc, &iv, &pad(&plain))?;
        let mut record = Vec::with_capacity(IV_BYTES + body.len() + TAG_BYTES);
        record.extend_from_slice(&iv);
        record.extend_from_slice(&body);
        let tag = self.tag(counter, previous, &record);
        record.extend_from_slice(&tag);
        if record.len() > MAX_RECORD_BYTES {
            return Err(SealError::Journal("an entry is too large for the log"));
        }
        Ok(record)
    }

    /// Opens record `counter`, which must be chained to `previous`.
    fn open(
        &self,
        counter: u64,
        previous: &[u8; TAG_BYTES],
        record: &[u8],
    ) -> Result<(CardUid, EntryKind, Vec<u8>), SealError> {
        self.open_as(Format::Current, counter, previous, record)
    }

    /// [`LogKeys::open`] of a record written in `format`.
    fn open_as(
        &self,
        format: Format,
        counter: u64,
        previous: &[u8; TAG_BYTES],
        record: &[u8],
    ) -> Result<(CardUid, EntryKind, Vec<u8>), SealError> {
        if record.len() < MIN_RECORD_BYTES
            || record.len() > MAX_RECORD_BYTES
            || (record.len() - IV_BYTES - TAG_BYTES) % 16 != 0
        {
            return Err(SealError::Journal("a log record has the wrong length"));
        }
        let (signed, stored) = record.split_at(record.len() - TAG_BYTES);
        if !ct_eq(&self.tag_as(format, counter, previous, signed), stored) {
            return Err(SealError::Journal("a log record fails its check"));
        }
        let iv: [u8; IV_BYTES] = signed[..IV_BYTES].try_into().expect("16 bytes");
        let padded = aes256_cbc_decrypt(&self.enc, &iv, &signed[IV_BYTES..])?;
        let plain = unpad(&padded).map_err(|_| SealError::Journal("a log record does not decode"))?;
        let undecodable = SealError::Journal("a log record does not decode");
        if plain.len() <= 1 + UID_BYTES {
            return Err(undecodable);
        }
        let kind = match plain[0] {
            1 => EntryKind::Open,
            2 => EntryKind::Fill,
            _ => return Err(undecodable),
        };
        let uid = CardUid(plain[1..1 + UID_BYTES].try_into().expect("7 bytes"));
        Ok((uid, kind, plain[1 + UID_BYTES..].to_vec()))
    }
}

fn tag_of(record: &[u8]) -> [u8; TAG_BYTES] {
    record[record.len() - TAG_BYTES..].try_into().expect("a record ends with its tag")
}

/// A log read and checked from its first record to its last.
struct Verified {
    counter: u64,
    tag: [u8; TAG_BYTES],
    entries: BTreeMap<(CardUid, EntryKind), Vec<u8>>,
}

fn verify(keys: &LogKeys, records: &[(u64, Vec<u8>)]) -> Result<Verified, SealError> {
    let mut verified = Verified { counter: 0, tag: [0u8; TAG_BYTES], entries: BTreeMap::new() };
    for (counter, record) in records {
        if Some(*counter) != verified.counter.checked_add(1) {
            return Err(SealError::Journal("the log has a gap, a repeat or a reorder"));
        }
        let (uid, kind, sealed) = keys.open(*counter, &verified.tag, record)?;
        verified.entries.insert((uid, kind), sealed);
        verified.counter = *counter;
        verified.tag = tag_of(record);
    }
    Ok(verified)
}

/// The two tag rules a record of the host's own log may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    /// The origin-bound tag (see the module notes).
    Current,
    /// The tag before the log was anchored: no origin length, no origin.
    Previous,
}

/// A log the store holds in the previous format, rewritten in the current
/// one: each record checked once with the previous rule, then the same
/// counter, IV and ciphertext (so the same entry) under the current tag,
/// chained to the rewritten record before it, as `keys`' origin's record.
/// `Ok(None)`: the log's first record is not one of the previous format (an
/// empty log is never upgraded). A log mixing the two formats, or a record
/// that fails the previous check, is refused.
fn upgrade(keys: &LogKeys, records: &[(u64, Vec<u8>)]) -> Result<Option<Vec<(u64, Vec<u8>)>>, SealError> {
    let Some((first_counter, first)) = records.first() else { return Ok(None) };
    if *first_counter != 1 || keys.open_as(Format::Previous, 1, &[0u8; TAG_BYTES], first).is_err() {
        return Ok(None);
    }
    let mut previous = [0u8; TAG_BYTES];
    let mut rewritten_previous = [0u8; TAG_BYTES];
    let mut rewritten = Vec::with_capacity(records.len());
    for (expected, (counter, record)) in (1u64..).zip(records) {
        if *counter != expected {
            return Err(SealError::Journal("the log has a gap, a repeat or a reorder"));
        }
        if keys.open_as(Format::Previous, *counter, &previous, record).is_err() {
            return Err(if keys.open_as(Format::Current, *counter, &rewritten_previous, record).is_ok() {
                SealError::Journal("the log mixes the previous record format with the current one")
            } else {
                SealError::Journal("a log record of the previous format fails its check")
            });
        }
        let signed = &record[..record.len() - TAG_BYTES];
        let tag = keys.tag(*counter, &rewritten_previous, signed);
        rewritten.push((*counter, [signed, &tag[..]].concat()));
        previous = tag_of(record);
        rewritten_previous = tag;
    }
    Ok(Some(rewritten))
}

/// Whether `records` are a log of region `origin` written in the previous
/// format under the keys of `master`, every record checked: a log not
/// upgraded yet (it is when it is next opened). What the region answers its
/// peers about its own log before it is open: a log never anchored, of
/// which no peer can hold a copy.
pub fn is_previous_format(master: &MasterKey, origin: &str, records: &[(u64, Vec<u8>)]) -> bool {
    matches!(upgrade(&LogKeys::derive(master, origin), records), Ok(Some(_)))
}

/// An append not taken as written yet: either its answer never came (the
/// store may or may not hold it), or the store took it and the anchor's
/// peers did not all acknowledge it.
struct Unsettled {
    counter: u64,
    record: Vec<u8>,
    uid: CardUid,
    kind: EntryKind,
    sealed: Vec<u8>,
    /// The store said the record is durable: a store that no longer shows
    /// it was rolled back.
    stored: bool,
}

struct LogState {
    store: Box<dyn LogStore>,
    keys: LogKeys,
    random: Box<dyn SealRandom + Send>,
    /// Where the log's head is kept beyond the store (none: the store only).
    anchor: Option<Box<dyn HeadAnchor>>,
    /// The last counter written (0: none).
    counter: u64,
    /// The last tag written (zeros: none).
    tag: [u8; TAG_BYTES],
    entries: BTreeMap<(CardUid, EntryKind), Vec<u8>>,
    unsettled: Option<Unsettled>,
    /// A rollback was seen: no save is taken again.
    refused: bool,
    /// The counter and tag written so far, behind a lock of their own.
    published: Arc<Mutex<(u64, [u8; TAG_BYTES])>>,
}

const ROLLED_BACK: SealError = SealError::Journal("the log store was rolled back or changed");

impl LogState {
    /// Reads the store again and checks it still ends where this log last
    /// wrote. An append that the store does hold at its end is taken as
    /// written: at once without an anchor, and with one only when `settle`
    /// is set and every peer acknowledges it (until then it stays unsettled
    /// and is not loaded).
    fn reconcile(&mut self, settle: bool) -> Result<(), SealError> {
        if self.refused {
            return Err(ROLLED_BACK);
        }
        let records = self.store.read_all()?;
        let Ok(verified) = verify(&self.keys, &records) else {
            self.refused = true;
            return Err(ROLLED_BACK);
        };
        if verified.counter == self.counter && ct_eq(&verified.tag, &self.tag) {
            if self.unsettled.as_ref().is_some_and(|unsettled| unsettled.stored) {
                // The store dropped a record it had said was durable.
                self.refused = true;
                return Err(ROLLED_BACK);
            }
            self.unsettled = None;
            return Ok(());
        }
        if let Some(mut unsettled) = self.unsettled.take()
            && verified.counter == unsettled.counter
            && records.last().is_some_and(|(_, record)| *record == unsettled.record)
        {
            unsettled.stored = true;
            if let Some(anchor) = self.anchor.as_mut() {
                if !settle {
                    self.unsettled = Some(unsettled);
                    return Ok(());
                }
                if let Err(error) = anchor.anchor(unsettled.counter, &unsettled.record, self.store.as_mut()) {
                    self.unsettled = Some(unsettled);
                    return Err(error);
                }
            }
            self.counter = unsettled.counter;
            self.tag = tag_of(&unsettled.record);
            self.publish();
            self.entries.insert((unsettled.uid, unsettled.kind), unsettled.sealed);
            return Ok(());
        }
        self.refused = true;
        Err(ROLLED_BACK)
    }

    fn save(&mut self, uid: &CardUid, kind: EntryKind, sealed: Vec<u8>) -> Result<(), SealError> {
        if self.refused {
            return Err(ROLLED_BACK);
        }
        if self.unsettled.is_some() {
            self.reconcile(true)?;
        }
        let counter = self.counter.checked_add(1).ok_or(SealError::Journal("the log is full"))?;
        let record = self.keys.seal(self.random.as_mut(), counter, &self.tag, uid, kind, &sealed)?;
        if let Err(error) = self.store.append(counter, &record) {
            self.unsettled = Some(Unsettled { counter, record, uid: *uid, kind, sealed, stored: false });
            return Err(match error {
                SealError::Journal(_) => error,
                _ => SealError::Journal("the log store failed"),
            });
        }
        if let Some(anchor) = self.anchor.as_mut()
            && let Err(error) = anchor.anchor(counter, &record, self.store.as_mut())
        {
            // Durable here, not acknowledged by every peer: not taken yet.
            self.unsettled = Some(Unsettled { counter, record, uid: *uid, kind, sealed, stored: true });
            return Err(match error {
                SealError::Journal(_) => error,
                _ => SealError::Journal("the log's head could not be anchored"),
            });
        }
        self.counter = counter;
        self.tag = tag_of(&record);
        self.publish();
        self.entries.insert((*uid, kind), sealed);
        Ok(())
    }

    /// Shows the head written so far to those who must not wait for this
    /// log's lock (the peers' restores, `journal_anchor::PeerLogs`).
    fn publish(&self) {
        *self.published.lock().unwrap_or_else(|e| e.into_inner()) = (self.counter, self.tag);
    }
}

/// Reads and checks every record of `store` and, with an `anchor`, appends
/// the records its peers hold past them; the whole log, checked again.
///
/// A store holding a log in the previous format (written before the log
/// was anchored) is upgraded first ([`upgrade`]): with an anchor, once the
/// anchor took the upgraded records ([`HeadAnchor::restore_upgraded`]), the
/// store's records are replaced by them at once ([`LogStore::replace_all`])
/// and read back, and only then is the log used. Until then the store keeps
/// the previous format, so a failed try is tried again from the same log.
fn settle_open(
    master: &MasterKey,
    keys: &LogKeys,
    store: &mut dyn LogStore,
    anchor: Option<&mut (dyn HeadAnchor + '_)>,
) -> Result<Verified, SealError> {
    let mut records = store.read_all()?;
    let upgraded = match verify(keys, &records) {
        Ok(_) => false,
        Err(error) => {
            records = upgrade(keys, &records)?.ok_or(error)?;
            true
        }
    };
    let missing = match anchor {
        Some(anchor) if upgraded => anchor.restore_upgraded(master, &records)?,
        Some(anchor) => anchor.restore(master, &records)?,
        None => Vec::new(),
    };
    if upgraded {
        store.replace_all(&records)?;
        if store.read_all()? != records {
            return Err(SealError::Journal("the log store did not keep the upgraded log"));
        }
    }
    for (counter, record) in &missing {
        store.append(*counter, record)?;
    }
    if upgraded || !missing.is_empty() {
        records = store.read_all()?;
    }
    verify(keys, &records)
}

/// The verified log. Clones are handles on the same log, behind one lock,
/// so every Seal of every session writes the same counters in turn.
#[derive(Clone)]
pub struct JournalLog {
    state: Arc<Mutex<LogState>>,
    published: Arc<Mutex<(u64, [u8; TAG_BYTES])>>,
}

impl JournalLog {
    /// Reads every record of `store` and checks the whole log with the keys
    /// of `master` (see the module notes); refuses it on any failure.
    pub fn open(master: &MasterKey, store: Box<dyn LogStore>) -> Result<JournalLog, SealError> {
        JournalLog::open_with(master, store, Box::new(SystemRandom))
    }

    /// [`JournalLog::open`] with the random source of the records' IVs.
    pub fn open_with(
        master: &MasterKey,
        mut store: Box<dyn LogStore>,
        random: Box<dyn SealRandom + Send>,
    ) -> Result<JournalLog, SealError> {
        let keys = LogKeys::derive(master, "");
        let verified = settle_open(master, &keys, store.as_mut(), None)?;
        Ok(JournalLog::from_verified(store, keys, random, None, verified))
    }

    /// [`JournalLog::open_with`] with the log's head kept by `anchor`: the
    /// log of the anchor's origin region (bound into every tag), the records
    /// its peers hold past the store's end restored to the store first, and
    /// each later save `Ok` only once every peer holds it.
    pub fn open_anchored(
        master: &MasterKey,
        mut store: Box<dyn LogStore>,
        random: Box<dyn SealRandom + Send>,
        mut anchor: Box<dyn HeadAnchor>,
    ) -> Result<JournalLog, SealError> {
        let keys = LogKeys::derive(master, anchor.origin());
        let verified = settle_open(master, &keys, store.as_mut(), Some(anchor.as_mut()))?;
        Ok(JournalLog::from_verified(store, keys, random, Some(anchor), verified))
    }

    fn from_verified(
        store: Box<dyn LogStore>,
        keys: LogKeys,
        random: Box<dyn SealRandom + Send>,
        anchor: Option<Box<dyn HeadAnchor>>,
        verified: Verified,
    ) -> JournalLog {
        let published = Arc::new(Mutex::new((verified.counter, verified.tag)));
        let state = LogState {
            store,
            keys,
            random,
            anchor,
            counter: verified.counter,
            tag: verified.tag,
            entries: verified.entries,
            unsettled: None,
            refused: false,
            published: Arc::clone(&published),
        };
        JournalLog { state: Arc::new(Mutex::new(state)), published }
    }

    /// The counter and tag of the last record written (0 and zeros: none),
    /// read without waiting for a save in progress.
    pub fn head(&self) -> (u64, [u8; TAG_BYTES]) {
        *self.published.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock(&self) -> MutexGuard<'_, LogState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reads the store again and checks that it still holds exactly the log
    /// written so far. A shorter log, a longer one or another tail is a
    /// rollback: refused, and no save is taken from then on. A store that
    /// cannot be read now is refused this once. It asks no peer: a record
    /// the store holds that the peers have not all acknowledged stays held
    /// back until the next save.
    pub fn check_store(&self) -> Result<(), SealError> {
        self.lock().reconcile(false)
    }

    /// Whether a record the store took is held back, waiting for every
    /// peer to acknowledge it (or for its answer).
    pub fn has_unsettled(&self) -> bool {
        self.lock().unsettled.is_some()
    }

    /// Whether a rollback was seen.
    pub fn refused(&self) -> bool {
        self.lock().refused
    }

    /// The counter of the last record written (0: none).
    pub fn counter(&self) -> u64 {
        self.lock().counter
    }

    /// Whether the log was opened with `master`.
    pub fn opened_with(&self, master: &MasterKey) -> bool {
        ct_eq(&self.lock().keys.mac[..], &LogKeys::derive(master, "").mac[..])
    }
}

impl Journal for JournalLog {
    fn load(&self, uid: &CardUid, kind: EntryKind) -> Option<Vec<u8>> {
        self.lock().entries.get(&(*uid, kind)).cloned()
    }

    fn save(&mut self, uid: &CardUid, kind: EntryKind, sealed: Vec<u8>) -> Result<(), SealError> {
        self.lock().save(uid, kind, sealed)
    }
}

/// What a log not opened yet waits with: its store, the random source of
/// its IVs and its anchor, if any.
type Waiting = (Box<dyn LogStore>, Box<dyn SealRandom + Send>, Option<Box<dyn HeadAnchor>>);

struct Opening {
    /// Until the log is opened (and after a failed try): the store, the
    /// random source and the anchor, kept for the next try.
    waiting: Option<Waiting>,
    /// The log, once opened and verified.
    open: Option<JournalLog>,
}

/// A log opened once, on first use, with the M then held; every later use
/// hands out a handle to the same log. What the enclave and the test server
/// install.
pub struct SharedLog {
    opening: Mutex<Opening>,
    /// The log once opened, readable while another open is being tried.
    opened: OnceLock<JournalLog>,
}

impl SharedLog {
    /// A log over `store`, not opened yet.
    pub fn new(store: Box<dyn LogStore>) -> SharedLog {
        SharedLog::with_random(store, Box::new(SystemRandom))
    }

    /// [`SharedLog::new`] with the random source of the records' IVs.
    pub fn with_random(store: Box<dyn LogStore>, random: Box<dyn SealRandom + Send>) -> SharedLog {
        SharedLog {
            opening: Mutex::new(Opening { waiting: Some((store, random, None)), open: None }),
            opened: OnceLock::new(),
        }
    }

    /// A log over `store` whose head `anchor` keeps (the enclave's: its
    /// peer regions), not opened yet. Opening it restores what the peers
    /// hold past the store first ([`JournalLog::open_anchored`]); a failure
    /// is returned and the next use tries again.
    pub fn anchored(store: Box<dyn LogStore>, anchor: Box<dyn HeadAnchor>) -> SharedLog {
        SharedLog::anchored_with_random(store, Box::new(SystemRandom), anchor)
    }

    /// [`SharedLog::anchored`] with the random source of the records' IVs.
    pub fn anchored_with_random(
        store: Box<dyn LogStore>,
        random: Box<dyn SealRandom + Send>,
        anchor: Box<dyn HeadAnchor>,
    ) -> SharedLog {
        SharedLog {
            opening: Mutex::new(Opening { waiting: Some((store, random, Some(anchor))), open: None }),
            opened: OnceLock::new(),
        }
    }

    /// Whether the log has been opened and verified.
    pub fn is_open(&self) -> bool {
        self.opened.get().is_some()
    }

    /// The counter and tag of the log's last record once it is open (and,
    /// anchored, restored and confirmed by every peer); `None` before. Never
    /// waits for an open or a save in progress.
    pub fn head(&self) -> Option<(u64, [u8; TAG_BYTES])> {
        self.opened.get().map(JournalLog::head)
    }

    /// The log for `master`. The first call reads and verifies the whole
    /// log (a failure is returned, and the next call tries again; a log that
    /// fails its checks fails them again). Each later call checks the store
    /// for a rollback ([`JournalLog::check_store`]) and hands out the same
    /// log. Another M is refused.
    pub fn journal(&self, master: &MasterKey) -> Result<JournalLog, SealError> {
        let mut opening = self.opening.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(log) = &opening.open {
            if !log.opened_with(master) {
                return Err(SealError::Journal("the log was opened with another M"));
            }
            log.check_store()?;
            return Ok(log.clone());
        }
        let (store, _, anchor) = opening.waiting.as_mut().ok_or(SealError::Journal("the log has no store"))?;
        let keys = LogKeys::derive(master, anchor.as_ref().map_or("", |anchor| anchor.origin()));
        let verified = settle_open(master, &keys, store.as_mut(), anchor.as_deref_mut())?;
        let (store, random, anchor) = opening.waiting.take().ok_or(SealError::Journal("the log has no store"))?;
        let log = JournalLog::from_verified(store, keys, random, anchor, verified);
        opening.open = Some(log.clone());
        let _ = self.opened.set(log.clone());
        Ok(log)
    }
}
