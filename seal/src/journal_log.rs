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
//! tag    = HMAC-SHA3-256(ghost-seal/v1/host-journal || counter (u64, big endian)
//!                        || the previous record's tag || IV || ciphertext)
//! ```
//!
//! The previous tag of record 1 is 32 zero bytes. Both keys come from HKDF
//! over M with the label [`HOST_JOURNAL_LABEL`]. The store holds the
//! counters and the records only: it sees no UID, no entry kind, no card
//! data and no key, and it never holds M.
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
//! later save, for good. One thing this cannot see: a store that cuts the
//! tail of the log while the Seal is stopped shows a shorter log that is
//! still valid at the next start. Closing that needs the log's head kept
//! where the host cannot touch it (`docs/sealed-card.md`, "Next").

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

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
}

/// The log's two keys, derived from M.
struct LogKeys {
    enc: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
}

impl LogKeys {
    fn derive(master: &MasterKey) -> LogKeys {
        let mut okm = Zeroizing::new([0u8; 64]);
        hkdf_sha3_256(HOST_JOURNAL_LABEL, master.derive_from(), &[HOST_JOURNAL_LABEL], &mut okm[..]);
        let mut enc = Zeroizing::new([0u8; 32]);
        let mut mac = Zeroizing::new([0u8; 32]);
        enc.copy_from_slice(&okm[..32]);
        mac.copy_from_slice(&okm[32..]);
        LogKeys { enc, mac }
    }

    fn tag(&self, counter: u64, previous: &[u8; TAG_BYTES], iv_and_body: &[u8]) -> [u8; TAG_BYTES] {
        hmac_sha3_256(&self.mac[..], &[HOST_JOURNAL_LABEL, &counter.to_be_bytes(), previous, iv_and_body])
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
        if record.len() < MIN_RECORD_BYTES
            || record.len() > MAX_RECORD_BYTES
            || (record.len() - IV_BYTES - TAG_BYTES) % 16 != 0
        {
            return Err(SealError::Journal("a log record has the wrong length"));
        }
        let (signed, stored) = record.split_at(record.len() - TAG_BYTES);
        if !ct_eq(&self.tag(counter, previous, signed), stored) {
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

/// An append whose answer never came: the store may or may not hold it.
struct Unsettled {
    counter: u64,
    record: Vec<u8>,
    uid: CardUid,
    kind: EntryKind,
    sealed: Vec<u8>,
}

struct LogState {
    store: Box<dyn LogStore>,
    keys: LogKeys,
    random: Box<dyn SealRandom + Send>,
    /// The last counter written (0: none).
    counter: u64,
    /// The last tag written (zeros: none).
    tag: [u8; TAG_BYTES],
    entries: BTreeMap<(CardUid, EntryKind), Vec<u8>>,
    unsettled: Option<Unsettled>,
    /// A rollback was seen: no save is taken again.
    refused: bool,
}

const ROLLED_BACK: SealError = SealError::Journal("the log store was rolled back or changed");

impl LogState {
    /// Reads the store again and checks it still ends where this log last
    /// wrote. An append whose answer was lost and that the store does hold
    /// is taken as written.
    fn reconcile(&mut self) -> Result<(), SealError> {
        if self.refused {
            return Err(ROLLED_BACK);
        }
        let records = self.store.read_all()?;
        let Ok(verified) = verify(&self.keys, &records) else {
            self.refused = true;
            return Err(ROLLED_BACK);
        };
        if verified.counter == self.counter && ct_eq(&verified.tag, &self.tag) {
            self.unsettled = None;
            return Ok(());
        }
        if let Some(unsettled) = self.unsettled.take()
            && verified.counter == unsettled.counter
            && records.last().is_some_and(|(_, record)| *record == unsettled.record)
        {
            self.counter = unsettled.counter;
            self.tag = tag_of(&unsettled.record);
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
            self.reconcile()?;
        }
        let counter = self.counter.checked_add(1).ok_or(SealError::Journal("the log is full"))?;
        let record = self.keys.seal(self.random.as_mut(), counter, &self.tag, uid, kind, &sealed)?;
        match self.store.append(counter, &record) {
            Ok(()) => {
                self.counter = counter;
                self.tag = tag_of(&record);
                self.entries.insert((*uid, kind), sealed);
                Ok(())
            }
            Err(error) => {
                self.unsettled = Some(Unsettled { counter, record, uid: *uid, kind, sealed });
                Err(match error {
                    SealError::Journal(_) => error,
                    _ => SealError::Journal("the log store failed"),
                })
            }
        }
    }
}

/// The verified log. Clones are handles on the same log, behind one lock,
/// so every Seal of every session writes the same counters in turn.
#[derive(Clone)]
pub struct JournalLog {
    state: Arc<Mutex<LogState>>,
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
        let keys = LogKeys::derive(master);
        let verified = verify(&keys, &store.read_all()?)?;
        Ok(JournalLog::from_verified(store, keys, random, verified))
    }

    fn from_verified(
        store: Box<dyn LogStore>,
        keys: LogKeys,
        random: Box<dyn SealRandom + Send>,
        verified: Verified,
    ) -> JournalLog {
        let state = LogState {
            store,
            keys,
            random,
            counter: verified.counter,
            tag: verified.tag,
            entries: verified.entries,
            unsettled: None,
            refused: false,
        };
        JournalLog { state: Arc::new(Mutex::new(state)) }
    }

    fn lock(&self) -> MutexGuard<'_, LogState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reads the store again and checks that it still holds exactly the log
    /// written so far. A shorter log, a longer one or another tail is a
    /// rollback: refused, and no save is taken from then on. A store that
    /// cannot be read now is refused this once.
    pub fn check_store(&self) -> Result<(), SealError> {
        self.lock().reconcile()
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
        ct_eq(&self.lock().keys.mac[..], &LogKeys::derive(master).mac[..])
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

struct Opening {
    /// Until the log is opened (and after a failed try): the store and the
    /// random source, kept for the next try.
    waiting: Option<(Box<dyn LogStore>, Box<dyn SealRandom + Send>)>,
    /// The log, once opened and verified.
    open: Option<JournalLog>,
}

/// A log opened once, on first use, with the M then held; every later use
/// hands out a handle to the same log. What the enclave and the test server
/// install.
pub struct SharedLog {
    opening: Mutex<Opening>,
}

impl SharedLog {
    /// A log over `store`, not opened yet.
    pub fn new(store: Box<dyn LogStore>) -> SharedLog {
        SharedLog::with_random(store, Box::new(SystemRandom))
    }

    /// [`SharedLog::new`] with the random source of the records' IVs.
    pub fn with_random(store: Box<dyn LogStore>, random: Box<dyn SealRandom + Send>) -> SharedLog {
        SharedLog { opening: Mutex::new(Opening { waiting: Some((store, random)), open: None }) }
    }

    /// Whether the log has been opened and verified.
    pub fn is_open(&self) -> bool {
        self.opening.lock().unwrap_or_else(|e| e.into_inner()).open.is_some()
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
        let (store, _) = opening.waiting.as_mut().ok_or(SealError::Journal("the log has no store"))?;
        let keys = LogKeys::derive(master);
        let verified = verify(&keys, &store.read_all()?)?;
        let (store, random) = opening.waiting.take().ok_or(SealError::Journal("the log has no store"))?;
        let log = JournalLog::from_verified(store, keys, random, verified);
        opening.open = Some(log.clone());
        Ok(log)
    }
}
