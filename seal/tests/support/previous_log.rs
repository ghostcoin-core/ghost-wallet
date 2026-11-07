//! The journal log as the previous release wrote it, before the log was
//! anchored in the other regions: the same keys and records, but a tag with
//! no origin field. Its `LogKeys::derive`, `tag` and `seal` and its save's
//! numbering are the previous `seal/src/journal_log.rs` as it was, line for
//! line; the only change is that the keys are derived from M's bytes, as a
//! test cannot read them from a `MasterKey`. The upgrade tests write a log
//! with it and open it with the current code.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use ghost_seal::journal_log::{HOST_JOURNAL_LABEL, LogStore, MAX_RECORD_BYTES, TAG_BYTES};
use ghost_seal::primitives::{aes256_cbc_encrypt, hkdf_sha3_256, hmac_sha3_256, pad};
use ghost_seal::{CardUid, EntryKind, Journal, SealError, SealRandom};

const IV_BYTES: usize = 16;
const UID_BYTES: usize = 7;

/// The log's two keys, derived from M.
struct LogKeys {
    enc: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
}

impl LogKeys {
    fn derive(master: &[u8; 32]) -> LogKeys {
        let mut okm = Zeroizing::new([0u8; 64]);
        hkdf_sha3_256(HOST_JOURNAL_LABEL, master, &[HOST_JOURNAL_LABEL], &mut okm[..]);
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
}

fn tag_of(record: &[u8]) -> [u8; TAG_BYTES] {
    record[record.len() - TAG_BYTES..].try_into().expect("a record ends with its tag")
}

struct State {
    store: Box<dyn LogStore>,
    keys: LogKeys,
    random: Box<dyn SealRandom + Send>,
    counter: u64,
    tag: [u8; TAG_BYTES],
    entries: BTreeMap<(CardUid, EntryKind), Vec<u8>>,
}

/// A log written by the previous release over a store that starts empty.
/// Clones are handles on the same log.
#[derive(Clone)]
pub struct PreviousLog {
    state: Arc<Mutex<State>>,
}

impl PreviousLog {
    /// A new log over the empty `store`, under the M of `master` (its
    /// bytes), its IVs from `random`.
    pub fn new(master: &[u8; 32], store: Box<dyn LogStore>, random: Box<dyn SealRandom + Send>) -> PreviousLog {
        let state = State {
            store,
            keys: LogKeys::derive(master),
            random,
            counter: 0,
            tag: [0u8; TAG_BYTES],
            entries: BTreeMap::new(),
        };
        PreviousLog { state: Arc::new(Mutex::new(state)) }
    }
}

impl Journal for PreviousLog {
    fn load(&self, uid: &CardUid, kind: EntryKind) -> Option<Vec<u8>> {
        self.state.lock().unwrap().entries.get(&(*uid, kind)).cloned()
    }

    fn save(&mut self, uid: &CardUid, kind: EntryKind, sealed: Vec<u8>) -> Result<(), SealError> {
        let mut state = self.state.lock().unwrap();
        let state = &mut *state;
        let counter = state.counter.checked_add(1).ok_or(SealError::Journal("the log is full"))?;
        let record = state.keys.seal(state.random.as_mut(), counter, &state.tag, uid, kind, &sealed)?;
        state.store.append(counter, &record)?;
        state.counter = counter;
        state.tag = tag_of(&record);
        state.entries.insert((*uid, kind), sealed);
        Ok(())
    }
}
