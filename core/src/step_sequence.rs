//! The restart-safe step sequence of a payment: prepared, backed up, signed,
//! sent, seen in a block, settled.
//!
//! Every step is saved through a [`StepStore`] (the Keychain, on the phone)
//! before its effect happens, so a kill at any point leaves a record of where
//! the payment stood. The signed transaction is saved with its hash before it
//! is sent. On launch, [`recover`] looks at a saved record and at the chain
//! (a [`ChainView`]) and says what to do next.
//!
//! Funds are never stranded and never paid twice:
//!
//! - Once a record is [`Step::Signed`], the only way forward is the stored
//!   bytes: nothing here takes new transaction bytes again, and
//!   [`StepSequence::start`] refuses an id that already has a record.
//! - A transaction the chain already has is never resent, so a kill after the
//!   broadcast and before its reply sends nothing more.
//! - A record that does not decode, has an unknown version or fails its
//!   checksum is an error to show, never a silent resend.
//! - A record only ever moves to the step after its own.
//!
//! The transaction bytes are opaque here; their hash is Keccak-256. Nothing is
//! logged and nothing secret is formatted: errors hold ids and steps only.

use core::fmt;
use std::sync::{Mutex, MutexGuard};

use tiny_keccak::{Hasher, Keccak};

/// The version of the record layout and checksum.
pub const RECORD_VERSION: u32 = 1;

/// How many blocks deep a transaction must be before it is settled.
pub const SETTLE_CONFIRMATIONS: u64 = 3;

const MAGIC: &[u8; 4] = b"GWSR";
const CHECKSUM_DOMAIN: &[u8] = b"ghost-wallet step record checksum";

/// Where a payment stands. Each step is saved before its effect happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, uniffi::Enum)]
pub enum Step {
    /// The payment is decided on; nothing is signed yet.
    Prepared,
    /// What the payment needs to be rebuilt is backed up.
    BackedUp,
    /// The signed transaction and its hash are saved; it may not be sent yet.
    Signed,
    /// The transaction is being sent (saved before the broadcast).
    Sent,
    /// The transaction is in a block.
    Seen,
    /// The transaction is [`SETTLE_CONFIRMATIONS`] blocks deep.
    Settled,
}

impl Step {
    /// Every step, in order.
    pub const ALL: [Step; 6] = [Step::Prepared, Step::BackedUp, Step::Signed, Step::Sent, Step::Seen, Step::Settled];

    /// The step after this one, if any.
    pub fn next(self) -> Option<Step> {
        Self::ALL.get(self.index() as usize + 1).copied()
    }

    fn index(self) -> u8 {
        self as u8
    }

    fn from_index(index: u8) -> Option<Step> {
        Self::ALL.get(usize::from(index)).copied()
    }

    /// Whether a record at this step holds the signed transaction.
    fn is_signed(self) -> bool {
        self >= Step::Signed
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Step::Prepared => "prepared",
            Step::BackedUp => "backed up",
            Step::Signed => "signed",
            Step::Sent => "sent",
            Step::Seen => "seen",
            Step::Settled => "settled",
        };
        f.write_str(name)
    }
}

/// One payment's saved step.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct StepRecord {
    /// The payment's id, the key of the record in the store.
    pub id: String,
    /// The last step saved.
    pub step: Step,
    /// The signed transaction, from [`Step::Signed`] on.
    pub signed_transaction: Option<Vec<u8>>,
    /// Its Keccak-256 hash, from [`Step::Signed`] on.
    pub transaction_hash: Option<Vec<u8>>,
    /// The record layout, [`RECORD_VERSION`].
    pub version: u32,
    /// Keccak-256 over every other field.
    pub checksum: Vec<u8>,
}

impl StepRecord {
    fn new(id: String, step: Step, signed_transaction: Option<Vec<u8>>) -> Self {
        let transaction_hash = signed_transaction.as_deref().map(|tx| keccak(&[tx]).to_vec());
        let mut record = StepRecord {
            id,
            step,
            signed_transaction,
            transaction_hash,
            version: RECORD_VERSION,
            checksum: Vec::new(),
        };
        record.checksum = record.computed_checksum().to_vec();
        record
    }

    fn computed_checksum(&self) -> [u8; 32] {
        keccak(&[CHECKSUM_DOMAIN, &self.body()])
    }

    /// Every field but the checksum, in the stored layout.
    fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.version.to_be_bytes());
        put_bytes(&mut out, self.id.as_bytes());
        out.push(self.step.index());
        for field in [&self.signed_transaction, &self.transaction_hash] {
            match field {
                None => out.push(0),
                Some(bytes) => {
                    out.push(1);
                    put_bytes(&mut out, bytes);
                }
            }
        }
        out
    }

    /// Refuses a record that is not exactly what this code saved.
    fn check(&self) -> Result<(), StepError> {
        let tampered = |reason: &str| StepError::Tampered { id: self.id.clone(), reason: reason.to_owned() };
        if self.version != RECORD_VERSION {
            return Err(StepError::UnsupportedVersion { id: self.id.clone(), version: self.version });
        }
        if self.checksum.as_slice() != self.computed_checksum() {
            return Err(tampered("the checksum does not match"));
        }
        if self.id.is_empty() {
            return Err(tampered("the id is empty"));
        }
        match (&self.signed_transaction, &self.transaction_hash) {
            (None, None) if !self.step.is_signed() => Ok(()),
            (Some(tx), Some(hash)) if self.step.is_signed() => {
                if tx.is_empty() || hash.as_slice() != keccak(&[tx]) {
                    return Err(tampered("the transaction hash does not match the transaction"));
                }
                Ok(())
            }
            _ => Err(tampered("the signed transaction does not fit the step")),
        }
    }

    fn hash(&self) -> &[u8] {
        self.transaction_hash.as_deref().unwrap_or_default()
    }
}

/// What to do with a saved record.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Recovery {
    /// Do and save this step next. From [`Step::Signed`] on, it never sends
    /// anything: a resend is always [`Recovery::ResendSame`].
    Resume { step: Step },
    /// The chain does not have the signed transaction: broadcast these stored
    /// bytes again (saving [`Step::Sent`] first if the record is still
    /// [`Step::Signed`]). Never build a new transaction.
    ResendSame { bytes: Vec<u8> },
    /// The transaction is in a block, not yet deep enough: wait for blocks.
    Wait,
    /// The payment is settled: the record can be removed.
    Done,
}

/// Why a step was refused. Nothing secret is ever in here.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum StepError {
    /// The store (the Keychain) failed.
    Store { reason: String },
    /// A stored record does not decode.
    Unreadable { id: String, reason: String },
    /// A stored record fails its checksum or does not hang together.
    Tampered { id: String, reason: String },
    /// A stored record has a layout this code does not know.
    UnsupportedVersion { id: String, version: u32 },
    /// No record has this id.
    NotFound { id: String },
    /// A record has this id already: that payment is resumed, never restarted.
    AlreadyStarted { id: String },
    /// Only the step after the record's own may be saved.
    OutOfOrder { from: Step, to: Step },
    /// The signed transaction is empty.
    EmptyTransaction,
    /// The chain does not have the transaction.
    NotOnChain,
    /// The transaction is not deep enough yet.
    NotSettled { confirmations: u64, needed: u64 },
    /// The record is not settled, so it is kept.
    NotFinished { step: Step },
    /// The chain could not be asked.
    Chain { reason: String },
}

impl fmt::Display for StepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store { reason } => write!(f, "the step store failed: {reason}"),
            Self::Unreadable { id, reason } => write!(f, "the step record {id} cannot be read: {reason}"),
            Self::Tampered { id, reason } => write!(f, "the step record {id} is refused: {reason}"),
            Self::UnsupportedVersion { id, version } => {
                write!(f, "the step record {id} has the unknown version {version}")
            }
            Self::NotFound { id } => write!(f, "no step record is named {id}"),
            Self::AlreadyStarted { id } => write!(f, "the payment {id} is started already: resume it"),
            Self::OutOfOrder { from, to } => write!(f, "a {from} payment cannot be saved as {to}"),
            Self::EmptyTransaction => f.write_str("the signed transaction is empty"),
            Self::NotOnChain => f.write_str("the chain does not have the transaction"),
            Self::NotSettled { confirmations, needed } => {
                write!(f, "the transaction has {confirmations} of {needed} confirmations")
            }
            Self::NotFinished { step } => write!(f, "the payment is {step}, not settled"),
            Self::Chain { reason } => write!(f, "the chain could not be asked: {reason}"),
        }
    }
}

impl std::error::Error for StepError {}

impl From<uniffi::UnexpectedUniFFICallbackError> for StepError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        StepError::Store { reason: error.reason }
    }
}

/// Where the records live: the Keychain, this device only, on the phone.
#[uniffi::export(callback_interface)]
pub trait StepStore: Send + Sync {
    /// Saves the record under its id, replacing the one there. Must be
    /// durable when it returns.
    fn save(&self, record: StepRecord) -> Result<(), StepError>;
    /// The record of `id`, if any; [`StepError::Unreadable`] if it does not
    /// decode.
    fn load(&self, id: String) -> Result<Option<StepRecord>, StepError>;
    /// The ids of every saved record: the unfinished payments.
    fn list(&self) -> Result<Vec<String>, StepError>;
    /// Removes the record of `id`.
    fn remove(&self, id: String) -> Result<(), StepError>;
}

/// What the chain says about a transaction.
#[uniffi::export(callback_interface)]
pub trait ChainView: Send + Sync {
    /// Whether the transaction with this hash is in a block.
    fn has_transaction(&self, hash: Vec<u8>) -> Result<bool, StepError>;
    /// How many blocks deep it is: 1 in the tip block, 0 if not in a block.
    fn confirmations(&self, hash: Vec<u8>) -> Result<u64, StepError>;
}

/// What to do with a saved record, given the chain. Refuses a record that
/// fails its checks instead of acting on it.
#[uniffi::export]
pub fn recover(record: StepRecord, chain: Box<dyn ChainView>) -> Result<Recovery, StepError> {
    recover_with(&record, chain.as_ref())
}

fn recover_with(record: &StepRecord, chain: &dyn ChainView) -> Result<Recovery, StepError> {
    record.check()?;
    let resend = || Recovery::ResendSame { bytes: record.signed_transaction.clone().unwrap_or_default() };
    Ok(match record.step {
        Step::Prepared => Recovery::Resume { step: Step::BackedUp },
        Step::BackedUp => Recovery::Resume { step: Step::Signed },
        Step::Signed | Step::Sent => {
            if chain.has_transaction(record.hash().to_vec())? {
                // Sent, and maybe killed before the reply: never resend.
                Recovery::Resume { step: record.step.next().expect("a later step") }
            } else {
                resend()
            }
        }
        Step::Seen => {
            if !chain.has_transaction(record.hash().to_vec())? {
                // Out of its block again: the same bytes, never new ones.
                resend()
            } else if chain.confirmations(record.hash().to_vec())? >= SETTLE_CONFIRMATIONS {
                Recovery::Resume { step: Step::Settled }
            } else {
                Recovery::Wait
            }
        }
        Step::Settled => Recovery::Done,
    })
}

/// The Keccak-256 hash of a signed transaction.
#[uniffi::export]
pub fn transaction_hash(signed_transaction: Vec<u8>) -> Vec<u8> {
    keccak(&[&signed_transaction]).to_vec()
}

/// How many blocks deep a transaction must be before it is settled.
#[uniffi::export]
pub fn settle_confirmations() -> u64 {
    SETTLE_CONFIRMATIONS
}

/// The stored form of a record: its fields, then its checksum.
#[uniffi::export]
pub fn encode_step_record(record: StepRecord) -> Vec<u8> {
    let mut out = record.body();
    out.extend_from_slice(&record.checksum);
    out
}

/// Reads a stored record. It is not checked here: [`StepSequence::open`]
/// and [`recover`] refuse one that fails its checksum.
#[uniffi::export]
pub fn decode_step_record(bytes: Vec<u8>) -> Result<StepRecord, StepError> {
    let unreadable = |reason: &str| StepError::Unreadable { id: String::new(), reason: reason.to_owned() };
    let mut reader = Reader { rest: &bytes };
    if reader.take(4) != Some(MAGIC.as_slice()) {
        return Err(unreadable("it is not a step record"));
    }
    let version = reader.u32().ok_or_else(|| unreadable("it ends early"))?;
    let id = reader.bytes().ok_or_else(|| unreadable("it ends early"))?;
    let id = String::from_utf8(id.to_vec()).map_err(|_| unreadable("the id is not UTF-8"))?;
    let step = reader.take(1).ok_or_else(|| unreadable("it ends early"))?[0];
    let step = Step::from_index(step).ok_or_else(|| unreadable("the step is unknown"))?;
    let mut optional = || -> Result<Option<Vec<u8>>, StepError> {
        match reader.take(1).map(|flag| flag[0]) {
            Some(0) => Ok(None),
            Some(1) => reader.bytes().map(|b| Some(b.to_vec())).ok_or_else(|| unreadable("it ends early")),
            Some(_) => Err(unreadable("a field flag is unknown")),
            None => Err(unreadable("it ends early")),
        }
    };
    let signed_transaction = optional()?;
    let transaction_hash = optional()?;
    if reader.rest.len() != 32 {
        return Err(unreadable("the checksum is not 32 bytes"));
    }
    Ok(StepRecord { id, step, signed_transaction, transaction_hash, version, checksum: reader.rest.to_vec() })
}

/// One payment, moved one step at a time; every step saved before its effect.
#[derive(uniffi::Object)]
pub struct StepSequence {
    store: Box<dyn StepStore>,
    record: Mutex<StepRecord>,
}

#[uniffi::export]
impl StepSequence {
    /// Starts a new payment and saves it as [`Step::Prepared`]. Refuses an id
    /// that has a record already: that payment is resumed with
    /// [`StepSequence::open`], never started again.
    #[uniffi::constructor]
    pub fn start(store: Box<dyn StepStore>, id: String) -> Result<std::sync::Arc<Self>, StepError> {
        if id.is_empty() {
            return Err(StepError::Tampered { id, reason: "the id is empty".to_owned() });
        }
        if store.load(id.clone())?.is_some() {
            return Err(StepError::AlreadyStarted { id });
        }
        let record = StepRecord::new(id, Step::Prepared, None);
        store.save(record.clone())?;
        Ok(std::sync::Arc::new(Self { store, record: Mutex::new(record) }))
    }

    /// Opens a saved payment, refusing a record that fails its checks.
    #[uniffi::constructor]
    pub fn open(store: Box<dyn StepStore>, id: String) -> Result<std::sync::Arc<Self>, StepError> {
        let record = store.load(id.clone())?.ok_or_else(|| StepError::NotFound { id: id.clone() })?;
        record.check()?;
        if record.id != id {
            return Err(StepError::Tampered { id, reason: "the record is saved under another id".to_owned() });
        }
        Ok(std::sync::Arc::new(Self { store, record: Mutex::new(record) }))
    }

    /// The record as saved.
    pub fn record(&self) -> StepRecord {
        self.lock().clone()
    }

    /// The last step saved.
    pub fn step(&self) -> Step {
        self.lock().step
    }

    /// What to do next, given the chain.
    pub fn recover(&self, chain: Box<dyn ChainView>) -> Result<Recovery, StepError> {
        recover_with(&self.lock(), chain.as_ref())
    }

    /// Saves [`Step::BackedUp`].
    pub fn mark_backed_up(&self) -> Result<(), StepError> {
        self.advance(Step::BackedUp, |_| Ok(None))
    }

    /// Saves [`Step::Signed`] with the signed transaction, before it is
    /// sent, and returns its hash. Only a backed-up payment takes bytes: once
    /// signed, nothing takes new ones.
    pub fn mark_signed(&self, signed_transaction: Vec<u8>) -> Result<Vec<u8>, StepError> {
        if signed_transaction.is_empty() {
            return Err(StepError::EmptyTransaction);
        }
        self.advance(Step::Signed, |_| Ok(Some(signed_transaction)))?;
        Ok(self.lock().hash().to_vec())
    }

    /// Saves [`Step::Sent`], before the broadcast.
    pub fn mark_sent(&self) -> Result<(), StepError> {
        self.advance(Step::Sent, keep_transaction)
    }

    /// Saves [`Step::Seen`] once the chain has the transaction.
    pub fn mark_seen(&self, chain: Box<dyn ChainView>) -> Result<(), StepError> {
        self.advance(Step::Seen, |record| {
            if !chain.has_transaction(record.hash().to_vec())? {
                return Err(StepError::NotOnChain);
            }
            keep_transaction(record)
        })
    }

    /// Saves [`Step::Settled`] once the transaction is deep enough.
    pub fn mark_settled(&self, chain: Box<dyn ChainView>) -> Result<(), StepError> {
        self.advance(Step::Settled, |record| {
            if !chain.has_transaction(record.hash().to_vec())? {
                return Err(StepError::NotOnChain);
            }
            let confirmations = chain.confirmations(record.hash().to_vec())?;
            if confirmations < SETTLE_CONFIRMATIONS {
                return Err(StepError::NotSettled { confirmations, needed: SETTLE_CONFIRMATIONS });
            }
            keep_transaction(record)
        })
    }

    /// Removes the record of a settled payment.
    pub fn finish(&self) -> Result<(), StepError> {
        let record = self.lock();
        if record.step != Step::Settled {
            return Err(StepError::NotFinished { step: record.step });
        }
        self.store.remove(record.id.clone())
    }
}

impl StepSequence {
    fn lock(&self) -> MutexGuard<'_, StepRecord> {
        // The record is replaced only after the store saved the new one, so
        // a panic leaves it as it was.
        self.record.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Saves the record at `to`, which must be the step after the current
    /// one, then takes it. A refused or failed save changes nothing.
    fn advance(
        &self,
        to: Step,
        transaction: impl FnOnce(&StepRecord) -> Result<Option<Vec<u8>>, StepError>,
    ) -> Result<(), StepError> {
        let mut record = self.lock();
        if record.step.next() != Some(to) {
            return Err(StepError::OutOfOrder { from: record.step, to });
        }
        let next = StepRecord::new(record.id.clone(), to, transaction(&record)?);
        self.store.save(next.clone())?;
        *record = next;
        Ok(())
    }
}

fn keep_transaction(record: &StepRecord) -> Result<Option<Vec<u8>>, StepError> {
    Ok(record.signed_transaction.clone())
}

fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.rest.len() < n {
            return None;
        }
        let (head, rest) = self.rest.split_at(n);
        self.rest = rest;
        Some(head)
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_be_bytes(b.try_into().expect("4 bytes")))
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}
