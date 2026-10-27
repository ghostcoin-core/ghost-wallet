//! The restart-safe state machine of a payment: prepared, backed up, signed,
//! sent, included in a block, settled; or failed, or conflicted.
//!
//! A [`PaymentRecord`] is the payment intent plus its identity: the account
//! nonce of a send or a Vanish, or the reveal marker of a Summon or a Claim.
//! The chain lets at most one transaction use an identity, so however many
//! attempts the record holds (the first one, a rebuild after the fee window
//! moved, a speed-up, a cancel), at most one of them can land.
//!
//! Every step is saved through a [`PaymentStore`] before its effect happens,
//! so a kill at any point leaves a record of where the payment stood. Each
//! attempt's signed bytes are saved (as a payload under their hash) before the
//! record lists the attempt, and the record is saved as [`Step::Sent`] before
//! the bytes are broadcast. On launch, [`PaymentSequence::recover`] reads the
//! chain (a [`ChainView`]), saves what the chain says and tells the app what
//! to do next.
//!
//! Funds are never stranded and never paid twice:
//!
//! - The same bytes are resent only while the chain does not have them and
//!   their window is open; once it has passed, a new attempt is signed with the
//!   same identity ([`Recovery::Rebuild`]), never with a new one.
//! - A receipt is read, not assumed: inclusion is not success. A failed
//!   receipt, or a successful one whose expected effect the chain does not
//!   show, is [`Step::Failed`]. Another transaction using the identity is
//!   [`Step::Conflicted`]. Neither ever sends again.
//! - A settled record is kept with its block hash. A reorg that takes the
//!   inclusion away moves the record back to [`Step::Sent`].
//! - A record or payload that does not decode, has an unknown version or fails
//!   its checks is an error to show, never a silent resend.
//!
//! Transaction bytes are opaque here; their hash is Keccak-256. Nothing is
//! logged, and signed bytes are never formatted: no type here that is
//! formatted holds them, and errors hold ids, steps and reasons only.

use core::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use tiny_keccak::{Hasher, Keccak};

/// The version of the record layout and checksum.
pub const RECORD_VERSION: u32 = 2;

/// How many blocks deep a transaction must be before it is settled.
pub const SETTLE_CONFIRMATIONS: u64 = 3;

/// How many attempts one payment may hold.
pub const MAX_ATTEMPTS: u32 = 32;

const MAGIC: &[u8; 4] = b"GWPR";
const CHECKSUM_DOMAIN: &[u8] = b"ghost-wallet payment record checksum";
const HASH_LEN: usize = 32;

/// What the payment is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum PaymentKind {
    /// A plain send, identified by its account nonce.
    Send,
    /// A Vanish, identified by its account nonce.
    Vanish,
    /// A Summon, identified by its reveal marker.
    Summon,
    /// A Claim, identified by its reveal marker.
    Claim,
}

impl PaymentKind {
    const ALL: [PaymentKind; 4] = [PaymentKind::Send, PaymentKind::Vanish, PaymentKind::Summon, PaymentKind::Claim];

    fn uses_nonce(self) -> bool {
        matches!(self, PaymentKind::Send | PaymentKind::Vanish)
    }
}

impl fmt::Display for PaymentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PaymentKind::Send => "send",
            PaymentKind::Vanish => "Vanish",
            PaymentKind::Summon => "Summon",
            PaymentKind::Claim => "Claim",
        })
    }
}

/// What the chain lets only one transaction use.
#[derive(Debug, Clone, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum Identity {
    /// The nonce of the sending account (a send or a Vanish).
    AccountNonce { account: Vec<u8>, nonce: u64 },
    /// The reveal marker (a Summon or a Claim).
    RevealMarker { marker: Vec<u8> },
}

/// The payment as decided: its kind, its identity and what it pays, in the
/// app's own encoding (enough to rebuild it).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PaymentIntent {
    pub kind: PaymentKind,
    pub identity: Identity,
    pub details: Vec<u8>,
}

/// One signed transaction for the payment. Its bytes are a payload in the
/// store under this hash, never in the record.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Attempt {
    /// The Keccak-256 hash of the signed bytes.
    pub transaction_hash: Vec<u8>,
    /// The last block height that may include it (the end of the fee window
    /// its proof was made for), if it has one.
    pub valid_until: Option<u64>,
}

/// Where a transaction landed.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Inclusion {
    pub transaction_hash: Vec<u8>,
    pub block_hash: Vec<u8>,
    pub block_height: u64,
}

/// Whether an included transaction did what it was sent to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ReceiptStatus {
    Success,
    Failed,
}

/// The receipt of a transaction in a block of the chain as it stands.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Receipt {
    pub status: ReceiptStatus,
    pub block_hash: Vec<u8>,
    pub block_height: u64,
}

/// Where a payment stands. Each step is saved before its effect happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum Step {
    /// The payment is decided on; nothing is signed yet.
    Prepared,
    /// What the payment needs to be rebuilt is backed up.
    BackedUp,
    /// The newest attempt is saved; it may not be sent yet.
    Signed,
    /// The newest attempt is being sent or waits for a block (saved before
    /// the broadcast).
    Sent,
    /// One attempt is in a block with a successful receipt and its effect.
    Included,
    /// That block is [`SETTLE_CONFIRMATIONS`] deep. The record is kept.
    Settled,
    /// One attempt is in a block, but its receipt failed or its effect is
    /// missing. Nothing more is sent.
    Failed,
    /// Another transaction used the identity. Nothing more is sent.
    Conflicted,
}

impl Step {
    /// Every step.
    pub const ALL: [Step; 8] = [
        Step::Prepared,
        Step::BackedUp,
        Step::Signed,
        Step::Sent,
        Step::Included,
        Step::Settled,
        Step::Failed,
        Step::Conflicted,
    ];

    fn index(self) -> u8 {
        self as u8
    }

    fn from_index(index: u8) -> Option<Step> {
        Self::ALL.get(usize::from(index)).copied()
    }

    /// Whether a record at this step holds at least one attempt.
    fn has_attempts(self) -> bool {
        !matches!(self, Step::Prepared | Step::BackedUp)
    }

    /// Whether a record at this step holds where a transaction landed.
    fn has_inclusion(self) -> bool {
        matches!(self, Step::Included | Step::Settled | Step::Failed | Step::Conflicted)
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Step::Prepared => "prepared",
            Step::BackedUp => "backed up",
            Step::Signed => "signed",
            Step::Sent => "sent",
            Step::Included => "included",
            Step::Settled => "settled",
            Step::Failed => "failed",
            Step::Conflicted => "conflicted",
        })
    }
}

/// One payment's saved state. Small: the signed bytes are payloads.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PaymentRecord {
    /// The payment's id, the key of the record in the store.
    pub id: String,
    pub intent: PaymentIntent,
    /// The last step saved.
    pub step: Step,
    /// Every attempt, oldest first.
    pub attempts: Vec<Attempt>,
    /// Where a transaction using the identity landed: one of the attempts
    /// (included, settled, failed) or another one (conflicted).
    pub inclusion: Option<Inclusion>,
    /// The record layout, [`RECORD_VERSION`].
    pub version: u32,
    /// Keccak-256 over every other field.
    pub checksum: Vec<u8>,
}

impl PaymentRecord {
    fn new(
        id: String,
        intent: PaymentIntent,
        step: Step,
        attempts: Vec<Attempt>,
        inclusion: Option<Inclusion>,
    ) -> Self {
        let mut record =
            PaymentRecord { id, intent, step, attempts, inclusion, version: RECORD_VERSION, checksum: Vec::new() };
        record.checksum = record.computed_checksum().to_vec();
        record
    }

    /// This record at another step, with the same attempts.
    fn moved(&self, step: Step, inclusion: Option<Inclusion>) -> Self {
        Self::new(self.id.clone(), self.intent.clone(), step, self.attempts.clone(), inclusion)
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
        out.push(self.intent.kind as u8);
        match &self.intent.identity {
            Identity::AccountNonce { account, nonce } => {
                out.push(0);
                put_bytes(&mut out, account);
                out.extend_from_slice(&nonce.to_be_bytes());
            }
            Identity::RevealMarker { marker } => {
                out.push(1);
                put_bytes(&mut out, marker);
            }
        }
        put_bytes(&mut out, &self.intent.details);
        out.push(self.step.index());
        out.extend_from_slice(&(self.attempts.len() as u32).to_be_bytes());
        for attempt in &self.attempts {
            put_bytes(&mut out, &attempt.transaction_hash);
            put_optional_u64(&mut out, attempt.valid_until);
        }
        match &self.inclusion {
            None => out.push(0),
            Some(inclusion) => {
                out.push(1);
                put_bytes(&mut out, &inclusion.transaction_hash);
                put_bytes(&mut out, &inclusion.block_hash);
                out.extend_from_slice(&inclusion.block_height.to_be_bytes());
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
        check_intent(&self.intent).map_err(|_| tampered("the identity does not fit the payment kind"))?;
        if self.attempts.len() > MAX_ATTEMPTS as usize {
            return Err(tampered("it holds too many attempts"));
        }
        for (at, attempt) in self.attempts.iter().enumerate() {
            if attempt.transaction_hash.len() != HASH_LEN {
                return Err(tampered("an attempt hash is not 32 bytes"));
            }
            if self.attempts[..at].iter().any(|earlier| earlier.transaction_hash == attempt.transaction_hash) {
                return Err(tampered("an attempt is listed twice"));
            }
        }
        if self.step.has_attempts() == self.attempts.is_empty() {
            return Err(tampered("the attempts do not fit the step"));
        }
        match (&self.inclusion, self.step.has_inclusion()) {
            (None, false) => Ok(()),
            (Some(inclusion), true) => {
                if inclusion.transaction_hash.len() != HASH_LEN || inclusion.block_hash.is_empty() {
                    return Err(tampered("the inclusion is incomplete"));
                }
                let ours = self.has_attempt(&inclusion.transaction_hash);
                if ours == (self.step == Step::Conflicted) {
                    return Err(tampered("the included transaction does not fit the step"));
                }
                Ok(())
            }
            _ => Err(tampered("the inclusion does not fit the step")),
        }
    }

    fn has_attempt(&self, hash: &[u8]) -> bool {
        self.attempts.iter().any(|attempt| attempt.transaction_hash == hash)
    }

    fn newest(&self) -> Option<&Attempt> {
        self.attempts.last()
    }
}

fn check_intent(intent: &PaymentIntent) -> Result<(), StepError> {
    let fits = match &intent.identity {
        Identity::AccountNonce { account, .. } => intent.kind.uses_nonce() && !account.is_empty(),
        Identity::RevealMarker { marker } => !intent.kind.uses_nonce() && !marker.is_empty(),
    };
    if fits { Ok(()) } else { Err(StepError::IdentityMismatch { kind: intent.kind }) }
}

/// What to do next. Never holds signed bytes: [`PaymentSequence::mark_sent`]
/// hands them out.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Recovery {
    /// Back up what the payment needs, then [`PaymentSequence::mark_backed_up`].
    BackUp,
    /// Sign the first attempt and save it with [`PaymentSequence::add_attempt`].
    Sign,
    /// Broadcast the stored bytes of this attempt: take them from
    /// [`PaymentSequence::mark_sent`], which saves [`Step::Sent`] first.
    Send { transaction_hash: Vec<u8> },
    /// Nothing landed and the newest attempt's window has passed: sign a new
    /// attempt with the same identity and save it with
    /// [`PaymentSequence::add_attempt`]. The old bytes are never sent again.
    Rebuild,
    /// The chain has the transaction (pending, or in a block not yet deep
    /// enough): wait for blocks.
    Wait,
    /// Settled, failed or conflicted: nothing to send. The record is kept;
    /// ask again later to catch a reorg.
    Done { step: Step },
}

/// Why a step was refused. Nothing secret is ever in here.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum StepError {
    /// The store failed.
    Store { reason: String },
    /// A stored record or payload does not decode.
    Unreadable { id: String, reason: String },
    /// A stored record or payload fails its checks.
    Tampered { id: String, reason: String },
    /// A stored record has a layout this code does not know.
    UnsupportedVersion { id: String, version: u32 },
    /// No record has this id.
    NotFound { id: String },
    /// A record has this id already: that payment is resumed, never restarted.
    AlreadyStarted { id: String },
    /// The payment at `from` cannot be saved as `to`.
    OutOfOrder { from: Step, to: Step },
    /// The signed transaction is empty.
    EmptyTransaction,
    /// The identity does not fit the payment kind.
    IdentityMismatch { kind: PaymentKind },
    /// These signed bytes are an attempt already.
    AttemptExists,
    /// The payment holds [`MAX_ATTEMPTS`] attempts already.
    TooManyAttempts { max: u32 },
    /// The signed bytes of an attempt are not in the store.
    PayloadMissing { id: String },
    /// The chain could not be asked, or its answers do not hang together.
    Chain { reason: String },
}

impl fmt::Display for StepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store { reason } => write!(f, "the payment store failed: {reason}"),
            Self::Unreadable { id, reason } => write!(f, "the payment record {id} cannot be read: {reason}"),
            Self::Tampered { id, reason } => write!(f, "the payment record {id} is refused: {reason}"),
            Self::UnsupportedVersion { id, version } => {
                write!(f, "the payment record {id} has the unknown version {version}")
            }
            Self::NotFound { id } => write!(f, "no payment record is named {id}"),
            Self::AlreadyStarted { id } => write!(f, "the payment {id} is started already: resume it"),
            Self::OutOfOrder { from, to } => write!(f, "a {from} payment cannot be saved as {to}"),
            Self::EmptyTransaction => f.write_str("the signed transaction is empty"),
            Self::IdentityMismatch { kind } => write!(f, "the identity does not fit a {kind}"),
            Self::AttemptExists => f.write_str("the payment has this attempt already"),
            Self::TooManyAttempts { max } => write!(f, "the payment holds {max} attempts already"),
            Self::PayloadMissing { id } => write!(f, "the signed transaction of payment {id} is not stored"),
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

/// Where the records and payloads live. On the phone: the small records in
/// the Keychain, the signed bytes in protected app storage.
#[uniffi::export(callback_interface)]
pub trait PaymentStore: Send + Sync {
    /// Saves the record under its id, replacing the one there. Must be
    /// durable when it returns.
    fn save(&self, record: PaymentRecord) -> Result<(), StepError>;
    /// The record of `id`, if any; [`StepError::Unreadable`] if it does not
    /// decode.
    fn load(&self, id: String) -> Result<Option<PaymentRecord>, StepError>;
    /// The ids of every saved record.
    fn list(&self) -> Result<Vec<String>, StepError>;
    /// Removes the record of `id` and every payload of it.
    fn remove(&self, id: String) -> Result<(), StepError>;
    /// Saves the signed bytes of an attempt of `id`, written whole or not at
    /// all. Must be durable when it returns.
    fn save_payload(&self, id: String, transaction_hash: Vec<u8>, signed_transaction: Vec<u8>)
    -> Result<(), StepError>;
    /// The signed bytes saved under that hash, if any.
    fn load_payload(&self, id: String, transaction_hash: Vec<u8>) -> Result<Option<Vec<u8>>, StepError>;
}

/// What the chain, as it stands now, says.
#[uniffi::export(callback_interface)]
pub trait ChainView: Send + Sync {
    /// The receipt of the transaction with this hash, if it is in a block.
    fn receipt(&self, transaction_hash: Vec<u8>) -> Result<Option<Receipt>, StepError>;
    /// Whether the node holds the transaction, not yet in a block.
    fn pending(&self, transaction_hash: Vec<u8>) -> Result<bool, StepError>;
    /// The hash of the transaction in a block that used this identity, if any.
    fn identity_used_by(&self, identity: Identity) -> Result<Option<Vec<u8>>, StepError>;
    /// Whether the chain shows the payment's expected effect from this
    /// transaction (the balance moved, the marker spent, the note created).
    fn effect_applied(&self, intent: PaymentIntent, transaction_hash: Vec<u8>) -> Result<bool, StepError>;
    /// The height of the tip block.
    fn tip_height(&self) -> Result<u64, StepError>;
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
pub fn encode_payment_record(record: PaymentRecord) -> Vec<u8> {
    let mut out = record.body();
    out.extend_from_slice(&record.checksum);
    out
}

/// Reads a stored record. It is not checked here: [`PaymentSequence::open`]
/// refuses one that fails its checks.
#[uniffi::export]
pub fn decode_payment_record(bytes: Vec<u8>) -> Result<PaymentRecord, StepError> {
    let unreadable = |reason: &str| StepError::Unreadable { id: String::new(), reason: reason.to_owned() };
    let short = || unreadable("it ends early");
    let mut reader = Reader { rest: &bytes };
    if reader.take(4) != Some(MAGIC.as_slice()) {
        return Err(unreadable("it is not a payment record"));
    }
    let version = reader.u32().ok_or_else(short)?;
    let id = reader.bytes().ok_or_else(short)?;
    let id = String::from_utf8(id.to_vec()).map_err(|_| unreadable("the id is not UTF-8"))?;
    let kind = reader.byte().ok_or_else(short)?;
    let kind = *PaymentKind::ALL.get(usize::from(kind)).ok_or_else(|| unreadable("the payment kind is unknown"))?;
    let identity = match reader.byte().ok_or_else(short)? {
        0 => {
            let account = reader.bytes().ok_or_else(short)?.to_vec();
            Identity::AccountNonce { account, nonce: reader.u64().ok_or_else(short)? }
        }
        1 => Identity::RevealMarker { marker: reader.bytes().ok_or_else(short)?.to_vec() },
        _ => return Err(unreadable("the identity is unknown")),
    };
    let details = reader.bytes().ok_or_else(short)?.to_vec();
    let step = reader.byte().ok_or_else(short)?;
    let step = Step::from_index(step).ok_or_else(|| unreadable("the step is unknown"))?;
    let count = reader.u32().ok_or_else(short)?;
    if count > MAX_ATTEMPTS {
        return Err(unreadable("it holds too many attempts"));
    }
    let mut attempts = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let transaction_hash = reader.bytes().ok_or_else(short)?.to_vec();
        let valid_until = reader.optional_u64().map_err(|reason| unreadable(reason))?;
        attempts.push(Attempt { transaction_hash, valid_until });
    }
    let inclusion = match reader.byte().ok_or_else(short)? {
        0 => None,
        1 => Some(Inclusion {
            transaction_hash: reader.bytes().ok_or_else(short)?.to_vec(),
            block_hash: reader.bytes().ok_or_else(short)?.to_vec(),
            block_height: reader.u64().ok_or_else(short)?,
        }),
        _ => return Err(unreadable("a field flag is unknown")),
    };
    if reader.rest.len() != 32 {
        return Err(unreadable("the checksum is not 32 bytes"));
    }
    Ok(PaymentRecord {
        id,
        intent: PaymentIntent { kind, identity, details },
        step,
        attempts,
        inclusion,
        version,
        checksum: reader.rest.to_vec(),
    })
}

/// One payment, moved one step at a time; every step saved before its effect.
#[derive(uniffi::Object)]
pub struct PaymentSequence {
    store: Box<dyn PaymentStore>,
    record: Mutex<PaymentRecord>,
}

#[uniffi::export]
impl PaymentSequence {
    /// Starts a new payment and saves it as [`Step::Prepared`]. Refuses an id
    /// that has a record already: that payment is resumed with
    /// [`PaymentSequence::open`], never started again.
    #[uniffi::constructor]
    pub fn start(store: Box<dyn PaymentStore>, id: String, intent: PaymentIntent) -> Result<Arc<Self>, StepError> {
        if id.is_empty() {
            return Err(StepError::Tampered { id, reason: "the id is empty".to_owned() });
        }
        check_intent(&intent)?;
        if store.load(id.clone())?.is_some() {
            return Err(StepError::AlreadyStarted { id });
        }
        let record = PaymentRecord::new(id, intent, Step::Prepared, Vec::new(), None);
        store.save(record.clone())?;
        Ok(Arc::new(Self { store, record: Mutex::new(record) }))
    }

    /// Opens a saved payment, refusing a record that fails its checks.
    #[uniffi::constructor]
    pub fn open(store: Box<dyn PaymentStore>, id: String) -> Result<Arc<Self>, StepError> {
        let record = store.load(id.clone())?.ok_or_else(|| StepError::NotFound { id: id.clone() })?;
        record.check()?;
        if record.id != id {
            return Err(StepError::Tampered { id, reason: "the record is saved under another id".to_owned() });
        }
        Ok(Arc::new(Self { store, record: Mutex::new(record) }))
    }

    /// The record as saved.
    pub fn record(&self) -> PaymentRecord {
        self.lock().clone()
    }

    /// The last step saved.
    pub fn step(&self) -> Step {
        self.lock().step
    }

    /// Reads the chain, saves what it says (a landing, a failure, a
    /// conflict, settling, or a reorg that undid any of them) and returns
    /// what to do next.
    pub fn recover(&self, chain: Box<dyn ChainView>) -> Result<Recovery, StepError> {
        let mut record = self.lock();
        record.check()?;
        // Each pass either acts or saves one move; a reorg is at most three
        // moves (back to sent, included, settled).
        for _ in 0..4 {
            match next(&record, chain.as_ref())? {
                Next::Act(recovery) => return Ok(recovery),
                Next::Save(moved) => {
                    self.store.save(moved.clone())?;
                    *record = moved;
                }
            }
        }
        Err(StepError::Chain { reason: "its answers keep changing".to_owned() })
    }

    /// Saves [`Step::BackedUp`].
    pub fn mark_backed_up(&self) -> Result<(), StepError> {
        let mut record = self.lock();
        if record.step != Step::Prepared {
            return Err(StepError::OutOfOrder { from: record.step, to: Step::BackedUp });
        }
        let moved = record.moved(Step::BackedUp, None);
        self.store.save(moved.clone())?;
        *record = moved;
        Ok(())
    }

    /// Saves a new attempt with the payment's identity (the first one, a
    /// rebuild, a speed-up or a cancel) and returns its hash. The signed
    /// bytes are saved first, then the record lists them as [`Step::Signed`].
    /// Refused once a transaction using the identity has landed.
    pub fn add_attempt(&self, signed_transaction: Vec<u8>, valid_until: Option<u64>) -> Result<Vec<u8>, StepError> {
        if signed_transaction.is_empty() {
            return Err(StepError::EmptyTransaction);
        }
        let mut record = self.lock();
        if !matches!(record.step, Step::BackedUp | Step::Signed | Step::Sent) {
            return Err(StepError::OutOfOrder { from: record.step, to: Step::Signed });
        }
        let hash = transaction_hash(signed_transaction.clone());
        if record.has_attempt(&hash) {
            return Err(StepError::AttemptExists);
        }
        if record.attempts.len() >= MAX_ATTEMPTS as usize {
            return Err(StepError::TooManyAttempts { max: MAX_ATTEMPTS });
        }
        self.store.save_payload(record.id.clone(), hash.clone(), signed_transaction)?;
        let mut attempts = record.attempts.clone();
        attempts.push(Attempt { transaction_hash: hash.clone(), valid_until });
        let moved = PaymentRecord::new(record.id.clone(), record.intent.clone(), Step::Signed, attempts, None);
        self.store.save(moved.clone())?;
        *record = moved;
        Ok(hash)
    }

    /// Saves [`Step::Sent`] (if the record is not sent already) and returns
    /// the stored bytes of the newest attempt, to broadcast. Refuses bytes
    /// that do not match their hash.
    pub fn mark_sent(&self) -> Result<Vec<u8>, StepError> {
        let mut record = self.lock();
        if !matches!(record.step, Step::Signed | Step::Sent) {
            return Err(StepError::OutOfOrder { from: record.step, to: Step::Sent });
        }
        let hash = record.newest().map(|attempt| attempt.transaction_hash.clone()).unwrap_or_default();
        let bytes = self
            .store
            .load_payload(record.id.clone(), hash.clone())?
            .ok_or_else(|| StepError::PayloadMissing { id: record.id.clone() })?;
        if keccak(&[&bytes]).as_slice() != hash {
            return Err(StepError::Tampered {
                id: record.id.clone(),
                reason: "the stored transaction does not match its hash".to_owned(),
            });
        }
        if record.step == Step::Signed {
            let moved = record.moved(Step::Sent, None);
            self.store.save(moved.clone())?;
            *record = moved;
        }
        Ok(bytes)
    }
}

impl PaymentSequence {
    fn lock(&self) -> MutexGuard<'_, PaymentRecord> {
        // The record is replaced only after the store saved the new one, so
        // a panic leaves it as it was.
        self.record.lock().unwrap_or_else(|e| e.into_inner())
    }
}

enum Next {
    Act(Recovery),
    Save(PaymentRecord),
}

/// One step of [`PaymentSequence::recover`]: what the chain says about a
/// checked record.
fn next(record: &PaymentRecord, chain: &dyn ChainView) -> Result<Next, StepError> {
    match record.step {
        Step::Prepared => Ok(Next::Act(Recovery::BackUp)),
        Step::BackedUp => Ok(Next::Act(Recovery::Sign)),
        Step::Signed | Step::Sent => in_flight(record, chain),
        Step::Included => {
            let Some(inclusion) = still_included(record, chain)? else {
                return Ok(Next::Save(record.moved(Step::Sent, None)));
            };
            let tip = chain.tip_height()?;
            let confirmations = (tip + 1).saturating_sub(inclusion.block_height);
            if confirmations >= SETTLE_CONFIRMATIONS {
                Ok(Next::Save(record.moved(Step::Settled, Some(inclusion))))
            } else {
                Ok(Next::Act(Recovery::Wait))
            }
        }
        Step::Settled | Step::Failed | Step::Conflicted => match still_included(record, chain)? {
            Some(_) => Ok(Next::Act(Recovery::Done { step: record.step })),
            // A reorg took the block away: pending again.
            None => Ok(Next::Save(record.moved(Step::Sent, None))),
        },
    }
}

/// A signed or sent payment: did an attempt land, did another transaction
/// take the identity, or is the newest attempt to be sent or rebuilt?
fn in_flight(record: &PaymentRecord, chain: &dyn ChainView) -> Result<Next, StepError> {
    for attempt in record.attempts.iter().rev() {
        let hash = attempt.transaction_hash.clone();
        if let Some(receipt) = chain.receipt(hash.clone())? {
            let worked =
                receipt.status == ReceiptStatus::Success && chain.effect_applied(record.intent.clone(), hash.clone())?;
            let step = if worked { Step::Included } else { Step::Failed };
            let inclusion =
                Inclusion { transaction_hash: hash, block_hash: receipt.block_hash, block_height: receipt.block_height };
            return Ok(Next::Save(record.moved(step, Some(inclusion))));
        }
    }
    if let Some(user) = chain.identity_used_by(record.intent.identity.clone())? {
        if !record.has_attempt(&user) {
            if let Some(receipt) = chain.receipt(user.clone())? {
                let inclusion = Inclusion {
                    transaction_hash: user,
                    block_hash: receipt.block_hash,
                    block_height: receipt.block_height,
                };
                return Ok(Next::Save(record.moved(Step::Conflicted, Some(inclusion))));
            }
        }
        // The chain has not settled its own answers yet.
        return Ok(Next::Act(Recovery::Wait));
    }
    let newest = record.newest().ok_or_else(|| StepError::Tampered {
        id: record.id.clone(),
        reason: "the attempts do not fit the step".to_owned(),
    })?;
    let hash = newest.transaction_hash.clone();
    let tip = chain.tip_height()?;
    if newest.valid_until.is_some_and(|until| tip >= until) {
        // The next block may not include it: its proof is for a window that
        // has passed. Never resend it.
        return Ok(Next::Act(Recovery::Rebuild));
    }
    if record.step == Step::Sent && chain.pending(hash.clone())? {
        return Ok(Next::Act(Recovery::Wait));
    }
    Ok(Next::Act(Recovery::Send { transaction_hash: hash }))
}

/// The receipt of the record's inclusion, if it is still in the same block.
fn still_included(record: &PaymentRecord, chain: &dyn ChainView) -> Result<Option<Inclusion>, StepError> {
    let Some(inclusion) = &record.inclusion else { return Ok(None) };
    let receipt = chain.receipt(inclusion.transaction_hash.clone())?;
    Ok(receipt.filter(|receipt| receipt.block_hash == inclusion.block_hash).map(|receipt| Inclusion {
        transaction_hash: inclusion.transaction_hash.clone(),
        block_hash: receipt.block_hash,
        block_height: receipt.block_height,
    }))
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

fn put_optional_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        None => out.push(0),
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
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

    fn byte(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_be_bytes(b.try_into().expect("4 bytes")))
    }

    fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|b| u64::from_be_bytes(b.try_into().expect("8 bytes")))
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn optional_u64(&mut self) -> Result<Option<u64>, &'static str> {
        match self.byte() {
            Some(0) => Ok(None),
            Some(1) => self.u64().map(Some).ok_or("it ends early"),
            Some(_) => Err("a field flag is unknown"),
            None => Err("it ends early"),
        }
    }
}
