//! The relay: how the phone carries the Seal's card traffic.
//!
//! The Seal never talks to a card itself. Its [`CardTransport`] is one APDU
//! in, one raw answer out, and the phone stands behind it over the network:
//! the phone holds the NFC session, the Seal holds every key. The phone
//! passes each APDU to the card and each answer back as opaque bytes; it
//! never decrypts them and holds no card key.
//!
//! Over plain request and answer pairs:
//!
//! 1. the phone starts a Check with the card's UID and a fresh 32-byte
//!    challenge ([`Relay::start_check`]);
//! 2. the Seal runs [`Seal::check`] on a worker thread whose transport
//!    hands each APDU to the phone as the next answer
//!    ([`Step::Apdu`], with the session id) and waits for the card's reply
//!    on the phone's next request ([`Relay::step`]);
//! 3. the last answer is the signed Seal answer ([`Step::Done`]).
//!
//! A session has an id (16 random bytes), an idle timeout (how long the
//! Seal waits for the card's reply) and a total limit, both well inside the
//! iOS NFC session limit of 60 seconds. An unknown or finished session id is
//! refused, and so is a session past either limit. The phone can end a
//! session early ([`Relay::abort`]) when the card leaves the field; the
//! Seal's flow then stops as a dropped connection and is run again from the
//! start.
//!
//! This module has no networking: the wire format over HTTP is in
//! `docs/seal-relay.md` and the development test server
//! (`test_server`, feature `test-server`) serves it.

use std::collections::HashMap;
use std::fmt;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::answer::SignedAnswer;
use crate::card_keys::CardUid;
use crate::error::SealError;
use crate::flows::{CheckRequest, Seal};
use crate::traits::{CardTransport, Dropped, SealRandom, SystemRandom};

/// The iOS limit on one Core NFC reader session. Every relay limit stays
/// well inside it.
pub const IOS_NFC_SESSION_LIMIT: Duration = Duration::from_secs(60);
/// The length of a session id.
pub const SESSION_ID_BYTES: usize = 16;
/// The longest card answer the Seal takes: a short APDU's 256 data bytes
/// and the two status bytes.
pub const MAX_CARD_ANSWER_BYTES: usize = 258;

/// How long a relay session may last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimits {
    /// How long the Seal waits for the card's reply to one command.
    pub idle_timeout: Duration,
    /// How long a whole session may last, from its start.
    pub total_limit: Duration,
    /// How many sessions may run at once.
    pub max_sessions: usize,
}

impl Default for RelayLimits {
    fn default() -> Self {
        RelayLimits { idle_timeout: Duration::from_secs(10), total_limit: Duration::from_secs(30), max_sessions: 32 }
    }
}

impl RelayLimits {
    /// Whether these limits are usable: each more than zero, the idle
    /// timeout within the total and the total well inside the iOS NFC
    /// session limit (at most 45 seconds).
    pub fn valid(&self) -> bool {
        !self.idle_timeout.is_zero()
            && self.idle_timeout <= self.total_limit
            && self.total_limit <= IOS_NFC_SESSION_LIMIT * 3 / 4
            && self.max_sessions > 0
    }
}

/// A relay session's id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; SESSION_ID_BYTES]);

impl SessionId {
    /// The id as lowercase hex.
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }

    /// Reads an id from hex.
    pub fn from_hex(text: &str) -> Option<SessionId> {
        from_hex(text)?.try_into().ok().map(SessionId)
    }
}

/// What the Seal answers the phone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Send `apdu` to the card and return its raw answer in the next
    /// request of `session`.
    Apdu {
        /// The session.
        session: SessionId,
        /// The command, opaque to the phone.
        apdu: Vec<u8>,
    },
    /// The flow is over: the Seal's signed answer. The session is finished.
    Done(SignedAnswer),
}

/// Why the relay refused a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// No such session: never started, finished, ended or swept away.
    UnknownSession,
    /// The session went past its idle timeout or its total limit.
    Expired,
    /// Too many sessions are running.
    Busy,
    /// The request is malformed.
    BadRequest(&'static str),
    /// The Seal's flow stopped with this error; the session is finished.
    Seal(SealError),
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayError::UnknownSession => f.write_str("unknown or finished session"),
            RelayError::Expired => f.write_str("the session timed out"),
            RelayError::Busy => f.write_str("too many sessions are running"),
            RelayError::BadRequest(what) => write!(f, "bad request: {what}"),
            RelayError::Seal(error) => write!(f, "the Seal refused: {error}"),
        }
    }
}

impl std::error::Error for RelayError {}

/// Makes the Seal a session's worker runs. Called on the worker's thread,
/// so the Seal need not be `Send`.
pub type SealFactory = Arc<dyn Fn() -> Seal + Send + Sync>;

/// From the worker to the phone.
enum ToPhone {
    Apdu(Vec<u8>),
    Done(Result<SignedAnswer, SealError>),
}

/// From the phone to the worker.
enum ToSeal {
    Answer(Vec<u8>),
    Abort,
}

/// The worker's card: each APDU goes to the phone, each answer comes back
/// from it. A reply that does not come within the idle timeout, or past the
/// session's end, is a dropped connection.
struct RelayedCard {
    to_phone: Sender<ToPhone>,
    from_phone: Receiver<ToSeal>,
    idle_timeout: Duration,
    deadline: Instant,
}

impl CardTransport for RelayedCard {
    fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Dropped> {
        self.to_phone.send(ToPhone::Apdu(apdu.to_vec())).map_err(|_| Dropped)?;
        let wait = self.idle_timeout.min(self.deadline.saturating_duration_since(Instant::now()));
        match self.from_phone.recv_timeout(wait) {
            Ok(ToSeal::Answer(answer)) => Ok(answer),
            Ok(ToSeal::Abort) | Err(_) => Err(Dropped),
        }
    }
}

/// One running session, as the relay holds it.
struct Session {
    to_seal: Sender<ToSeal>,
    from_seal: Receiver<ToPhone>,
    started: Instant,
    /// When the Seal last handed out a command (the idle clock).
    waiting_since: Instant,
}

/// The Seal's side of the relay: its running sessions.
pub struct Relay {
    factory: SealFactory,
    limits: RelayLimits,
    sessions: Mutex<HashMap<SessionId, Arc<Mutex<Session>>>>,
    random: Mutex<Box<dyn SealRandom + Send>>,
}

impl Relay {
    /// A relay whose sessions each run a Seal made by `factory`.
    pub fn new(factory: SealFactory, limits: RelayLimits) -> Relay {
        Relay { factory, limits, sessions: Mutex::new(HashMap::new()), random: Mutex::new(Box::new(SystemRandom)) }
    }

    /// The relay's limits.
    pub fn limits(&self) -> RelayLimits {
        self.limits
    }

    /// How many sessions are held right now (finished ones are dropped at
    /// once; timed-out ones at the next start or request).
    pub fn session_count(&self) -> usize {
        self.sessions.lock().map(|s| s.len()).unwrap_or(0)
    }

    /// Starts a Check of card `uid` over `challenge`, and returns the first
    /// command for the card (or the Seal's refusal).
    pub fn start_check(&self, uid: CardUid, challenge: [u8; 32]) -> Result<Step, RelayError> {
        self.sweep();
        if self.session_count() >= self.limits.max_sessions {
            return Err(RelayError::Busy);
        }
        let mut id = [0u8; SESSION_ID_BYTES];
        self.random
            .lock()
            .map_err(|_| RelayError::Seal(SealError::Random))?
            .fill(&mut id)
            .map_err(RelayError::Seal)?;
        let id = SessionId(id);

        let started = Instant::now();
        let deadline = started + self.limits.total_limit;
        let (to_phone, from_seal) = mpsc::channel();
        let (to_seal, from_phone) = mpsc::channel();
        let factory = Arc::clone(&self.factory);
        let idle_timeout = self.limits.idle_timeout;
        std::thread::Builder::new()
            .name("seal-relay".into())
            .spawn(move || {
                let mut card = RelayedCard { to_phone: to_phone.clone(), from_phone, idle_timeout, deadline };
                let mut seal = factory();
                let result = seal.check(&mut card, &CheckRequest { uid, challenge });
                let _ = to_phone.send(ToPhone::Done(result));
            })
            .map_err(|_| RelayError::Busy)?;

        let session = Session { to_seal, from_seal, started, waiting_since: started };
        match Self::next(&session, deadline) {
            Ok(ToPhone::Apdu(apdu)) => {
                let session = Session { waiting_since: Instant::now(), ..session };
                self.sessions
                    .lock()
                    .map_err(|_| RelayError::Busy)?
                    .insert(id, Arc::new(Mutex::new(session)));
                Ok(Step::Apdu { session: id, apdu })
            }
            Ok(ToPhone::Done(Ok(answer))) => Ok(Step::Done(answer)),
            Ok(ToPhone::Done(Err(error))) => Err(RelayError::Seal(error)),
            Err(error) => Err(error),
        }
    }

    /// Hands the card's raw `answer` to session `id` and returns the next
    /// command, or the signed answer when the flow is over.
    pub fn step(&self, id: &SessionId, answer: &[u8]) -> Result<Step, RelayError> {
        if answer.len() < 2 || answer.len() > MAX_CARD_ANSWER_BYTES {
            return Err(RelayError::BadRequest("a card answer is 2 to 258 bytes"));
        }
        let held = self.held(id)?;
        let mut session = held.lock().map_err(|_| RelayError::UnknownSession)?;
        let now = Instant::now();
        let deadline = session.started + self.limits.total_limit;
        if now >= deadline || now.duration_since(session.waiting_since) >= self.limits.idle_timeout {
            let _ = session.to_seal.send(ToSeal::Abort);
            self.forget(id);
            return Err(RelayError::Expired);
        }
        if session.to_seal.send(ToSeal::Answer(answer.to_vec())).is_err() {
            self.forget(id);
            return Err(RelayError::Expired);
        }
        let next = Self::next(&session, deadline);
        match next {
            Ok(ToPhone::Apdu(apdu)) => {
                session.waiting_since = Instant::now();
                Ok(Step::Apdu { session: *id, apdu })
            }
            Ok(ToPhone::Done(result)) => {
                self.forget(id);
                result.map(Step::Done).map_err(RelayError::Seal)
            }
            Err(error) => {
                let _ = session.to_seal.send(ToSeal::Abort);
                self.forget(id);
                Err(error)
            }
        }
    }

    /// Ends session `id` at the phone's request (the card left the field):
    /// the Seal's flow stops as a dropped connection.
    pub fn abort(&self, id: &SessionId) -> Result<(), RelayError> {
        let held = self.held(id)?;
        self.forget(id);
        if let Ok(session) = held.lock() {
            let _ = session.to_seal.send(ToSeal::Abort);
        }
        Ok(())
    }

    /// The worker's next message, waiting no later than `deadline`.
    fn next(session: &Session, deadline: Instant) -> Result<ToPhone, RelayError> {
        let wait = deadline.saturating_duration_since(Instant::now());
        session.from_seal.recv_timeout(wait).map_err(|_| RelayError::Expired)
    }

    fn held(&self, id: &SessionId) -> Result<Arc<Mutex<Session>>, RelayError> {
        let sessions = self.sessions.lock().map_err(|_| RelayError::UnknownSession)?;
        sessions.get(id).cloned().ok_or(RelayError::UnknownSession)
    }

    fn forget(&self, id: &SessionId) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(id);
        }
    }

    /// Drops every session past its limits. A session busy with a request
    /// is left to that request.
    fn sweep(&self) {
        let now = Instant::now();
        let Ok(mut sessions) = self.sessions.lock() else { return };
        sessions.retain(|_, held| match held.try_lock() {
            Ok(session) => {
                let alive = now < session.started + self.limits.total_limit
                    && now.duration_since(session.waiting_since) < self.limits.idle_timeout;
                if !alive {
                    let _ = session.to_seal.send(ToSeal::Abort);
                }
                alive
            }
            Err(_) => true,
        });
    }
}

/// Bytes as lowercase hex.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex (either case) as bytes; `None` for anything else.
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len() / 2).map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()).collect()
}
