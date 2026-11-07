//! What the enclave serves on its service port (feature `nitro`): one public
//! port for phones and for other enclaves.
//!
//! The first byte of a connection picks its protocol:
//!
//! - `0x16` (a TLS handshake record): TLS ended inside the enclave
//!   (`enclave_tls`), then the relay's HTTP routes (`relay_http`): Check,
//!   Fill, Fill confirmation and Open for phones, and the phone attestation.
//! - `0x00` (the top byte of a frame length of at most 64 KiB): the framed
//!   service protocol: kind (1 key-share request, 2 phone attestation with a
//!   32-byte challenge) || body; the answer is 0 || body, or 1 || why it was
//!   refused.
//! - anything else: the connection is closed unanswered.
//!
//! Fail closed: the flows are served only once the enclave holds M **and**
//! a chain status check, a card registry and a durable journal are
//! installed ([`ServiceDeps`]). Until then every flow request is answered
//! HTTP 503 `unavailable` ("This Seal is not ready to answer cards") and no
//! card traffic is sent; the attestation route still answers once M is
//! held. A Seal built without the three is never reachable from the
//! network.
//!
//! The service log ([`ServiceLog`]) takes a fixed set of events with no
//! field for carried bytes: no path, header, body, PIN or key is ever
//! logged.

use core::fmt;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};

use zeroize::Zeroizing;

use crate::attestation::{AttestationSource, AttestationVerifier};
use crate::chain_check::CoinStatusCheck;
use crate::enclave_tls::EnclaveTls;
use crate::flows::{Seal, SealConfig};
use crate::journal::Journal;
use crate::key_share::{self, GiverContext, read_frame, write_frame};
use crate::measurements::TrustedList;
use crate::phone_attestation::{self, CHALLENGE_BYTES};
use crate::registry::CardRegistry;
use crate::relay::{KeyMakerFactory, PaymentCheckFactory, Relay, RelayLimits, SealFactory};
use crate::relay_http::{AttestRefused, Flows, PhoneAttester, ReadWrite, Routes};
use crate::secrets::MasterKey;
use crate::traits::{ChainCheck, Clock, PhantomKeyMaker, SystemRandom};

/// The first byte of a TLS connection: a handshake record.
pub const FIRST_BYTE_TLS: u8 = 0x16;
/// The first byte of a framed connection: the top byte of a frame length of
/// at most 64 KiB.
pub const FIRST_BYTE_FRAME: u8 = 0x00;
/// A framed key-share request.
pub const KIND_KEY_SHARE: u8 = 1;
/// A framed phone attestation request (a 32-byte challenge).
pub const KIND_PHONE_ATTESTATION: u8 = 2;
/// A framed answer: the body follows.
pub const ANSWER_OK: u8 = 0;
/// A framed answer: why it was refused follows.
pub const ANSWER_REFUSED: u8 = 1;

/// The chain status check, as the Seal asks it before it answers Sealed and
/// before it seals a filled card (`ChainNode`s over the host's vsock port
/// 5003 in a real Seal). Each session's Seal gets its own handles.
pub trait ChainStatus: Send + Sync {
    /// The coin status check a session's Seal is built with.
    fn status_check(&self) -> Box<dyn CoinStatusCheck>;
    /// The payment check a Fill's confirmation asks.
    fn payment_check(&self) -> Box<dyn ChainCheck>;
}

/// The card registry, as a session's Seal looks cards up in it.
pub trait RegistrySource: Send + Sync {
    /// The registry a session's Seal is built with.
    fn registry(&self) -> Box<dyn CardRegistry>;
}

/// A durable journal: one whose saves survive the enclave (a journal
/// in enclave memory only is not one). Every session's Seal writes to the
/// same store.
pub trait DurableJournal: Send + Sync {
    /// The journal a session's Seal is built with.
    fn journal(&self) -> Box<dyn Journal>;
}

/// The wallet core's Phantom Key derivation, which a Fill needs.
pub trait KeyMakerSource: Send + Sync {
    /// The key maker a Fill's worker uses.
    fn key_maker(&self) -> Box<dyn PhantomKeyMaker>;
}

/// What the enclave must be given before it may answer a card. The enclave
/// program installs none of them yet, so it answers every flow request
/// `unavailable`.
#[derive(Clone, Default)]
pub struct ServiceDeps {
    /// The chain status check.
    pub chain: Option<Arc<dyn ChainStatus>>,
    /// The card registry.
    pub registry: Option<Arc<dyn RegistrySource>>,
    /// The durable journal.
    pub journal: Option<Arc<dyn DurableJournal>>,
    /// The Phantom Key maker. Without it a Fill is answered `unavailable`
    /// even when the other flows are served.
    pub key_maker: Option<Arc<dyn KeyMakerSource>>,
}

impl ServiceDeps {
    /// Nothing installed: every flow is refused.
    pub fn none() -> ServiceDeps {
        ServiceDeps::default()
    }

    /// Whether the chain status check, the card registry and the durable
    /// journal are all installed.
    pub fn ready(&self) -> bool {
        self.chain.is_some() && self.registry.is_some() && self.journal.is_some()
    }
}

/// The enclave's own attestation: its NSM in a real enclave, a fake in
/// tests.
pub trait EnclaveAttestation: Send + Sync {
    /// A source of this enclave's documents.
    fn source(&self) -> Result<Box<dyn AttestationSource>, String>;
    /// The verifier another enclave's documents are checked with (the
    /// pinned AWS root in a real enclave).
    fn verifier(&self) -> Box<dyn AttestationVerifier>;
}

/// An event of the service. No variant carries a key, a PIN or any bytes a
/// connection carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceEvent {
    /// M was installed; whether the flows are served from now on.
    MasterInstalled {
        /// Whether a chain status check, a registry and a durable journal
        /// are installed.
        serves_flows: bool,
    },
    /// M was handed, encrypted, to an attested build on the trusted list.
    HandedMaster {
        /// The receiving build's name, as the list names it.
        build: String,
    },
    /// A key-share request was refused.
    KeyShareRefused,
    /// A connection began with neither a TLS record nor a frame, and was
    /// closed.
    UnknownProtocol,
}

impl fmt::Display for ServiceEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceEvent::MasterInstalled { serves_flows: true } => f.write_str("holds M; serves the flows"),
            ServiceEvent::MasterInstalled { serves_flows: false } => {
                f.write_str("holds M; not ready to answer cards (no chain check, registry or durable journal)")
            }
            ServiceEvent::HandedMaster { build } => write!(f, "handed M to build {build}"),
            ServiceEvent::KeyShareRefused => f.write_str("refused a key-share request"),
            ServiceEvent::UnknownProtocol => f.write_str("closed a connection of no known protocol"),
        }
    }
}

/// Where the service writes its events.
pub trait ServiceLog: Send + Sync {
    /// Records `event`.
    fn record(&self, event: ServiceEvent);
}

/// A log in memory, for tests.
#[derive(Debug, Default)]
pub struct MemoryServiceLog(pub Mutex<Vec<ServiceEvent>>);

impl ServiceLog for MemoryServiceLog {
    fn record(&self, event: ServiceEvent) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).push(event);
    }
}

/// A log that keeps nothing.
#[derive(Debug, Default)]
pub struct NoServiceLog;

impl ServiceLog for NoServiceLog {
    fn record(&self, _event: ServiceEvent) {}
}

/// How the flows' Seals are configured.
#[derive(Clone)]
pub struct ServiceConfig {
    /// The measurement every answer carries (the enclave's PCR0).
    pub measurement: [u8; crate::answer::MEASUREMENT_BYTES],
    /// How long an answer is good for, in seconds.
    pub answer_lifetime_secs: u64,
    /// The relay's session limits.
    pub relay_limits: RelayLimits,
    /// The clock of the answers' expiry and of the key share.
    pub clock: Arc<dyn Clock + Send + Sync>,
}

/// What the enclave holds, as the control port changes it.
pub struct ServiceState {
    /// Whether the one start has happened.
    pub started: bool,
    /// M, once made or received.
    pub master: Option<MasterKey>,
    /// The only list another enclave is checked against.
    pub trusted: TrustedList,
}

/// What the attester and the service share.
struct Shared {
    state: Mutex<ServiceState>,
    answer_key: Mutex<Option<Vec<u8>>>,
    kem_key: Vec<u8>,
    certificate_hash: [u8; 32],
    attestation: Arc<dyn EnclaveAttestation>,
    clock: Arc<dyn Clock + Send + Sync>,
    log: Arc<dyn ServiceLog>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// The `GPA2` phone attestation of this enclave.
struct Attester(Arc<Shared>);

impl PhoneAttester for Attester {
    fn attest(&self, challenge: &[u8; CHALLENGE_BYTES]) -> Result<Vec<u8>, AttestRefused> {
        self.0.phone_attestation(challenge)
    }
}

impl Shared {
    fn phone_attestation(&self, challenge: &[u8; CHALLENGE_BYTES]) -> Result<Vec<u8>, AttestRefused> {
        // The keys are public; nothing is held while the NSM works.
        let answer_key = lock(&self.answer_key).clone().ok_or(AttestRefused::NotReady)?;
        let mut source = self.attestation.source().map_err(|_| AttestRefused::Failed)?;
        phone_attestation::make(source.as_mut(), &answer_key, &self.kem_key, &self.certificate_hash, challenge)
            .map_err(|_| AttestRefused::Failed)
    }
}

/// The Seal's session clock: the service's.
struct SharedClock(Arc<dyn Clock + Send + Sync>);

impl Clock for SharedClock {
    fn now_unix(&self) -> u64 {
        self.0.now_unix()
    }
}

/// The enclave's service port.
pub struct EnclaveService {
    shared: Arc<Shared>,
    tls: EnclaveTls,
    deps: ServiceDeps,
    config: ServiceConfig,
    routes: Mutex<Arc<Routes>>,
}

impl EnclaveService {
    /// A service with TLS `tls`, the enclave's ML-KEM-768 encapsulation key
    /// `kem_key` (for phones), the `trusted` list, the enclave's
    /// `attestation`, the installed `deps` and `config`. It holds no M yet:
    /// every flow and every attestation is refused until
    /// [`EnclaveService::install_master`].
    pub fn new(
        tls: EnclaveTls,
        kem_key: Vec<u8>,
        trusted: TrustedList,
        attestation: Arc<dyn EnclaveAttestation>,
        deps: ServiceDeps,
        config: ServiceConfig,
        log: Arc<dyn ServiceLog>,
    ) -> EnclaveService {
        let shared = Arc::new(Shared {
            state: Mutex::new(ServiceState { started: false, master: None, trusted }),
            answer_key: Mutex::new(None),
            kem_key,
            certificate_hash: tls.certificate_hash(),
            attestation,
            clock: Arc::clone(&config.clock),
            log,
        });
        let routes = Mutex::new(Arc::new(Routes::new(None, Some(Arc::new(Attester(Arc::clone(&shared)))))));
        EnclaveService { shared, tls, deps, config, routes }
    }

    /// What the enclave holds, for the control port.
    pub fn state(&self) -> MutexGuard<'_, ServiceState> {
        lock(&self.shared.state)
    }

    /// The SHA-256 of the TLS certificate the service presents.
    pub fn certificate_hash(&self) -> [u8; 32] {
        self.tls.certificate_hash()
    }

    /// The DER of the TLS certificate the service presents.
    pub fn certificate_der(&self) -> &[u8] {
        self.tls.certificate_der()
    }

    /// Whether the flows are served: M is held and the chain status check,
    /// the registry and the durable journal are installed.
    pub fn serves_flows(&self) -> bool {
        lock(&self.routes).serves_flows()
    }

    /// The routes as they stand.
    pub fn routes(&self) -> Arc<Routes> {
        Arc::clone(&lock(&self.routes))
    }

    /// Takes M (made or received) and, if the three are installed, starts
    /// serving the flows with Seals holding it.
    pub fn install_master(&self, master: MasterKey) {
        let answer_key = phone_attestation::answer_key(&master);
        let flows = self.deps.ready().then(|| self.flows(&master)).flatten();
        let serves_flows = flows.is_some();
        let routes = Routes::new(flows, Some(Arc::new(Attester(Arc::clone(&self.shared)))));
        *lock(&self.shared.answer_key) = Some(answer_key);
        lock(&self.shared.state).master = Some(master);
        *lock(&self.routes) = Arc::new(routes);
        self.shared.log.record(ServiceEvent::MasterInstalled { serves_flows });
    }

    /// The flows over Seals holding `master`, with the installed deps.
    fn flows(&self, master: &MasterKey) -> Option<Flows> {
        let chain = self.deps.chain.clone()?;
        let registry = self.deps.registry.clone()?;
        let journal = self.deps.journal.clone()?;
        // Each session's Seal holds its own copy of M, wiped when it is
        // dropped; the copies live in enclave memory only.
        let held = Arc::new(Zeroizing::new(*master.derive_from()));
        let seal_config = SealConfig {
            measurement: self.config.measurement,
            answer_lifetime_secs: self.config.answer_lifetime_secs,
        };
        let clock = Arc::clone(&self.config.clock);
        let session_chain = Arc::clone(&chain);
        let factory: SealFactory = Arc::new(move || {
            let mut bytes = **held;
            let master = MasterKey::take(&mut bytes);
            Seal::new(
                master,
                seal_config.clone(),
                Box::new(SystemRandom),
                Box::new(SharedClock(Arc::clone(&clock))),
                journal.journal(),
            )
            .with_chain_status(session_chain.status_check())
            .with_registry(registry.registry())
        });
        let payment: PaymentCheckFactory = Arc::new(move || chain.payment_check());
        let key_maker = self.deps.key_maker.clone().map(|source| {
            let factory: KeyMakerFactory = Arc::new(move || source.key_maker());
            factory
        });
        Some(Flows { relay: Arc::new(Relay::new(factory, self.config.relay_limits)), key_maker, payment })
    }

    /// Serves one connection of the service port: TLS and the HTTP routes,
    /// or the framed protocol, by its first byte; anything else is closed.
    /// The caller bounds the whole connection's time (the bounded service's
    /// connection time, a slow TLS handshake included) and closes it.
    pub fn serve_connection(&self, stream: &mut dyn ReadWrite) {
        let mut first = [0u8; 1];
        loop {
            match stream.read(&mut first) {
                Ok(1) => break,
                Ok(_) => return,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            }
        }
        let mut stream = Prefixed { first: Some(first[0]), inner: stream };
        match first[0] {
            FIRST_BYTE_TLS => {
                let routes = self.routes();
                self.tls.serve(&mut stream, &routes);
            }
            FIRST_BYTE_FRAME => self.serve_frames(&mut stream),
            _ => self.shared.log.record(ServiceEvent::UnknownProtocol),
        }
    }

    /// Answers service frames until the connection closes or fails.
    fn serve_frames(&self, stream: &mut dyn ReadWrite) {
        while let Ok(frame) = read_frame(stream) {
            let answer = match self.answer_frame(&frame) {
                Ok(body) => [&[ANSWER_OK][..], &body].concat(),
                Err(why) => [&[ANSWER_REFUSED][..], why.as_bytes()].concat(),
            };
            if write_frame(stream, &answer).is_err() {
                break;
            }
        }
    }

    /// The answer to one framed request.
    pub fn answer_frame(&self, frame: &[u8]) -> Result<Vec<u8>, String> {
        let (&kind, body) = frame.split_first().ok_or("an empty frame")?;
        match kind {
            KIND_KEY_SHARE => self.key_share(body),
            KIND_PHONE_ATTESTATION => {
                let challenge: [u8; CHALLENGE_BYTES] = body.try_into().map_err(|_| "a challenge is 32 bytes")?;
                self.shared.phone_attestation(&challenge).map_err(|why| match why {
                    AttestRefused::NotReady => "this enclave holds no M yet".to_owned(),
                    AttestRefused::Failed => "no attestation could be made".to_owned(),
                })
            }
            _ => Err("unknown request".into()),
        }
    }

    /// Hands M, encrypted, only to an attested build on the trusted list.
    fn key_share(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        let held = lock(&self.shared.state);
        let master = held.master.as_ref().ok_or("this enclave holds no M yet")?;
        let mut source = self.shared.attestation.source()?;
        let verifier = self.shared.attestation.verifier();
        let given = key_share::package_for(
            master,
            request,
            GiverContext {
                verifier: verifier.as_ref(),
                list: &held.trusted,
                source: source.as_mut(),
                random: &mut SystemRandom,
                now_unix: self.shared.clock.now_unix(),
            },
        );
        match given {
            Ok(given) => {
                self.shared.log.record(ServiceEvent::HandedMaster { build: given.receiver.name.clone() });
                Ok(given.package)
            }
            Err(why) => {
                self.shared.log.record(ServiceEvent::KeyShareRefused);
                Err(why.to_string())
            }
        }
    }
}

/// A stream whose first byte was already read: it is read again first.
struct Prefixed<'a> {
    first: Option<u8>,
    inner: &'a mut dyn ReadWrite,
}

impl Read for Prefixed<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(byte) = self.first.take() {
            buf[0] = byte;
            return Ok(1);
        }
        self.inner.read(buf)
    }
}

impl Write for Prefixed<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
