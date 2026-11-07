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
//! a chain status check, a card registry (loaded) and a durable journal are
//! installed ([`ServiceDeps`]). Until then every flow request is answered
//! HTTP 503 `unavailable` ("This Seal is not ready to answer cards") and no
//! card traffic is sent; the attestation route still answers once M is
//! held. Every session's Seal is built by `Seal::new`, which takes the chain
//! status check and the registry: there is no other way to build one.
//!
//! The enclave program installs the chain status check over the release
//! node list ([`NodeChainStatus`]), the registry the host loads
//! (`LoadedRegistry`), the durable journal: the append-only sealed log
//! (`journal_log::SharedLog`) over the parent's store
//! (`host_journal::HostJournal`), and the Phantom Key maker a Fill needs
//! ([`CoreKeyMakerSource`], the wallet core's derivation, on the network the
//! chain check follows). When the first registry load arrives after M,
//! [`EnclaveService::refresh_flows`] rebuilds the routes.
//!
//! The journal is opened and verified once, with the M just installed
//! ([`DurableJournal::journal`]). A journal that cannot be read, fails its
//! checks (a gap, a repeat, a reorder, a bad tag, another M) leaves every
//! flow 503 and logs [`ServiceEvent::JournalRefused`]; `refresh_flows`
//! tries again. Each session's Seal gets a handle to the same log, after
//! the host's log is read again: a rollback seen then refuses that session
//! (and every later save), and is logged the same way.
//!
//! The service log ([`ServiceLog`]) takes a fixed set of events with no
//! field for carried bytes: no path, header, body, PIN or key is ever
//! logged.

use core::fmt;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};

use zeroize::Zeroizing;

use crate::attestation::{AttestationSource, AttestationVerifier};
use crate::card_keys::CardUid;
use crate::chain_check::{
    ChainNode, CoinQuery, CoinStatus, CoinStatusCheck, Network, NodeChainCheck, NodeListError,
};
use crate::enclave_tls::EnclaveTls;
use crate::error::SealError;
use crate::flows::{Seal, SealConfig};
use crate::journal::{EntryKind, Journal};
use crate::journal_log::SharedLog;
use crate::key_maker::CoreKeyMaker;
use crate::key_share::{self, GiverContext, read_frame, write_frame};
use crate::measurements::TrustedList;
use crate::node_rpc::RpcNode;
use crate::phone_attestation::{self, CHALLENGE_BYTES};
use crate::registry::CardRegistry;
use crate::relay::{KeyMakerFactory, PaymentCheckFactory, Relay, RelayLimits, SealFactory};
use crate::relay_http::{AttestRefused, Flows, PhoneAttester, ReadWrite, Routes};
use crate::secrets::MasterKey;
use crate::traits::{ChainCheck, Clock, CoinClaim, PaymentVerdict, PhantomKeyMaker, SystemRandom};

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
/// before it seals a filled card (`RpcNode`s over the host's vsock ports in
/// a real Seal: [`NodeChainStatus`]). Each session's Seal gets its own
/// handles.
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
    /// Whether the registry has been loaded. Until it has, no flow is
    /// served.
    fn loaded(&self) -> bool;
}

/// The chain status check over the release nodes: each session's Seal gets
/// a [`NodeChainCheck`] over clones of the same [`RpcNode`]s, so what their
/// scans found is shared.
pub struct NodeChainStatus {
    network: Network,
    nodes: Vec<RpcNode>,
}

impl NodeChainStatus {
    /// A check on `network` over `nodes`: at least two, each named once.
    pub fn new(network: Network, nodes: Vec<RpcNode>) -> Result<NodeChainStatus, NodeListError> {
        let status = NodeChainStatus { network, nodes };
        status.check()?;
        Ok(status)
    }

    fn check(&self) -> Result<NodeChainCheck, NodeListError> {
        let nodes = self.nodes.iter().map(|node| Box::new(node.clone()) as Box<dyn ChainNode>).collect();
        NodeChainCheck::new(self.network, nodes)
    }
}

/// A check that could not be made: it never answers Sealed.
struct NoCheck;

impl CoinStatusCheck for NoCheck {
    fn coin_status(&self, _query: &CoinQuery) -> CoinStatus {
        CoinStatus::CantCheckNow
    }
}

/// A Fill confirmation's payment check that leaves the decision to the
/// session Seal's own chain status check: the card names its coin by hash
/// only, and only the Seal's Fill journal entry holds its commit data and
/// spend marker. Every Seal is built with that check (`Seal::new`), and its
/// confirmation asks it after this one before it writes Sealed, so this
/// answer alone seals nothing.
struct SealDecides;

impl ChainCheck for SealDecides {
    fn confirm_payment(&self, _claim: &CoinClaim) -> PaymentVerdict {
        PaymentVerdict::Paid
    }
}

impl ChainStatus for NodeChainStatus {
    fn status_check(&self) -> Box<dyn CoinStatusCheck> {
        match self.check() {
            Ok(check) => Box::new(check),
            Err(_) => Box::new(NoCheck),
        }
    }

    fn payment_check(&self) -> Box<dyn ChainCheck> {
        Box::new(SealDecides)
    }
}

/// A durable journal: one whose saves survive the enclave (a journal
/// in enclave memory only is not one). Every session's Seal writes to the
/// same store.
pub trait DurableJournal: Send + Sync {
    /// The journal a session's Seal holding `master` is built with. The
    /// first call opens and verifies the journal with `master` (the M just
    /// installed); every later call hands out a handle to the same journal.
    /// An error leaves the flows unserved.
    fn journal(&self, master: &MasterKey) -> Result<Box<dyn Journal>, SealError>;
}

/// The enclave's durable journal: the append-only log (`journal_log`) over
/// the parent host's store (`host_journal::HostJournal`), opened once with
/// M and shared by every session behind one lock. Each later call reads the
/// host's log again and refuses a rollback.
impl DurableJournal for SharedLog {
    fn journal(&self, master: &MasterKey) -> Result<Box<dyn Journal>, SealError> {
        SharedLog::journal(self, master).map(|log| Box::new(log) as Box<dyn Journal>)
    }
}

/// The journal of a session whose journal could not be handed out (the
/// host's log was rolled back, or could not be read): it holds nothing and
/// takes no save, so its Seal changes no card.
struct RefusedJournal;

impl Journal for RefusedJournal {
    fn load(&self, _uid: &CardUid, _kind: EntryKind) -> Option<Vec<u8>> {
        None
    }

    fn save(&mut self, _uid: &CardUid, _kind: EntryKind, _sealed: Vec<u8>) -> Result<(), SealError> {
        Err(SealError::Journal("the journal is refused"))
    }
}

/// The wallet core's Phantom Key derivation, which a Fill needs.
pub trait KeyMakerSource: Send + Sync {
    /// The key maker a Fill's worker uses.
    fn key_maker(&self) -> Box<dyn PhantomKeyMaker>;
}

/// The enclave's Phantom Key maker: a fresh [`CoreKeyMaker`] for each Fill,
/// making coins on `chain_id`, the network the chain check follows. It
/// draws from the session Seal's random source (the enclave's `getrandom`).
#[derive(Clone, Copy)]
pub struct CoreKeyMakerSource {
    /// The chain the coins are made for.
    pub chain_id: u64,
}

impl KeyMakerSource for CoreKeyMakerSource {
    fn key_maker(&self) -> Box<dyn PhantomKeyMaker> {
        Box::new(CoreKeyMaker::new(self.chain_id))
    }
}

/// What the enclave must be given before it may answer a card. The enclave
/// program installs the chain status check, the registry, the durable
/// journal (the sealed log over the parent's store) and the Phantom Key
/// maker ([`CoreKeyMakerSource`]); until the journal has been opened and
/// verified with M it still answers every flow request `unavailable`.
#[derive(Clone, Default)]
pub struct ServiceDeps {
    /// The chain status check.
    pub chain: Option<Arc<dyn ChainStatus>>,
    /// The card registry; it counts once it is loaded.
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

    /// Whether the chain status check, the card registry (loaded) and the
    /// durable journal are all installed.
    pub fn ready(&self) -> bool {
        self.chain.is_some() && self.registry.as_ref().is_some_and(|r| r.loaded()) && self.journal.is_some()
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
        /// Whether a chain status check, a loaded registry and a durable
        /// journal are installed.
        serves_flows: bool,
    },
    /// What was missing arrived after M (the first registry load): the
    /// flows are served from now on.
    FlowsServed,
    /// M was handed, encrypted, to an attested build on the trusted list.
    HandedMaster {
        /// The receiving build's name, as the list names it.
        build: String,
    },
    /// The durable journal could not be opened or verified with M (or a
    /// session's could not be handed out): no flow is served on it.
    JournalRefused,
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
            ServiceEvent::MasterInstalled { serves_flows: false } => f.write_str(
                "holds M; not ready to answer cards (no chain check, loaded registry or durable journal)",
            ),
            ServiceEvent::FlowsServed => f.write_str("serves the flows from now on"),
            ServiceEvent::HandedMaster { build } => write!(f, "handed M to build {build}"),
            ServiceEvent::JournalRefused => {
                f.write_str("the durable journal was refused (unreadable, failed its checks or rolled back)")
            }
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
    /// the loaded registry and the durable journal are installed.
    pub fn serves_flows(&self) -> bool {
        lock(&self.routes).serves_flows()
    }

    /// Starts serving the flows if M is held and what they need has arrived
    /// since (the first registry load); call it after each registry load.
    /// Routes already serving are left as they are. Whether the flows are
    /// served.
    pub fn refresh_flows(&self) -> bool {
        // The routes' lock is held throughout, so two loads at once build
        // the routes once.
        let mut routes = lock(&self.routes);
        if routes.serves_flows() {
            return true;
        }
        let flows = {
            let held = lock(&self.shared.state);
            let Some(master) = held.master.as_ref() else { return false };
            if !self.deps.ready() {
                return false;
            }
            self.flows(master)
        };
        let Some(flows) = flows else { return false };
        *routes = Arc::new(Routes::new(Some(flows), Some(Arc::new(Attester(Arc::clone(&self.shared))))));
        self.shared.log.record(ServiceEvent::FlowsServed);
        true
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

    /// The flows over Seals holding `master`, with the installed deps; none
    /// until all three are installed, the registry is loaded and the
    /// durable journal opened and verified with `master`.
    fn flows(&self, master: &MasterKey) -> Option<Flows> {
        let chain = self.deps.chain.clone()?;
        let registry = self.deps.registry.clone().filter(|r| r.loaded())?;
        let journal = self.deps.journal.clone()?;
        // Opens and verifies the journal once, with the M just installed. A
        // journal that fails leaves every flow unserved (HTTP 503); the next
        // `refresh_flows` tries again.
        if journal.journal(master).is_err() {
            self.shared.log.record(ServiceEvent::JournalRefused);
            return None;
        }
        let log = Arc::clone(&self.shared.log);
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
            // The same shared journal for every session, checked again for a
            // rollback each time; a session it is refused to changes no card.
            let session_journal = journal.journal(&master).unwrap_or_else(|_| {
                log.record(ServiceEvent::JournalRefused);
                Box::new(RefusedJournal)
            });
            Seal::new(
                master,
                seal_config.clone(),
                Box::new(SystemRandom),
                Box::new(SharedClock(Arc::clone(&clock))),
                session_journal,
                session_chain.status_check(),
                registry.registry(),
            )
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
