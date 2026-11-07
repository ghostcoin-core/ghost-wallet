//! An enclave service for the tests, run as library code over local sockets
//! (the sandbox has no Nitro device): the tests' attestation authority
//! stands in for the NSM and the AWS root, and fakes stand in for the chain
//! status check (the fake chain and its nodes), the card registry
//! (`MemoryRegistry`), the durable journal (a shared journal in memory) and
//! the Phantom Key maker (a stand-in, or the enclave's own
//! `CoreKeyMakerSource` on the tests' chain). Included by path by the tests
//! that need it, next
//! to `authority` (fixtures/nitro_authority.rs), `release`
//! (fixtures/test_release_key.rs) and `support`.
#![allow(dead_code)]

use std::net::{SocketAddr, TcpListener};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ghost_seal::attestation::cbor::Value;
use ghost_seal::attestation::{AttestationError, AttestationSource, AttestationVerifier};
use ghost_seal::chain_check::safe_depth;
use ghost_seal::enclave_serve::{
    ChainStatus, CoreKeyMakerSource, DurableJournal, EnclaveAttestation, EnclaveService, KeyMakerSource,
    MemoryServiceLog, RegistrySource, ServiceConfig, ServiceDeps,
};
use ghost_seal::enclave_tls::EnclaveTls;
use ghost_seal::journal::Journal;
use ghost_seal::measurements::{Pcrs, TrustedList};
use ghost_seal::proxy::{BoundedService, ServiceLimits};
use ghost_seal::{
    CardRegistry, CardUid, ChainCheck, CoinQuery, CoinStatusCheck, LoadedRegistry, MasterKey, MemoryRegistry,
    NodeChainCheck, PhantomKeyMaker, RegistryEntry, RelayLimits, SealError,
};

use crate::authority::{Authority, AuthoritySource, NOW};
use crate::release::TestOnlyReleaseKey;
use crate::support::nodes::{FakeChain, NETWORK, node_check, two_nodes};
use crate::support::{FixedClock, MEASUREMENT, SharedJournal, SyncMaker, UID};

/// The published-list fixture.
pub const FIXTURE: &str = include_str!("../fixtures/measurements.json");
/// The seed of the tests' attestation authority.
pub const AUTHORITY_SEED: u8 = 0x21;

/// The parent-instance PCR (PCR4) the tests' authority writes by default.
pub const DEFAULT_PCR4: [u8; 48] = [0x44; 48];

/// The tests' NSM: documents from the tests' authority with `pcrs`, on the
/// parent instance `pcr4`.
pub struct TestAttestation {
    pub seed: u8,
    pub pcrs: Pcrs,
    pub pcr4: [u8; 48],
}

/// A test enclave's NSM on the instance `pcr4`: the authority's documents,
/// their PCR4 set (test only).
pub struct InstanceSource {
    pub authority: Rc<Authority>,
    pub pcrs: Pcrs,
    pub pcr4: [u8; 48],
}

impl AttestationSource for InstanceSource {
    fn attest(&mut self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, AttestationError> {
        let mut fields = self.authority.fields(&self.pcrs, user_data, nonce, self.authority.now * 1000);
        for (key, value) in fields.iter_mut() {
            if let (Value::Text(name), Value::Map(pcrs)) = (&*key, value)
                && name == "pcrs"
            {
                for (index, pcr) in pcrs.iter_mut() {
                    if *index == Value::Unsigned(4) {
                        *pcr = Value::Bytes(self.pcr4.to_vec());
                    }
                }
            }
        }
        Ok(self.authority.sign_fields(fields))
    }
}

impl EnclaveAttestation for TestAttestation {
    fn source(&self) -> Result<Box<dyn AttestationSource>, String> {
        if self.pcr4 == DEFAULT_PCR4 {
            return Ok(Box::new(AuthoritySource::new(Rc::new(Authority::new(self.seed)), self.pcrs)));
        }
        Ok(Box::new(InstanceSource { authority: Rc::new(Authority::new(self.seed)), pcrs: self.pcrs, pcr4: self.pcr4 }))
    }

    fn verifier(&self) -> Box<dyn AttestationVerifier> {
        Box::new(Authority::new(self.seed).verifier())
    }
}

/// The fixture, signed by the tests' stand-in release key, as an enclave
/// holding it trusts it.
pub fn trusted_fixture() -> TrustedList {
    let release = TestOnlyReleaseKey::new();
    let mut trusted = TrustedList::compiled_in();
    trusted.install_signed(&release.sign(FIXTURE), &release.release_key()).unwrap();
    trusted
}

/// The chain status check over the fake chain: each session's Seal gets two
/// fake nodes over a snapshot of it, which agree.
#[derive(Default)]
pub struct FakeChainStatus {
    pub chain: Mutex<Option<FakeChain>>,
    /// The coins a Fill's confirmation may be asked about, with their commit
    /// data and spend markers.
    pub coins: Mutex<Vec<CoinQuery>>,
}

impl FakeChainStatus {
    pub fn new() -> FakeChainStatus {
        FakeChainStatus { chain: Mutex::new(Some(FakeChain::new())), coins: Mutex::new(Vec::new()) }
    }

    fn check(&self) -> NodeChainCheck {
        let shared = self.chain.lock().unwrap().clone().expect("a chain").shared();
        let (a, b) = two_nodes(&shared);
        let mut check = node_check(&[&a, &b]);
        for coin in self.coins.lock().unwrap().iter() {
            check = check.with_coin(coin.clone());
        }
        check
    }

    /// The exact Vanish of `coin`, settled.
    pub fn pay(&self, coin: CoinQuery) {
        self.chain.lock().unwrap().as_mut().unwrap().pay(&coin, safe_depth(coin.amount_wei));
        self.coins.lock().unwrap().push(coin);
    }
}

impl ChainStatus for FakeChainStatus {
    fn status_check(&self) -> Box<dyn CoinStatusCheck> {
        Box::new(self.check())
    }

    fn payment_check(&self) -> Box<dyn ChainCheck> {
        Box::new(self.check())
    }
}

/// The card registry: a `MemoryRegistry` holding these cards, loaded.
pub struct TestRegistry(pub Vec<CardUid>);

impl RegistrySource for TestRegistry {
    fn registry(&self) -> Box<dyn CardRegistry> {
        let mut registry = MemoryRegistry::new();
        for uid in &self.0 {
            registry.record(&RegistryEntry::new(*uid, "2026-11-01", "test-batch").unwrap()).unwrap();
        }
        Box::new(registry)
    }

    fn loaded(&self) -> bool {
        true
    }
}

/// The text of a registry file holding `uids`, as the host loads it.
pub fn registry_text(uids: &[CardUid]) -> String {
    uids.iter().map(|uid| RegistryEntry::new(*uid, "2026-11-01", "test-batch").unwrap().to_line()).collect()
}

/// Deps with the fake chain check, the journal and the key maker, and
/// `registry` (a `LoadedRegistry` the test loads) as the card registry.
pub fn deps_with_loaded(registry: &LoadedRegistry) -> (ServiceDeps, Fakes) {
    let (mut deps, fakes) = deps(true, false, true);
    deps.registry = Some(Arc::new(registry.clone()) as Arc<dyn RegistrySource>);
    (deps, fakes)
}

/// The durable journal: here a journal in memory shared by every session
/// (test only).
pub struct TestJournal(pub SharedJournal);

impl DurableJournal for TestJournal {
    fn journal(&self, _master: &MasterKey) -> Result<Box<dyn Journal>, SealError> {
        Ok(Box::new(self.0.clone()))
    }
}

/// Deps with the fake chain check, the registry (holding [`UID`]), the key
/// maker and `journal` as the durable journal.
pub fn deps_with_journal(journal: Arc<dyn DurableJournal>) -> (ServiceDeps, Fakes) {
    let (mut deps, fakes) = deps(true, true, true);
    deps.journal = Some(journal);
    (deps, fakes)
}

/// The Phantom Key maker.
pub struct TestKeyMaker(pub SyncMaker);

impl KeyMakerSource for TestKeyMaker {
    fn key_maker(&self) -> Box<dyn PhantomKeyMaker> {
        Box::new(self.0.clone())
    }
}

/// The enclave's own Phantom Key maker, as the enclave program installs it,
/// for coins on the tests' chain.
pub fn core_key_maker() -> Arc<dyn KeyMakerSource> {
    Arc::new(CoreKeyMakerSource { chain_id: NETWORK.chain_id })
}

/// Deps with the fake chain check, the registry (holding [`UID`]) and the
/// journal, and `key_maker` as the Phantom Key maker (none: a Fill is
/// answered `unavailable`).
pub fn deps_with_maker(key_maker: Option<Arc<dyn KeyMakerSource>>) -> (ServiceDeps, Fakes) {
    let (mut deps, fakes) = deps(true, true, true);
    deps.key_maker = key_maker;
    (deps, fakes)
}

/// The fakes behind a [`ServiceDeps`], for the test to drive and read.
pub struct Fakes {
    pub chain: Arc<FakeChainStatus>,
    pub journal: SharedJournal,
    pub maker: SyncMaker,
}

/// Deps with the chain check, the registry (holding [`UID`]) and the journal
/// each installed or not; the key maker always.
pub fn deps(chain: bool, registry: bool, journal: bool) -> (ServiceDeps, Fakes) {
    let fakes =
        Fakes { chain: Arc::new(FakeChainStatus::new()), journal: SharedJournal::default(), maker: SyncMaker::default() };
    let deps = ServiceDeps {
        chain: chain.then(|| Arc::clone(&fakes.chain) as Arc<dyn ChainStatus>),
        registry: registry.then(|| Arc::new(TestRegistry(vec![UID])) as Arc<dyn RegistrySource>),
        journal: journal.then(|| Arc::new(TestJournal(fakes.journal.clone())) as Arc<dyn DurableJournal>),
        key_maker: Some(Arc::new(TestKeyMaker(fakes.maker.clone()))),
        regions: None,
        peer_logs: None,
    };
    (deps, fakes)
}

/// How the tests' service is configured: the tests' measurement and clock.
pub fn config() -> ServiceConfig {
    ServiceConfig {
        measurement: MEASUREMENT,
        answer_lifetime_secs: 120,
        relay_limits: RelayLimits::default(),
        clock: Arc::new(FixedClock(NOW)),
    }
}

/// The enclave's ML-KEM-768 key, for phones (a test key).
pub fn kem_key() -> Vec<u8> {
    crate::support::phone(0x24).public_key()
}

/// A service measuring as `pcrs` with `deps`, holding no M yet.
pub fn service(deps: ServiceDeps, pcrs: Pcrs, log: Arc<MemoryServiceLog>) -> EnclaveService {
    service_on_instance(deps, pcrs, DEFAULT_PCR4, log)
}

/// [`service`] on the parent instance `pcr4` (its documents' PCR4).
pub fn service_on_instance(deps: ServiceDeps, pcrs: Pcrs, pcr4: [u8; 48], log: Arc<MemoryServiceLog>) -> EnclaveService {
    EnclaveService::new(
        EnclaveTls::generate().expect("a fresh certificate"),
        kem_key(),
        trusted_fixture(),
        Arc::new(TestAttestation { seed: AUTHORITY_SEED, pcrs, pcr4 }),
        deps,
        config(),
        log,
    )
}

/// Serves `service` on a local TCP port as the enclave serves its service
/// port: 4 workers, a queue of 8 and `connection_time` per connection.
pub fn serve(service: Arc<EnclaveService>, connection_time: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let limits = ServiceLimits { workers: 4, queue: 8, connection_time };
    thread::spawn(move || {
        let _ = BoundedService::new(listener, limits)
            .serve(move |stream: &mut ghost_seal::proxy::DeadlineStream<std::net::TcpStream>| service.serve_connection(stream), None);
    });
    addr
}
