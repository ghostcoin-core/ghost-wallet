//! An enclave service for the tests, run as library code over local sockets
//! (the sandbox has no Nitro device): the tests' attestation authority
//! stands in for the NSM and the AWS root, and fakes stand in for the chain
//! status check (the fake chain and its nodes), the card registry
//! (`MemoryRegistry`), the durable journal (a shared journal in memory) and
//! the Phantom Key maker. Included by path by the tests that need it, next
//! to `authority` (fixtures/nitro_authority.rs), `release`
//! (fixtures/test_release_key.rs) and `support`.
#![allow(dead_code)]

use std::net::{SocketAddr, TcpListener};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ghost_seal::attestation::{AttestationSource, AttestationVerifier};
use ghost_seal::chain_check::safe_depth;
use ghost_seal::enclave_serve::{
    ChainStatus, DurableJournal, EnclaveAttestation, EnclaveService, KeyMakerSource, MemoryServiceLog, RegistrySource,
    ServiceConfig, ServiceDeps,
};
use ghost_seal::enclave_tls::EnclaveTls;
use ghost_seal::journal::Journal;
use ghost_seal::measurements::{Pcrs, TrustedList};
use ghost_seal::proxy::{BoundedService, ServiceLimits};
use ghost_seal::{
    CardRegistry, CardUid, ChainCheck, CoinQuery, CoinStatusCheck, LoadedRegistry, MemoryRegistry, NodeChainCheck,
    PhantomKeyMaker, RegistryEntry, RelayLimits,
};

use crate::authority::{Authority, AuthoritySource, NOW};
use crate::release::TestOnlyReleaseKey;
use crate::support::nodes::{FakeChain, node_check, two_nodes};
use crate::support::{FixedClock, MEASUREMENT, SharedJournal, SyncMaker, UID};

/// The published-list fixture.
pub const FIXTURE: &str = include_str!("../fixtures/measurements.json");
/// The seed of the tests' attestation authority.
pub const AUTHORITY_SEED: u8 = 0x21;

/// The tests' NSM: documents from the tests' authority with `pcrs`.
pub struct TestAttestation {
    pub seed: u8,
    pub pcrs: Pcrs,
}

impl EnclaveAttestation for TestAttestation {
    fn source(&self) -> Result<Box<dyn AttestationSource>, String> {
        Ok(Box::new(AuthoritySource::new(Rc::new(Authority::new(self.seed)), self.pcrs)))
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
    fn journal(&self) -> Box<dyn Journal> {
        Box::new(self.0.clone())
    }
}

/// The Phantom Key maker.
pub struct TestKeyMaker(pub SyncMaker);

impl KeyMakerSource for TestKeyMaker {
    fn key_maker(&self) -> Box<dyn PhantomKeyMaker> {
        Box::new(self.0.clone())
    }
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
    EnclaveService::new(
        EnclaveTls::generate().expect("a fresh certificate"),
        kem_key(),
        trusted_fixture(),
        Arc::new(TestAttestation { seed: AUTHORITY_SEED, pcrs }),
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
