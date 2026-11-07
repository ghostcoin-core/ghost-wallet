//! The Seal's enclave program, as it runs inside an AWS Nitro Enclave.
//!
//! It does exactly this:
//!
//! - On start it builds the only list it will ever check another enclave
//!   against (a [`TrustedList`]): the builds compiled into its own image and
//!   its own build, read from its own attestation document. Later, only a
//!   list signed by the release key compiled into its image is added. A list
//!   the host writes is never trusted.
//! - Waits on its control port (vsock [`CONTROL_PORT`], reached only from the
//!   parent instance; the parent proxy never forwards to it) for one start
//!   frame. A second start is refused for the life of the enclave.
//! - In genesis mode it makes M inside itself from the enclave's random
//!   source. That is the first enclave only; a copy is always started in
//!   join mode, and join mode never makes M, not even when the handover
//!   fails. A list sent with a genesis start must be signed.
//! - In join mode it gets M from a running enclave through the key-share
//!   protocol: it sends its request through the parent's outbound proxy
//!   (vsock [`PEER_PORT`] on the parent) to the giving region and opens the
//!   package it gets back, checking the giver against its compiled-in builds,
//!   a list signed by the compiled-in release key that it took before the
//!   start, and its own build. Any list the host sends with a join start is
//!   ignored. Each region runs its own image (its region is compiled in), so
//!   a giver in another region is never its own build: the release's signed
//!   list, which `seal_proxy start` offers before the start frame, names it.
//! - Before and after it has started, takes a list on the control port only
//!   if it is signed by the compiled-in release key and extends the one held.
//! - On its service port (vsock [`SERVICE_PORT`], which the parent proxy
//!   forwards to from the internet, still encrypted) it serves, by each
//!   connection's first byte, TLS ended inside the enclave and the relay's
//!   HTTP routes for phones (Check, Fill, Fill confirmation, Open and the
//!   phone attestation), or the framed protocol (key-share requests, handing
//!   M only to an attested build on its trusted list, and framed phone
//!   attestation requests): see `ghost_seal::enclave_serve`. All on a fixed
//!   pool of [`SERVICE_WORKERS`] threads with a queue of [`SERVICE_QUEUE`]
//!   and [`SERVICE_TIMEOUT`] for a whole connection, a TLS handshake
//!   included; a connection that finds the queue full is closed.
//! - It makes its TLS key pair and self-signed certificate fresh at each
//!   start, inside itself, and keeps them in memory only.
//! - It installs the chain status check: the compiled-in release node list
//!   (`ghost_seal::node_list`), each node an `RpcNode` (JSON-RPC over TLS
//!   1.3 ended inside the enclave, trusting only the compiled-in ISRG Root
//!   X1) reached through a vsock stream to the parent on the node's own port
//!   (5003, 5004), which the host's outbound proxy carries to the node.
//! - It installs the card registry the host loads (a `LoadedRegistry`):
//!   empty until the first control frame 4, after the start; later frames
//!   add cards and may never drop or change one. No flow is served until
//!   the first load.
//! - It installs the durable journal: the append-only log of records it
//!   seals and MACs under keys derived from M (`ghost_seal::journal_log`),
//!   kept by the parent's store (`seal_proxy journal 5005
//!   /var/lib/seal/journal.log`), reached over a vsock stream to the parent
//!   (CID 3) port 5005, one connection and 10 seconds per
//!   request (`ghost_seal::host_journal::HostJournal`). The parent sees
//!   counters and ciphertext only. Once M is installed it reads the whole
//!   log and checks every counter and tag; a log that cannot be read or
//!   fails a check leaves every flow `unavailable` and logs a fixed event,
//!   and it is tried again every [`JOURNAL_RETRY`] and at each registry
//!   load.
//! - It installs the Phantom Key maker a Fill needs: the wallet core's
//!   derivation (`ghost_seal::enclave_serve::CoreKeyMakerSource`, a fresh
//!   `CoreKeyMaker` per Fill) on the chain of the release network, the one
//!   the chain check follows. Each key is made inside the enclave from its
//!   `getrandom`, held only until it is written to the card, and is never
//!   logged. With the chain check, the loaded registry, the journal and the
//!   key maker, Check, Fill, Fill confirmation and Open are served.
//! - Its region: the release's ordered region list is compiled in
//!   (`ghost_seal::journal_anchor::RELEASE_REGIONS`), and so is its own
//!   region id, `SEAL_REGION` at build time ([`OWN_REGION`]): the build
//!   argument of `enclave/Dockerfile`, which refuses to build without one on
//!   the list. One image per region, each with its own PCRs and its own
//!   entry on the signed list (`enclave/scripts/compute-pcrs.sh`), and each
//!   region deployed with its own image (`enclave/scripts/deploy.sh`);
//!   nothing the host sends names a region. Each card is served by
//!   its home region only; every other region refuses it `wrong-region`
//!   before any card traffic. An image built without a region on the list
//!   installs no journal and serves no card.
//! - The journal's head is anchored in the other regions
//!   (`ghost_seal::journal_anchor`): after each append the record
//!   (ciphertext only) goes to both peer enclaves, through the parent's
//!   vsock ports 5006 and 5007 (one per peer, in the order of the region
//!   list, this region left out), which the host's outbound proxy carries to
//!   their inbound proxies, 10 seconds each; a save is `Ok` only once both
//!   acknowledged it. Once M is installed, before any flow, it restores
//!   every log it keeps: its copies of the other regions' logs (each from
//!   that region or the other peer) and its own (from both peers), asking
//!   every peer with a fresh nonce and taking what the host's store lacks (a
//!   cut tail, or an empty store on a replaced host). Each answer must carry
//!   a fresh attestation document from the answering enclave with that
//!   nonce, verified with the AWS root, of a build on the trusted list, of
//!   the region of the port it came on, and on a parent instance (PCR4)
//!   other than this enclave's own and other than the other peer's. With a
//!   peer silent, an answer not taken, a fork or a bad restore, every flow
//!   stays `unavailable`, a fixed event is logged, and it is tried again
//!   every [`JOURNAL_RETRY`]. As a peer it keeps the other regions' logs on
//!   its parent's store (`/var/lib/seal/peer-<region>.log`, the same port
//!   5005) and answers their service requests kind 3 with M, attested, and
//!   answers about its own log from the same store once that log is open.
//!
//! It never writes M anywhere, and no frame it sends carries M except a
//! key-share package, encrypted to the receiving enclave.
//!
//! Frames are a 4-byte big-endian length and the bytes. Control frames (at
//! most 8 MiB): 1 (genesis) [|| signed list JSON], 2 (join; anything after
//! is ignored), 3 (a signed list JSON, before or after the start), 4 (the
//! card registry's text, after the start);
//! answer: a status text. Service request: kind (1 key share, 2 phone
//! attestation, 3 a peer region's journal head request) || body; service
//! answer: 0 || body, or 1 || why it was refused.

#![deny(unsafe_op_in_unsafe_fn)]

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ghost_seal::attestation::{
    AttestationError, AttestationSource, AttestationVerifier, NitroVerifier, NsmDevice, NsmSource,
};
use ghost_seal::enclave_serve::{
    ANSWER_OK, ANSWER_REFUSED, ChainStatus, CoreKeyMakerSource, DurableJournal, EnclaveAttestation, EnclaveService,
    KIND_KEY_SHARE, KeyMakerSource, NodeChainStatus, RegistrySource, ServiceConfig, ServiceDeps, ServiceEvent,
    ServiceLog, ServicePeer,
};
use ghost_seal::enclave_tls::EnclaveTls;
use ghost_seal::flows::ANSWER_LIFETIME_SECS;
use ghost_seal::host_journal::HostJournal;
use ghost_seal::journal_anchor::{Anchor, PEER_PORTS, Peer, PeerLink, PeerLogs, Peers, Regions};
use ghost_seal::journal_log::{LogStore, SharedLog};
use ghost_seal::key_share::{ControlFrame, Receiver, read_control_frame, read_frame, write_frame};
use ghost_seal::measurements::{ReleaseKey, TrustedList};
use ghost_seal::node_list::NodeList;
use ghost_seal::node_rpc::{NodeAddress, RpcNode, VsockTransport};
use ghost_seal::proxy::{BoundedService, DeadlineStream, ServiceLimits};
use ghost_seal::{Clock, LoadedRegistry, MasterKey, RelayLimits, SealRandom, SystemClock, SystemRandom};
use ml_kem::{DecapsulationKey, KeyExport, MlKem768};
use vsock::{VMADDR_CID_ANY, VsockListener, VsockStream};

/// The control port: frames from the parent.
const CONTROL_PORT: u32 = 5000;
/// The service port the parent proxy forwards to.
const SERVICE_PORT: u32 = 5001;
/// The parent's port that relays to the giving region's service.
const PEER_PORT: u32 = 5002;
/// The parent instance's context ID, as seen from an enclave.
const PARENT_CID: u32 = 3;
/// Service worker threads, all started up front.
const SERVICE_WORKERS: usize = 4;
/// Service connections that may wait for a worker; more are closed at once.
const SERVICE_QUEUE: usize = 8;
/// The longest one service connection may last, from accept to close.
const SERVICE_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest the whole handover may take when joining.
const JOIN_TIMEOUT: Duration = Duration::from_secs(60);
/// How long the control port waits for a frame.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
/// How often a journal that could not be opened (or anchored) is tried
/// again.
const JOURNAL_RETRY: Duration = Duration::from_secs(60);
/// This image's region id, compiled in (`SEAL_REGION` when it was built):
/// one of the release's region list. The host cannot change it.
const OWN_REGION: Option<&str> = option_env!("SEAL_REGION");

/// `/dev/nsm`'s one ioctl: `_IOWR(0x0A, 0, struct nsm_message)`, the message
/// being two `struct iovec` (32 bytes).
const NSM_IOCTL: u64 = 0xc020_0a00;
const NSM_RESPONSE_MAX_BYTES: usize = 0x3000;

#[repr(C)]
struct NsmMessage {
    request: libc::iovec,
    response: libc::iovec,
}

/// The Nitro Secure Module device.
struct DevNsm {
    file: File,
}

impl DevNsm {
    fn open() -> Result<DevNsm, AttestationError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/nsm")
            .map_err(|e| AttestationError::Device(e.to_string()))?;
        Ok(DevNsm { file })
    }
}

impl NsmDevice for DevNsm {
    fn call(&mut self, request: &[u8]) -> Result<Vec<u8>, AttestationError> {
        let mut response = vec![0u8; NSM_RESPONSE_MAX_BYTES];
        let mut message = NsmMessage {
            request: libc::iovec { iov_base: request.as_ptr() as *mut libc::c_void, iov_len: request.len() },
            response: libc::iovec { iov_base: response.as_mut_ptr() as *mut libc::c_void, iov_len: response.len() },
        };
        // SAFETY: both iovecs point at live buffers of the stated lengths for
        // the whole call; the driver reads the request, writes at most the
        // response length into the response buffer and sets its length.
        let rc = unsafe { libc::ioctl(self.file.as_raw_fd(), NSM_IOCTL as _, &mut message as *mut NsmMessage) };
        if rc < 0 {
            return Err(AttestationError::Device(io::Error::last_os_error().to_string()));
        }
        let length = message.response.iov_len.min(NSM_RESPONSE_MAX_BYTES);
        response.truncate(length);
        Ok(response)
    }
}

fn nsm() -> Result<NsmSource<DevNsm>, String> {
    DevNsm::open().map(NsmSource::new).map_err(|e| e.to_string())
}

/// The enclave's own attestation: its NSM, and the pinned AWS root for other
/// enclaves' documents.
struct Nitro;

impl EnclaveAttestation for Nitro {
    fn source(&self) -> Result<Box<dyn AttestationSource>, String> {
        Ok(Box::new(nsm()?))
    }

    fn verifier(&self) -> Box<dyn AttestationVerifier> {
        Box::new(NitroVerifier::aws())
    }
}

/// The service's fixed events, on standard error. No event carries bytes a
/// connection carried.
struct StatusLog;

impl ServiceLog for StatusLog {
    fn record(&self, event: ServiceEvent) {
        status(&event.to_string());
    }
}

fn status(text: &str) {
    eprintln!("seal_enclave: {text}");
}

fn main() {
    // The enclave's own ML-KEM-768 key, for phones, fresh on every start.
    let mut seed = [0u8; 64];
    if SystemRandom.fill(&mut seed).is_err() {
        status("no random source");
        std::process::exit(1);
    }
    let kem = DecapsulationKey::<MlKem768>::from_seed(ml_kem::Seed::from(seed));
    seed.fill(0);

    // What this image trusts by itself: its compiled-in builds and its own
    // attested build. Nothing from the host.
    let mut trusted = TrustedList::compiled_in();
    let own = nsm().and_then(|mut source| {
        trusted.trust_own_build(&mut source, &NitroVerifier::aws(), SystemClock.now_unix()).map_err(|e| e.to_string())
    });
    // The answers carry the enclave's own PCR0. Without its own document the
    // enclave cannot attest anything, and serves no flow anyway.
    let measurement = match own {
        Ok(pcrs) => {
            status("trusts the compiled-in builds and its own build");
            pcrs.pcr0
        }
        Err(why) => {
            status(&format!("trusts only the compiled-in builds: {why}"));
            [0u8; 48]
        }
    };

    // TLS ends here: a fresh key pair and certificate, in memory only.
    let tls = match EnclaveTls::generate() {
        Ok(tls) => tls,
        Err(error) => {
            status(&format!("no TLS: {error}"));
            std::process::exit(1);
        }
    };

    // The chain status check over the compiled-in release nodes, each
    // through its own vsock port on the parent.
    let chain = match chain_status() {
        Ok(chain) => chain,
        Err(why) => {
            status(&format!("no chain check: {why}"));
            std::process::exit(1);
        }
    };
    // The card registry, empty until the host loads it.
    let registry = LoadedRegistry::new();
    // The region list and this region, both compiled in. Without a region
    // on the list no journal is installed and no card is served.
    let regions = match OWN_REGION.map(Regions::release) {
        Some(Ok(regions)) => {
            status(&format!("serves the cards whose home region is {}", regions.own()));
            Some(regions)
        }
        Some(Err(why)) => {
            status(&format!("no region: {why}; not answering cards"));
            None
        }
        None => {
            status("no region was compiled into this image; not answering cards");
            None
        }
    };
    // The durable journal: the sealed, chained log kept by the parent's
    // store (vsock port 5005), its head anchored in the peer regions
    // (vsock ports 5006 and 5007), opened, restored and verified once M is
    // installed. And the logs this enclave keeps for its peers, on the same
    // store.
    let (journal, peer_logs) = match &regions {
        Some(regions) => {
            let links: Vec<Peer> = regions
                .peers()
                .into_iter()
                .zip(PEER_PORTS)
                .map(|(region, port)| Peer {
                    region: region.to_owned(),
                    link: Arc::new(ServicePeer::parent(port)) as Arc<dyn PeerLink>,
                })
                .collect();
            // One set of peers for the anchor and the peer logs; the service
            // installs its attester (this enclave's NSM, the AWS root and
            // the trusted list) when it is made.
            let peers = Arc::new(Peers::new(regions.own(), links));
            let anchor = Anchor::new(Arc::clone(&peers));
            let journal = Arc::new(SharedLog::anchored(Box::new(HostJournal::parent()), Box::new(anchor)));
            let stores = regions
                .peers()
                .into_iter()
                .map(|region| (region.to_owned(), Box::new(HostJournal::parent_peer(region)) as Box<dyn LogStore>))
                .collect();
            let logs = PeerLogs::new(peers, stores).with_own_log(Arc::clone(&journal), Box::new(HostJournal::parent()));
            (Some(journal as Arc<dyn DurableJournal>), Some(Arc::new(logs)))
        }
        None => (None, None),
    };
    // The Phantom Key maker: coins on the network the chain check follows.
    let key_maker = CoreKeyMakerSource { chain_id: NodeList::release().network.chain_id };
    let deps = ServiceDeps {
        chain: Some(Arc::new(chain) as Arc<dyn ChainStatus>),
        registry: Some(Arc::new(registry.clone()) as Arc<dyn RegistrySource>),
        journal,
        key_maker: Some(Arc::new(key_maker) as Arc<dyn KeyMakerSource>),
        regions,
        peer_logs,
    };
    let config = ServiceConfig {
        measurement,
        answer_lifetime_secs: ANSWER_LIFETIME_SECS,
        relay_limits: RelayLimits::default(),
        clock: Arc::new(SystemClock),
    };
    let service = Arc::new(EnclaveService::new(
        tls,
        kem.encapsulation_key().to_bytes().to_vec(),
        trusted,
        Arc::new(Nitro),
        deps,
        config,
        Arc::new(StatusLog),
    ));

    let served = service.clone();
    if let Err(error) = thread::Builder::new().name("service".into()).spawn(move || serve_port(served)) {
        status(&format!("no thread for the service port: {error}"));
        std::process::exit(1);
    }
    // A journal the host could not serve when M arrived is tried again.
    let retried = service.clone();
    if let Err(error) = thread::Builder::new().name("journal-retry".into()).spawn(move || retry_flows(&retried)) {
        status(&format!("no thread for the journal retry: {error}"));
        std::process::exit(1);
    }

    let control = match VsockListener::bind_with_cid_port(VMADDR_CID_ANY, CONTROL_PORT) {
        Ok(listener) => listener,
        Err(error) => {
            status(&format!("control port: {error}"));
            std::process::exit(1);
        }
    };
    loop {
        let mut stream = match control.accept() {
            Ok((stream, _)) => stream,
            Err(_) => {
                thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let _ = stream.set_read_timeout(Some(CONTROL_TIMEOUT));
        let _ = stream.set_write_timeout(Some(CONTROL_TIMEOUT));
        let answer = match read_control_frame(&mut stream) {
            Ok(frame) => control_frame(&frame, &service, &registry),
            Err(error) => format!("refused: {error}"),
        };
        status(&answer);
        let _ = write_frame(&mut stream, answer.as_bytes());
    }
}

/// The service port, on a fixed pool of workers: TLS and the HTTP routes,
/// or the framed protocol, by each connection's first byte.
fn serve_port(service: Arc<EnclaveService>) {
    let listener = match VsockListener::bind_with_cid_port(VMADDR_CID_ANY, SERVICE_PORT) {
        Ok(listener) => listener,
        Err(error) => {
            status(&format!("service port: {error}"));
            return;
        }
    };
    let limits = ServiceLimits { workers: SERVICE_WORKERS, queue: SERVICE_QUEUE, connection_time: SERVICE_TIMEOUT };
    let handler = move |stream: &mut DeadlineStream<VsockStream>| service.serve_connection(stream);
    if let Err(error) = BoundedService::new(listener, limits).serve(handler, None) {
        status(&format!("service port stopped: {error}"));
    }
}

/// Every [`JOURNAL_RETRY`], while M is held, the registry loaded and the
/// flows still not served (the journal could not be read or verified),
/// tries to start them again.
fn retry_flows(service: &EnclaveService) {
    loop {
        thread::sleep(JOURNAL_RETRY);
        // One lock at a time: the state's guard ends with this statement.
        let holds_master = service.state().master.is_some();
        if holds_master && !service.serves_flows() && service.refresh_flows() {
            status("the durable journal is open and anchored; serves the flows");
        }
    }
}

/// The chain status check over the release node list: an `RpcNode` per
/// entry, over a vsock stream to the parent on the entry's port.
fn chain_status() -> Result<NodeChainStatus, String> {
    let list = NodeList::release();
    let nodes = list
        .nodes
        .iter()
        .map(|entry| {
            let transport = Arc::new(VsockTransport { cid: PARENT_CID, port: entry.vsock_port });
            RpcNode::new(NodeAddress::from_entry(entry), transport)
        })
        .collect::<Result<Vec<_>, _>>()?;
    NodeChainStatus::new(list.network, nodes).map_err(|e| e.to_string())
}

/// Handles one control frame.
fn control_frame(frame: &[u8], service: &EnclaveService, registry: &LoadedRegistry) -> String {
    match ControlFrame::parse(frame) {
        Err(why) => format!("refused: {why}"),
        Ok(ControlFrame::Registry(text)) => {
            if !service.state().started {
                return "refused: the registry comes after the start".into();
            }
            match registry.load(text) {
                Ok(report) => {
                    let serves = service.refresh_flows();
                    format!(
                        "ok: took the card registry ({} cards, {} new, {} lines left out){}",
                        report.cards,
                        report.added,
                        report.ignored_lines,
                        if serves { "" } else { "; not answering cards yet" }
                    )
                }
                Err(why) => format!("refused: {why}"),
            }
        }
        Ok(ControlFrame::SignedList(text)) => {
            // Before the start too: each region runs its own image, so a
            // joining enclave's own build is never its giver's. The release
            // key's signature lets it trust the other regions' builds of
            // its release (and only what that key signed) before it joins.
            let mut held = service.state();
            let when = if held.started { "" } else { " before the start" };
            match install_signed(&mut held.trusted, text) {
                Ok(()) => format!("ok: took a signed list{when}"),
                Err(why) => format!("refused: {why}"),
            }
        }
        Ok(ControlFrame::Genesis { signed_list }) => start(true, signed_list, service),
        Ok(ControlFrame::Join) => start(false, None, service),
    }
}

/// Takes a list only if the release key compiled into this image signed it.
fn install_signed(trusted: &mut TrustedList, text: &str) -> Result<(), String> {
    let key = ReleaseKey::compiled_in().map_err(|e| e.to_string())?;
    trusted.install_signed(text, &key).map_err(|e| e.to_string())
}

/// Handles the one start. A join takes no list from the host: it checks its
/// giver against what this image trusts by itself.
fn start(genesis: bool, signed_list: Option<&str>, service: &EnclaveService) -> String {
    let trusted = {
        let mut held = service.state();
        if held.started {
            return "refused: already started".into();
        }
        if let Some(text) = signed_list
            && let Err(why) = install_signed(&mut held.trusted, text)
        {
            return format!("refused: {why}");
        }
        held.started = true;
        held.trusted.clone()
    };
    let master = if genesis {
        let mut bytes = [0u8; 32];
        if SystemRandom.fill(&mut bytes).is_err() {
            return "refused: no random source".into();
        }
        MasterKey::take(&mut bytes)
    } else {
        match join(&trusted) {
            Ok(received) => received,
            Err(why) => return format!("refused: join failed: {why}"),
        }
    };
    service.install_master(master);
    if genesis { "ok: made M (genesis)".into() } else { "ok: received M from a running enclave".into() }
}

/// Gets M from a running enclave through the parent's outbound proxy, the
/// whole exchange limited to [`JOIN_TIMEOUT`].
fn join(trusted: &TrustedList) -> Result<MasterKey, String> {
    let mut source = nsm()?;
    let receiver = Receiver::start(&mut source, &mut SystemRandom).map_err(|e| e.to_string())?;
    let peer = VsockStream::connect_with_cid_port(PARENT_CID, PEER_PORT).map_err(|e| e.to_string())?;
    let mut peer = DeadlineStream::new(peer, Instant::now() + JOIN_TIMEOUT);
    let mut request = vec![KIND_KEY_SHARE];
    request.extend_from_slice(&receiver.request());
    write_frame(&mut peer, &request).map_err(|e| e.to_string())?;
    let answer = read_frame(&mut peer).map_err(|e| e.to_string())?;
    peer.close();
    match answer.split_first() {
        Some((&ANSWER_OK, package)) => {
            let (received, giver) = receiver
                .accept(package, &NitroVerifier::aws(), trusted, SystemClock.now_unix())
                .map_err(|e| e.to_string())?;
            status(&format!("joined from build {}", giver.name));
            Ok(received)
        }
        Some((&ANSWER_REFUSED, why)) => Err(format!("the giver refused: {}", String::from_utf8_lossy(why))),
        _ => Err("the giver's answer is not a frame".into()),
    }
}
