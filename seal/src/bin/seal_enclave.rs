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
//!   package it gets back, checking the giver against its compiled-in builds
//!   and its own build only. Any list the host sends with a join start is
//!   ignored.
//! - After it has started, takes a later list on the control port only if
//!   it is signed by the compiled-in release key and extends the one held.
//! - On its service port (vsock [`SERVICE_PORT`], which the parent proxy
//!   forwards to from the internet) it answers key-share requests (handing
//!   M only to an attested build on its trusted list, through the protocol)
//!   and phone attestation requests, on a fixed pool of [`SERVICE_WORKERS`]
//!   threads with a queue of [`SERVICE_QUEUE`] and [`SERVICE_TIMEOUT`] for a
//!   whole connection; a connection that finds the queue full is closed.
//!
//! It never writes M anywhere, and no frame it sends carries M except a
//! key-share package, encrypted to the receiving enclave.
//!
//! Frames are a 4-byte big-endian length and the bytes. Control frames: 1
//! (genesis) [|| signed list JSON], 2 (join; anything after is ignored), 3
//! (a signed list JSON); answer: a status text. Service request: kind (1 key
//! share, 2 phone attestation) || body; service answer: 0 || body, or 1 ||
//! why it was refused.

#![deny(unsafe_op_in_unsafe_fn)]

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ghost_seal::attestation::{AttestationError, NitroVerifier, NsmDevice, NsmSource};
use ghost_seal::key_share::{self, ControlFrame, GiverContext, Receiver, read_frame, write_frame};
use ghost_seal::measurements::{ReleaseKey, TrustedList};
use ghost_seal::phone_attestation::{self, CHALLENGE_BYTES};
use ghost_seal::proxy::{BoundedService, DeadlineStream, ProxyStream, ServiceLimits};
use ghost_seal::{Clock, MasterKey, SealRandom, SystemClock, SystemRandom};
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

const KIND_KEY_SHARE: u8 = 1;
const KIND_PHONE_ATTESTATION: u8 = 2;
const ANSWER_OK: u8 = 0;
const ANSWER_REFUSED: u8 = 1;

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

/// What the enclave holds.
struct State {
    started: bool,
    master: Option<MasterKey>,
    /// The only list another enclave is checked against.
    trusted: TrustedList,
    answer_key: Vec<u8>,
    kem_key: Vec<u8>,
}

fn status(text: &str) {
    eprintln!("seal_enclave: {text}");
}

fn lock(state: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    state.lock().unwrap_or_else(|e| e.into_inner())
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
    match own {
        Ok(_) => status("trusts the compiled-in builds and its own build"),
        Err(why) => status(&format!("trusts only the compiled-in builds: {why}")),
    }

    let state = Arc::new(Mutex::new(State {
        started: false,
        master: None,
        trusted,
        answer_key: Vec::new(),
        kem_key: kem.encapsulation_key().to_bytes().to_vec(),
    }));

    let service_state = state.clone();
    if let Err(error) = thread::Builder::new().name("service".into()).spawn(move || service(service_state)) {
        status(&format!("no thread for the service port: {error}"));
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
        let answer = match read_frame(&mut stream) {
            Ok(frame) => control_frame(&frame, &state),
            Err(error) => format!("refused: {error}"),
        };
        status(&answer);
        let _ = write_frame(&mut stream, answer.as_bytes());
    }
}

/// The service port, on a fixed pool of workers.
fn service(state: Arc<Mutex<State>>) {
    let listener = match VsockListener::bind_with_cid_port(VMADDR_CID_ANY, SERVICE_PORT) {
        Ok(listener) => listener,
        Err(error) => {
            status(&format!("service port: {error}"));
            return;
        }
    };
    let limits = ServiceLimits { workers: SERVICE_WORKERS, queue: SERVICE_QUEUE, connection_time: SERVICE_TIMEOUT };
    if let Err(error) = BoundedService::new(listener, limits).serve(move |stream| serve(stream, &state), None) {
        status(&format!("service port stopped: {error}"));
    }
}

/// Handles one control frame.
fn control_frame(frame: &[u8], state: &Mutex<State>) -> String {
    match ControlFrame::parse(frame) {
        Err(why) => format!("refused: {why}"),
        Ok(ControlFrame::SignedList(text)) => {
            let mut held = lock(state);
            if !held.started {
                return "refused: a list comes after the start".into();
            }
            match install_signed(&mut held.trusted, text) {
                Ok(()) => "ok: took a signed list".into(),
                Err(why) => format!("refused: {why}"),
            }
        }
        Ok(ControlFrame::Genesis { signed_list }) => start(true, signed_list, state),
        Ok(ControlFrame::Join) => start(false, None, state),
    }
}

/// Takes a list only if the release key compiled into this image signed it.
fn install_signed(trusted: &mut TrustedList, text: &str) -> Result<(), String> {
    let key = ReleaseKey::compiled_in().map_err(|e| e.to_string())?;
    trusted.install_signed(text, &key).map_err(|e| e.to_string())
}

/// Handles the one start. A join takes no list from the host: it checks its
/// giver against what this image trusts by itself.
fn start(genesis: bool, signed_list: Option<&str>, state: &Mutex<State>) -> String {
    let trusted = {
        let mut held = lock(state);
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
    let mut held = lock(state);
    held.answer_key = phone_attestation::answer_key(&master);
    held.master = Some(master);
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

/// Answers service frames on one connection until it closes or its time is
/// up.
fn serve<S: ProxyStream>(stream: &mut DeadlineStream<S>, state: &Mutex<State>) {
    while let Ok(frame) = read_frame(stream) {
        if stream.expired() {
            break;
        }
        let answer = match answer(&frame, state) {
            Ok(body) => [&[ANSWER_OK][..], &body].concat(),
            Err(why) => [&[ANSWER_REFUSED][..], why.as_bytes()].concat(),
        };
        if write_frame(stream, &answer).is_err() {
            break;
        }
    }
}

fn answer(frame: &[u8], state: &Mutex<State>) -> Result<Vec<u8>, String> {
    let (&kind, body) = frame.split_first().ok_or("an empty frame")?;
    match kind {
        KIND_KEY_SHARE => {
            let held = lock(state);
            let master = held.master.as_ref().ok_or("this enclave holds no M yet")?;
            let mut source = nsm()?;
            let given = key_share::package_for(
                master,
                body,
                GiverContext {
                    verifier: &NitroVerifier::aws(),
                    list: &held.trusted,
                    source: &mut source,
                    random: &mut SystemRandom,
                    now_unix: SystemClock.now_unix(),
                },
            )
            .map_err(|e| e.to_string())?;
            status(&format!("handed M to build {}", given.receiver.name));
            Ok(given.package)
        }
        KIND_PHONE_ATTESTATION => {
            let challenge: [u8; CHALLENGE_BYTES] = body.try_into().map_err(|_| "a challenge is 32 bytes")?;
            // The keys are public; the state is not held while the NSM works.
            let (answer_key, kem_key) = {
                let held = lock(state);
                if held.master.is_none() {
                    return Err("this enclave holds no M yet".into());
                }
                (held.answer_key.clone(), held.kem_key.clone())
            };
            let mut source = nsm()?;
            phone_attestation::make(&mut source, &answer_key, &kem_key, &challenge).map_err(|e| e.to_string())
        }
        _ => Err("unknown request".into()),
    }
}
