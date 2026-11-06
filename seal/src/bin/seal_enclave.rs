//! The Seal's enclave program, as it runs inside an AWS Nitro Enclave.
//!
//! It does exactly this:
//!
//! - Waits on its control port (vsock [`CONTROL_PORT`], reached only from the
//!   parent instance; the parent proxy never forwards to it) for one start
//!   frame: the mode and the published measurements list it is to enforce.
//!   A second start is refused for the life of the enclave.
//! - In genesis mode it makes M inside itself from the enclave's random
//!   source. That is the first enclave only; a copy is always started in
//!   join mode, and join mode never makes M, not even when the handover
//!   fails.
//! - In join mode it gets M from a running enclave through the key-share
//!   protocol: it sends its request through the parent's outbound proxy
//!   (vsock [`PEER_PORT`] on the parent) to the giving region and opens the
//!   package it gets back.
//! - On its service port (vsock [`SERVICE_PORT`], which the parent proxy
//!   forwards to from the internet) it answers key-share requests (handing
//!   M only to an attested allowed build, through the protocol) and phone
//!   attestation requests.
//!
//! It never writes M anywhere, and no frame it sends carries M except a
//! key-share package, encrypted to the receiving enclave.
//!
//! Frames are a 4-byte big-endian length and the bytes. Start frame: mode
//! (1 genesis, 2 join) || list JSON; answer: a status text. Service request:
//! kind (1 key share, 2 phone attestation) || body; service answer: 0 ||
//! body, or 1 || why it was refused.

#![deny(unsafe_op_in_unsafe_fn)]

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ghost_seal::attestation::{AttestationError, NitroVerifier, NsmDevice, NsmSource};
use ghost_seal::key_share::{self, GiverContext, Receiver, read_frame, write_frame};
use ghost_seal::measurements::MeasurementList;
use ghost_seal::phone_attestation::{self, CHALLENGE_BYTES};
use ghost_seal::{Clock, MasterKey, SealRandom, SystemClock, SystemRandom};
use ml_kem::{DecapsulationKey, KeyExport, MlKem768};
use vsock::{VMADDR_CID_ANY, VsockListener, VsockStream};

/// The control port: one start frame from the parent.
const CONTROL_PORT: u32 = 5000;
/// The service port the parent proxy forwards to.
const SERVICE_PORT: u32 = 5001;
/// The parent's port that relays to the giving region's service.
const PEER_PORT: u32 = 5002;
/// The parent instance's context ID, as seen from an enclave.
const PARENT_CID: u32 = 3;
/// How long a service connection may wait for a frame.
const SERVICE_TIMEOUT: Duration = Duration::from_secs(30);

const KIND_KEY_SHARE: u8 = 1;
const KIND_PHONE_ATTESTATION: u8 = 2;
const MODE_GENESIS: u8 = 1;
const MODE_JOIN: u8 = 2;
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
    list: MeasurementList,
    answer_key: Vec<u8>,
    kem_key: Vec<u8>,
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
    let state = Arc::new(Mutex::new(State {
        started: false,
        master: None,
        list: MeasurementList::empty(),
        answer_key: Vec::new(),
        kem_key: kem.encapsulation_key().to_bytes().to_vec(),
    }));

    let service_state = state.clone();
    thread::spawn(move || match VsockListener::bind_with_cid_port(VMADDR_CID_ANY, SERVICE_PORT) {
        Ok(listener) => {
            for stream in listener.incoming().flatten() {
                let state = service_state.clone();
                thread::spawn(move || serve(stream, &state));
            }
        }
        Err(error) => status(&format!("service port: {error}")),
    });

    let control = match VsockListener::bind_with_cid_port(VMADDR_CID_ANY, CONTROL_PORT) {
        Ok(listener) => listener,
        Err(error) => {
            status(&format!("control port: {error}"));
            std::process::exit(1);
        }
    };
    for mut stream in control.incoming().flatten() {
        let answer = match read_frame(&mut stream) {
            Ok(frame) => start(&frame, &state),
            Err(error) => format!("refused: {error}"),
        };
        status(&answer);
        let _ = write_frame(&mut stream, answer.as_bytes());
    }
}

/// Handles the one start frame.
fn start(frame: &[u8], state: &Mutex<State>) -> String {
    let Some((&mode, list)) = frame.split_first() else {
        return "refused: an empty start".into();
    };
    let list = match std::str::from_utf8(list).map_err(|e| e.to_string()).and_then(|text| {
        MeasurementList::parse(text).map_err(|e| e.to_string())
    }) {
        Ok(list) => list,
        Err(why) => return format!("refused: {why}"),
    };
    {
        let mut held = state.lock().unwrap_or_else(|e| e.into_inner());
        if held.started {
            return "refused: already started".into();
        }
        held.started = true;
        held.list = list.clone();
    }
    let master = match mode {
        MODE_GENESIS => {
            let mut bytes = [0u8; 32];
            if SystemRandom.fill(&mut bytes).is_err() {
                return "refused: no random source".into();
            }
            MasterKey::take(&mut bytes)
        }
        MODE_JOIN => match join(&list) {
            Ok(master) => master,
            Err(why) => return format!("refused: join failed: {why}"),
        },
        _ => return "refused: unknown mode".into(),
    };
    let mut held = state.lock().unwrap_or_else(|e| e.into_inner());
    held.answer_key = phone_attestation::answer_key(&master);
    held.master = Some(master);
    if mode == MODE_GENESIS { "ok: made M (genesis)".into() } else { "ok: received M from a running enclave".into() }
}

/// Gets M from a running enclave through the parent's outbound proxy.
fn join(list: &MeasurementList) -> Result<MasterKey, String> {
    let mut source = nsm()?;
    let receiver = Receiver::start(&mut source, &mut SystemRandom).map_err(|e| e.to_string())?;
    let mut peer = VsockStream::connect_with_cid_port(PARENT_CID, PEER_PORT).map_err(|e| e.to_string())?;
    peer.set_read_timeout(Some(SERVICE_TIMEOUT)).map_err(|e| e.to_string())?;
    let mut request = vec![KIND_KEY_SHARE];
    request.extend_from_slice(&receiver.request());
    write_frame(&mut peer, &request).map_err(|e| e.to_string())?;
    let answer = read_frame(&mut peer).map_err(|e| e.to_string())?;
    match answer.split_first() {
        Some((&ANSWER_OK, package)) => {
            let (master, giver) = receiver
                .accept(package, &NitroVerifier::aws(), list, SystemClock.now_unix())
                .map_err(|e| e.to_string())?;
            status(&format!("joined from build {}", giver.name));
            Ok(master)
        }
        Some((&ANSWER_REFUSED, why)) => Err(format!("the giver refused: {}", String::from_utf8_lossy(why))),
        _ => Err("the giver's answer is not a frame".into()),
    }
}

/// Answers service frames on one connection until it closes.
fn serve(mut stream: VsockStream, state: &Mutex<State>) {
    let _ = stream.set_read_timeout(Some(SERVICE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(SERVICE_TIMEOUT));
    while let Ok(frame) = read_frame(&mut stream) {
        let answer = match answer(&frame, state) {
            Ok(body) => [&[ANSWER_OK][..], &body].concat(),
            Err(why) => [&[ANSWER_REFUSED][..], why.as_bytes()].concat(),
        };
        if write_frame(&mut stream, &answer).is_err() {
            break;
        }
    }
}

fn answer(frame: &[u8], state: &Mutex<State>) -> Result<Vec<u8>, String> {
    let (&kind, body) = frame.split_first().ok_or("an empty frame")?;
    let held = state.lock().unwrap_or_else(|e| e.into_inner());
    let master = held.master.as_ref().ok_or("this enclave holds no M yet")?;
    let mut source = nsm()?;
    match kind {
        KIND_KEY_SHARE => {
            let given = key_share::package_for(
                master,
                body,
                GiverContext {
                    verifier: &NitroVerifier::aws(),
                    list: &held.list,
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
            phone_attestation::make(&mut source, &held.answer_key, &held.kem_key, &challenge).map_err(|e| e.to_string())
        }
        _ => Err("unknown request".into()),
    }
}
