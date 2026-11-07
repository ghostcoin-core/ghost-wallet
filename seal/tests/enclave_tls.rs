//! TLS ended inside the enclave, on the one service port that also carries
//! the framed protocol: a rustls client that trusts nothing but the
//! certificate's SHA-256 completes a handshake and a request; a client
//! pinning another hash is refused; TLS 1.2 is refused; the same port still
//! answers a framed key-share request and a framed phone attestation; any
//! other first byte closes the connection; a slow handshake runs out of the
//! same connection time.

#[path = "fixtures/nitro_authority.rs"]
mod authority;
#[path = "support/enclave.rs"]
mod enclave;
#[path = "fixtures/test_release_key.rs"]
mod release;
mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use authority::{Authority, AuthoritySource, NOW, allowed_new, allowed_old};
use ghost_seal::attestation::certificate_fingerprint;
use ghost_seal::enclave_serve::{
    ANSWER_OK, ANSWER_REFUSED, EnclaveService, KIND_KEY_SHARE, KIND_PHONE_ATTESTATION, MemoryServiceLog, ServiceDeps,
    ServiceEvent,
};
use ghost_seal::enclave_tls::{CERTIFICATE_NAME, EnclaveTls};
use ghost_seal::key_share::{Receiver, read_frame, write_frame};
use ghost_seal::measurements::MeasurementList;
use ghost_seal::phone_attestation::{self, PhoneAttestationRejected, answer_key};
use ghost_seal::primitives::sha3_256;
use ghost_seal::relay::{from_hex, to_hex};
use ghost_seal::{SealError, SealRandom};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use serde_json::{Value, json};

/// A client check that trusts nothing but the SHA-256 of the certificate:
/// no name, no dates, no authority. It records the hash it saw.
#[derive(Debug)]
struct PinnedHash {
    hash: [u8; 32],
    seen: Mutex<Option<[u8; 32]>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedHash {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let hash = certificate_fingerprint(end_entity);
        *self.seen.lock().unwrap() = Some(hash);
        if hash == self.hash {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("no TLS 1.2".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn pinned(hash: [u8; 32]) -> Arc<PinnedHash> {
    Arc::new(PinnedHash { hash, seen: Mutex::new(None), provider: Arc::new(rustls::crypto::ring::default_provider()) })
}

fn tls_client(addr: SocketAddr, check: Arc<PinnedHash>) -> StreamOwned<ClientConnection, TcpStream> {
    let config = ClientConfig::builder_with_provider(check.provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(check)
        .with_no_client_auth();
    let connection = ClientConnection::new(Arc::new(config), ServerName::try_from("ghost-seal").unwrap()).unwrap();
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    StreamOwned::new(connection, tcp)
}

/// One HTTP request and its answer over `stream`.
fn http(stream: &mut impl ReadWrite, path: &str, body: &Value) -> std::io::Result<(u16, String, Value)> {
    let body = body.to_string();
    let request = format!("POST {path} HTTP/1.1\r\nHost: ghost-seal\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 {
            return Err(std::io::Error::other("closed"));
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap().to_lowercase();
    let length: usize =
        head.lines().find_map(|l| l.strip_prefix("content-length: ")).unwrap().trim().parse().unwrap();
    let mut answer = vec![0u8; length];
    stream.read_exact(&mut answer)?;
    Ok((head[9..12].parse().unwrap(), head, serde_json::from_slice(&answer).unwrap()))
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// A service holding the test M, measuring as an allowed build, nothing
/// else installed, on a local port.
fn running() -> (Arc<EnclaveService>, SocketAddr, Arc<MemoryServiceLog>) {
    let log = Arc::new(MemoryServiceLog::default());
    let service = Arc::new(enclave::service(ServiceDeps::none(), allowed_old(), log.clone()));
    service.install_master(support::master());
    let addr = enclave::serve(service.clone(), Duration::from_secs(30));
    (service, addr, log)
}

#[test]
fn a_client_that_pins_the_certificate_hash_completes_a_handshake_and_a_request() {
    let (service, addr, _) = running();
    let hash = service.certificate_hash();
    assert_eq!(hash, certificate_fingerprint(service.certificate_der()));
    let check = pinned(hash);
    let mut tls = tls_client(addr, check.clone());

    // The attestation over TLS binds exactly the certificate this connection used.
    let challenge = [0x5c; 32];
    let (status, head, body) = http(&mut tls, "/v1/attestation", &json!({ "challenge": to_hex(&challenge) })).unwrap();
    assert_eq!(status, 200, "{body}");
    assert!(head.contains("cache-control: no-store"));
    assert_eq!(tls.conn.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
    assert_eq!(tls.conn.alpn_protocol(), None, "the client offered no ALPN");
    let seen = check.seen.lock().unwrap().expect("the client saw a certificate");
    let attestation = from_hex(body["attestation"].as_str().unwrap()).unwrap();
    let authority = Authority::new(enclave::AUTHORITY_SEED);
    let list = MeasurementList::parse(enclave::FIXTURE).unwrap();
    let seal = phone_attestation::verify(&attestation, &challenge, &seen, &authority.verifier(), &list, NOW).unwrap();
    assert_eq!(seal.answer_key, answer_key(&support::master()));
    assert_eq!(seal.kem_key, enclave::kem_key());

    // A second request on the same connection: no flow is served yet.
    let (status, _, body) = http(&mut tls, "/v1/check/start", &json!({ "uid": "04518dfaa96180", "challenge": to_hex(&[1; 32]) })).unwrap();
    assert_eq!((status, body["error"].as_str()), (503, Some("unavailable")));
}

#[test]
fn a_client_that_pins_another_hash_is_refused() {
    let (service, addr, _) = running();
    let mut other = service.certificate_hash();
    other[0] ^= 0x01;
    let check = pinned(other);
    let mut tls = tls_client(addr, check.clone());
    let result = http(&mut tls, "/v1/attestation", &json!({ "challenge": to_hex(&[2; 32]) }));
    assert!(result.is_err(), "the handshake must fail");
    assert_eq!(*check.seen.lock().unwrap(), Some(service.certificate_hash()), "the server presented its own certificate");
}

#[test]
fn the_server_is_tls_1_3_only_with_no_resumption_and_a_fresh_certificate() {
    let tls = EnclaveTls::generate().unwrap();
    let config = tls.config();
    assert_eq!(config.send_tls13_tickets, 0);
    assert_eq!(config.max_early_data_size, 0);
    assert!(!config.session_storage.can_cache());
    assert!(!config.ticketer.enabled());
    assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    let der = tls.certificate_der();
    assert!(der.windows(CERTIFICATE_NAME.len()).any(|w| w == CERTIFICATE_NAME.as_bytes()));
    // A restart makes another key and certificate.
    let again = EnclaveTls::generate().unwrap();
    assert_ne!(again.certificate_hash(), tls.certificate_hash());
}

/// A TLS 1.2 ClientHello, by hand: no supported_versions extension (a TLS
/// 1.2 client), or one offering TLS 1.2 only.
fn tls12_client_hello(offer_tls12_in_supported_versions: bool) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x42; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x04, 0xc0, 0x2b, 0xc0, 0x2f]);
    body.extend_from_slice(&[0x01, 0x00]);
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17]);
    extensions.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
    extensions.extend_from_slice(&[0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04]);
    if offer_tls12_in_supported_versions {
        extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x03]);
    }
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[test]
fn tls_1_2_is_refused() {
    let (_, addr, _) = running();
    for offer in [false, true] {
        let mut tcp = TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        tcp.write_all(&tls12_client_hello(offer)).unwrap();
        let mut answer = Vec::new();
        let _ = tcp.read_to_end(&mut answer);
        // A fatal alert and the end of the connection: never a ServerHello.
        assert!(answer.len() >= 7, "the server answers with an alert, got {answer:02x?}");
        assert_eq!(answer[0], 0x15, "an alert record, got {answer:02x?}");
        assert_eq!(answer[5], 0x02, "a fatal alert");
    }
}

#[test]
fn the_same_port_answers_a_framed_key_share_and_a_framed_phone_attestation() {
    let (service, addr, log) = running();
    let authority = Rc::new(Authority::new(enclave::AUTHORITY_SEED));

    // A key-share request from an allowed new build gets M, encrypted to it alone.
    let mut source = AuthoritySource::new(authority.clone(), allowed_new());
    let receiver = Receiver::start(&mut source, &mut Random(7)).unwrap();
    let mut tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write_frame(&mut tcp, &[&[KIND_KEY_SHARE][..], &receiver.request()].concat()).unwrap();
    let answer = read_frame(&mut tcp).unwrap();
    assert_eq!(answer[0], ANSWER_OK, "{}", String::from_utf8_lossy(&answer[1..]));
    let master = support::master();
    let (received, giver) = receiver.accept(&answer[1..], &authority.verifier(), &enclave::trusted_fixture(), NOW).unwrap();
    assert_eq!(giver.name, "seal-2026-10-01");
    assert_eq!(answer_key(&received), answer_key(&master));
    assert!(!support::contains(&answer, &master_bytes()), "the package never carries M in the clear");

    // On the same connection: a framed phone attestation binding the TLS certificate.
    let challenge = [0x33; 32];
    write_frame(&mut tcp, &[&[KIND_PHONE_ATTESTATION][..], &challenge].concat()).unwrap();
    let answer = read_frame(&mut tcp).unwrap();
    assert_eq!(answer[0], ANSWER_OK);
    let list = MeasurementList::parse(enclave::FIXTURE).unwrap();
    let hash = service.certificate_hash();
    phone_attestation::verify(&answer[1..], &challenge, &hash, &authority.verifier(), &list, NOW).unwrap();
    assert_eq!(
        phone_attestation::verify(&answer[1..], &challenge, &[0; 32], &authority.verifier(), &list, NOW),
        Err(PhoneAttestationRejected::Certificate)
    );
    // A malformed request is refused with a reason.
    write_frame(&mut tcp, &[KIND_PHONE_ATTESTATION, 1, 2]).unwrap();
    let answer = read_frame(&mut tcp).unwrap();
    assert_eq!(answer[0], ANSWER_REFUSED);
    let events = log.0.lock().unwrap().clone();
    assert!(events.iter().any(|e| matches!(e, ServiceEvent::HandedMaster { build } if build == "seal-2026-11-01")));
}

#[test]
fn a_first_byte_that_is_neither_tls_nor_a_frame_closes_the_connection() {
    let (_, addr, log) = running();
    for first in [b"GET / HTTP/1.1\r\n\r\n".to_vec(), vec![0x01, 0, 0, 0], vec![0x17, 3, 3, 0, 1, 0], vec![0xff]] {
        let mut tcp = TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        tcp.write_all(&first).unwrap();
        let mut answer = Vec::new();
        let _ = tcp.read_to_end(&mut answer);
        assert!(answer.is_empty(), "nothing is answered to {first:02x?}");
    }
    assert!(log.0.lock().unwrap().iter().filter(|e| **e == ServiceEvent::UnknownProtocol).count() >= 4);
}

#[test]
fn a_slow_handshake_runs_out_of_the_same_connection_time() {
    let log = Arc::new(MemoryServiceLog::default());
    let service = Arc::new(enclave::service(ServiceDeps::none(), allowed_old(), log));
    service.install_master(support::master());
    let addr = enclave::serve(service, Duration::from_millis(700));
    let mut tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let hello = tls12_client_hello(false);
    let started = Instant::now();
    // The first bytes of a handshake, then nothing.
    tcp.write_all(&hello[..10]).unwrap();
    let mut answer = Vec::new();
    let _ = tcp.read_to_end(&mut answer);
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(500) && took < Duration::from_secs(5), "closed after {took:?}");
    assert!(answer.is_empty() || answer[0] == 0x15, "no handshake answer, at most an alert: {answer:02x?}");
}

fn master_bytes() -> Vec<u8> {
    (0..32u8).map(|i| 0x40 + i).collect()
}

/// A deterministic random source (test only).
struct Random(u64);

impl SealRandom for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), SealError> {
        for chunk in out.chunks_mut(32) {
            self.0 += 1;
            chunk.copy_from_slice(&sha3_256(&[b"tls test random", &self.0.to_be_bytes()])[..chunk.len()]);
        }
        Ok(())
    }
}
