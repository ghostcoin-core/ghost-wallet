//! A phone's TLS client to the enclave's service port: rustls, TLS 1.3 only,
//! trusting nothing but the SHA-256 of the enclave's certificate (no name,
//! no dates, no authority), as the app pins the hash the attestation binds;
//! and one HTTP/1.1 request at a time over it. Included by path by the tests
//! that need it (feature `nitro`).
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use ghost_seal::attestation::certificate_fingerprint;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use serde_json::Value;

/// Trusts only a certificate whose SHA-256 is `hash`.
#[derive(Debug)]
pub struct PinnedHash {
    hash: [u8; 32],
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
        if certificate_fingerprint(end_entity) == self.hash {
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

/// A TLS 1.3 connection to `addr` that trusts only the certificate `hash`.
pub fn connect(addr: SocketAddr, hash: [u8; 32]) -> StreamOwned<ClientConnection, TcpStream> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let check = Arc::new(PinnedHash { hash, provider: provider.clone() });
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(check)
        .with_no_client_auth();
    let connection = ClientConnection::new(Arc::new(config), ServerName::try_from("ghost-seal").unwrap()).unwrap();
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    StreamOwned::new(connection, tcp)
}

/// One POST of `body` to `path` over `stream`, kept open for the next: the
/// status and the JSON answer.
pub fn post(stream: &mut (impl Read + Write), path: &str, body: &Value) -> (u16, Value) {
    let body = body.to_string();
    let request = format!("POST {path} HTTP/1.1\r\nHost: ghost-seal\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    stream.write_all(request.as_bytes()).expect("the request is sent");
    stream.flush().expect("the request is sent");
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(stream.read(&mut byte).expect("an answer"), 1, "the connection closed");
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap().to_lowercase();
    let length: usize =
        head.lines().find_map(|line| line.strip_prefix("content-length: ")).expect("a length").trim().parse().unwrap();
    let mut answer = vec![0u8; length];
    stream.read_exact(&mut answer).expect("the whole answer");
    (head[9..12].parse().unwrap(), serde_json::from_slice(&answer).expect("JSON"))
}
