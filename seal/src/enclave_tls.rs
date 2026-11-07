//! TLS ended inside the enclave (feature `nitro`).
//!
//! At start the enclave makes a fresh ECDSA P-256 key pair and a self-signed
//! certificate for the name [`CERTIFICATE_NAME`] inside itself
//! ([`EnclaveTls::generate`], with `rcgen` on its `ring` backend), with a
//! fixed wide validity window so no clock is needed. The key and the
//! certificate live in enclave memory only: nothing writes them anywhere,
//! and a restart makes new ones.
//!
//! The server speaks TLS 1.3 only (`rustls` with the `ring` provider; the
//! crate is built without TLS 1.2), asks for no client certificate, keeps no
//! sessions, issues no session tickets and takes no 0-RTT data.
//!
//! This key is transport authentication only and holds no GHOST: the card
//! traffic is already end to end between the chip and the Seal, and an
//! Open's release is ML-KEM to the phone's key. Even so the certificate is
//! not trusted on a name. A phone trusts it only through the `GPA2` phone
//! attestation (`phone_attestation`), which binds the SHA-256 of its DER
//! ([`EnclaveTls::certificate_hash`]) to the enclave's measurement: a man in
//! the middle could otherwise swap the phone key of an Open.
//!
//! No elliptic-curve or TLS code is written here; the audited, exact-pinned
//! crates do it.

use core::fmt;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};

use crate::attestation::certificate_fingerprint;
use crate::relay_http::{ReadWrite, Routes, serve_http};

/// The certificate's subject name (its common name and its one DNS name).
pub const CERTIFICATE_NAME: &str = "ghost-seal";
/// The protocol the server offers over ALPN.
pub const ALPN_HTTP_1_1: &[u8] = b"http/1.1";

/// Why TLS could not be set up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsError(pub String);

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tls: {}", self.0)
    }
}

impl std::error::Error for TlsError {}

/// The enclave's TLS server: its configuration and the certificate it
/// serves. The private key is inside the configuration only.
pub struct EnclaveTls {
    config: Arc<ServerConfig>,
    certificate: CertificateDer<'static>,
    certificate_hash: [u8; 32],
}

impl EnclaveTls {
    /// Makes a fresh key pair and self-signed certificate inside this
    /// process and the TLS 1.3 server configuration around them.
    pub fn generate() -> Result<EnclaveTls, TlsError> {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| TlsError(e.to_string()))?;
        let mut params =
            rcgen::CertificateParams::new(vec![CERTIFICATE_NAME.to_owned()]).map_err(|e| TlsError(e.to_string()))?;
        let mut name = rcgen::DistinguishedName::new();
        name.push(rcgen::DnType::CommonName, CERTIFICATE_NAME);
        params.distinguished_name = name;
        // A fixed wide window: the enclave needs no clock to make it, and
        // the phone trusts it through the attestation, not through dates.
        params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        params.not_after = rcgen::date_time_ymd(4095, 12, 31);
        let certificate = params.self_signed(&key_pair).map_err(|e| TlsError(e.to_string()))?;
        let certificate = certificate.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        drop(key_pair);
        Self::with_certificate(certificate, key)
    }

    /// The server configuration for `certificate` and its `key`.
    fn with_certificate(certificate: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> Result<EnclaveTls, TlsError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| TlsError(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .map_err(|e| TlsError(e.to_string()))?;
        // No resumption: no session cache, no tickets, no early data.
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        config.max_early_data_size = 0;
        config.alpn_protocols = vec![ALPN_HTTP_1_1.to_vec()];
        let certificate_hash = certificate_fingerprint(&certificate);
        Ok(EnclaveTls { config: Arc::new(config), certificate, certificate_hash })
    }

    /// The DER of the certificate the server presents.
    pub fn certificate_der(&self) -> &[u8] {
        self.certificate.as_ref()
    }

    /// The SHA-256 of [`EnclaveTls::certificate_der`], which the phone
    /// attestation binds.
    pub fn certificate_hash(&self) -> [u8; 32] {
        self.certificate_hash
    }

    /// The server configuration.
    pub fn config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.config)
    }

    /// Ends TLS on `stream` (whose first bytes are a TLS handshake record)
    /// and serves the HTTP routes over it until the connection ends. A
    /// failed or slow handshake just ends the connection; the caller's
    /// connection time bounds it like any other read.
    pub fn serve(&self, stream: &mut dyn ReadWrite, routes: &Routes) {
        let Ok(mut connection) = ServerConnection::new(self.config()) else {
            return;
        };
        {
            let mut io: &mut dyn ReadWrite = &mut *stream;
            let mut tls = rustls::Stream::new(&mut connection, &mut io);
            serve_http(&mut tls, routes);
        }
        connection.send_close_notify();
        while connection.wants_write() {
            if connection.write_tls(&mut *stream).is_err() {
                break;
            }
        }
        let _ = stream.flush();
    }
}
