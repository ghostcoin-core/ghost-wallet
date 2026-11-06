//! How a new enclave gets M from a running one, and the only way M ever
//! leaves an enclave: encrypted to another attested enclave on the
//! published list.
//!
//! 1. The receiving enclave makes a fresh ML-KEM-768 key pair and a fresh
//!    32-byte nonce, and asks the NSM for a document whose `user_data` is
//!    SHA3-256([`REQUEST_LABEL`] || its encapsulation key) and whose `nonce`
//!    is the nonce. Request: `GKQ1` || encapsulation key (1184) ||
//!    document length (u32) || document.
//! 2. The giving enclave verifies that document (chain to the pinned root,
//!    validity, freshness), accepts it only when PCR0, PCR1 and PCR2 are one
//!    allowed build of its list, checks the binding of the key, and checks
//!    that it is itself an allowed build of that list. It encapsulates to the
//!    key and asks for its own document: `user_data` SHA3-256
//!    ([`PACKAGE_LABEL`] || the receiver document's hash || nonce || KEM
//!    ciphertext), `nonce` the receiver's nonce. From the shared secret HKDF
//!    (HMAC-SHA3-256, salt [`PACKAGE_LABEL`], info [`PACKAGE_LABEL`] ||
//!    receiver document hash || giver document hash || nonce) derives an
//!    AES-256 key and an HMAC-SHA3-256 key. M is padded (ISO/IEC 9797-1
//!    method 2) and encrypted with AES-256-CBC under a fresh IV, and the
//!    package is MACed (encrypt-then-MAC). Package: `GKP1` || document length
//!    (u32) || giver document || KEM ciphertext (1088) || IV (16) ||
//!    ciphertext (48) || tag (32), the tag over [`PACKAGE_LABEL`] || receiver
//!    document hash || giver document hash || nonce || everything before the
//!    tag.
//! 3. The receiver verifies the giver's document the same way, its nonce and
//!    its binding of the KEM ciphertext to this receiver's document, before
//!    it decapsulates or reads anything else; then checks the tag, decrypts,
//!    and holds M as a [`MasterKey`] inside the enclave.
//!
//! A package opens only for the one receiver whose document and nonce it
//! was made for, and a receiver takes one package and is used up.

use core::fmt;
use std::io::{Read, Write};

use ml_kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, KeyExport, MlKem768, TryKeyInit};
use zeroize::{Zeroize, Zeroizing};

use crate::attestation::{AttestationError, AttestationRejected, AttestationSource, AttestationVerifier, AttestedDocument};
use crate::measurements::{Build, MeasurementList, MeasurementRefused};
use crate::primitives::{aes256_cbc_decrypt, aes256_cbc_encrypt, ct_eq, hkdf_sha3_256, hmac_sha3_256, pad, sha3_256, unpad};
use crate::release::{KEM_CIPHERTEXT_BYTES, PHONE_KEY_BYTES};
use crate::secrets::MasterKey;
use crate::traits::{DrawnRandom, SealRandom};

/// The label of the receiver's key binding.
pub const REQUEST_LABEL: &[u8] = b"ghost-seal/v1/key-share/request";
/// The HKDF salt, HKDF info prefix, MAC label and giver binding label.
pub const PACKAGE_LABEL: &[u8] = b"ghost-seal/v1/key-share/package";
/// The nonce's length.
pub const NONCE_BYTES: usize = 32;
/// An ML-KEM-768 encapsulation key's length.
pub const KEM_KEY_BYTES: usize = PHONE_KEY_BYTES;
/// The longest request or package frame.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

const REQUEST_MAGIC: &[u8; 4] = b"GKQ1";
const PACKAGE_MAGIC: &[u8; 4] = b"GKP1";
const BODY_BYTES: usize = 48;
const TAG_BYTES: usize = 32;

/// Why a key share was refused. No variant carries a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareRefused {
    /// The request or package is not this format.
    Malformed(&'static str),
    /// The receiver's document does not verify.
    ReceiverDocument(AttestationRejected),
    /// The receiver is not an allowed build of the list.
    ReceiverNotAllowed(MeasurementRefused),
    /// The giver's document does not verify.
    GiverDocument(AttestationRejected),
    /// The giver is not an allowed build of the list.
    GiverNotAllowed(MeasurementRefused),
    /// A document does not bind what it must (key, nonce, receiver).
    Binding(&'static str),
    /// The package's tag does not verify, or it does not decrypt to M.
    BadPackage,
    /// No attestation document could be had.
    Attestation(AttestationError),
    /// The random source failed.
    Random,
}

impl fmt::Display for ShareRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShareRefused::Malformed(what) => write!(f, "key share: malformed: {what}"),
            ShareRefused::ReceiverDocument(why) => write!(f, "key share: receiver: {why}"),
            ShareRefused::ReceiverNotAllowed(why) => write!(f, "key share: receiver: {why}"),
            ShareRefused::GiverDocument(why) => write!(f, "key share: giver: {why}"),
            ShareRefused::GiverNotAllowed(why) => write!(f, "key share: giver: {why}"),
            ShareRefused::Binding(what) => write!(f, "key share: binding: {what}"),
            ShareRefused::BadPackage => f.write_str("key share: the package does not open"),
            ShareRefused::Attestation(why) => write!(f, "key share: {why}"),
            ShareRefused::Random => f.write_str("key share: the random source failed"),
        }
    }
}

impl std::error::Error for ShareRefused {}

fn request_binding(kem_key: &[u8]) -> [u8; 32] {
    sha3_256(&[REQUEST_LABEL, kem_key])
}

fn package_binding(receiver_hash: &[u8; 32], nonce: &[u8], kem_ciphertext: &[u8]) -> [u8; 32] {
    sha3_256(&[PACKAGE_LABEL, receiver_hash, nonce, kem_ciphertext])
}

fn package_keys(
    shared: &[u8],
    receiver_hash: &[u8; 32],
    giver_hash: &[u8; 32],
    nonce: &[u8],
) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mut okm = Zeroizing::new([0u8; 64]);
    hkdf_sha3_256(PACKAGE_LABEL, shared, &[PACKAGE_LABEL, receiver_hash, giver_hash, nonce], &mut okm[..]);
    let mut enc = Zeroizing::new([0u8; 32]);
    let mut mac = Zeroizing::new([0u8; 32]);
    enc.copy_from_slice(&okm[..32]);
    mac.copy_from_slice(&okm[32..]);
    (enc, mac)
}

fn package_tag(mac: &[u8; 32], receiver_hash: &[u8; 32], giver_hash: &[u8; 32], nonce: &[u8], body: &[u8]) -> [u8; 32] {
    hmac_sha3_256(mac, &[PACKAGE_LABEL, receiver_hash, giver_hash, nonce, body])
}

fn read_u32(bytes: &[u8], at: usize) -> Option<usize> {
    let raw: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(raw) as usize)
}

/// A parsed request.
struct Request<'a> {
    kem_key: &'a [u8],
    document: &'a [u8],
}

impl<'a> Request<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Request<'a>, ShareRefused> {
        if bytes.len() > MAX_FRAME_BYTES || bytes.len() < 4 + KEM_KEY_BYTES + 4 || &bytes[..4] != REQUEST_MAGIC {
            return Err(ShareRefused::Malformed("not a key-share request"));
        }
        let kem_key = &bytes[4..4 + KEM_KEY_BYTES];
        let length = read_u32(bytes, 4 + KEM_KEY_BYTES).ok_or(ShareRefused::Malformed("no document length"))?;
        let document = &bytes[4 + KEM_KEY_BYTES + 4..];
        if document.len() != length || length == 0 {
            return Err(ShareRefused::Malformed("the document length is wrong"));
        }
        Ok(Request { kem_key, document })
    }
}

/// A parsed package.
struct Package<'a> {
    document: &'a [u8],
    kem_ciphertext: &'a [u8],
    iv: [u8; 16],
    body: &'a [u8],
    signed: &'a [u8],
    tag: &'a [u8],
}

impl<'a> Package<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Package<'a>, ShareRefused> {
        if bytes.len() > MAX_FRAME_BYTES || bytes.len() < 8 || &bytes[..4] != PACKAGE_MAGIC {
            return Err(ShareRefused::Malformed("not a key-share package"));
        }
        let length = read_u32(bytes, 4).ok_or(ShareRefused::Malformed("no document length"))?;
        if length == 0 || bytes.len() != 8 + length + KEM_CIPHERTEXT_BYTES + 16 + BODY_BYTES + TAG_BYTES {
            return Err(ShareRefused::Malformed("the package length is wrong"));
        }
        let mut at = 8;
        let document = &bytes[at..at + length];
        at += length;
        let kem_ciphertext = &bytes[at..at + KEM_CIPHERTEXT_BYTES];
        at += KEM_CIPHERTEXT_BYTES;
        let iv: [u8; 16] = bytes[at..at + 16].try_into().expect("16 bytes");
        at += 16;
        let body = &bytes[at..at + BODY_BYTES];
        at += BODY_BYTES;
        Ok(Package { document, kem_ciphertext, iv, body, signed: &bytes[..at], tag: &bytes[at..] })
    }
}

/// What a giving enclave needs besides M.
pub struct GiverContext<'a> {
    /// Checks the receiver's document (the AWS chain in an enclave).
    pub verifier: &'a dyn AttestationVerifier,
    /// The published list the receiver must be an allowed build of.
    pub list: &'a MeasurementList,
    /// The giving enclave's own NSM.
    pub source: &'a mut dyn AttestationSource,
    /// Randomness for the encapsulation and the IV.
    pub random: &'a mut dyn SealRandom,
    /// Now, seconds since the Unix epoch.
    pub now_unix: u64,
}

/// A package the giving enclave made, and for which build.
pub struct GivenPackage {
    /// The package bytes, for the receiver.
    pub package: Vec<u8>,
    /// The receiving build, as the list names it.
    pub receiver: Build,
}

/// The giving side: answers one `request` with a package of M for that
/// receiver only, or refuses. M itself is never returned.
pub fn package_for(master: &MasterKey, request: &[u8], context: GiverContext<'_>) -> Result<GivenPackage, ShareRefused> {
    let request = Request::parse(request)?;
    let receiver = context.verifier.verify(request.document, context.now_unix).map_err(ShareRefused::ReceiverDocument)?;
    let build = context.list.check(&receiver.pcrs).map_err(ShareRefused::ReceiverNotAllowed)?.clone();
    let nonce = receiver_nonce(&receiver)?;
    if receiver.user_data.as_deref() != Some(&request_binding(request.kem_key)[..]) {
        return Err(ShareRefused::Binding("the receiver's document does not bind its key"));
    }
    let kem_key = <EncapsulationKey<MlKem768> as TryKeyInit>::new_from_slice(request.kem_key)
        .map_err(|_| ShareRefused::Malformed("not an ML-KEM-768 key"))?;

    let mut drawn = DrawnRandom::draw(context.random).map_err(|_| ShareRefused::Random)?;
    let (kem_ciphertext, shared) = kem_key.encapsulate_with_rng(&mut drawn);
    let shared = Zeroizing::new(shared);
    let document = context
        .source
        .attest(&package_binding(&receiver.hash, &nonce, &kem_ciphertext), &nonce)
        .map_err(ShareRefused::Attestation)?;
    // A giver hands M over only while it is itself an allowed build: a
    // revoked build stops giving.
    let giver = context.verifier.verify(&document, context.now_unix).map_err(ShareRefused::GiverDocument)?;
    context.list.check(&giver.pcrs).map_err(ShareRefused::GiverNotAllowed)?;

    let (enc, mac) = package_keys(&shared, &receiver.hash, &giver.hash, &nonce);
    let mut iv = [0u8; 16];
    context.random.fill(&mut iv).map_err(|_| ShareRefused::Random)?;
    let body = aes256_cbc_encrypt(&enc, &iv, &pad(master.for_key_share_package())).map_err(|_| ShareRefused::BadPackage)?;
    let mut package = Vec::with_capacity(8 + document.len() + KEM_CIPHERTEXT_BYTES + 16 + BODY_BYTES + TAG_BYTES);
    package.extend_from_slice(PACKAGE_MAGIC);
    package.extend_from_slice(&(document.len() as u32).to_be_bytes());
    package.extend_from_slice(&document);
    package.extend_from_slice(&kem_ciphertext);
    package.extend_from_slice(&iv);
    package.extend_from_slice(&body);
    let tag = package_tag(&mac, &receiver.hash, &giver.hash, &nonce, &package);
    package.extend_from_slice(&tag);
    Ok(GivenPackage { package, receiver: build })
}

fn receiver_nonce(document: &AttestedDocument) -> Result<[u8; NONCE_BYTES], ShareRefused> {
    document
        .nonce
        .as_deref()
        .and_then(|n| n.try_into().ok())
        .ok_or(ShareRefused::Binding("the receiver's document has no 32-byte nonce"))
}

/// The receiving side: a fresh key pair, a fresh nonce and the document
/// that binds them. Used for exactly one package.
pub struct Receiver {
    key: DecapsulationKey<MlKem768>,
    kem_key: Vec<u8>,
    nonce: [u8; NONCE_BYTES],
    document: Vec<u8>,
    document_hash: [u8; 32],
}

impl Receiver {
    /// Makes the key pair and nonce and asks `source` for the document.
    pub fn start(source: &mut dyn AttestationSource, random: &mut dyn SealRandom) -> Result<Receiver, ShareRefused> {
        let mut seed = Zeroizing::new([0u8; 64]);
        random.fill(&mut seed[..]).map_err(|_| ShareRefused::Random)?;
        let mut seed_array = ml_kem::Seed::from(*seed);
        let key = DecapsulationKey::<MlKem768>::from_seed(seed_array);
        seed_array.zeroize();
        let kem_key = key.encapsulation_key().to_bytes().to_vec();
        let mut nonce = [0u8; NONCE_BYTES];
        random.fill(&mut nonce).map_err(|_| ShareRefused::Random)?;
        let document = source.attest(&request_binding(&kem_key), &nonce).map_err(ShareRefused::Attestation)?;
        let document_hash = crate::attestation::document_hash(&document);
        Ok(Receiver { key, kem_key, nonce, document, document_hash })
    }

    /// The request to send to a giving enclave.
    pub fn request(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + KEM_KEY_BYTES + 4 + self.document.len());
        out.extend_from_slice(REQUEST_MAGIC);
        out.extend_from_slice(&self.kem_key);
        out.extend_from_slice(&(self.document.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.document);
        out
    }

    /// Opens the giver's package: the giver's document is checked with
    /// `verifier` and must be an allowed build of `list` and bind this
    /// receiver and nonce before anything is decapsulated. On success the
    /// receiver holds M as a [`MasterKey`], which never gives its bytes out.
    pub fn accept(
        self,
        package: &[u8],
        verifier: &dyn AttestationVerifier,
        list: &MeasurementList,
        now_unix: u64,
    ) -> Result<(MasterKey, Build), ShareRefused> {
        let package = Package::parse(package)?;
        let giver = verifier.verify(package.document, now_unix).map_err(ShareRefused::GiverDocument)?;
        let build = list.check(&giver.pcrs).map_err(ShareRefused::GiverNotAllowed)?.clone();
        if giver.nonce.as_deref() != Some(&self.nonce[..]) {
            return Err(ShareRefused::Binding("the package is for another nonce"));
        }
        let binding = package_binding(&self.document_hash, &self.nonce, package.kem_ciphertext);
        if giver.user_data.as_deref() != Some(&binding[..]) {
            return Err(ShareRefused::Binding("the package is for another receiver"));
        }
        let shared =
            Zeroizing::new(self.key.decapsulate_slice(package.kem_ciphertext).map_err(|_| ShareRefused::BadPackage)?);
        let (enc, mac) = package_keys(&shared, &self.document_hash, &giver.hash, &self.nonce);
        let tag = package_tag(&mac, &self.document_hash, &giver.hash, &self.nonce, package.signed);
        if !ct_eq(&tag, package.tag) {
            return Err(ShareRefused::BadPackage);
        }
        let plain = aes256_cbc_decrypt(&enc, &package.iv, package.body).map_err(|_| ShareRefused::BadPackage)?;
        let plain = unpad(&plain).map_err(|_| ShareRefused::BadPackage)?;
        let mut bytes: [u8; 32] = plain.as_slice().try_into().map_err(|_| ShareRefused::BadPackage)?;
        Ok((MasterKey::take(&mut bytes), build))
    }
}

/// Writes one frame: a 4-byte big-endian length, then the bytes.
pub fn write_frame(out: &mut dyn Write, bytes: &[u8]) -> std::io::Result<()> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too long"));
    }
    out.write_all(&(bytes.len() as u32).to_be_bytes())?;
    out.write_all(bytes)?;
    out.flush()
}

/// Reads one frame of at most [`MAX_FRAME_BYTES`].
pub fn read_frame(input: &mut dyn Read) -> std::io::Result<Vec<u8>> {
    let mut length = [0u8; 4];
    input.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too long"));
    }
    let mut bytes = vec![0u8; length];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}
