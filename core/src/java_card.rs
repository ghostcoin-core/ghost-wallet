//! The phone's side of a Ghost Java Card (`docs/bearer-card-spec.md`, and the
//! applet's command interface in `card-applet/README.md`). No Seal and no
//! Ghost server takes part: Fill, Check, Open and Refill run between the
//! card, this phone and the chain.
//!
//! What is checked here, on the phone:
//!
//! - the card's **certificate**: signed with SLH-DSA-SHAKE-128s (Ghost's own
//!   `slh_dsa`) by an issuer key pinned in this app, for a batch that issuer
//!   lists, an applet code hash this app knows, and a card that is not
//!   revoked ([`Trust`]);
//! - the card's **seal statement**: the LMS signature (RFC 8554,
//!   LMS_SHA256_M32_H10 with LMOTS_SHA256_N32_W4) under the attestation key
//!   the certificate names, over this tap's own challenge, about the card the
//!   certificate names ([`verify_java_card_check`]);
//! - the **commit data** a card hands out: its SHA-256 is the statement's
//!   signed digest, and the commitment from its F and the signed amount is
//!   the statement's commitment;
//! - an **Open**: the card's AES-CMAC tag before anything is decrypted, then
//!   the Phantom Key's seed bytes recomputed from what the card released, and
//!   F, the commitment, the marker and the commit data's digest recomputed
//!   from them with Ghost's client and compared with the card's statement.
//!   Only then is the key held for the Summon or Claim ([`crate::card`]).
//!
//! The released seed material crosses from the card module to this core
//! through one C function the JavaScript bindings do not carry
//! ([`ghost_wallet_java_card_take_open`]); JavaScript gets only a verdict.
//! No cryptography is written here: SHA3-256 is `sha3`, SHA-256 `sha2`, LMS
//! `lms-signature`, AES-256-CTR and AES-CMAC `ctr`, `cmac` and `aes`, and
//! SLH-DSA, F, the commitment, the marker and the commit data come from
//! `ghost_client`. Nothing here logs, prints or formats a code, a seed or a
//! key.

use std::sync::{Mutex, MutexGuard, PoisonError};

use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use cmac::{Cmac, KeyInit, Mac};
use ghost_client::commit::salted_commit_data;
use ghost_client::slh_dsa;
use ghost_client::{Amount, Rule, Salt};
use lms_signature::lms::{LmsSha256M32H10, Signature as LmsSignature, VerifyingKey as LmsVerifyingKey};
use lms_signature::ots::LmsOtsSha256N32W4;
use rand::TryRng;
use rand::rngs::SysRng;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use signature::Verifier;
use zeroize::{Zeroize, Zeroizing};

use crate::card::hold_card_words;
use crate::seal_open::{GivenBytes, KEY_FORMAT_CODE, phantom_key_from_bytes};
use crate::send::{PUBLIC_TEST_CHAIN_ID, TEST_CHAIN_ID};
use crate::vanish::{COMMIT_DATA_BYTES, CoinLeaf};

/// The applet's AID, as the app's ISO 7816 select identifiers list it.
pub const CARD_AID_HEX: &str = "A000000847474341524401";
/// A card id's length.
pub const CARD_ID_BYTES: usize = 16;
/// An open code's length: 160 bits.
pub const OPEN_CODE_BYTES: usize = 20;
/// An open code's length as the app shows it: 32 base32 characters.
pub const OPEN_CODE_CHARS: usize = 32;
/// A challenge's length.
pub const CHALLENGE_BYTES: usize = 32;
/// A seal statement's length.
pub const STATEMENT_BYTES: usize = 194;
/// An LMS signature's length, H10 and W4.
pub const LMS_SIGNATURE_BYTES: usize = 2508;
/// An LMS public key's length (RFC 8554: type, OTS type, I, T[1]).
pub const LMS_PUBLIC_KEY_BYTES: usize = 56;
/// Identify's answer.
pub const IDENTIFY_BYTES: usize = 29;
/// Open's answer: fill 4, counter block 16, ciphertext 64, tag 16.
pub const OPEN_ANSWER_BYTES: usize = 100;
/// What Open releases: the card random and the writer nonce.
pub const RELEASE_BYTES: usize = 64;
/// Make's answer: fill 4, commitment 32, commit data 430.
pub const MAKE_ANSWER_BYTES: usize = 4 + 32 + COMMIT_DATA_BYTES;
/// Make refuses a card with fewer seal checks left than this.
pub const MAKE_MIN_CHECKS: u32 = 16;
/// The writer's app warns before Make when fewer seal checks than this remain.
pub const LOW_CHECKS: u32 = 64;

const STATEMENT_DOMAIN: &[u8; 18] = b"ghost-card-seal-v1";
const CODE_DOMAIN: &[u8] = b"ghost-card-code";
const KEY_DOMAIN: &[u8] = b"ghost-card-key";
const OPEN_ENC_DOMAIN: &[u8] = b"ghost-card-open-enc";
const OPEN_MAC_DOMAIN: &[u8] = b"ghost-card-open-mac";
const OPEN_DOMAIN: &[u8] = b"ghost-card-open-v1";

/// The certificate's domain, its first bytes and its SLH-DSA context.
pub const CERT_DOMAIN: &[u8; 18] = b"ghost-card-cert-v1";
/// The label of an issuer id.
pub const ISSUER_ID_DOMAIN: &[u8] = b"ghost-card-issuer";
/// An issuer id's length: the first bytes of SHA3-256(label || public key).
pub const ISSUER_ID_BYTES: usize = 8;
/// The signed part of a certificate: domain 18, issuer id 8, card id 16, LMS
/// public key 56, applet code hash 32, batch 4.
pub const CERT_BODY_BYTES: usize = 18 + ISSUER_ID_BYTES + CARD_ID_BYTES + LMS_PUBLIC_KEY_BYTES + 32 + 4;
/// A certificate: its body, then the issuer's SLH-DSA-SHAKE-128s signature.
pub const CERT_BYTES: usize = CERT_BODY_BYTES + slh_dsa::SIGNATURE_BYTES;

// ---------------------------------------------------------------- trust

/// An issuer key the app pins, with the batches it published.
#[derive(Debug, Clone, Copy)]
pub struct PinnedIssuer {
    /// SLH-DSA-SHAKE-128s public key.
    pub public_key: [u8; slh_dsa::PUBLIC_KEY_BYTES],
    /// A development issuer: trusted only by builds for a test network.
    pub dev: bool,
    /// The batches this issuer published; a card from any other is refused.
    pub batches: &'static [u32],
}

/// What a certificate is checked against: the pinned issuers, the published
/// applet code hashes, and the revocation list.
#[derive(Debug, Clone, Copy)]
pub struct Trust {
    pub issuers: &'static [PinnedIssuer],
    pub applet_hashes: &'static [[u8; 32]],
    pub revoked_cards: &'static [[u8; CARD_ID_BYTES]],
    /// Whether development issuers count.
    pub allow_dev: bool,
}

/// The development issuer: certifies the test cards. Its private key never
/// leaves the loading station and is not in this repository.
const DEV_ISSUER: PinnedIssuer = PinnedIssuer {
    public_key: [
        0x19, 0x3f, 0x65, 0x8a, 0x6e, 0xf0, 0x19, 0xca, 0x5e, 0x55, 0xc1, 0x2e, 0x54, 0x2d, 0x52, 0xda, 0x8d, 0xa1,
        0x3d, 0x7a, 0x73, 0x43, 0x8b, 0xeb, 0xc6, 0x86, 0xd7, 0xae, 0x54, 0x3d, 0x0c, 0xf8,
    ],
    dev: true,
    batches: &[1],
};

/// The issuers this app pins.
pub const ISSUERS: &[PinnedIssuer] = &[DEV_ISSUER];

/// The applet builds a card may carry: the code hash `card-applet/build.sh`
/// prints, which every certificate names.
pub const APPLET_HASHES: &[[u8; 32]] = &[[
    0x2c, 0x79, 0x42, 0x80, 0xf0, 0xa6, 0x24, 0x02, 0x41, 0x3f, 0x11, 0x26, 0x35, 0x70, 0x88, 0x5a, 0xc0, 0xd6, 0xb6,
    0xf1, 0xb8, 0xde, 0x5e, 0x8c, 0xff, 0x75, 0xbe, 0x15, 0xa8, 0x04, 0xb2, 0xb0,
]];

/// Cards an issuer revoked (lost from a loading station, failed a sample).
pub const REVOKED_CARDS: &[[u8; CARD_ID_BYTES]] = &[];

/// Whether a build for `chain_id` trusts development issuers: only the test
/// networks' builds do.
pub fn dev_issuers_trusted(chain_id: u64) -> bool {
    chain_id == TEST_CHAIN_ID || chain_id == PUBLIC_TEST_CHAIN_ID
}

/// The app's trust for a build on `chain_id`.
pub fn pinned_trust(chain_id: u64) -> Trust {
    Trust { issuers: ISSUERS, applet_hashes: APPLET_HASHES, revoked_cards: REVOKED_CARDS, allow_dev: dev_issuers_trusted(chain_id) }
}

/// An issuer's id: the first 8 bytes of SHA3-256("ghost-card-issuer" || key).
pub fn issuer_id(public_key: &[u8; slh_dsa::PUBLIC_KEY_BYTES]) -> [u8; ISSUER_ID_BYTES] {
    let digest = sha3(&[ISSUER_ID_DOMAIN, public_key]);
    let mut id = [0u8; ISSUER_ID_BYTES];
    id.copy_from_slice(&digest[..ISSUER_ID_BYTES]);
    id
}

/// A certificate's signed body, as the issuer signs it.
pub fn certificate_body(
    issuer_public_key: &[u8; slh_dsa::PUBLIC_KEY_BYTES],
    card_id: &[u8; CARD_ID_BYTES],
    lms_public_key: &[u8; LMS_PUBLIC_KEY_BYTES],
    applet_hash: &[u8; 32],
    batch: u32,
) -> [u8; CERT_BODY_BYTES] {
    let mut body = [0u8; CERT_BODY_BYTES];
    let mut at = 0;
    for part in [
        &CERT_DOMAIN[..],
        &issuer_id(issuer_public_key)[..],
        &card_id[..],
        &lms_public_key[..],
        &applet_hash[..],
        &batch.to_be_bytes()[..],
    ] {
        body[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    body
}

/// A certificate that passed [`check_certificate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardCertificate {
    pub card_id: [u8; CARD_ID_BYTES],
    pub lms_public_key: [u8; LMS_PUBLIC_KEY_BYTES],
    pub applet_hash: [u8; 32],
    pub batch: u32,
    pub dev: bool,
}

/// Why a card is not shown as genuine. Each is a short code the screens map
/// to "Not a genuine Ghost card".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    CertificateMalformed,
    UnknownIssuer,
    DevIssuer,
    IssuerSignature,
    UnknownBatch,
    Revoked,
    UnknownApplet,
    StatementMalformed,
    StatementSignature,
    WrongCard,
    WrongChallenge,
    CommitDataMalformed,
    CommitDataDigest,
    CommitDataCommitment,
    WrongChain,
}

impl Refusal {
    /// The refusal's code, as JavaScript sees it.
    pub fn code(self) -> &'static str {
        match self {
            Refusal::CertificateMalformed => "certificate-malformed",
            Refusal::UnknownIssuer => "unknown-issuer",
            Refusal::DevIssuer => "dev-issuer",
            Refusal::IssuerSignature => "issuer-signature",
            Refusal::UnknownBatch => "unknown-batch",
            Refusal::Revoked => "revoked",
            Refusal::UnknownApplet => "unknown-applet",
            Refusal::StatementMalformed => "statement-malformed",
            Refusal::StatementSignature => "statement-signature",
            Refusal::WrongCard => "wrong-card",
            Refusal::WrongChallenge => "wrong-challenge",
            Refusal::CommitDataMalformed => "commit-data-malformed",
            Refusal::CommitDataDigest => "commit-data-digest",
            Refusal::CommitDataCommitment => "commit-data-commitment",
            Refusal::WrongChain => "wrong-chain",
        }
    }
}

/// Checks a card's certificate against `trust`: its layout, a pinned issuer
/// (a development one only when `trust` allows), the issuer's SLH-DSA
/// signature, a published batch, a known applet and no revocation.
pub fn check_certificate(certificate: &[u8], trust: &Trust) -> Result<CardCertificate, Refusal> {
    if certificate.len() != CERT_BYTES || &certificate[..18] != CERT_DOMAIN {
        return Err(Refusal::CertificateMalformed);
    }
    let (body, signature) = certificate.split_at(CERT_BODY_BYTES);
    let id = &body[18..26];
    let issuer = trust.issuers.iter().find(|issuer| issuer_id(&issuer.public_key) == id).ok_or(Refusal::UnknownIssuer)?;
    if issuer.dev && !trust.allow_dev {
        return Err(Refusal::DevIssuer);
    }
    if !slh_dsa::verify(&issuer.public_key, body, CERT_DOMAIN, signature) {
        return Err(Refusal::IssuerSignature);
    }
    let card_id: [u8; CARD_ID_BYTES] = body[26..42].try_into().map_err(|_| Refusal::CertificateMalformed)?;
    let lms_public_key: [u8; LMS_PUBLIC_KEY_BYTES] = body[42..98].try_into().map_err(|_| Refusal::CertificateMalformed)?;
    let applet_hash: [u8; 32] = body[98..130].try_into().map_err(|_| Refusal::CertificateMalformed)?;
    let batch = u32::from_be_bytes(body[130..134].try_into().map_err(|_| Refusal::CertificateMalformed)?);
    if !issuer.batches.contains(&batch) {
        return Err(Refusal::UnknownBatch);
    }
    if trust.revoked_cards.contains(&card_id) {
        return Err(Refusal::Revoked);
    }
    if !trust.applet_hashes.contains(&applet_hash) {
        return Err(Refusal::UnknownApplet);
    }
    Ok(CardCertificate { card_id, lms_public_key, applet_hash, batch, dev: issuer.dev })
}

// ---------------------------------------------------------------- statements

/// The card's state, as a statement or Identify says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardState {
    Blank,
    Sealed,
    Opened,
}

impl CardState {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(CardState::Blank),
            1 => Some(CardState::Sealed),
            2 => Some(CardState::Opened),
            _ => None,
        }
    }

    /// The state's name, as JavaScript sees it.
    pub fn name(self) -> &'static str {
        match self {
            CardState::Blank => "blank",
            CardState::Sealed => "sealed",
            CardState::Opened => "opened",
        }
    }
}

/// A seal statement, read field by field (`card-applet/README.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub card_id: [u8; CARD_ID_BYTES],
    pub state: CardState,
    pub fill: u32,
    pub chain_id: u64,
    pub amount: u128,
    pub commitment: [u8; 32],
    pub digest: [u8; 32],
    pub marker: [u8; 32],
    pub checks_left: u32,
    pub leaf: u32,
    /// 0 not asked, 1 right, 2 wrong.
    pub code: u8,
    pub challenge: [u8; CHALLENGE_BYTES],
}

fn array<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[at..at + N]);
    out
}

/// Reads a statement's 194 bytes; `None` for anything else.
pub fn parse_statement(bytes: &[u8]) -> Option<Statement> {
    if bytes.len() != STATEMENT_BYTES || &bytes[..18] != STATEMENT_DOMAIN {
        return None;
    }
    let mut amount = [0u8; 16];
    amount[4..].copy_from_slice(&bytes[47..59]);
    let code = bytes[161];
    if code > 2 {
        return None;
    }
    Some(Statement {
        card_id: array(bytes, 18),
        state: CardState::from_byte(bytes[34])?,
        fill: u32::from_be_bytes(array(bytes, 35)),
        chain_id: u64::from_be_bytes(array(bytes, 39)),
        amount: u128::from_be_bytes(amount),
        commitment: array(bytes, 59),
        digest: array(bytes, 91),
        marker: array(bytes, 123),
        checks_left: u32::from(u16::from_be_bytes(array(bytes, 155))),
        leaf: u32::from_be_bytes(array(bytes, 157)),
        code,
        challenge: array(bytes, 162),
    })
}

type CardLms = LmsSha256M32H10<LmsOtsSha256N32W4>;

/// Whether `signature` is the LMS signature of `message` under `public_key`.
pub fn lms_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != LMS_PUBLIC_KEY_BYTES || signature.len() != LMS_SIGNATURE_BYTES {
        return false;
    }
    let Ok(key) = LmsVerifyingKey::<CardLms>::try_from(public_key) else {
        return false;
    };
    let Ok(signature) = LmsSignature::<CardLms>::try_from(signature) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

/// What one Check tap gave: the card's certificate, its statement and the
/// statement's LMS signature, the challenge this phone sent, and the commit
/// data when the card was sealed and handed it over.
pub struct CheckParts<'a> {
    pub certificate: &'a [u8],
    pub statement: &'a [u8],
    pub signature: &'a [u8],
    pub challenge: &'a [u8],
    pub commit_data: Option<&'a [u8]>,
}

/// A Check that passed: the card, its signed statement, and the coin's leaf
/// when commit data came with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedCard {
    pub certificate: CardCertificate,
    pub statement: Statement,
    pub leaf: Option<CoinLeaf>,
}

/// Checks one Check tap for a build on `chain_id`: the certificate, the LMS
/// signature under its key, the statement's card and challenge, a coin on
/// this build's chain, and the commit data (if any) against the signed
/// digest and commitment.
pub fn check_card(parts: &CheckParts<'_>, trust: &Trust, chain_id: u64) -> Result<CheckedCard, Refusal> {
    let certificate = check_certificate(parts.certificate, trust)?;
    if parts.statement.len() != STATEMENT_BYTES {
        return Err(Refusal::StatementMalformed);
    }
    if !lms_verify(&certificate.lms_public_key, parts.statement, parts.signature) {
        return Err(Refusal::StatementSignature);
    }
    let statement = parse_statement(parts.statement).ok_or(Refusal::StatementMalformed)?;
    if statement.card_id != certificate.card_id {
        return Err(Refusal::WrongCard);
    }
    if parts.challenge.len() != CHALLENGE_BYTES || statement.challenge[..] != parts.challenge[..] {
        return Err(Refusal::WrongChallenge);
    }
    if statement.state != CardState::Blank && statement.chain_id != chain_id {
        return Err(Refusal::WrongChain);
    }
    let leaf = match parts.commit_data {
        Some(data) => Some(check_commit_data(data, &statement)?),
        None => None,
    };
    Ok(CheckedCard { certificate, statement, leaf })
}

/// Checks a card's commit data against its signed statement: its SHA-256 is
/// the digest, and the commitment from its F and the signed amount is the
/// statement's. Returns the coin tree leaf the Vanish adds.
pub fn check_commit_data(data: &[u8], statement: &Statement) -> Result<CoinLeaf, Refusal> {
    if statement.state == CardState::Blank || data.len() != COMMIT_DATA_BYTES {
        return Err(Refusal::CommitDataMalformed);
    }
    if sha256(data) != statement.digest {
        return Err(Refusal::CommitDataDigest);
    }
    let leaf = crate::vanish::commit_leaf(data.to_vec(), statement.amount.to_string())
        .map_err(|_| Refusal::CommitDataMalformed)?;
    if leaf.commitment[..] != statement.commitment[..] {
        return Err(Refusal::CommitDataCommitment);
    }
    Ok(leaf)
}

// ---------------------------------------------------------------- open codes

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// An open code's 32 base32 characters (RFC 4648 alphabet).
pub fn open_code_text(code: &[u8; OPEN_CODE_BYTES]) -> String {
    let mut out = String::with_capacity(OPEN_CODE_CHARS);
    for chunk in code.chunks(5) {
        let mut value: u64 = 0;
        for byte in chunk {
            value = (value << 8) | u64::from(*byte);
        }
        for i in (0..8).rev() {
            out.push(BASE32[((value >> (i * 5)) & 31) as usize] as char);
        }
    }
    out
}

/// An open code from its text: 32 base32 characters, in any case, with any
/// spaces or dashes between them. `None` for anything else.
pub fn open_code_from_text(text: &str) -> Option<Zeroizing<[u8; OPEN_CODE_BYTES]>> {
    let mut code = Zeroizing::new([0u8; OPEN_CODE_BYTES]);
    let mut value: u64 = 0;
    let mut count = 0usize;
    for c in text.chars() {
        if c == ' ' || c == '-' {
            continue;
        }
        let upper = c.to_ascii_uppercase();
        let digit = BASE32.iter().position(|&b| b as char == upper)?;
        if count >= OPEN_CODE_CHARS {
            return None;
        }
        value = (value << 5) | digit as u64;
        count += 1;
        if count % 8 == 0 {
            let at = (count / 8 - 1) * 5;
            code[at..at + 5].copy_from_slice(&value.to_be_bytes()[3..]);
            value = 0;
        }
    }
    value.zeroize();
    (count == OPEN_CODE_CHARS).then_some(code)
}

/// SHA3-256 of an open code: what Make stores on the card.
pub fn code_hash(code: &[u8]) -> [u8; 32] {
    sha3(&[code])
}

/// The value a Check sends to confirm an open code for one challenge.
pub fn code_confirmation(code: &[u8], challenge: &[u8]) -> [u8; 32] {
    sha3(&[CODE_DOMAIN, &code_hash(code), challenge])
}

fn sha3(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

// ---------------------------------------------------------------- open

/// Why an Open did not give a key. Never holds a code, a seed or a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenRefusal {
    /// The answer is not an Open answer, or it is for another fill.
    Malformed,
    /// The answer's tag is wrong: altered, or not for this code and challenge.
    BadTag,
    /// Nothing was released to this core, or it was already used.
    NothingHeld,
    /// The release is for another card or fill than the one checked.
    OtherFill,
    /// The key recomputed from the release does not make the card's coin.
    NotTheCoin,
    /// What the release makes is not a Phantom Key.
    NotAKey,
}

impl OpenRefusal {
    /// The refusal's code, as JavaScript sees it.
    pub fn code(self) -> &'static str {
        match self {
            OpenRefusal::Malformed => "open-malformed",
            OpenRefusal::BadTag => "open-bad-tag",
            OpenRefusal::NothingHeld => "open-nothing-held",
            OpenRefusal::OtherFill => "open-other-fill",
            OpenRefusal::NotTheCoin => "open-not-the-coin",
            OpenRefusal::NotAKey => "open-not-a-key",
        }
    }
}

/// Checks an Open answer's tag, then decrypts it: the card random and the
/// writer nonce, and the fill it is for.
pub fn open_release(
    card_id: &[u8; CARD_ID_BYTES],
    code: &[u8; OPEN_CODE_BYTES],
    challenge: &[u8; CHALLENGE_BYTES],
    answer: &[u8],
) -> Result<(u32, Zeroizing<[u8; RELEASE_BYTES]>), OpenRefusal> {
    if answer.len() != OPEN_ANSWER_BYTES {
        return Err(OpenRefusal::Malformed);
    }
    let fill = &answer[..4];
    let counter: [u8; 16] = array(answer, 4);
    let ciphertext = &answer[20..84];
    let tag = &answer[84..100];
    let enc = Zeroizing::new(sha3(&[OPEN_ENC_DOMAIN, card_id, fill, code, challenge]));
    let mac_key = Zeroizing::new(sha3(&[OPEN_MAC_DOMAIN, card_id, fill, code, challenge]));
    let mut mac = <Cmac<Aes256> as KeyInit>::new_from_slice(&mac_key[..]).map_err(|_| OpenRefusal::Malformed)?;
    mac.update(OPEN_DOMAIN);
    mac.update(card_id);
    mac.update(fill);
    mac.update(challenge);
    mac.update(&counter);
    mac.update(ciphertext);
    mac.verify_slice(tag).map_err(|_| OpenRefusal::BadTag)?;
    let mut release = Zeroizing::new([0u8; RELEASE_BYTES]);
    release.copy_from_slice(ciphertext);
    let mut cipher = ctr::Ctr128BE::<Aes256>::new_from_slices(&enc[..], &counter).map_err(|_| OpenRefusal::Malformed)?;
    cipher.apply_keystream(&mut release[..]);
    Ok((u32::from_be_bytes(array(answer, 0)), release))
}

/// The coin a card's release makes, recomputed with Ghost's client: the
/// Phantom Key's seed bytes from the card random and the writer nonce, then
/// F, the commitment and the marker with `salt` and `amount`, and the commit
/// data with `note` (the 380 sealed note bytes, from the commit data or the
/// coin's leaf on chain).
pub struct RecomputedCoin {
    pub key_bytes: Zeroizing<Vec<u8>>,
    pub commitment: [u8; 32],
    pub marker: [u8; 32],
    pub digest: [u8; 32],
}

/// See [`RecomputedCoin`].
pub fn recompute_coin(
    release: &[u8; RELEASE_BYTES],
    salt: &[u8; 16],
    note: &[u8],
    amount: u128,
) -> Result<RecomputedCoin, OpenRefusal> {
    let seed = Zeroizing::new(sha3(&[KEY_DOMAIN, &release[..32], &release[32..]]));
    let mut key_bytes = Zeroizing::new(Vec::with_capacity(33));
    key_bytes.push(KEY_FORMAT_CODE);
    key_bytes.extend_from_slice(&seed[..]);
    let key = phantom_key_from_bytes(&key_bytes).map_err(|_| OpenRefusal::NotAKey)?;
    let amount = Amount::new(amount).map_err(|_| OpenRefusal::NotTheCoin)?;
    let mut salt_source = GivenBytes::new(salt);
    let commit = key.salted_coin_commit(0, amount, Rule::EMPTY, &mut salt_source).map_err(|_| OpenRefusal::NotTheCoin)?;
    if !salt_source.drawn_exactly() || commit.salt != Salt::from_bytes(*salt) {
        return Err(OpenRefusal::NotTheCoin);
    }
    let note: &[u8; COMMIT_DATA_BYTES - 50] = note.try_into().map_err(|_| OpenRefusal::NotTheCoin)?;
    let data = salted_commit_data(&commit.fingerprint, &commit.salt, note);
    Ok(RecomputedCoin {
        key_bytes,
        commitment: *commit.commitment.as_bytes(),
        marker: *commit.marker.as_bytes(),
        digest: sha256(&data),
    })
}

/// A release the card module handed over, waiting for its check.
struct PendingRelease {
    card_id: [u8; CARD_ID_BYTES],
    fill: u32,
    release: Zeroizing<[u8; RELEASE_BYTES]>,
}

static RELEASED: Mutex<Option<PendingRelease>> = Mutex::new(None);

fn released() -> MutexGuard<'static, Option<PendingRelease>> {
    RELEASED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Checks and decrypts an Open answer and holds what it released.
pub fn take_open(
    card_id: &[u8; CARD_ID_BYTES],
    code: &[u8; OPEN_CODE_BYTES],
    challenge: &[u8; CHALLENGE_BYTES],
    answer: &[u8],
) -> Result<(), OpenRefusal> {
    let (fill, release) = open_release(card_id, code, challenge, answer)?;
    *released() = Some(PendingRelease { card_id: *card_id, fill, release });
    Ok(())
}

/// Recomputes the coin from the held release, checks it is the coin the
/// card's verified statement names, and holds its Phantom Key for the
/// Summon or Claim. The release is wiped either way.
pub fn finish_open(expect: &OpenExpect<'_>) -> Result<(), OpenRefusal> {
    let pending = released().take().ok_or(OpenRefusal::NothingHeld)?;
    if pending.card_id != expect.card_id || pending.fill != expect.fill {
        return Err(OpenRefusal::OtherFill);
    }
    let coin = recompute_coin(&pending.release, expect.salt, expect.note, expect.amount)?;
    if coin.commitment != expect.commitment || coin.marker != expect.marker || coin.digest != expect.digest {
        return Err(OpenRefusal::NotTheCoin);
    }
    let phantom = phantom_key_from_bytes(&coin.key_bytes).map_err(|_| OpenRefusal::NotAKey)?;
    let words = phantom.format_words().ok_or(OpenRefusal::NotAKey)?.as_str().to_owned();
    if !hold_card_words(words) {
        return Err(OpenRefusal::NotAKey);
    }
    Ok(())
}

/// What an Open must give: the card and fill, and the coin its verified
/// statement names, with the salt and sealed note of the coin's commit data.
pub struct OpenExpect<'a> {
    pub card_id: [u8; CARD_ID_BYTES],
    pub fill: u32,
    pub amount: u128,
    pub commitment: [u8; 32],
    pub marker: [u8; 32],
    pub digest: [u8; 32],
    pub salt: &'a [u8; 16],
    pub note: &'a [u8],
}

/// Wipes a held release.
pub fn forget_release() {
    released().take();
}

/// The Open answer was taken and is held.
pub const JAVA_OPEN_OK: isize = 0;
/// The answer's tag is wrong, or it is not an Open answer.
pub const JAVA_OPEN_REFUSED: isize = -1;
/// A length is wrong.
pub const JAVA_OPEN_WRONG_LENGTH: isize = -2;
/// A null pointer was passed.
pub const JAVA_OPEN_NULL: isize = -3;

/// Takes a card's Open answer (`answer_len` bytes at `answer`) for card
/// `card_id` (16 bytes), opened with `code` (20 bytes) over `challenge` (32
/// bytes): checks its tag, decrypts it and holds the release for
/// [`finish_java_card_open`]. Returns [`JAVA_OPEN_OK`], [`JAVA_OPEN_REFUSED`],
/// [`JAVA_OPEN_WRONG_LENGTH`] or [`JAVA_OPEN_NULL`]. The card module calls
/// this; JavaScript cannot.
///
/// # Safety
///
/// Each pointer must be valid for reads of its length: 16 bytes at
/// `card_id`, 20 at `code`, 32 at `challenge` and `answer_len` at `answer`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_wallet_java_card_take_open(
    card_id: *const u8,
    code: *const u8,
    challenge: *const u8,
    answer: *const u8,
    answer_len: usize,
) -> isize {
    if card_id.is_null() || code.is_null() || challenge.is_null() || answer.is_null() {
        return JAVA_OPEN_NULL;
    }
    if answer_len != OPEN_ANSWER_BYTES {
        return JAVA_OPEN_WRONG_LENGTH;
    }
    // SAFETY: the caller guarantees each pointer holds its length.
    let (card_id, code, challenge, answer) = unsafe {
        (
            &*card_id.cast::<[u8; CARD_ID_BYTES]>(),
            &*code.cast::<[u8; OPEN_CODE_BYTES]>(),
            &*challenge.cast::<[u8; CHALLENGE_BYTES]>(),
            core::slice::from_raw_parts(answer, answer_len),
        )
    };
    match take_open(card_id, code, challenge, answer) {
        Ok(()) => JAVA_OPEN_OK,
        Err(_) => JAVA_OPEN_REFUSED,
    }
}

// ---------------------------------------------------------------- UniFFI

/// Why a call failed.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum JavaCardError {
    /// `code` is a short code, never a secret.
    Failed { code: String },
}

impl core::fmt::Display for JavaCardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            JavaCardError::Failed { code } => write!(f, "the card call failed: {code}"),
        }
    }
}

fn failed(code: &str) -> JavaCardError {
    JavaCardError::Failed { code: code.to_owned() }
}

/// A new open code, from the operating system's random source, as its 32
/// base32 characters: shown once, kept nowhere.
#[uniffi::export]
pub fn java_card_new_open_code() -> Result<String, JavaCardError> {
    let mut code = Zeroizing::new([0u8; OPEN_CODE_BYTES]);
    SysRng.try_fill_bytes(&mut code[..]).map_err(|_| failed("randomness"))?;
    Ok(open_code_text(&code))
}

/// 32 bytes from the operating system's random source: a Check's or Open's
/// challenge, or a Make's writer nonce.
#[uniffi::export]
pub fn java_card_random() -> Result<Vec<u8>, JavaCardError> {
    let mut bytes = vec![0u8; CHALLENGE_BYTES];
    SysRng.try_fill_bytes(&mut bytes).map_err(|_| failed("randomness"))?;
    Ok(bytes)
}

/// The open code typed or scanned as `text`, as the 20 bytes the card takes.
#[uniffi::export]
pub fn java_card_open_code(text: String) -> Result<Vec<u8>, JavaCardError> {
    let code = open_code_from_text(&text).ok_or_else(|| failed("not-an-open-code"));
    crate::accounts::wipe_string(text);
    Ok(code?.to_vec())
}

/// SHA3-256 of an open code, for Make.
#[uniffi::export]
pub fn java_card_code_hash(code: Vec<u8>) -> Vec<u8> {
    code_hash(&code).to_vec()
}

/// The open-code confirmation a Check sends with `challenge`.
#[uniffi::export]
pub fn java_card_code_confirmation(code: Vec<u8>, challenge: Vec<u8>) -> Vec<u8> {
    code_confirmation(&code, &challenge).to_vec()
}

/// The card number printed on a card's face: its 16-byte id as 26 base32
/// characters in groups of four (the last of two).
#[uniffi::export]
pub fn java_card_number(card_id: Vec<u8>) -> String {
    let mut padded = [0u8; 20];
    let n = card_id.len().min(CARD_ID_BYTES);
    padded[..n].copy_from_slice(&card_id[..n]);
    let text: String = open_code_text(&padded).chars().take(26).collect();
    text.as_bytes().chunks(4).map(|chunk| String::from_utf8_lossy(chunk).into_owned()).collect::<Vec<_>>().join(" ")
}

/// Identify's answer, read: unsigned, for labelling a card only.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct JavaCardIdentity {
    /// 0 loading, 1 ready.
    pub phase: u8,
    /// "blank", "sealed" or "opened".
    pub state: String,
    pub card_id: Vec<u8>,
    pub card_number: String,
    pub fill: u32,
    pub checks_left: u32,
    pub certificate_bytes: u32,
}

/// Reads Identify's 29 bytes.
#[uniffi::export]
pub fn java_card_identity(answer: Vec<u8>) -> Result<JavaCardIdentity, JavaCardError> {
    if answer.len() != IDENTIFY_BYTES || answer[0] != 1 {
        return Err(failed("identify-malformed"));
    }
    let state = CardState::from_byte(answer[2]).ok_or_else(|| failed("identify-malformed"))?;
    let card_id = answer[3..19].to_vec();
    Ok(JavaCardIdentity {
        phase: answer[1],
        state: state.name().to_owned(),
        card_number: java_card_number(card_id.clone()),
        card_id,
        fill: u32::from_be_bytes(array(&answer, 19)),
        checks_left: u32::from(u16::from_be_bytes(array(&answer, 23))),
        certificate_bytes: u32::from(u16::from_be_bytes(array(&answer, 27))),
    })
}

/// One Check tap, as the card module read it, for [`verify_java_card_check`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct JavaCardCheckInput {
    pub certificate: Vec<u8>,
    pub statement: Vec<u8>,
    pub signature: Vec<u8>,
    /// The challenge this phone sent with the Check.
    pub challenge: Vec<u8>,
    /// The commit data, when the card was sealed and handed it over.
    pub commit_data: Option<Vec<u8>>,
    /// This build's chain.
    pub chain_id: u64,
}

/// A verified seal statement, as the screens use it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct JavaCardStatement {
    pub card_id: Vec<u8>,
    pub card_number: String,
    /// "blank", "sealed" or "opened".
    pub state: String,
    pub fill: u32,
    pub chain_id: u64,
    pub amount_wei: String,
    pub commitment: Vec<u8>,
    pub digest: Vec<u8>,
    pub marker: Vec<u8>,
    pub checks_left: u32,
    /// "not-asked", "right" or "wrong".
    pub open_code: String,
    pub batch: u32,
    pub dev_issuer: bool,
    /// The leaf the coin's Vanish adds, when commit data came with the Check.
    pub leaf: Option<CoinLeaf>,
}

/// A Check's verdict: a refusal code (empty when it passed) and the
/// statement it verified.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct JavaCardVerdict {
    pub refusal: String,
    pub statement: Option<JavaCardStatement>,
}

fn statement_record(card: CheckedCard) -> JavaCardStatement {
    let s = card.statement;
    JavaCardStatement {
        card_id: s.card_id.to_vec(),
        card_number: java_card_number(s.card_id.to_vec()),
        state: s.state.name().to_owned(),
        fill: s.fill,
        chain_id: s.chain_id,
        amount_wei: s.amount.to_string(),
        commitment: s.commitment.to_vec(),
        digest: s.digest.to_vec(),
        marker: s.marker.to_vec(),
        checks_left: s.checks_left,
        open_code: ["not-asked", "right", "wrong"][usize::from(s.code)].to_owned(),
        batch: card.certificate.batch,
        dev_issuer: card.certificate.dev,
        leaf: card.leaf,
    }
}

/// Verifies one Check tap against the pinned issuers for a build on
/// `chain_id` ([`check_card`]).
#[uniffi::export]
pub fn verify_java_card_check(input: JavaCardCheckInput) -> JavaCardVerdict {
    let parts = CheckParts {
        certificate: &input.certificate,
        statement: &input.statement,
        signature: &input.signature,
        challenge: &input.challenge,
        commit_data: input.commit_data.as_deref(),
    };
    match check_card(&parts, &pinned_trust(input.chain_id), input.chain_id) {
        Ok(card) => JavaCardVerdict { refusal: String::new(), statement: Some(statement_record(card)) },
        Err(refusal) => JavaCardVerdict { refusal: refusal.code().to_owned(), statement: None },
    }
}

/// What [`finish_java_card_open`] checks the release against: the card's
/// verified statement and the salt and sealed note of its coin.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct JavaCardOpenExpect {
    pub card_id: Vec<u8>,
    pub fill: u32,
    pub amount_wei: String,
    pub commitment: Vec<u8>,
    pub marker: Vec<u8>,
    pub digest: Vec<u8>,
    pub salt: Vec<u8>,
    pub note: Vec<u8>,
}

/// Recomputes the coin from the release the card module took and, when it
/// is the coin `expect` names, holds its Phantom Key for the Summon or
/// Claim. Returns "" or an [`OpenRefusal`] code.
#[uniffi::export]
pub fn finish_java_card_open(expect: JavaCardOpenExpect) -> String {
    let parsed = (|| {
        Some(OpenExpect {
            card_id: expect.card_id.as_slice().try_into().ok()?,
            fill: expect.fill,
            amount: expect.amount_wei.parse().ok()?,
            commitment: expect.commitment.as_slice().try_into().ok()?,
            marker: expect.marker.as_slice().try_into().ok()?,
            digest: expect.digest.as_slice().try_into().ok()?,
            salt: expect.salt.as_slice().try_into().ok()?,
            note: &expect.note,
        })
    })();
    let Some(parsed) = parsed else {
        forget_release();
        return OpenRefusal::Malformed.code().to_owned();
    };
    match finish_open(&parsed) {
        Ok(()) => String::new(),
        Err(refusal) => refusal.code().to_owned(),
    }
}

/// Holds the Phantom Key of the held release with no statement to check it
/// against: for a card with no seal checks left. The card must still carry a
/// certificate that passes [`check_certificate`] for a build on `chain_id`,
/// for the card the release came from, at the fill its Identify gave. The
/// chain then decides: the Summon finds a coin only if this is its key.
/// Returns "" or a refusal code.
#[uniffi::export]
pub fn finish_java_card_open_unchecked(certificate: Vec<u8>, chain_id: u64, fill: u32) -> String {
    let card = match check_certificate(&certificate, &pinned_trust(chain_id)) {
        Ok(card) => card,
        Err(refusal) => {
            forget_release();
            return refusal.code().to_owned();
        }
    };
    let result = hold_unchecked(&card.card_id, fill);
    match result {
        Ok(()) => String::new(),
        Err(refusal) => refusal.code().to_owned(),
    }
}

/// [`finish_java_card_open_unchecked`] after its certificate passed.
pub fn hold_unchecked(card_id: &[u8; CARD_ID_BYTES], fill: u32) -> Result<(), OpenRefusal> {
    let pending = released().take().ok_or(OpenRefusal::NothingHeld)?;
    if pending.card_id != *card_id || pending.fill != fill {
        return Err(OpenRefusal::OtherFill);
    }
    let seed = Zeroizing::new(sha3(&[KEY_DOMAIN, &pending.release[..32], &pending.release[32..]]));
    let mut key_bytes = Zeroizing::new(Vec::with_capacity(33));
    key_bytes.push(KEY_FORMAT_CODE);
    key_bytes.extend_from_slice(&seed[..]);
    let phantom = phantom_key_from_bytes(&key_bytes).map_err(|_| OpenRefusal::NotAKey)?;
    let words = phantom.format_words().ok_or(OpenRefusal::NotAKey)?.as_str().to_owned();
    if !hold_card_words(words) {
        return Err(OpenRefusal::NotAKey);
    }
    Ok(())
}

/// Whether a release is held, waiting for [`finish_java_card_open`].
#[uniffi::export]
pub fn has_java_card_release() -> bool {
    released().is_some()
}

/// Wipes a held release.
#[uniffi::export]
pub fn forget_java_card_release() {
    forget_release();
}
