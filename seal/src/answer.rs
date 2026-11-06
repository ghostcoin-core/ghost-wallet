//! The Seal's signed answers. Every Check, Fill and Open answer is signed with
//! ML-DSA-65 (FIPS 204, deterministic signing, context
//! [`ANSWER_CONTEXT`]) under a key derived from M. No elliptic-curve key is
//! involved anywhere.
//!
//! Answer bytes ([`ANSWER_BYTES`] bytes, integers big endian):
//!
//! | offset | bytes | field |
//! | --- | --- | --- |
//! | 0 | 20 | domain `ghost-seal/v1/answer` |
//! | 20 | 1 | kind: 1 Check, 2 Fill, 3 Open |
//! | 21 | 32 | the phone's random challenge |
//! | 53 | 7 | the card UID |
//! | 60 | 4 | the generation |
//! | 64 | 32 | the coin: SHA3-256 of its commit data |
//! | 96 | 48 | the Seal's code measurement |
//! | 144 | 1 | the state: 0 Empty, 1 Sealed, 2 Opening, 3 Opened |
//! | 145 | 16 | the amount in wei |
//! | 161 | 8 | expiry, seconds since the Unix epoch |
//! | 169 | 32 | binding: SHA3-256 of the commit data (Fill), of the release package (Open), zeros (Check) |
//! | 201 | 1 | Open PIN: 0 none, 1 an Open of this card needs a PIN |
//! | 202 | 1 | Open PIN tries left (0 without a PIN) |
//!
//! A receiver who is not given the PIN of a card whose answer says it needs
//! one cannot redeem the card and must not accept it.

use ml_dsa::{EncodedVerifyingKey, ExpandedSigningKey, MlDsa65, Seed, Signature, VerifyingKey};
use zeroize::Zeroize;

use crate::card_keys::CardUid;
use crate::error::SealError;
use crate::primitives::hkdf_sha3_256;
use crate::record::CardState;
use crate::secrets::MasterKey;

/// The answer's domain.
pub const ANSWER_DOMAIN: &[u8; 20] = b"ghost-seal/v1/answer";
/// The ML-DSA context string of every answer signature.
pub const ANSWER_CONTEXT: &[u8] = b"ghost-seal answer";
/// The answer's length.
pub const ANSWER_BYTES: usize = 203;
/// The length of the Seal's code measurement.
pub const MEASUREMENT_BYTES: usize = 48;
/// The HKDF label of the answer-signing key's seed.
pub const ANSWER_KEY_LABEL: &[u8] = b"ghost-seal/v1/answer-signing-key";

/// Which flow answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerKind {
    /// Check.
    Check = 1,
    /// Fill.
    Fill = 2,
    /// Open.
    Open = 3,
}

/// What an answer says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerBody {
    /// Which flow answered.
    pub kind: AnswerKind,
    /// The phone's random challenge.
    pub challenge: [u8; 32],
    /// The card.
    pub uid: CardUid,
    /// The card's generation.
    pub generation: u32,
    /// SHA3-256 of the coin's commit data (zeros for an empty card).
    pub coin: [u8; 32],
    /// The Seal's code measurement.
    pub measurement: [u8; MEASUREMENT_BYTES],
    /// The card's state.
    pub state: CardState,
    /// The coin's amount in wei (0 for an empty card).
    pub amount_wei: u128,
    /// The answer is not to be trusted at or after this time.
    pub expires_at: u64,
    /// SHA3-256 of what the answer hands over with it, or zeros.
    pub binding: [u8; 32],
    /// Whether an Open of this card needs its Open PIN.
    pub pin_required: bool,
    /// Open PIN tries left on the card (0 without a PIN).
    pub pin_tries_left: u8,
}

impl AnswerBody {
    /// Whether whoever holds the card can Open it with no PIN: the
    /// receiver's test before accepting a card whose PIN it was not given.
    pub fn opens_without_pin(&self) -> bool {
        !self.pin_required
    }
}

impl AnswerBody {
    /// The bytes that are signed.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ANSWER_BYTES);
        out.extend_from_slice(ANSWER_DOMAIN);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.challenge);
        out.extend_from_slice(&self.uid.0);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.coin);
        out.extend_from_slice(&self.measurement);
        out.push(self.state as u8);
        out.extend_from_slice(&self.amount_wei.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.binding);
        out.push(u8::from(self.pin_required));
        out.push(if self.pin_required { self.pin_tries_left } else { 0 });
        debug_assert_eq!(out.len(), ANSWER_BYTES);
        out
    }

    /// Reads answer bytes.
    pub fn decode(bytes: &[u8]) -> Option<AnswerBody> {
        if bytes.len() != ANSWER_BYTES || &bytes[..20] != ANSWER_DOMAIN {
            return None;
        }
        let kind = match bytes[20] {
            1 => AnswerKind::Check,
            2 => AnswerKind::Fill,
            3 => AnswerKind::Open,
            _ => return None,
        };
        let pin_required = match bytes[201] {
            0 => false,
            1 => true,
            _ => return None,
        };
        let pin_tries_left = bytes[202];
        if !pin_required && pin_tries_left != 0 {
            return None;
        }
        let take = |from: usize, to: usize| &bytes[from..to];
        Some(AnswerBody {
            pin_required,
            pin_tries_left,
            kind,
            challenge: take(21, 53).try_into().ok()?,
            uid: CardUid(take(53, 60).try_into().ok()?),
            generation: u32::from_be_bytes(take(60, 64).try_into().ok()?),
            coin: take(64, 96).try_into().ok()?,
            measurement: take(96, 144).try_into().ok()?,
            state: CardState::from_byte(bytes[144])?,
            amount_wei: u128::from_be_bytes(take(145, 161).try_into().ok()?),
            expires_at: u64::from_be_bytes(take(161, 169).try_into().ok()?),
            binding: take(169, 201).try_into().ok()?,
        })
    }
}

/// An answer and its signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAnswer {
    /// What it says.
    pub body: AnswerBody,
    /// The signed bytes.
    pub bytes: Vec<u8>,
    /// The ML-DSA-65 signature over `bytes`.
    pub signature: Vec<u8>,
}

/// The Seal's answer-signing key: ML-DSA-65 from a seed derived from M.
pub(crate) struct AnswerSigner {
    key: ExpandedSigningKey<MlDsa65>,
}

impl AnswerSigner {
    pub(crate) fn derive(master: &MasterKey) -> AnswerSigner {
        let mut seed_bytes = [0u8; 32];
        hkdf_sha3_256(ANSWER_KEY_LABEL, master.derive_from(), &[ANSWER_KEY_LABEL], &mut seed_bytes);
        let mut seed = Seed::from(seed_bytes);
        seed_bytes.zeroize();
        let key = ExpandedSigningKey::<MlDsa65>::from_seed(&seed);
        seed.zeroize();
        AnswerSigner { key }
    }

    pub(crate) fn verifying_key(&self) -> Vec<u8> {
        self.key.verifying_key().encode().to_vec()
    }

    pub(crate) fn sign(&self, body: AnswerBody) -> Result<SignedAnswer, SealError> {
        let bytes = body.encode();
        let signature = self
            .key
            .sign_deterministic(&bytes, ANSWER_CONTEXT)
            .map_err(|_| SealError::Integrity("the answer could not be signed"))?;
        Ok(SignedAnswer { body, bytes, signature: signature.encode().to_vec() })
    }
}

/// Why an answer was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerRejected {
    /// Not answer bytes, or a signature of the wrong size.
    Malformed,
    /// The signature does not verify under the Seal's key.
    BadSignature,
    /// The answer is for another challenge: an old answer replayed.
    WrongChallenge,
    /// The answer is about another card.
    WrongCard,
    /// The answer has expired.
    Expired,
    /// The answer was signed by Seal code with another measurement.
    WrongMeasurement,
}

/// Checks the Seal's answers, as a phone does: the Seal's public key and the
/// code measurement it expects are pinned.
pub struct AnswerVerifier {
    key: VerifyingKey<MlDsa65>,
    measurement: [u8; MEASUREMENT_BYTES],
}

impl AnswerVerifier {
    /// A verifier for the Seal's encoded ML-DSA-65 public key.
    pub fn new(verifying_key: &[u8], measurement: [u8; MEASUREMENT_BYTES]) -> Result<AnswerVerifier, AnswerRejected> {
        let encoded =
            EncodedVerifyingKey::<MlDsa65>::try_from(verifying_key).map_err(|_| AnswerRejected::Malformed)?;
        Ok(AnswerVerifier { key: VerifyingKey::decode(&encoded), measurement })
    }

    /// Accepts an answer only when its signature verifies, it answers this
    /// `challenge` about card `uid`, it has not expired at `now` and it was
    /// signed by the pinned Seal code.
    pub fn verify(
        &self,
        bytes: &[u8],
        signature: &[u8],
        challenge: &[u8; 32],
        uid: &CardUid,
        now: u64,
    ) -> Result<AnswerBody, AnswerRejected> {
        let signature = Signature::<MlDsa65>::try_from(signature).map_err(|_| AnswerRejected::Malformed)?;
        if !self.key.verify_with_context(bytes, ANSWER_CONTEXT, &signature) {
            return Err(AnswerRejected::BadSignature);
        }
        let body = AnswerBody::decode(bytes).ok_or(AnswerRejected::Malformed)?;
        if body.measurement != self.measurement {
            return Err(AnswerRejected::WrongMeasurement);
        }
        if &body.challenge != challenge {
            return Err(AnswerRejected::WrongChallenge);
        }
        if &body.uid != uid {
            return Err(AnswerRejected::WrongCard);
        }
        if now >= body.expires_at {
            return Err(AnswerRejected::Expired);
        }
        Ok(body)
    }
}
