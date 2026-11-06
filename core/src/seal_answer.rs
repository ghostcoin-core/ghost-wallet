//! The phone's check of the Seal's signed answers (`docs/sealed-card.md`,
//! "Signed answers"; the Seal's own reference is `AnswerVerifier` in
//! `seal/src/answer.rs`).
//!
//! Every Check, Fill and Open answer is 203 bytes signed with ML-DSA-65
//! (FIPS 204, context [`ANSWER_CONTEXT`]). The phone accepts one only when:
//!
//! - the Seal's code measurement it was given is on the app's pinned list;
//! - the signature verifies under the Seal's key;
//! - the answer carries that same measurement;
//! - it answers the flow the phone ran, over the challenge the phone just
//!   sent, about the card it tapped;
//! - it has not expired;
//! - for a Fill, it binds the commit data the Seal handed back (and an Open's
//!   binding of its release package is checked in `crate::seal_open`).
//!
//! The state, amount and PIN status the app shows come from these checked
//! bytes only. No cryptography is written here: ML-DSA is `ml-dsa` and
//! SHA3-256 is `sha3`, at the versions `seal/` pins.

use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use sha3::{Digest, Sha3_256};

/// The answer's domain.
pub const ANSWER_DOMAIN: &[u8; 20] = b"ghost-seal/v1/answer";
/// The ML-DSA context string of every answer signature.
pub const ANSWER_CONTEXT: &[u8] = b"ghost-seal answer";
/// The answer's length.
pub const ANSWER_BYTES: usize = 203;
/// The length of the Seal's code measurement (PCR0, SHA-384).
pub const MEASUREMENT_BYTES: usize = 48;
/// The length of a card UID.
pub const CARD_UID_BYTES: usize = 7;
/// The length of the phone's challenge.
pub const CHALLENGE_BYTES: usize = 32;

/// What a checked answer says. Public values only: nothing here is secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SealAnswer {
    /// Which flow answered: `check`, `fill` or `open`.
    pub kind: String,
    /// The card's UID (7 bytes).
    pub uid: Vec<u8>,
    /// The card's key generation.
    pub generation: u32,
    /// SHA3-256 of the coin's commit data (zeros for an empty card).
    pub coin: Vec<u8>,
    /// The card's state: `empty`, `sealed`, `opening` or `opened`.
    pub state: String,
    /// The coin's amount in wei, as decimal digits (0 for an empty card).
    pub amount_wei: String,
    /// The answer is not to be trusted at or after this time (Unix seconds).
    pub expires_at: u64,
    /// SHA3-256 of what the answer hands over with it, or zeros.
    pub binding: Vec<u8>,
    /// Whether an Open of this card needs its Open PIN.
    pub pin_required: bool,
    /// Open PIN tries left (0 without a PIN).
    pub pin_tries_left: u8,
}

/// What the phone checks an answer against.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SealAnswerCheck {
    /// The Seal's encoded ML-DSA-65 verifying key.
    pub verifying_key: Vec<u8>,
    /// The Seal's code measurement, as its attestation gave it (48 bytes).
    pub measurement: Vec<u8>,
    /// The measurements the app pins (each 48 bytes): the PCR0 of every
    /// allowed build of `lib/seal/pinned-measurements.ts`.
    pub pinned_measurements: Vec<Vec<u8>>,
    /// The answer bytes.
    pub answer: Vec<u8>,
    /// The ML-DSA-65 signature over them.
    pub signature: Vec<u8>,
    /// The challenge the phone sent (32 bytes).
    pub challenge: Vec<u8>,
    /// The UID of the card the phone tapped (7 bytes).
    pub uid: Vec<u8>,
    /// Now, in Unix seconds.
    pub now: u64,
    /// The flow the phone ran: `check`, `fill` or `open`.
    pub kind: String,
}

/// The verdict on an answer: `refusal` is empty and `answer` set when it was
/// accepted. Otherwise `refusal` says why, and nothing the answer says is
/// handed back.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SealAnswerVerdict {
    /// `""` when accepted, else one of [`Refusal::code`]'s codes.
    pub refusal: String,
    /// The checked answer, only when accepted.
    pub answer: Option<SealAnswer>,
}

/// Why an answer was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The Seal's measurement is not on the app's pinned list (the list is
    /// empty until the first Seal build is published).
    NotPinned,
    /// Not answer bytes, a key or signature of the wrong size, or a
    /// challenge or UID of the wrong length.
    Malformed,
    /// The signature does not verify under the Seal's key.
    BadSignature,
    /// The answer was signed by Seal code with another measurement.
    WrongMeasurement,
    /// The answer is about another flow.
    WrongKind,
    /// The answer is for another challenge: an old answer replayed.
    WrongChallenge,
    /// The answer is about another card.
    WrongCard,
    /// The answer has expired.
    Expired,
    /// The answer does not bind what came with it.
    WrongBinding,
}

impl Refusal {
    /// The refusal's code, as JavaScript sees it.
    pub fn code(self) -> &'static str {
        match self {
            Refusal::NotPinned => "not-pinned",
            Refusal::Malformed => "malformed",
            Refusal::BadSignature => "bad-signature",
            Refusal::WrongMeasurement => "wrong-measurement",
            Refusal::WrongKind => "wrong-kind",
            Refusal::WrongChallenge => "wrong-challenge",
            Refusal::WrongCard => "wrong-card",
            Refusal::Expired => "expired",
            Refusal::WrongBinding => "wrong-binding",
        }
    }
}

const KINDS: [&str; 3] = ["check", "fill", "open"];
const STATES: [&str; 4] = ["empty", "sealed", "opening", "opened"];

/// SHA3-256 of `data`.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data).into()
}

/// Reads answer bytes, refusing anything that is not exactly an answer.
pub fn decode_answer(bytes: &[u8]) -> Option<SealAnswer> {
    if bytes.len() != ANSWER_BYTES || &bytes[..20] != ANSWER_DOMAIN {
        return None;
    }
    let kind = KINDS.get(usize::from(bytes[20]).checked_sub(1)?)?;
    let state = STATES.get(usize::from(bytes[144]))?;
    let pin_required = match bytes[201] {
        0 => false,
        1 => true,
        _ => return None,
    };
    let pin_tries_left = bytes[202];
    if !pin_required && pin_tries_left != 0 {
        return None;
    }
    Some(SealAnswer {
        kind: (*kind).to_owned(),
        uid: bytes[53..60].to_vec(),
        generation: u32::from_be_bytes(bytes[60..64].try_into().ok()?),
        coin: bytes[64..96].to_vec(),
        state: (*state).to_owned(),
        amount_wei: u128::from_be_bytes(bytes[145..161].try_into().ok()?).to_string(),
        expires_at: u64::from_be_bytes(bytes[161..169].try_into().ok()?),
        binding: bytes[169..201].to_vec(),
        pin_required,
        pin_tries_left,
    })
}

/// Checks an answer; `bound` is what a Fill answer must bind (its commit
/// data), or nothing.
pub fn check_answer(check: &SealAnswerCheck, bound: Option<&[u8]>) -> Result<SealAnswer, Refusal> {
    if check.measurement.len() != MEASUREMENT_BYTES
        || !check.pinned_measurements.iter().any(|pinned| pinned.as_slice() == check.measurement.as_slice())
    {
        return Err(Refusal::NotPinned);
    }
    if check.challenge.len() != CHALLENGE_BYTES || check.uid.len() != CARD_UID_BYTES {
        return Err(Refusal::Malformed);
    }
    let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(check.verifying_key.as_slice())
        .map_err(|_| Refusal::Malformed)?;
    let key = VerifyingKey::<MlDsa65>::decode(&encoded);
    let signature = Signature::<MlDsa65>::try_from(check.signature.as_slice()).map_err(|_| Refusal::Malformed)?;
    if !key.verify_with_context(&check.answer, ANSWER_CONTEXT, &signature) {
        return Err(Refusal::BadSignature);
    }
    let answer = decode_answer(&check.answer).ok_or(Refusal::Malformed)?;
    if check.answer[96..144] != check.measurement[..] {
        return Err(Refusal::WrongMeasurement);
    }
    if answer.kind != check.kind {
        return Err(Refusal::WrongKind);
    }
    if answer_challenge(&check.answer) != check.challenge.as_slice() {
        return Err(Refusal::WrongChallenge);
    }
    if answer.uid != check.uid {
        return Err(Refusal::WrongCard);
    }
    if check.now >= answer.expires_at {
        return Err(Refusal::Expired);
    }
    if let Some(bound) = bound {
        let hash = sha3_256(bound);
        if answer.binding != hash || (answer.kind == "fill" && answer.coin != hash) {
            return Err(Refusal::WrongBinding);
        }
    }
    Ok(answer)
}

fn answer_challenge(bytes: &[u8]) -> &[u8] {
    &bytes[21..53]
}

pub(crate) fn verdict(result: Result<SealAnswer, Refusal>) -> SealAnswerVerdict {
    match result {
        Ok(answer) => SealAnswerVerdict { refusal: String::new(), answer: Some(answer) },
        Err(refusal) => SealAnswerVerdict { refusal: refusal.code().to_owned(), answer: None },
    }
}

/// Checks a Check answer (or any answer that hands nothing over with it).
#[uniffi::export]
pub fn verify_seal_answer(check: SealAnswerCheck) -> SealAnswerVerdict {
    verdict(check_answer(&check, None))
}

/// Checks a Fill answer, which must bind exactly `commit_data`: the answer's
/// coin and binding are both its SHA3-256.
#[uniffi::export]
pub fn verify_seal_fill_answer(check: SealAnswerCheck, commit_data: Vec<u8>) -> SealAnswerVerdict {
    if check.kind != "fill" {
        return verdict(Err(Refusal::WrongKind));
    }
    verdict(check_answer(&check, Some(&commit_data)))
}
