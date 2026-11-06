//! The Seal: the logic that talks to Ghost Sealed NTAG 424 DNA cards end to
//! end and runs Fill, Check and Open. It is what later runs inside the
//! enclave; it has no networking and no cloud code. Everything it needs from
//! outside (randomness, the clock, the card transport the phone relays, the
//! chain check, the wallet core's Phantom Key derivation and the journal
//! store) comes in through a trait.
//!
//! The design, the record layout, the frame and answer formats and the
//! labels of every key derivation are in `docs/sealed-card.md`.
//!
//! Secrets (the master key M, card keys, session keys, Phantom Keys and
//! PINs) are never logged, formatted or returned, except the Phantom Key an
//! Open releases, and that only encrypted to the phone key bound when the
//! Open started. Nothing hands M out.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod answer;
pub mod apdu;
pub mod card_keys;
pub mod error;
pub mod flows;
pub mod journal;
pub mod link;
pub mod primitives;
pub mod record;
pub mod release;
pub mod secrets;
pub mod session;
pub mod traits;

pub use answer::{AnswerBody, AnswerKind, AnswerRejected, AnswerVerifier, SignedAnswer};
pub use card_keys::{CardKeys, CardUid, card_keys, card_keys_at};
pub use error::SealError;
pub use flows::{CheckRequest, FillOutcome, FillRequest, OpenOutcome, OpenRequest, Seal, SealConfig};
pub use journal::{EntryKind, Journal, MemoryJournal};
pub use record::CardState;
pub use release::PhoneSecret;
pub use secrets::{MasterKey, PhantomKey, Pin};
pub use traits::{
    CardTransport, ChainCheck, Clock, CoinClaim, Dropped, MadeKey, PaymentVerdict, PhantomKeyMaker, SealRandom,
    SystemClock, SystemRandom,
};
