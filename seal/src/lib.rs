//! The Seal: the logic that talks to Ghost Sealed NTAG 424 DNA cards end to
//! end and runs Fill, Check and Open. It is what later runs inside the
//! enclave; it has no networking and no cloud code. Everything it needs from
//! outside (randomness, the clock, the card transport the phone relays, the
//! chain nodes, the wallet core's Phantom Key derivation and the journal
//! store) comes in through a trait. The chain check (`chain_check`) reuses
//! the wallet core's coin-tree check, coin leaf code and settlement depth.
//!
//! The design, the record layout, the frame and answer formats and the
//! labels of every key derivation are in `docs/sealed-card.md`.
//!
//! Secrets (the master key M, card keys, session keys, Phantom Keys and
//! PINs) are never logged, formatted or returned, except the Phantom Key an
//! Open releases, and that only encrypted to the phone key bound when the
//! Open started. Nothing hands M out.
//!
//! The `nitro` feature (off by default) adds what runs the Seal on AWS Nitro
//! Enclaves: the published measurements (`measurements`), checking and
//! asking for attestation documents (`attestation`), the handover of M
//! between attested enclaves, the only way M ever leaves one, and only
//! encrypted to an attested copy (`key_share`), the document phones get
//! (`phone_attestation`) and the parent proxy (`proxy`). Its design is in
//! `docs/seal-enclave.md`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod answer;
pub mod apdu;
#[cfg(feature = "nitro")]
pub mod attestation;
pub mod card_keys;
pub mod chain_check;
pub mod error;
pub mod flows;
pub mod journal;
#[cfg(feature = "nitro")]
pub mod key_share;
pub mod link;
#[cfg(feature = "nitro")]
pub mod measurements;
#[cfg(feature = "nitro")]
pub mod phone_attestation;
pub mod primitives;
#[cfg(feature = "nitro")]
pub mod proxy;
pub mod record;
pub mod registry;
pub mod release;
pub mod secrets;
pub mod session;
pub mod setup;
pub mod traits;

pub use answer::{AnswerBody, AnswerKind, AnswerRejected, AnswerVerifier, SignedAnswer};
pub use card_keys::{CardKeys, CardUid, card_keys, card_keys_at};
pub use chain_check::{
    BlockRef, ChainNode, CoinQuery, CoinStatus, CoinStatusCheck, CoinTreeAt, Network, NodeChainCheck, NodeError,
    NodeListError, TxOutcome, VanishReceipt,
};
pub use error::SealError;
pub use flows::{CheckRequest, FillOutcome, FillRequest, OpenOutcome, OpenRequest, Seal, SealConfig};
pub use journal::{EntryKind, Journal, MemoryJournal};
pub use record::CardState;
pub use registry::{CardRegistry, FileRegistry, MemoryRegistry, RegistryEntry};
pub use setup::{SetupReport, SetupRequest, set_up_card};
pub use release::PhoneSecret;
pub use secrets::{MasterKey, PhantomKey, Pin};
pub use traits::{
    CardTransport, ChainCheck, Clock, CoinClaim, Dropped, MadeKey, PaymentVerdict, PhantomKeyMaker, SealRandom,
    SystemClock, SystemRandom,
};
