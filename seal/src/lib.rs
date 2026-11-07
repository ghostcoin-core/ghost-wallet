//! The Seal: the logic that talks to Ghost Sealed NTAG 424 DNA cards end to
//! end and runs Fill, Check and Open. It is what later runs inside the
//! enclave; it has no networking and no cloud code. Everything it needs from
//! outside (randomness, the clock, the card transport the phone relays, the
//! chain nodes, the wallet core's Phantom Key derivation and the journal
//! store) comes in through a trait. The Phantom Key maker (`key_maker`,
//! `CoreKeyMaker`) is the wallet core's own derivation, drawing its
//! randomness from the Seal's source. The chain check (`chain_check`) reuses
//! the wallet core's coin-tree check, coin leaf code and settlement depth.
//! `Seal::new` is the only way to build a Seal, and it takes the chain
//! status check and the card registry (`registry`): no Seal answers Sealed
//! unchecked or serves an unregistered card. The release node list the
//! chain check asks is compiled in (`node_list`); the real node, JSON-RPC
//! over TLS 1.3, is `node_rpc` (features `nitro` and `test-server`). The
//! journal's durable layer is an append-only log of records sealed under M
//! and chained by counter and tag (`journal_log`), kept by a store the Seal
//! does not trust: the parent host's file (`host_journal`, features `nitro`
//! and `test-server`). Its head is anchored in the other regions, which keep
//! a copy of each region's log (ciphertext only), restore their copies at
//! their own start and restore a cut or lost one; every answer between
//! regions carries the responder's fresh attestation, and each card is
//! served by its home region only (`journal_anchor`).
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
//! (`phone_attestation`), the parent proxy (`proxy`), and the relay served
//! to phones from the enclave: its HTTP routes (`relay_http`), TLS ended
//! inside the enclave (`enclave_tls`) and the service port that carries both
//! TLS and the framed key-share protocol (`enclave_serve`). Its design is in
//! `docs/seal-enclave.md`.
//!
//! The phone carries the Seal's card traffic (`relay`): each APDU and each
//! answer crosses it as opaque bytes, over the wire format in
//! `docs/seal-relay.md`. The `test-server` feature (off by default) adds a
//! development test Seal that serves it over HTTP(S) with a public test M,
//! a card registry file and the chain check over real nodes
//! (`test_server`), for development and the speed test only, never for real
//! money.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod answer;
pub mod apdu;
#[cfg(feature = "nitro")]
pub mod attestation;
pub mod card_keys;
pub mod chain_check;
#[cfg(feature = "nitro")]
pub mod enclave_serve;
#[cfg(feature = "nitro")]
pub mod enclave_tls;
pub mod error;
pub mod flows;
#[cfg(any(feature = "nitro", feature = "test-server"))]
pub mod host_journal;
pub mod journal;
pub mod journal_anchor;
pub mod journal_log;
pub mod key_maker;
#[cfg(feature = "nitro")]
pub mod key_share;
pub mod link;
#[cfg(feature = "nitro")]
pub mod measurements;
pub mod node_list;
#[cfg(any(feature = "nitro", feature = "test-server"))]
pub mod node_rpc;
#[cfg(feature = "nitro")]
pub mod phone_attestation;
pub mod primitives;
#[cfg(feature = "nitro")]
pub mod proxy;
pub mod record;
pub mod registry;
pub mod relay;
#[cfg(feature = "nitro")]
pub mod relay_http;
pub mod release;
pub mod secrets;
pub mod session;
pub mod setup;
#[cfg(feature = "test-server")]
pub mod test_server;
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
pub use journal_anchor::{Anchor, AnswerAttester, Peer, PeerLink, PeerLogs, Peers, Regions};
pub use journal_log::{HeadAnchor, JournalLog, LogStore, MemoryLogStore, SharedLog};
pub use key_maker::CoreKeyMaker;
pub use record::CardState;
pub use node_list::{NodeEntry, NodeList};
pub use registry::{CardRegistry, FileRegistry, LoadedRegistry, MemoryRegistry, RegistryEntry};
pub use relay::{
    Finished, FlowStep, KeyMakerFactory, PaymentCheckFactory, Relay, RelayError, RelayLimits, SessionId, Step,
};
pub use setup::{SetupReport, SetupRequest, set_up_card};
pub use release::PhoneSecret;
pub use secrets::{MasterKey, PhantomKey, Pin};
pub use traits::{
    CardTransport, ChainCheck, Clock, CoinClaim, Dropped, MadeKey, PaymentVerdict, PhantomKeyMaker, SealRandom,
    SystemClock, SystemRandom,
};
