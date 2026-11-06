//! `seal-setup`: sets up Ghost **test** cards on the Mac Studio, with the
//! dev test Seal's master key only, and records each one in a card registry
//! file. It runs the Seal's own setup flow (`ghost_seal::set_up_card`) over a
//! card transport: the PC/SC reader behind the `pcsc-reader` feature, or a
//! simulated card in the tests.
//!
//! Production cards are never set up by this tool: the production master key
//! exists only inside the enclave, and production cards are loaded by the card
//! maker's key-loading service as `docs/card-setup.md` describes.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::PathBuf;

use ghost_seal::card_keys::CardUid;
use ghost_seal::primitives::sha3_256;
use ghost_seal::registry::date_of_unix;
use ghost_seal::{CardTransport, FileRegistry, MasterKey, SealError, SealRandom, SetupReport, SetupRequest, set_up_card};

#[cfg(feature = "pcsc-reader")]
pub mod reader;

/// The text whose SHA3-256 is the dev test Seal's master key. The test Seal
/// server uses the same value; it guards test cards only.
pub const DEV_TEST_MASTER_LABEL: &str = "ghost-seal/dev-test-master/v1";

/// The flag without which the tool refuses to run.
pub const DEV_TEST_FLAG: &str = "--dev-test-seal";

/// How to use the tool.
pub const USAGE: &str = "usage: seal-setup --dev-test-seal --batch <name> --registry <file> \
[--uid <14 hex digits>] [--date YYYY-MM-DD] [--reader <name>]

Sets up one test card on the reader with the dev test Seal's keys and records
it in the registry file. Test cards only: production cards are loaded by the
card maker (docs/card-setup.md). Run it in a room with no other readers.";

/// The dev test Seal's master key: SHA3-256 of [`DEV_TEST_MASTER_LABEL`].
pub fn dev_test_master() -> MasterKey {
    let mut bytes = sha3_256(&[DEV_TEST_MASTER_LABEL.as_bytes()]);
    MasterKey::take(&mut bytes)
}

/// What the command line asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// The batch recorded with the card.
    pub batch: String,
    /// The registry file.
    pub registry: PathBuf,
    /// The UID the operator expects; the reader's must match it.
    pub uid: Option<CardUid>,
    /// The set-up date to record; today (UTC) when not given.
    pub date: Option<String>,
    /// The reader to use; the only one attached when not given.
    pub reader: Option<String>,
}

/// What the command line asked for instead of a setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `--help`.
    Help,
    /// A command line the tool does not run, and why.
    Usage(String),
}

/// Reads the arguments (without the program name).
pub fn parse_args(args: &[String]) -> Result<Options, Refusal> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        return Err(Refusal::Help);
    }
    if !args.iter().any(|a| a == DEV_TEST_FLAG) {
        return Err(Refusal::Usage(format!(
            "refusing to run without {DEV_TEST_FLAG}: this tool sets up test cards with the dev test Seal only; \
             production cards are set up by the card maker (docs/card-setup.md)"
        )));
    }
    let (mut batch, mut registry, mut uid, mut date, mut reader) = (None, None, None, None, None);
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg == DEV_TEST_FLAG {
            continue;
        }
        let mut value = || rest.next().cloned().ok_or_else(|| Refusal::Usage(format!("{arg} needs a value")));
        match arg.as_str() {
            "--batch" => batch = Some(value()?),
            "--registry" => registry = Some(PathBuf::from(value()?)),
            "--uid" => uid = Some(parse_uid(&value()?).ok_or_else(|| Refusal::Usage("--uid is 14 hex digits".into()))?),
            "--date" => date = Some(value()?),
            "--reader" => reader = Some(value()?),
            other => return Err(Refusal::Usage(format!("unknown argument {other}"))),
        }
    }
    let batch = batch.ok_or_else(|| Refusal::Usage("--batch is required".into()))?;
    let registry = registry.ok_or_else(|| Refusal::Usage("--registry is required".into()))?;
    Ok(Options { batch, registry, uid, date, reader })
}

/// A 7-byte UID from 14 hex digits (spaces and colons allowed between bytes).
pub fn parse_uid(text: &str) -> Option<CardUid> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    if digits.len() != 14 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut uid = [0u8; 7];
    for (i, byte) in uid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(CardUid(uid))
}

/// A UID as lowercase hex.
pub fn uid_hex(uid: &CardUid) -> String {
    uid.0.iter().map(|b| format!("{b:02x}")).collect()
}

/// Sets up the card on `card`, whose reader reported `uid`, with the dev
/// test Seal's keys, and records it in the registry file. `now_unix` dates
/// the entry when `--date` was not given.
pub fn run_setup(
    card: &mut dyn CardTransport,
    uid: CardUid,
    options: &Options,
    now_unix: u64,
    random: &mut dyn SealRandom,
) -> Result<SetupReport, SealError> {
    if options.uid.is_some_and(|expected| expected != uid) {
        return Err(SealError::UnknownKeys);
    }
    let mut registry = FileRegistry::open(&options.registry)?;
    let request = SetupRequest {
        uid,
        set_up_on: options.date.clone().unwrap_or_else(|| date_of_unix(now_unix)),
        batch: options.batch.clone(),
    };
    set_up_card(card, &dev_test_master(), &request, random, &mut registry)
}

/// One line about what a setup did.
pub fn describe(uid: &CardUid, report: &SetupReport) -> String {
    let uid = uid_hex(uid);
    if report.already_registered {
        format!("{uid}: already set up and registered; verified, nothing changed")
    } else if report.resumed {
        format!("{uid}: finished a setup that was cut off ({} keys changed), verified and registered", report.keys_changed)
    } else {
        format!("{uid}: set up ({} keys changed), verified and registered", report.keys_changed)
    }
}
