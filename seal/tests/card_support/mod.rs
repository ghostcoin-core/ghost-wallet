//! Helpers for the card setup and registry tests, over the simulated card of
//! `tests/support`.
#![allow(dead_code)]

use std::path::PathBuf;

use ghost_seal::card_keys::{CardUid, card_keys, key_version};
use ghost_seal::flows::record_file_settings;
use ghost_seal::{CardRegistry, MasterKey, SealError, SetupReport, SetupRequest, set_up_card};

use crate::support::{SimCard, TestRandom, master};

/// The batch the tests set cards up in.
pub const BATCH: &str = "test-batch-1";
/// The set-up date the tests record.
pub const DATE: &str = "2026-11-06";

/// A setup of card `uid` in the test batch.
pub fn request(uid: CardUid) -> SetupRequest {
    SetupRequest { uid, set_up_on: DATE.to_owned(), batch: BATCH.to_owned() }
}

/// Runs the setup with the test master key on `card`, for its own UID.
pub fn run_setup(card: &mut SimCard, registry: &mut dyn CardRegistry, label: u64) -> Result<SetupReport, SealError> {
    let uid = CardUid(card.uid);
    set_up_card(card, &master(), &request(uid), &mut TestRandom::new(label), registry)
}

/// Everything a setup could change on a card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardSnapshot {
    pub keys: [[u8; 16]; 5],
    pub versions: [u8; 5],
    pub settings: [u8; 3],
    pub file: Vec<u8>,
}

pub fn snapshot(card: &SimCard) -> CardSnapshot {
    CardSnapshot { keys: card.keys, versions: card.versions, settings: card.settings, file: card.file.clone() }
}

/// The card as the setup must leave it: the five keys M derives for its UID
/// at generation 0, each with the generation 0 version, file 2 in
/// CommMode.Full with exactly the Seal's rights and SDM off, the record blank.
pub fn expected_set_up(uid: CardUid, master: &MasterKey) -> CardSnapshot {
    let keys = card_keys(master, &uid);
    CardSnapshot {
        keys: [0u8, 1, 2, 3, 4].map(|k| *keys.key(k)),
        versions: [key_version(0); 5],
        settings: record_file_settings(),
        file: vec![0u8; 256],
    }
}

pub fn assert_set_up(card: &SimCard) {
    let uid = CardUid(card.uid);
    assert_eq!(snapshot(card), expected_set_up(uid, &master()));
    // FileOption: CommMode.Full (bits 0-1 = 11), SDM off (bit 6 clear).
    assert_eq!(card.settings[0], 0x03);
    assert_eq!(card.settings[0] & 0x40, 0);
    // Read&Write key 2, Change key 0, Read key 1, Write key 2.
    assert_eq!(card.settings[1..], [0x20, 0x12]);
}

/// The commands (not the answers) a card was sent, from a transcript with
/// no dropped command.
pub fn commands(card: &SimCard) -> Vec<Vec<u8>> {
    card.transcript.iter().step_by(2).cloned().collect()
}

/// Whether any command in `commands` is the native command `ins`.
pub fn sent_command(commands: &[Vec<u8>], ins: u8) -> bool {
    commands.iter().any(|apdu| apdu.len() >= 2 && apdu[0] == 0x90 && apdu[1] == ins)
}

/// A fresh path in the temporary directory for a registry file.
pub fn temp_registry(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("ghost-seal-registry-{}-{name}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}
