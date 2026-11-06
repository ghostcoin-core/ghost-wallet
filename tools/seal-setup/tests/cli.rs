//! The setup tool: it refuses to run without `--dev-test-seal`, uses the dev
//! test Seal's master key, and sets up and registers a simulated card.

#[path = "../../../seal/tests/support/mod.rs"]
mod support;

use std::path::PathBuf;
use std::process::Command;

use ghost_seal::card_keys::{CardUid, card_keys, key_version};
use ghost_seal::flows::record_file_settings;
use ghost_seal::primitives::sha3_256;
use ghost_seal::{CardRegistry, FileRegistry, MasterKey, SealError};
use seal_setup::{DEV_TEST_FLAG, DEV_TEST_MASTER_LABEL, Options, Refusal, describe, dev_test_master, parse_args, run_setup};
use support::{SimCard, TestRandom, UID, hex, unhex};

/// The dev test master key the test Seal server also uses.
const DEV_TEST_MASTER_HEX: &str = "d7c19145c84d99edf3c8fbe63d29dfe4e7a89e39e5454e3903a123e4cf7b6040";

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn temp_registry(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("seal-setup-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

fn options(registry: PathBuf) -> Options {
    Options { batch: "mac-studio-test".into(), registry, uid: None, date: Some("2026-11-06".into()), reader: None }
}

#[test]
fn the_dev_test_master_is_sha3_of_its_label() {
    assert_eq!(DEV_TEST_MASTER_LABEL, "ghost-seal/dev-test-master/v1");
    assert_eq!(hex(&sha3_256(&[DEV_TEST_MASTER_LABEL.as_bytes()])).to_lowercase(), DEV_TEST_MASTER_HEX);
    // The tool derives card keys from exactly that value.
    let mut bytes: [u8; 32] = unhex(DEV_TEST_MASTER_HEX).try_into().unwrap();
    let expected = card_keys(&MasterKey::take(&mut bytes), &UID);
    let derived = card_keys(&dev_test_master(), &UID);
    for key_no in 0..5u8 {
        assert_eq!(derived.key(key_no), expected.key(key_no));
    }
}

#[test]
fn it_refuses_to_run_without_the_dev_test_flag() {
    let refused = parse_args(&args(&["--batch", "b1", "--registry", "/tmp/r"]));
    match refused {
        Err(Refusal::Usage(why)) => assert!(why.contains(DEV_TEST_FLAG), "{why}"),
        other => panic!("not refused: {other:?}"),
    }
    let output = Command::new(env!("CARGO_BIN_EXE_seal-setup"))
        .args(["--batch", "b1", "--registry", "/tmp/seal-setup-never-written"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to run without --dev-test-seal"));
    assert!(!std::path::Path::new("/tmp/seal-setup-never-written").exists());
}

#[cfg(not(feature = "pcsc-reader"))]
#[test]
fn a_default_build_has_no_reader_and_says_so() {
    let output = Command::new(env!("CARGO_BIN_EXE_seal-setup"))
        .args([DEV_TEST_FLAG, "--batch", "b1", "--registry", "/tmp/seal-setup-never-written"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("pcsc-reader"));
}

#[test]
fn it_reads_its_arguments() {
    let options = parse_args(&args(&[
        DEV_TEST_FLAG,
        "--batch",
        "lot-7",
        "--registry",
        "cards.registry",
        "--uid",
        "04:51:8d:fa:a9:61:80",
        "--date",
        "2026-11-06",
    ]))
    .unwrap();
    assert_eq!(options.batch, "lot-7");
    assert_eq!(options.registry, PathBuf::from("cards.registry"));
    assert_eq!(options.uid, Some(UID));
    assert_eq!(options.date.as_deref(), Some("2026-11-06"));
    assert_eq!(options.reader, None);

    for bad in [
        &[DEV_TEST_FLAG, "--registry", "r"][..],
        &[DEV_TEST_FLAG, "--batch", "b"][..],
        &[DEV_TEST_FLAG, "--batch", "b", "--registry", "r", "--uid", "0451"][..],
        &[DEV_TEST_FLAG, "--batch", "b", "--registry", "r", "--master", "x"][..],
        &[DEV_TEST_FLAG, "--batch"][..],
    ] {
        assert!(matches!(parse_args(&args(bad)), Err(Refusal::Usage(_))), "{bad:?}");
    }
    assert_eq!(parse_args(&args(&["--help"])), Err(Refusal::Help));
}

#[test]
fn it_sets_up_and_registers_a_factory_card_with_the_dev_test_keys() {
    let path = temp_registry("factory");
    let mut card = SimCard::factory(UID.0);
    let report = run_setup(&mut card, UID, &options(path.clone()), 0, &mut TestRandom::new(1)).expect("setup");
    assert!(!report.already_registered);
    assert_eq!(report.keys_changed, 5);
    assert_eq!(describe(&UID, &report), "04518dfaa96180: set up (5 keys changed), verified and registered");

    let keys = card_keys(&dev_test_master(), &UID);
    for key_no in 0..5u8 {
        assert_eq!(&card.keys[usize::from(key_no)], keys.key(key_no));
        assert_eq!(card.versions[usize::from(key_no)], key_version(0));
    }
    assert_eq!(card.settings, record_file_settings());
    assert_eq!(card.file, vec![0u8; 256]);

    let registry = FileRegistry::open(&path).unwrap();
    let entry = registry.lookup(&UID).expect("registered");
    assert_eq!((entry.set_up_on(), entry.batch()), ("2026-11-06", "mac-studio-test"));

    // Again: verified, nothing changed, not registered twice.
    let before = (card.keys, card.versions, card.settings, card.file.clone());
    let again = run_setup(&mut card, UID, &options(path.clone()), 0, &mut TestRandom::new(2)).unwrap();
    assert!(again.already_registered);
    assert_eq!((card.keys, card.versions, card.settings, card.file.clone()), before);
    assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn it_dates_the_entry_today_when_no_date_is_given() {
    let path = temp_registry("today");
    let mut card = SimCard::factory(UID.0);
    let mut undated = options(path.clone());
    undated.date = None;
    run_setup(&mut card, UID, &undated, 1_800_000_000, &mut TestRandom::new(3)).unwrap();
    assert_eq!(FileRegistry::open(&path).unwrap().lookup(&UID).unwrap().set_up_on(), "2027-01-15");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn it_refuses_a_card_with_other_keys_or_another_uid_untouched() {
    // Set up under another master key (the Seal tests' key).
    let path = temp_registry("foreign");
    let mut card = SimCard::set_up(UID);
    let before = (card.keys, card.versions, card.settings);
    let result = run_setup(&mut card, UID, &options(path.clone()), 0, &mut TestRandom::new(4));
    assert_eq!(result.err(), Some(SealError::UnknownKeys));
    assert_eq!((card.keys, card.versions, card.settings), before);
    assert!(FileRegistry::open(&path).unwrap().entries().is_empty());

    // The reader reports another UID than the operator asked for.
    let mut card = SimCard::factory(UID.0);
    let mut expecting = options(path.clone());
    expecting.uid = Some(CardUid([0x04, 1, 2, 3, 4, 5, 6]));
    let result = run_setup(&mut card, UID, &expecting, 0, &mut TestRandom::new(5));
    assert_eq!(result.err(), Some(SealError::UnknownKeys));
    assert_eq!(card.sent, 0);
    let _ = std::fs::remove_file(&path);
}
