//! The release key tool's library: keygen, sign and verify, and the
//! enclave's own `TrustedList` taking a list the tool signed. Every key here
//! is a test-only key made from a fixed one-byte pattern (or a fresh random
//! key that is deleted at the end); none of them is the release key.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ghost_seal::measurements::{
    MeasurementList, Pcrs, RELEASE_CONTEXT, RELEASE_SIGNATURE_BYTES, ReleaseKey, TrustedList, parse_pcr,
};
use ml_dsa::{ExpandedSigningKey, MlDsa65, Seed};
use seal_release_key::{
    PUBLIC_HEX_DIGITS, SigningSeed, canonical_signed, hex, keygen, keygen_with_seed, read_key_file, read_public,
    sign_file, sign_text, verify_file, verify_text,
};

/// The pattern of the tests' stand-in release key.
const TEST_ONLY_PATTERN: u8 = 0x5e;
/// The pattern of a key that is not the stand-in (an attacker's).
const TEST_ONLY_OTHER_PATTERN: u8 = 0x6f;

const LIST: &str = r#"{
  "version": 1,
  "builds": [
    {"name": "seal-2026-10-01", "released": "2026-10-01",
     "pcr0": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
     "pcr1": "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1",
     "pcr2": "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1",
     "status": "revoked"},
    {"name": "seal-2026-11-01", "released": "2026-11-01",
     "pcr0": "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2",
     "pcr1": "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1",
     "pcr2": "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2",
     "status": "allowed"}
  ]
}"#;

/// A scratch directory for one test, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("seal-release-key-lib-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch directory");
        Scratch(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn test_seed(pattern: u8) -> SigningSeed {
    SigningSeed::from_bytes(&mut [pattern; 32])
}

/// The public half of a test-only key, computed straight from ml-dsa (not
/// through the tool), so the tool's derivation is checked too.
fn test_public(pattern: u8) -> Vec<u8> {
    ExpandedSigningKey::<MlDsa65>::from_seed(&Seed::from([pattern; 32])).verifying_key().encode().to_vec()
}

fn release_key(pattern: u8) -> ReleaseKey {
    ReleaseKey::from_bytes(&test_public(pattern)).expect("an ML-DSA-65 verifying key")
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}

fn write_list(scratch: &Scratch, name: &str, text: &str) -> PathBuf {
    let path = scratch.path(name);
    fs::write(&path, text).expect("write list");
    path
}

fn signature_field(text: &str) -> String {
    let start = text.find("\"signature\": \"").expect("a signature field") + "\"signature\": \"".len();
    let end = start + text[start..].find('"').expect("the signature's end");
    text[start..end].to_owned()
}

fn pcrs(a: &str, b: &str, c: &str) -> Pcrs {
    Pcrs {
        pcr0: parse_pcr(&a.repeat(48)).expect("pcr0"),
        pcr1: parse_pcr(&b.repeat(48)).expect("pcr1"),
        pcr2: parse_pcr(&c.repeat(48)).expect("pcr2"),
    }
}

#[test]
fn keygen_then_sign_then_verify_round_trip() {
    let scratch = Scratch::new("round-trip");
    let key = scratch.path("release.key");
    let public_hex = keygen_with_seed(&key, test_seed(TEST_ONLY_PATTERN)).expect("keygen");
    assert_eq!(public_hex, hex(&test_public(TEST_ONLY_PATTERN)));
    assert_eq!(public_hex.len(), PUBLIC_HEX_DIGITS);
    assert!(public_hex.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));

    // The key file is the seed as 64 lowercase hex digits and a newline.
    let text = fs::read_to_string(&key).expect("key file");
    assert_eq!(text, format!("{}\n", hex(&[TEST_ONLY_PATTERN; 32])));
    assert_eq!(mode(&key), 0o600);

    let list = write_list(&scratch, "measurements.json", LIST);
    let signed = scratch.path("signed.json");
    assert_eq!(sign_file(&list, &key, &signed, false).expect("sign"), 2);
    assert_eq!(verify_file(&signed, &public_hex).expect("verify with the hex"), 2);

    // The public half may also come from a file, with a trailing newline.
    let public_file = scratch.path("release.pub");
    fs::write(&public_file, format!("{public_hex}\n")).expect("public file");
    assert_eq!(verify_file(&signed, public_file.to_str().expect("utf-8 path")).expect("verify with a file"), 2);

    // The signed list holds the same builds and is what the Seal reads.
    let signed_text = fs::read_to_string(&signed).expect("signed list");
    assert_eq!(MeasurementList::parse(&signed_text).expect("parses"), MeasurementList::parse(LIST).expect("parses"));
    let checked = MeasurementList::parse_signed(&signed_text, &release_key(TEST_ONLY_PATTERN)).expect("verifies");
    assert_eq!(checked.builds().len(), 2);
    assert_eq!(signature_field(&signed_text).len(), 2 * RELEASE_SIGNATURE_BYTES);
}

#[test]
fn the_signature_is_over_the_signing_message_with_the_release_context() {
    let seed_key = ExpandedSigningKey::<MlDsa65>::from_seed(&Seed::from([TEST_ONLY_PATTERN; 32]));
    let list = MeasurementList::parse(LIST).expect("parses");
    let expected = seed_key.sign_deterministic(&list.signing_message(), RELEASE_CONTEXT).expect("signs");
    let signed = sign_text(LIST, &test_seed(TEST_ONLY_PATTERN)).expect("sign");
    assert_eq!(signature_field(&signed), hex(&expected.encode()));
    assert_eq!(signed, canonical_signed(&list, &hex(&expected.encode())));
}

#[test]
fn the_signed_list_has_one_canonical_layout() {
    let signed = sign_text(LIST, &test_seed(TEST_ONLY_PATTERN)).expect("sign");
    let signature = signature_field(&signed);
    let lines: Vec<&str> = signed.lines().collect();
    assert_eq!(lines.len(), 4, "{signed}");
    assert_eq!(lines[0], "{\"version\": 1, \"builds\": [");
    assert!(lines[1].starts_with("{\"name\": \"seal-2026-10-01\", \"released\": \"2026-10-01\", \"pcr0\": \"a1a1"));
    assert!(lines[1].ends_with("\"status\": \"revoked\"},"));
    assert!(lines[2].starts_with("{\"name\": \"seal-2026-11-01\""));
    assert!(lines[2].ends_with("\"status\": \"allowed\"}"));
    assert_eq!(lines[3], format!("], \"signature\": \"{signature}\"}}"));
    assert!(signed.ends_with("}\n"));

    // An empty list signs too, and is still read by the Seal.
    let empty = sign_text(r#"{"version": 1, "builds": []}"#, &test_seed(TEST_ONLY_PATTERN)).expect("sign");
    assert!(empty.starts_with("{\"version\": 1, \"builds\": [], \"signature\": \""));
    assert!(MeasurementList::parse_signed(&empty, &release_key(TEST_ONLY_PATTERN)).expect("verifies").is_empty());
}

#[test]
fn a_list_changed_after_signing_is_refused() {
    let scratch = Scratch::new("changed");
    let key = scratch.path("release.key");
    let public_hex = keygen_with_seed(&key, test_seed(TEST_ONLY_PATTERN)).expect("keygen");
    let list = write_list(&scratch, "measurements.json", LIST);
    let signed = scratch.path("signed.json");
    sign_file(&list, &key, &signed, false).expect("sign");
    let text = fs::read_to_string(&signed).expect("signed list");
    let public = read_public(&public_hex).expect("public");
    assert!(verify_text(&text, &public).is_ok());

    // The revoked build brought back, a PCR changed, a build dropped, a
    // build renamed: each is refused.
    let changes = [
        text.replacen("\"status\": \"revoked\"", "\"status\": \"allowed\"", 1),
        text.replacen("c2c2c2c2", "c3c2c2c2", 1),
        text.replacen("seal-2026-11-01\"", "seal-2026-11-02\"", 1),
        {
            let lines: Vec<&str> = text.lines().collect();
            format!("{}\n{}\n{}\n", lines[0], lines[2], lines[3])
        },
    ];
    for (index, changed) in changes.iter().enumerate() {
        assert_ne!(changed, &text, "change {index} changed nothing");
        assert!(MeasurementList::parse(changed).is_ok(), "change {index} still parses");
        assert!(verify_text(changed, &public).is_err(), "change {index} was accepted");
        let path = write_list(&scratch, &format!("changed-{index}.json"), changed);
        assert!(verify_file(&path, &public_hex).is_err(), "change {index} was accepted from a file");
    }

    // A changed signature is refused too, and so is no signature at all.
    let signature = signature_field(&text);
    let flipped = if signature.starts_with('0') { "1" } else { "0" };
    let bad_signature = text.replacen(&signature, &format!("{flipped}{}", &signature[1..]), 1);
    assert!(verify_text(&bad_signature, &public).is_err());
    assert!(verify_text(LIST, &public).is_err());

    // The signature covers the builds, not the spacing.
    let respaced = text.replace(", ", ",\n   ");
    assert!(verify_text(&respaced, &public).is_ok());
}

#[test]
fn a_signature_from_another_key_is_refused() {
    let signed = sign_text(LIST, &test_seed(TEST_ONLY_OTHER_PATTERN)).expect("sign");
    let release = read_public(&hex(&test_public(TEST_ONLY_PATTERN))).expect("public");
    assert!(verify_text(&signed, &release).is_err());
    let other = read_public(&hex(&test_public(TEST_ONLY_OTHER_PATTERN))).expect("public");
    assert!(verify_text(&signed, &other).is_ok());

    let mut trusted = TrustedList::compiled_in();
    assert!(trusted.install_signed(&signed, &release_key(TEST_ONLY_PATTERN)).is_err());
    assert!(!trusted.has_signed_list());
}

#[test]
fn an_already_signed_list_is_signed_again() {
    let scratch = Scratch::new("resign");
    let other_key = scratch.path("other.key");
    keygen_with_seed(&other_key, test_seed(TEST_ONLY_OTHER_PATTERN)).expect("keygen");
    let key = scratch.path("release.key");
    let public_hex = keygen_with_seed(&key, test_seed(TEST_ONLY_PATTERN)).expect("keygen");

    let list = write_list(&scratch, "measurements.json", LIST);
    let first = scratch.path("first.json");
    sign_file(&list, &other_key, &first, false).expect("sign with the other key");
    let second = scratch.path("second.json");
    sign_file(&first, &key, &second, false).expect("sign again");

    let second_text = fs::read_to_string(&second).expect("second");
    assert_eq!(second_text.matches("\"signature\"").count(), 1);
    assert_ne!(signature_field(&second_text), signature_field(&fs::read_to_string(&first).expect("first")));
    assert!(verify_file(&second, &public_hex).is_ok());
    assert!(verify_file(&first, &public_hex).is_err());
    // Signing the list again with the same key gives the same file.
    assert_eq!(second_text, sign_text(LIST, &test_seed(TEST_ONLY_PATTERN)).expect("sign"));

    // An existing output is kept unless --force.
    let before = fs::read_to_string(&first).expect("first");
    assert!(sign_file(&list, &key, &first, false).is_err());
    assert_eq!(fs::read_to_string(&first).expect("first"), before);
    sign_file(&list, &key, &first, true).expect("sign with force");
    assert_eq!(fs::read_to_string(&first).expect("first"), second_text);
}

#[test]
fn keygen_writes_a_private_file_and_never_overwrites_one() {
    let scratch = Scratch::new("keygen");
    let key = scratch.path("release.key");
    let public_hex = keygen(&key).expect("keygen");
    assert_eq!(mode(&key), 0o600);
    assert_eq!(public_hex.len(), PUBLIC_HEX_DIGITS);
    let first = fs::read(&key).expect("key file");
    assert_eq!(first.len(), 65);
    assert_eq!(first[64], b'\n');
    // The public half printed is the one of the seed written.
    assert_eq!(hex(&read_key_file(&key).expect("reads").public_bytes()), public_hex);

    // A second keygen to the same path is refused and leaves the file alone.
    assert!(keygen(&key).is_err());
    assert!(keygen_with_seed(&key, test_seed(TEST_ONLY_PATTERN)).is_err());
    assert_eq!(fs::read(&key).expect("key file"), first);
    assert_eq!(mode(&key), 0o600);

    // Two keygens make two different keys.
    let again = scratch.path("again.key");
    assert_ne!(keygen(&again).expect("keygen"), public_hex);
}

#[test]
fn sign_refuses_a_key_file_others_can_read() {
    let scratch = Scratch::new("mode");
    let key = scratch.path("release.key");
    keygen_with_seed(&key, test_seed(TEST_ONLY_PATTERN)).expect("keygen");
    let list = write_list(&scratch, "measurements.json", LIST);

    for open in [0o644, 0o640, 0o604, 0o660] {
        fs::set_permissions(&key, fs::Permissions::from_mode(open)).expect("chmod");
        let out = scratch.path(&format!("signed-{open:o}.json"));
        let refused = sign_file(&list, &key, &out, false).expect_err("an open key file is refused");
        assert!(refused.to_string().contains("group or others"), "{refused}");
        assert!(!out.exists(), "nothing is written for mode {open:o}");
    }

    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("chmod");
    let out = scratch.path("signed.json");
    sign_file(&list, &key, &out, false).expect("a 0600 key file signs");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).expect("chmod");
    let out = scratch.path("signed-400.json");
    sign_file(&list, &key, &out, false).expect("a 0400 key file signs");
}

#[test]
fn a_malformed_key_file_or_list_is_refused_without_echoing_it() {
    let scratch = Scratch::new("malformed");
    let list = write_list(&scratch, "measurements.json", LIST);
    let bad = scratch.path("bad.key");
    for content in [hex(&[0xab; 32]).to_uppercase(),hex(&[0xab; 31]), format!("{}\n\n", hex(&[0xab; 32])), String::new()] {
        let _ = fs::remove_file(&bad);
        fs::write(&bad, &content).expect("write");
        fs::set_permissions(&bad, fs::Permissions::from_mode(0o600)).expect("chmod");
        let refused = sign_file(&list, &bad, &scratch.path("out.json"), false).expect_err("refused").to_string();
        assert!(refused.contains("lowercase hex digits"), "{refused}");
        assert!(content.is_empty() || !refused.contains(content.trim()), "{refused}");
        assert!(!scratch.path("out.json").exists());
    }

    let key = scratch.path("release.key");
    keygen_with_seed(&key, test_seed(TEST_ONLY_PATTERN)).expect("keygen");
    let not_a_list = write_list(&scratch, "bad.json", r#"{"version": 2, "builds": []}"#);
    assert!(sign_file(&not_a_list, &key, &scratch.path("out.json"), false).is_err());
    assert!(!scratch.path("out.json").exists());
    assert!(read_public("abcd").is_err());
    assert!(read_public(&hex(&test_public(TEST_ONLY_PATTERN)).to_uppercase()).is_err());
}

#[test]
fn the_enclaves_trusted_list_accepts_a_list_the_tool_signed() {
    let scratch = Scratch::new("trusted");
    let key = scratch.path("release.key");
    let public_hex = keygen_with_seed(&key, test_seed(TEST_ONLY_PATTERN)).expect("keygen");
    let list = write_list(&scratch, "measurements.json", LIST);
    let signed = scratch.path("signed.json");
    sign_file(&list, &key, &signed, false).expect("sign");
    let text = fs::read_to_string(&signed).expect("signed list");

    // The public half as an enclave holds it: the bytes of the printed hex.
    let public: Vec<u8> = (0..public_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&public_hex[i..i + 2], 16).expect("hex"))
        .collect();
    let mut trusted = TrustedList::compiled_in();
    // Nothing is compiled in, so the new build is refused until the list is in.
    assert!(trusted.check(&pcrs("a2", "b1", "c2")).is_err());
    trusted.install_signed(&text, &ReleaseKey::from_bytes(&public).expect("key")).expect("installs");
    assert!(trusted.has_signed_list());
    assert_eq!(trusted.check(&pcrs("a2", "b1", "c2")).expect("allowed").name, "seal-2026-11-01");
    assert!(trusted.check(&pcrs("a1", "b1", "c1")).is_err(), "the revoked build stays refused");

    // A list the tool signed with another key is not installed.
    let other_key = scratch.path("other.key");
    keygen_with_seed(&other_key, test_seed(TEST_ONLY_OTHER_PATTERN)).expect("keygen");
    let forged = scratch.path("forged.json");
    sign_file(&list, &other_key, &forged, false).expect("sign");
    let mut fresh = TrustedList::compiled_in();
    let forged_text = fs::read_to_string(&forged).expect("forged");
    assert!(fresh.install_signed(&forged_text, &ReleaseKey::from_bytes(&public).expect("key")).is_err());
    assert!(!fresh.has_signed_list());
}
