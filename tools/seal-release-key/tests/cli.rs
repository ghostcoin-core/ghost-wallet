//! The built `seal-release-key` binary: what it prints, what it never prints
//! (the private half) and its exit codes. Keys here are fresh test-only keys
//! made in a scratch directory that is removed at the end.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_seal-release-key");

const LIST: &str = r#"{"version": 1, "builds": [
  {"name": "seal-2026-11-01", "released": "2026-11-01",
   "pcr0": "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2",
   "pcr1": "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1",
   "pcr2": "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2",
   "status": "allowed"}
]}"#;

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("seal-release-key-cli-{}-{name}", std::process::id()));
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

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().expect("the binary runs")
}

fn arg(path: &Path) -> &str {
    path.to_str().expect("a UTF-8 path")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("UTF-8 output")
}

/// Every command's output, gathered to check the private half is in none.
struct Outputs(Vec<Output>);

impl Outputs {
    fn run(&mut self, args: &[&str]) -> Output {
        let output = run(args);
        self.0.push(output.clone());
        output
    }

    fn assert_none_contains(&self, secret_hex: &str) {
        assert_eq!(secret_hex.len(), 64);
        for output in &self.0 {
            for stream in [&output.stdout, &output.stderr] {
                let stream = text(stream);
                assert!(!stream.contains(secret_hex), "an output holds the private half");
                assert!(!stream.to_uppercase().contains(&secret_hex.to_uppercase()), "an output holds the private half");
            }
        }
    }
}

fn key_hex(key: &Path) -> String {
    let content = fs::read_to_string(key).expect("key file");
    content.strip_suffix('\n').expect("a newline at the end").to_owned()
}

#[test]
fn keygen_prints_only_the_public_half() {
    let scratch = Scratch::new("keygen");
    let key = scratch.path("release.key");
    let mut outputs = Outputs(Vec::new());
    let keygen = outputs.run(&["keygen", "--out", arg(&key)]);
    assert!(keygen.status.success(), "{}", text(&keygen.stderr));
    let stdout = text(&keygen.stdout);
    assert_eq!(stdout.len(), 3905);
    assert!(stdout.ends_with('\n'));
    assert!(stdout[..3904].bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)), "{stdout}");
    assert!(keygen.stderr.is_empty(), "keygen wrote to stderr: {}", text(&keygen.stderr));

    let secret = key_hex(&key);
    assert!(!stdout.contains(&secret));

    // A second keygen to the same path is refused, says so plainly, and
    // leaves the key alone.
    let again = outputs.run(&["keygen", "--out", arg(&key)]);
    assert!(!again.status.success());
    assert!(again.stdout.is_empty());
    assert_eq!(text(&again.stderr).lines().count(), 1, "{}", text(&again.stderr));
    assert_eq!(key_hex(&key), secret);

    outputs.assert_none_contains(&secret);
}

#[test]
fn sign_and_verify_exit_codes_and_no_private_half_in_any_output() {
    let scratch = Scratch::new("sign-verify");
    let key = scratch.path("release.key");
    let other_key = scratch.path("other.key");
    let mut outputs = Outputs(Vec::new());
    let public = text(&outputs.run(&["keygen", "--out", arg(&key)]).stdout).trim_end().to_owned();
    let other_public = text(&outputs.run(&["keygen", "--out", arg(&other_key)]).stdout).trim_end().to_owned();
    assert_ne!(public, other_public);

    let list = scratch.path("measurements.json");
    fs::write(&list, LIST).expect("list");
    let signed = scratch.path("signed.json");

    let sign = outputs.run(&["sign", arg(&list), "--key", arg(&key), "--out", arg(&signed)]);
    assert!(sign.status.success(), "{}", text(&sign.stderr));
    assert!(text(&sign.stdout).starts_with("ok: signed 1 builds"));

    // An existing output is refused without --force, and taken with it.
    let again = outputs.run(&["sign", arg(&list), "--key", arg(&key), "--out", arg(&signed)]);
    assert_eq!(again.status.code(), Some(1));
    let forced = outputs.run(&["sign", arg(&list), "--key", arg(&key), "--out", arg(&signed), "--force"]);
    assert!(forced.status.success(), "{}", text(&forced.stderr));

    // Verify: 0 for the right key (as hex or as a file), 1 for anything else.
    let verify = outputs.run(&["verify", arg(&signed), "--public", &public]);
    assert_eq!(verify.status.code(), Some(0), "{}", text(&verify.stderr));
    assert!(text(&verify.stdout).starts_with("ok: "));
    let public_file = scratch.path("release.pub");
    fs::write(&public_file, format!("{public}\n")).expect("public file");
    assert_eq!(outputs.run(&["verify", arg(&signed), "--public", arg(&public_file)]).status.code(), Some(0));

    let refusals = [
        outputs.run(&["verify", arg(&signed), "--public", &other_public]),
        outputs.run(&["verify", arg(&list), "--public", &public]),
        {
            let changed = scratch.path("changed.json");
            let signed_text = fs::read_to_string(&signed).expect("signed");
            fs::write(&changed, signed_text.replacen("\"allowed\"", "\"revoked\"", 1)).expect("changed");
            outputs.run(&["verify", arg(&changed), "--public", &public])
        },
        outputs.run(&["verify", arg(&scratch.path("missing.json")), "--public", &public]),
        outputs.run(&["verify", arg(&signed), "--public", "abcd"]),
    ];
    for (index, refused) in refusals.iter().enumerate() {
        assert_eq!(refused.status.code(), Some(1), "refusal {index}");
        assert!(refused.stdout.is_empty(), "refusal {index}");
        let stderr = text(&refused.stderr);
        assert_eq!(stderr.lines().count(), 1, "refusal {index}: {stderr}");
        assert!(stderr.starts_with("seal-release-key: "), "refusal {index}: {stderr}");
    }

    // A key file others can read is refused.
    let open_key = scratch.path("open.key");
    fs::write(&open_key, fs::read(&key).expect("key")).expect("copy");
    fs::set_permissions(&open_key, fs::Permissions::from_mode(0o644)).expect("chmod");
    let open = outputs.run(&["sign", arg(&list), "--key", arg(&open_key), "--out", arg(&scratch.path("o.json"))]);
    assert_eq!(open.status.code(), Some(1));
    assert!(!scratch.path("o.json").exists());

    // Usage errors exit 2.
    assert_eq!(outputs.run(&[]).status.code(), Some(2));
    assert_eq!(outputs.run(&["keygen"]).status.code(), Some(2));
    assert_eq!(outputs.run(&["sign", arg(&list), "--key", arg(&key)]).status.code(), Some(2));
    assert_eq!(outputs.run(&["verify", arg(&signed)]).status.code(), Some(2));
    assert_eq!(outputs.run(&["export", arg(&key)]).status.code(), Some(2));

    // The signed list itself never holds the private half either.
    let signed_text = fs::read_to_string(&signed).expect("signed");
    for secret in [key_hex(&key), key_hex(&other_key)] {
        assert!(!signed_text.contains(&secret));
        outputs.assert_none_contains(&secret);
    }
}
