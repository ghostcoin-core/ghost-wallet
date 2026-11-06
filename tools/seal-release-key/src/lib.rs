//! The Seal's release key, kept on an offline machine.
//!
//! An enclave trusts a published measurements list only when the release key
//! signed it; the image holds the key's public half (`RELEASE_KEY_HEX` in
//! `seal/src/measurements.rs`). This crate makes that key and signs lists
//! with it, using the Seal's own reader ([`MeasurementList`]), signing message
//! ([`MeasurementList::signing_message`]) and context ([`RELEASE_CONTEXT`]),
//! so what it signs is exactly what an enclave checks.
//!
//! - `keygen --out FILE`: draws a 32-byte ML-DSA-65 seed from the operating
//!   system, writes it to a new FILE (mode 0600) as 64 lowercase hex digits
//!   and a newline, and returns the public half (1952 bytes) as lowercase hex.
//! - `sign LIST --key FILE --out FILE2 [--force]`: signs LIST's builds and
//!   writes the list in one canonical layout with its `"signature"`.
//! - `verify LIST --public HEX_OR_FILE`: accepts only a signed list whose
//!   signature verifies under the public half.
//!
//! The private half is never printed, logged or put into an error: every
//! message here names files and reasons only. It is wiped from memory once
//! used. The tool reads and writes local files only; it never opens a socket.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ghost_seal::measurements::{
    BuildStatus, ListError, MeasurementList, RELEASE_CONTEXT, RELEASE_KEY_BYTES, RELEASE_SIGNATURE_BYTES,
    ReleaseKey, pcr_hex,
};
use ml_dsa::{ExpandedSigningKey, MlDsa65, Seed};
use zeroize::{Zeroize, Zeroizing};

/// The private half's length: an ML-DSA-65 seed.
pub const SEED_BYTES: usize = 32;
/// The public half's length as hex digits.
pub const PUBLIC_HEX_DIGITS: usize = 2 * RELEASE_KEY_BYTES;
/// A signature's length as hex digits.
pub const SIGNATURE_HEX_DIGITS: usize = 2 * RELEASE_SIGNATURE_BYTES;
/// The most bytes the tool reads from a key file or a list file.
const MAX_FILE_BYTES: u64 = 1 << 20;

/// How to run the tool.
pub const USAGE: &str = "\
usage:
  seal-release-key keygen --out KEY_FILE
      Makes a new release key. Writes its private half to KEY_FILE (a new
      file, mode 0600) and prints only its public half, as 3904 lowercase hex
      digits. Run it on the offline machine only.
  seal-release-key sign LIST --key KEY_FILE --out SIGNED_LIST [--force]
      Signs LIST's builds with the release key (context \"ghost-seal
      measurements\") and writes the list with its \"signature\" to
      SIGNED_LIST. A signature LIST already carries is replaced. --force
      overwrites an existing SIGNED_LIST.
  seal-release-key verify LIST --public PUBLIC_HEX_OR_FILE
      Exits 0 only when LIST is signed and its signature verifies under the
      public half (the hex itself, or a file holding it).";

/// Why the tool stopped. Its text never holds the private half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolError(String);

impl ToolError {
    fn new(what: impl Into<String>) -> ToolError {
        ToolError(what.into())
    }
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ToolError {}

impl From<ListError> for ToolError {
    fn from(error: ListError) -> ToolError {
        ToolError(error.to_string())
    }
}

/// One command line, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `keygen --out FILE`.
    Keygen {
        /// The new key file.
        out: PathBuf,
    },
    /// `sign LIST --key FILE --out FILE2 [--force]`.
    Sign {
        /// The list to sign.
        list: PathBuf,
        /// The key file.
        key: PathBuf,
        /// Where the signed list goes.
        out: PathBuf,
        /// Overwrite `out` if it exists.
        force: bool,
    },
    /// `verify LIST --public HEX_OR_FILE`.
    Verify {
        /// The signed list.
        list: PathBuf,
        /// The public half, as hex or as a file holding it.
        public: String,
    },
    /// `help`, `--help` or `-h`.
    Help,
}

/// Reads the arguments after the program name.
pub fn parse_args(args: &[String]) -> Result<Command, ToolError> {
    let Some((command, rest)) = args.split_first() else {
        return Err(ToolError::new("no command given"));
    };
    let mut positional: Vec<&String> = Vec::new();
    let mut out = None;
    let mut key = None;
    let mut public = None;
    let mut force = false;
    let mut iter = rest.iter();
    while let Some(arg) = iter.next() {
        let slot = match arg.as_str() {
            "--out" => &mut out,
            "--key" => &mut key,
            "--public" => &mut public,
            "--force" => {
                force = true;
                continue;
            }
            other if other.starts_with('-') => return Err(ToolError::new(format!("unknown option {other}"))),
            _ => {
                positional.push(arg);
                continue;
            }
        };
        let value = iter.next().ok_or_else(|| ToolError::new(format!("{arg} needs a value")))?;
        if slot.replace(value.clone()).is_some() {
            return Err(ToolError::new(format!("{arg} is given twice")));
        }
    }
    let unexpected = |what: &str| ToolError::new(format!("{command} does not take {what}"));
    match command.as_str() {
        "help" | "--help" | "-h" => Ok(Command::Help),
        "keygen" => {
            if !positional.is_empty() {
                return Err(unexpected("a list"));
            }
            if key.is_some() || public.is_some() || force {
                return Err(unexpected("--key, --public or --force"));
            }
            let out = out.ok_or_else(|| ToolError::new("keygen needs --out KEY_FILE"))?;
            Ok(Command::Keygen { out: out.into() })
        }
        "sign" => {
            let [list] = positional.as_slice() else {
                return Err(ToolError::new("sign needs exactly one LIST"));
            };
            if public.is_some() {
                return Err(unexpected("--public"));
            }
            let key = key.ok_or_else(|| ToolError::new("sign needs --key KEY_FILE"))?;
            let out = out.ok_or_else(|| ToolError::new("sign needs --out SIGNED_LIST"))?;
            Ok(Command::Sign { list: (*list).into(), key: key.into(), out: out.into(), force })
        }
        "verify" => {
            let [list] = positional.as_slice() else {
                return Err(ToolError::new("verify needs exactly one LIST"));
            };
            if key.is_some() || out.is_some() || force {
                return Err(unexpected("--key, --out or --force"));
            }
            let public = public.ok_or_else(|| ToolError::new("verify needs --public PUBLIC_HEX_OR_FILE"))?;
            Ok(Command::Verify { list: (*list).into(), public })
        }
        other => Err(ToolError::new(format!("unknown command {other}"))),
    }
}

/// The release key's private half: the 32-byte ML-DSA-65 seed. Wiped when
/// dropped; it has no `Debug` and no `Display`.
pub struct SigningSeed(Zeroizing<[u8; SEED_BYTES]>);

impl SigningSeed {
    /// Takes `bytes` and wipes the caller's copy.
    pub fn from_bytes(bytes: &mut [u8; SEED_BYTES]) -> SigningSeed {
        let seed = SigningSeed(Zeroizing::new(*bytes));
        bytes.zeroize();
        seed
    }

    /// A new seed from the operating system's random source.
    pub fn generate() -> Result<SigningSeed, ToolError> {
        let mut bytes = Zeroizing::new([0u8; SEED_BYTES]);
        getrandom::fill(&mut bytes[..]).map_err(|_| ToolError::new("the operating system gave no random bytes"))?;
        Ok(SigningSeed(bytes))
    }

    fn signing_key(&self) -> ExpandedSigningKey<MlDsa65> {
        let mut seed = Seed::from(*self.0);
        let key = ExpandedSigningKey::<MlDsa65>::from_seed(&seed);
        seed.zeroize();
        key
    }

    /// The public half: the encoded ML-DSA-65 verifying key (1952 bytes).
    pub fn public_bytes(&self) -> Vec<u8> {
        self.signing_key().verifying_key().encode().to_vec()
    }

    /// The release signature over `list`'s builds, as lowercase hex.
    pub fn signature_hex(&self, list: &MeasurementList) -> Result<String, ToolError> {
        let signature = self
            .signing_key()
            .sign_deterministic(&list.signing_message(), RELEASE_CONTEXT)
            .map_err(|_| ToolError::new("the list could not be signed"))?;
        Ok(hex(&signature.encode()))
    }
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(2 * bytes.len());
    push_hex(bytes, &mut out);
    String::from_utf8(out).expect("hex digits are ASCII")
}

/// Appends `bytes` as lowercase hex to `out`.
fn push_hex(bytes: &[u8], out: &mut Vec<u8>) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)]);
        out.push(DIGITS[usize::from(byte & 0x0f)]);
    }
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Reads lowercase hex of exactly `bytes` bytes.
fn parse_hex(text: &[u8], bytes: usize) -> Option<Vec<u8>> {
    if text.len() != 2 * bytes {
        return None;
    }
    text.chunks(2).map(|pair| Some(hex_digit(pair[0])? << 4 | hex_digit(pair[1])?)).collect()
}

/// Makes a new release key: writes its private half to `out` and returns its
/// public half as lowercase hex.
pub fn keygen(out: &Path) -> Result<String, ToolError> {
    keygen_with_seed(out, SigningSeed::generate()?)
}

/// Writes `seed` to `out` as the key file (a new file, mode 0600, 64
/// lowercase hex digits and a newline) and returns the public half as
/// lowercase hex. [`keygen`] passes a fresh random seed; tests pass fixed
/// test-only ones.
pub fn keygen_with_seed(out: &Path, seed: SigningSeed) -> Result<String, ToolError> {
    let public = hex(&seed.public_bytes());
    let mut text = Zeroizing::new(Vec::with_capacity(2 * SEED_BYTES + 1));
    push_hex(&seed.0[..], &mut text);
    text.push(b'\n');
    drop(seed);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .map_err(|e| ToolError::new(format!("cannot create the key file {}: {e}", out.display())))?;
    let written = file
        .set_permissions(fs::Permissions::from_mode(0o600))
        .and_then(|()| file.write_all(&text))
        .and_then(|()| file.sync_all());
    if let Err(e) = written {
        drop(file);
        let _ = fs::remove_file(out);
        return Err(ToolError::new(format!("cannot write the key file {}: {e}", out.display())));
    }
    Ok(public)
}

fn read_limited(path: &Path, what: &str) -> Result<Zeroizing<Vec<u8>>, ToolError> {
    let file = File::open(path).map_err(|e| ToolError::new(format!("cannot read {what} {}: {e}", path.display())))?;
    // Room for a whole key file up front, so reading it never moves (and
    // leaves behind) a copy of the private half.
    let mut bytes = Zeroizing::new(Vec::with_capacity(4096));
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| ToolError::new(format!("cannot read {what} {}: {e}", path.display())))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(ToolError::new(format!("{what} {} is too large", path.display())));
    }
    Ok(bytes)
}

/// Reads a key file `keygen` wrote. Refuses one that group or others may
/// read or write, and one that is not 64 lowercase hex digits (and an
/// optional newline).
pub fn read_key_file(path: &Path) -> Result<SigningSeed, ToolError> {
    let metadata =
        fs::metadata(path).map_err(|e| ToolError::new(format!("cannot read the key file {}: {e}", path.display())))?;
    if !metadata.is_file() {
        return Err(ToolError::new(format!("the key file {} is not a file", path.display())));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(ToolError::new(format!(
            "the key file {} is open to group or others (mode {mode:04o}); it must be mode 0600",
            path.display()
        )));
    }
    let text = read_limited(path, "the key file")?;
    let digits = text.strip_suffix(b"\n").unwrap_or(&text);
    let bytes = Zeroizing::new(
        parse_hex(digits, SEED_BYTES)
            .ok_or_else(|| ToolError::new(format!("the key file {} is not 64 lowercase hex digits", path.display())))?,
    );
    let mut seed = [0u8; SEED_BYTES];
    seed.copy_from_slice(&bytes);
    Ok(SigningSeed::from_bytes(&mut seed))
}

/// `list` with `signature_hex`, in the tool's one layout: the version, the
/// builds one per line, then the signature.
pub fn canonical_signed(list: &MeasurementList, signature_hex: &str) -> String {
    let mut out = String::from("{\"version\": 1, \"builds\": [");
    for (index, build) in list.builds().iter().enumerate() {
        out.push_str(if index == 0 { "\n" } else { ",\n" });
        let status = match build.status {
            BuildStatus::Allowed => "allowed",
            BuildStatus::Revoked => "revoked",
        };
        // Names are only a-z, A-Z, 0-9, '-', '.', '_' and dates only digits
        // and '-' (the reader refuses anything else), so nothing needs escaping.
        out.push_str(&format!(
            "{{\"name\": \"{}\", \"released\": \"{}\", \"pcr0\": \"{}\", \"pcr1\": \"{}\", \"pcr2\": \"{}\", \"status\": \"{status}\"}}",
            build.name,
            build.released,
            pcr_hex(&build.pcrs.pcr0),
            pcr_hex(&build.pcrs.pcr1),
            pcr_hex(&build.pcrs.pcr2),
        ));
    }
    if !list.is_empty() {
        out.push('\n');
    }
    out.push_str(&format!("], \"signature\": \"{signature_hex}\"}}\n"));
    out
}

/// Signs `list_text` (read strictly; a signature it carries is dropped) and
/// returns the signed list in the canonical layout.
pub fn sign_text(list_text: &str, seed: &SigningSeed) -> Result<String, ToolError> {
    let list = MeasurementList::parse(list_text)?;
    let signature = seed.signature_hex(&list)?;
    Ok(canonical_signed(&list, &signature))
}

/// `sign LIST --key KEY --out OUT [--force]`. Returns how many builds the
/// signed list holds.
pub fn sign_file(list: &Path, key: &Path, out: &Path, force: bool) -> Result<usize, ToolError> {
    let seed = read_key_file(key)?;
    let text = read_text(list, "the list")?;
    let signed = sign_text(&text, &seed)?;
    drop(seed);
    let builds = MeasurementList::parse(&signed)?.builds().len();
    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options
        .open(out)
        .map_err(|e| ToolError::new(format!("cannot create the signed list {}: {e}", out.display())))?;
    file.write_all(signed.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| ToolError::new(format!("cannot write the signed list {}: {e}", out.display())))?;
    Ok(builds)
}

fn read_text(path: &Path, what: &str) -> Result<String, ToolError> {
    let bytes = read_limited(path, what)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| ToolError::new(format!("{what} {} is not UTF-8", path.display())))
}

/// The public half from `arg`: 3904 lowercase hex digits, or a file holding
/// them (surrounding white space is ignored).
pub fn read_public(arg: &str) -> Result<ReleaseKey, ToolError> {
    let text = if arg.len() == PUBLIC_HEX_DIGITS && arg.bytes().all(|c| hex_digit(c).is_some()) {
        arg.to_owned()
    } else {
        read_text(Path::new(arg), "the public key file")?
    };
    let bytes = parse_hex(text.trim().as_bytes(), RELEASE_KEY_BYTES)
        .ok_or_else(|| ToolError::new(format!("the public key is not {PUBLIC_HEX_DIGITS} lowercase hex digits")))?;
    Ok(ReleaseKey::from_bytes(&bytes)?)
}

/// Checks that `list_text` is signed and that its signature verifies under
/// `public`, as an enclave does; returns the list.
pub fn verify_text(list_text: &str, public: &ReleaseKey) -> Result<MeasurementList, ToolError> {
    Ok(MeasurementList::parse_signed(list_text, public)?)
}

/// `verify LIST --public HEX_OR_FILE`. Returns how many builds the list holds.
pub fn verify_file(list: &Path, public: &str) -> Result<usize, ToolError> {
    let public = read_public(public)?;
    let text = read_text(list, "the list")?;
    Ok(verify_text(&text, &public)?.builds().len())
}
