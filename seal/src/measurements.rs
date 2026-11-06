//! The published list of Seal builds and the rules for reading it.
//!
//! The list is `enclave/measurements.json` in the repository, and the app
//! pins a list of the same format. Each build is named by its three Nitro
//! measurements: PCR0 (the whole enclave image, the Seal's answer
//! measurement), PCR1 (the kernel and boot ramdisk) and PCR2 (the Seal
//! program). A document is accepted only when all three equal one build
//! whose status is `allowed`; a build marked `revoked` is never accepted and
//! never given M.
//!
//! ```json
//! {"version": 1, "builds": [{"name": "seal-2026-11-01", "released": "2026-11-01",
//!   "pcr0": "<96 hex>", "pcr1": "<96 hex>", "pcr2": "<96 hex>", "status": "allowed"}]}
//! ```
//!
//! The reader is strict: the version must be 1, every build has exactly
//! these six fields, PCRs are 96 lowercase hex digits and never all zeros
//! (a debug-mode enclave reports zeros), `released` is a real date, names are
//! unique, and no two builds share PCR0. Anything else refuses the whole
//! list. An empty list is valid and refuses every Seal.

use core::fmt;

use crate::answer::MEASUREMENT_BYTES;

/// The format version this reader accepts.
pub const MEASUREMENTS_VERSION: u64 = 1;
/// The most builds a list may hold.
pub const MAX_BUILDS: usize = 256;
/// The longest build name, in bytes.
pub const MAX_NAME_BYTES: usize = 64;

/// One PCR value: SHA-384, 48 bytes.
pub type Pcr = [u8; MEASUREMENT_BYTES];

/// The three measurements that name a build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pcrs {
    /// The enclave image.
    pub pcr0: Pcr,
    /// The kernel and boot ramdisk.
    pub pcr1: Pcr,
    /// The Seal program.
    pub pcr2: Pcr,
}

/// Whether a build may run as the Seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildStatus {
    /// Accepted, and may be given M.
    Allowed,
    /// Never accepted, never given M.
    Revoked,
}

/// One published build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Build {
    /// Its name.
    pub name: String,
    /// The day it was published, `YYYY-MM-DD`.
    pub released: String,
    /// Its measurements.
    pub pcrs: Pcrs,
    /// Whether it may run.
    pub status: BuildStatus,
}

/// Why a list could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListError {
    /// Not JSON, or JSON nested too deep.
    Syntax(&'static str),
    /// JSON, but not this format.
    Format(String),
}

impl fmt::Display for ListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ListError::Syntax(what) => write!(f, "measurements list is not JSON: {what}"),
            ListError::Format(what) => write!(f, "measurements list: {what}"),
        }
    }
}

impl std::error::Error for ListError {}

/// Why measurements were not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeasurementRefused {
    /// No build has these three measurements.
    NotListed,
    /// The build with these measurements is revoked.
    Revoked {
        /// The build's name.
        name: String,
    },
    /// A PCR is all zeros: an enclave started in debug mode.
    DebugMode,
}

impl fmt::Display for MeasurementRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MeasurementRefused::NotListed => f.write_str("the measurements are not on the published list"),
            MeasurementRefused::Revoked { name } => write!(f, "build {name} is revoked"),
            MeasurementRefused::DebugMode => f.write_str("a debug-mode enclave is never accepted"),
        }
    }
}

impl std::error::Error for MeasurementRefused {}

/// A published list of builds.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MeasurementList {
    builds: Vec<Build>,
}

impl MeasurementList {
    /// A list with no build: every Seal is refused.
    pub fn empty() -> MeasurementList {
        MeasurementList { builds: Vec::new() }
    }

    /// Reads a list in the published format.
    pub fn parse(text: &str) -> Result<MeasurementList, ListError> {
        let value = json::parse(text)?;
        let top = value.object("the list")?;
        json::only_keys(top, &["version", "builds"], "the list")?;
        let version = json::field(top, "version", "the list")?.integer("version")?;
        if version != MEASUREMENTS_VERSION {
            return Err(format_error(format!("version {version} is not {MEASUREMENTS_VERSION}")));
        }
        let entries = json::field(top, "builds", "the list")?.array("builds")?;
        if entries.len() > MAX_BUILDS {
            return Err(format_error(format!("more than {MAX_BUILDS} builds")));
        }
        let mut builds: Vec<Build> = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            let build = read_build(entry, index)?;
            if builds.iter().any(|b| b.name == build.name) {
                return Err(format_error(format!("build name {} is listed twice", build.name)));
            }
            if builds.iter().any(|b| shares_pcr(&b.pcrs, &build.pcrs)) {
                return Err(format_error(format!("build {} repeats a listed PCR0", build.name)));
            }
            builds.push(build);
        }
        Ok(MeasurementList { builds })
    }

    /// The builds, in the order listed.
    pub fn builds(&self) -> &[Build] {
        &self.builds
    }

    /// The builds that may run.
    pub fn allowed(&self) -> impl Iterator<Item = &Build> {
        self.builds.iter().filter(|b| b.status == BuildStatus::Allowed)
    }

    /// Whether no build is listed.
    pub fn is_empty(&self) -> bool {
        self.builds.is_empty()
    }

    /// Accepts `pcrs` only when PCR0, PCR1 and PCR2 all equal one allowed
    /// build's, and returns that build.
    pub fn check(&self, pcrs: &Pcrs) -> Result<&Build, MeasurementRefused> {
        if is_zero(&pcrs.pcr0) || is_zero(&pcrs.pcr1) || is_zero(&pcrs.pcr2) {
            return Err(MeasurementRefused::DebugMode);
        }
        let build = self.builds.iter().find(|b| &b.pcrs == pcrs).ok_or(MeasurementRefused::NotListed)?;
        match build.status {
            BuildStatus::Allowed => Ok(build),
            BuildStatus::Revoked => Err(MeasurementRefused::Revoked { name: build.name.clone() }),
        }
    }

    /// SHA3-256 of the list in its canonical form (the builds in order, each
    /// field length-prefixed), so two copies holding the same list agree on
    /// its hash however the JSON was spaced.
    pub fn digest(&self) -> [u8; 32] {
        let mut parts: Vec<Vec<u8>> = vec![b"ghost-seal/v1/measurements".to_vec()];
        parts.push((self.builds.len() as u32).to_be_bytes().to_vec());
        for build in &self.builds {
            for field in [build.name.as_bytes(), build.released.as_bytes()] {
                parts.push((field.len() as u32).to_be_bytes().to_vec());
                parts.push(field.to_vec());
            }
            parts.push(build.pcrs.pcr0.to_vec());
            parts.push(build.pcrs.pcr1.to_vec());
            parts.push(build.pcrs.pcr2.to_vec());
            parts.push(vec![match build.status {
                BuildStatus::Allowed => 1,
                BuildStatus::Revoked => 2,
            }]);
        }
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        crate::primitives::sha3_256(&refs)
    }
}

fn format_error(what: String) -> ListError {
    ListError::Format(what)
}

fn is_zero(pcr: &Pcr) -> bool {
    pcr.iter().all(|b| *b == 0)
}

/// PCR0 measures the whole image, so two entries with one PCR0 are one
/// build listed twice (perhaps with two statuses). Builds may share PCR1 (the
/// same kernel).
fn shares_pcr(a: &Pcrs, b: &Pcrs) -> bool {
    a.pcr0 == b.pcr0
}

fn read_build(entry: &json::Value, index: usize) -> Result<Build, ListError> {
    let what = format!("build {index}");
    let object = entry.object(&what)?;
    json::only_keys(object, &["name", "released", "pcr0", "pcr1", "pcr2", "status"], &what)?;
    let name = json::field(object, "name", &what)?.string("name")?.to_owned();
    if name.is_empty()
        || name.len() > MAX_NAME_BYTES
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
    {
        return Err(format_error(format!("{what}: a name is 1 to {MAX_NAME_BYTES} of a-z, A-Z, 0-9, '-', '.', '_'")));
    }
    let released = json::field(object, "released", &what)?.string("released")?.to_owned();
    if !is_date(&released) {
        return Err(format_error(format!("{what}: released is not a YYYY-MM-DD date")));
    }
    let pcr = |key: &str| -> Result<Pcr, ListError> {
        let text = json::field(object, key, &what)?.string(key)?;
        let pcr = parse_pcr(text).ok_or_else(|| format_error(format!("{what}: {key} is not 96 lowercase hex digits")))?;
        if is_zero(&pcr) {
            return Err(format_error(format!("{what}: {key} is all zeros (a debug-mode enclave)")));
        }
        Ok(pcr)
    };
    let pcrs = Pcrs { pcr0: pcr("pcr0")?, pcr1: pcr("pcr1")?, pcr2: pcr("pcr2")? };
    let status = match json::field(object, "status", &what)?.string("status")? {
        "allowed" => BuildStatus::Allowed,
        "revoked" => BuildStatus::Revoked,
        other => return Err(format_error(format!("{what}: status {other:?} is not allowed or revoked"))),
    };
    Ok(Build { name, released, pcrs, status })
}

/// Reads 96 lowercase hex digits.
pub fn parse_pcr(text: &str) -> Option<Pcr> {
    let bytes = text.as_bytes();
    if bytes.len() != 2 * MEASUREMENT_BYTES {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; MEASUREMENT_BYTES];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = digit(bytes[2 * i])? << 4 | digit(bytes[2 * i + 1])?;
    }
    Some(out)
}

/// A PCR as 96 lowercase hex digits.
pub fn pcr_hex(pcr: &Pcr) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 * MEASUREMENT_BYTES);
    for byte in pcr {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn is_date(text: &str) -> bool {
    let b = text.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let number = |range: core::ops::Range<usize>| -> Option<u32> {
        let mut n = 0u32;
        for &c in &b[range] {
            if !c.is_ascii_digit() {
                return None;
            }
            n = n * 10 + u32::from(c - b'0');
        }
        Some(n)
    };
    let (Some(year), Some(month), Some(day)) = (number(0..4), number(5..7), number(8..10)) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    year >= 2000 && (1..=days).contains(&day)
}

/// A small strict JSON reader (RFC 8259) for the measurements list: no
/// duplicate keys, no trailing data, nesting at most 16 deep.
mod json {
    use super::ListError;

    const MAX_DEPTH: usize = 16;

    /// A JSON value; booleans and null are read (so a list holding one is
    /// refused by its field checks, not by the reader) but never used.
    #[allow(dead_code)]
    pub(super) enum Value {
        Null,
        Bool(bool),
        Number(String),
        String(String),
        Array(Vec<Value>),
        Object(Vec<(String, Value)>),
    }

    impl Value {
        pub(super) fn object(&self, what: &str) -> Result<&[(String, Value)], ListError> {
            match self {
                Value::Object(fields) => Ok(fields),
                _ => Err(ListError::Format(format!("{what} is not an object"))),
            }
        }

        pub(super) fn array(&self, what: &str) -> Result<&[Value], ListError> {
            match self {
                Value::Array(items) => Ok(items),
                _ => Err(ListError::Format(format!("{what} is not an array"))),
            }
        }

        pub(super) fn string(&self, what: &str) -> Result<&str, ListError> {
            match self {
                Value::String(text) => Ok(text),
                _ => Err(ListError::Format(format!("{what} is not a string"))),
            }
        }

        pub(super) fn integer(&self, what: &str) -> Result<u64, ListError> {
            match self {
                Value::Number(text) if !text.is_empty() && text.bytes().all(|c| c.is_ascii_digit()) => {
                    text.parse().map_err(|_| ListError::Format(format!("{what} is too large")))
                }
                _ => Err(ListError::Format(format!("{what} is not a whole number"))),
            }
        }
    }

    pub(super) fn field<'a>(fields: &'a [(String, Value)], key: &str, what: &str) -> Result<&'a Value, ListError> {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
            .ok_or_else(|| ListError::Format(format!("{what} has no {key}")))
    }

    pub(super) fn only_keys(fields: &[(String, Value)], keys: &[&str], what: &str) -> Result<(), ListError> {
        for (key, _) in fields {
            if !keys.contains(&key.as_str()) {
                return Err(ListError::Format(format!("{what} has an unknown field {key:?}")));
            }
        }
        Ok(())
    }

    pub(super) fn parse(text: &str) -> Result<Value, ListError> {
        let mut reader = Reader { bytes: text.as_bytes(), at: 0 };
        let value = reader.value(0)?;
        reader.space();
        if reader.at != reader.bytes.len() {
            return Err(ListError::Syntax("data after the end"));
        }
        Ok(value)
    }

    struct Reader<'a> {
        bytes: &'a [u8],
        at: usize,
    }

    impl Reader<'_> {
        fn space(&mut self) {
            while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.bytes.get(self.at) {
                self.at += 1;
            }
        }

        fn peek(&self) -> Option<u8> {
            self.bytes.get(self.at).copied()
        }

        fn expect(&mut self, byte: u8) -> Result<(), ListError> {
            if self.peek() == Some(byte) {
                self.at += 1;
                Ok(())
            } else {
                Err(ListError::Syntax("unexpected character"))
            }
        }

        fn literal(&mut self, word: &[u8], value: Value) -> Result<Value, ListError> {
            if self.bytes[self.at..].starts_with(word) {
                self.at += word.len();
                Ok(value)
            } else {
                Err(ListError::Syntax("unknown literal"))
            }
        }

        fn value(&mut self, depth: usize) -> Result<Value, ListError> {
            if depth > MAX_DEPTH {
                return Err(ListError::Syntax("nested too deep"));
            }
            self.space();
            match self.peek() {
                Some(b'{') => self.object(depth),
                Some(b'[') => self.array(depth),
                Some(b'"') => Ok(Value::String(self.string()?)),
                Some(b't') => self.literal(b"true", Value::Bool(true)),
                Some(b'f') => self.literal(b"false", Value::Bool(false)),
                Some(b'n') => self.literal(b"null", Value::Null),
                Some(b'-' | b'0'..=b'9') => self.number(),
                _ => Err(ListError::Syntax("expected a value")),
            }
        }

        fn object(&mut self, depth: usize) -> Result<Value, ListError> {
            self.expect(b'{')?;
            let mut fields: Vec<(String, Value)> = Vec::new();
            self.space();
            if self.peek() == Some(b'}') {
                self.at += 1;
                return Ok(Value::Object(fields));
            }
            loop {
                self.space();
                let key = self.string()?;
                if fields.iter().any(|(k, _)| *k == key) {
                    return Err(ListError::Syntax("a key appears twice in one object"));
                }
                self.space();
                self.expect(b':')?;
                let value = self.value(depth + 1)?;
                fields.push((key, value));
                self.space();
                match self.peek() {
                    Some(b',') => self.at += 1,
                    Some(b'}') => {
                        self.at += 1;
                        return Ok(Value::Object(fields));
                    }
                    _ => return Err(ListError::Syntax("expected , or }")),
                }
            }
        }

        fn array(&mut self, depth: usize) -> Result<Value, ListError> {
            self.expect(b'[')?;
            let mut items = Vec::new();
            self.space();
            if self.peek() == Some(b']') {
                self.at += 1;
                return Ok(Value::Array(items));
            }
            loop {
                items.push(self.value(depth + 1)?);
                self.space();
                match self.peek() {
                    Some(b',') => self.at += 1,
                    Some(b']') => {
                        self.at += 1;
                        return Ok(Value::Array(items));
                    }
                    _ => return Err(ListError::Syntax("expected , or ]")),
                }
            }
        }

        fn number(&mut self) -> Result<Value, ListError> {
            let start = self.at;
            if self.peek() == Some(b'-') {
                self.at += 1;
            }
            match self.peek() {
                Some(b'0') => self.at += 1,
                Some(b'1'..=b'9') => self.digits(),
                _ => return Err(ListError::Syntax("bad number")),
            }
            if self.peek() == Some(b'.') {
                self.at += 1;
                self.digits_required()?;
            }
            if let Some(b'e' | b'E') = self.peek() {
                self.at += 1;
                if let Some(b'+' | b'-') = self.peek() {
                    self.at += 1;
                }
                self.digits_required()?;
            }
            let text = core::str::from_utf8(&self.bytes[start..self.at]).map_err(|_| ListError::Syntax("bad number"))?;
            Ok(Value::Number(text.to_owned()))
        }

        fn digits(&mut self) {
            while let Some(b'0'..=b'9') = self.peek() {
                self.at += 1;
            }
        }

        fn digits_required(&mut self) -> Result<(), ListError> {
            let start = self.at;
            self.digits();
            if self.at == start { Err(ListError::Syntax("bad number")) } else { Ok(()) }
        }

        fn hex4(&mut self) -> Result<u32, ListError> {
            let end = self.at + 4;
            let digits = self.bytes.get(self.at..end).ok_or(ListError::Syntax("bad escape"))?;
            let text = core::str::from_utf8(digits).map_err(|_| ListError::Syntax("bad escape"))?;
            if !text.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(ListError::Syntax("bad escape"));
            }
            self.at = end;
            u32::from_str_radix(text, 16).map_err(|_| ListError::Syntax("bad escape"))
        }

        fn string(&mut self) -> Result<String, ListError> {
            self.expect(b'"')?;
            let mut out = String::new();
            loop {
                let start = self.at;
                while let Some(c) = self.peek() {
                    if c == b'"' || c == b'\\' || c < 0x20 {
                        break;
                    }
                    self.at += 1;
                }
                let run = core::str::from_utf8(&self.bytes[start..self.at]).map_err(|_| ListError::Syntax("not UTF-8"))?;
                out.push_str(run);
                match self.peek() {
                    Some(b'"') => {
                        self.at += 1;
                        return Ok(out);
                    }
                    Some(b'\\') => {
                        self.at += 1;
                        let escape = self.peek().ok_or(ListError::Syntax("bad escape"))?;
                        self.at += 1;
                        let c = match escape {
                            b'"' => '"',
                            b'\\' => '\\',
                            b'/' => '/',
                            b'b' => '\u{8}',
                            b'f' => '\u{c}',
                            b'n' => '\n',
                            b'r' => '\r',
                            b't' => '\t',
                            b'u' => {
                                let first = self.hex4()?;
                                let code = if (0xd800..0xdc00).contains(&first) {
                                    self.expect(b'\\')?;
                                    self.expect(b'u')?;
                                    let second = self.hex4()?;
                                    if !(0xdc00..0xe000).contains(&second) {
                                        return Err(ListError::Syntax("bad surrogate pair"));
                                    }
                                    0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                                } else {
                                    first
                                };
                                char::from_u32(code).ok_or(ListError::Syntax("bad escape"))?
                            }
                            _ => return Err(ListError::Syntax("bad escape")),
                        };
                        out.push(c);
                    }
                    _ => return Err(ListError::Syntax("unterminated string")),
                }
            }
        }
    }
}
