//! The card registry: every card the card setup finished, by UID, with the
//! date it was set up and its batch. It holds public values only: no key, no
//! secret and nothing derived from M.
//!
//! The card setup records a UID only after every step of the setup was
//! verified on the card. A Seal with a registry installed
//! ([`crate::Seal::with_registry`]) refuses any other UID with
//! [`SealError::NotAGhostCard`] before it sends the card anything.
//!
//! [`FileRegistry`] keeps the registry as an append-only text file, one card
//! per line:
//!
//! `<UID, 14 lowercase hex digits> <set-up date, YYYY-MM-DD> <batch> <check>`
//!
//! The check is the first 8 bytes of SHA3-256(`ghost-seal/v1/registry-line`
//! || the line's text before the check), in lowercase hex. Only lines that
//! end in a newline and pass their check are read: a line torn by a crash
//! mid-write is ignored, and the next append starts on a fresh line.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::card_keys::CardUid;
use crate::error::SealError;
use crate::primitives::sha3_256;

/// The label of a registry line's check.
pub const REGISTRY_LINE_LABEL: &[u8] = b"ghost-seal/v1/registry-line";
/// The longest batch name.
pub const BATCH_MAX_BYTES: usize = 32;

const CHECK_BYTES: usize = 8;

/// One registered card: public values only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEntry {
    uid: CardUid,
    set_up_on: String,
    batch: String,
}

impl RegistryEntry {
    /// An entry for card `uid`, set up on `set_up_on` (`YYYY-MM-DD`), of
    /// `batch` (1 to 32 letters, digits, `.`, `_` or `-`).
    pub fn new(uid: CardUid, set_up_on: &str, batch: &str) -> Result<RegistryEntry, SealError> {
        if !valid_date(set_up_on) {
            return Err(SealError::Registry("the set-up date is not YYYY-MM-DD"));
        }
        if !valid_batch(batch) {
            return Err(SealError::Registry("a batch is 1 to 32 letters, digits, '.', '_' or '-'"));
        }
        Ok(RegistryEntry { uid, set_up_on: set_up_on.to_owned(), batch: batch.to_owned() })
    }

    /// The card's UID.
    pub fn uid(&self) -> CardUid {
        self.uid
    }

    /// The date the card was set up, `YYYY-MM-DD`.
    pub fn set_up_on(&self) -> &str {
        &self.set_up_on
    }

    /// The card's batch.
    pub fn batch(&self) -> &str {
        &self.batch
    }

    /// The entry's line in a [`FileRegistry`], with its newline.
    pub fn to_line(&self) -> String {
        let body = format!("{} {} {}", hex(&self.uid.0), self.set_up_on, self.batch);
        format!("{body} {}\n", line_check(&body))
    }

    /// Reads one line (without its newline); `None` for anything that is not
    /// a whole, checked entry.
    pub fn from_line(line: &str) -> Option<RegistryEntry> {
        let (body, check) = line.rsplit_once(' ')?;
        if check != line_check(body) {
            return None;
        }
        let mut fields = body.split(' ');
        let (uid, date, batch) = (fields.next()?, fields.next()?, fields.next()?);
        if fields.next().is_some() {
            return None;
        }
        let uid: [u8; 7] = unhex(uid)?.try_into().ok()?;
        RegistryEntry::new(CardUid(uid), date, batch).ok()
    }
}

fn line_check(body: &str) -> String {
    hex(&sha3_256(&[REGISTRY_LINE_LABEL, body.as_bytes()])[..CHECK_BYTES])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    (0..text.len() / 2).map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()).collect()
}

fn valid_batch(batch: &str) -> bool {
    !batch.is_empty()
        && batch.len() <= BATCH_MAX_BYTES
        && batch.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn valid_date(date: &str) -> bool {
    let bytes = date.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let digits = |range: core::ops::Range<usize>| -> Option<u32> {
        let part = &date[range];
        part.bytes().all(|b| b.is_ascii_digit()).then(|| part.parse().ok()).flatten()
    };
    match (digits(0..4), digits(5..7), digits(8..10)) {
        (Some(_), Some(month), Some(day)) => (1..=12).contains(&month) && (1..=31).contains(&day),
        _ => false,
    }
}

/// The UTC date of a Unix time, `YYYY-MM-DD`.
pub fn date_of_unix(seconds: u64) -> String {
    // Howard Hinnant's days-to-civil algorithm, for days since 1970-01-01.
    let days = (seconds / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Where the Seal looks up which cards the card setup finished.
pub trait CardRegistry {
    /// The entry of card `uid`, if it is registered.
    fn lookup(&self, uid: &CardUid) -> Option<RegistryEntry>;

    /// Records `entry`. A UID already registered keeps its first entry and
    /// is not recorded again.
    fn record(&mut self, entry: &RegistryEntry) -> Result<(), SealError>;

    /// Whether card `uid` is registered.
    fn contains(&self, uid: &CardUid) -> bool {
        self.lookup(uid).is_some()
    }
}

/// A registry in memory. Clones share the same entries, so a test can hand
/// one to the card setup and another to a Seal.
#[derive(Clone, Default)]
pub struct MemoryRegistry {
    entries: Rc<RefCell<BTreeMap<CardUid, RegistryEntry>>>,
}

impl MemoryRegistry {
    /// An empty registry.
    pub fn new() -> MemoryRegistry {
        MemoryRegistry::default()
    }

    /// Every entry, by UID.
    pub fn entries(&self) -> Vec<RegistryEntry> {
        self.entries.borrow().values().cloned().collect()
    }
}

impl CardRegistry for MemoryRegistry {
    fn lookup(&self, uid: &CardUid) -> Option<RegistryEntry> {
        self.entries.borrow().get(uid).cloned()
    }

    fn record(&mut self, entry: &RegistryEntry) -> Result<(), SealError> {
        self.entries.borrow_mut().entry(entry.uid).or_insert_with(|| entry.clone());
        Ok(())
    }
}

/// The registry as an append-only line file (see the module notes). It is
/// read once when opened; [`CardRegistry::record`] appends a line, flushes
/// it to the disk and only then counts the card as registered.
pub struct FileRegistry {
    path: PathBuf,
    entries: BTreeMap<CardUid, RegistryEntry>,
}

impl FileRegistry {
    /// Opens the registry at `path`; a file that does not exist yet is an
    /// empty registry (it is created by the first record).
    pub fn open(path: impl AsRef<Path>) -> Result<FileRegistry, SealError> {
        let path = path.as_ref().to_path_buf();
        let text = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
            Err(_) => return Err(SealError::Registry("the registry file cannot be read")),
        };
        let mut entries = BTreeMap::new();
        // Only lines that end in a newline: whatever follows the last newline
        // is a torn write.
        let whole = match text.iter().rposition(|b| *b == b'\n') {
            Some(end) => &text[..end],
            None => &text[..0],
        };
        for line in whole.split(|b| *b == b'\n') {
            let Ok(line) = core::str::from_utf8(line) else { continue };
            if let Some(entry) = RegistryEntry::from_line(line) {
                entries.entry(entry.uid).or_insert(entry);
            }
        }
        Ok(FileRegistry { path, entries })
    }

    /// Where the file is.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Every entry read or recorded, by UID.
    pub fn entries(&self) -> Vec<RegistryEntry> {
        self.entries.values().cloned().collect()
    }
}

impl CardRegistry for FileRegistry {
    fn lookup(&self, uid: &CardUid) -> Option<RegistryEntry> {
        self.entries.get(uid).cloned()
    }

    fn record(&mut self, entry: &RegistryEntry) -> Result<(), SealError> {
        if self.entries.contains_key(&entry.uid) {
            return Ok(());
        }
        let failed = |_| SealError::Registry("the registry file cannot be written");
        let mut file = OpenOptions::new().read(true).append(true).create(true).open(&self.path).map_err(failed)?;
        let length = file.metadata().map_err(failed)?.len();
        let mut line = entry.to_line();
        if length > 0 {
            // A torn last line is closed first, so this entry starts a line
            // of its own.
            let mut last = [0u8; 1];
            file.seek(SeekFrom::End(-1)).map_err(failed)?;
            file.read_exact(&mut last).map_err(failed)?;
            if last[0] != b'\n' {
                line.insert(0, '\n');
            }
        }
        file.write_all(line.as_bytes()).map_err(failed)?;
        file.sync_all().map_err(failed)?;
        self.entries.insert(entry.uid, entry.clone());
        Ok(())
    }
}
