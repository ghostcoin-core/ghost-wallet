//! The journal store on the parent host, and the enclave's way to it.
//!
//! The host keeps the log of `journal_log` in one file
//! (`/var/lib/seal/journal.log` in a real Seal) and serves it on vsock port
//! [`JOURNAL_PORT`] (`seal_proxy journal <vsock port> <file>`). It holds
//! only counters and records the enclave encrypted and MACed: no UID, entry
//! kind, card data, key or M. The host is not trusted for integrity; the
//! enclave checks the log itself (`journal_log`). The host checks only what
//! keeps its file sound:
//!
//! - an append carries the next counter (the number of records plus 1) and
//!   a record of 1 to [`MAX_RECORD_BYTES`] bytes;
//! - each record is written as `counter (u64) || length (u32) || record ||
//!   check`, the check being SHA3-256 of `ghost-seal/v1/host-journal/file`
//!   and what comes before it (unkeyed: it finds torn writes), then the file
//!   and its directory are flushed to disk (`fsync`), and only then is the
//!   append answered ok. A failed write or flush is undone and answered
//!   refused;
//! - a torn last record (cut short, or failing its check, at the end of the
//!   file) is dropped when the file is opened; a damaged record with more
//!   after it stops the store from opening;
//! - the file is created mode 0600.
//!
//! Requests are frames (`key_share::read_frame` and `write_frame`):
//! [`REQUEST_APPEND`] || counter (u64) || record, answered [`ANSWER_OK`] or
//! [`ANSWER_REFUSED`] || why; and [`REQUEST_READ_ALL`], answered with one
//! frame [`ANSWER_RECORD`] || counter || record per record, in order, then
//! [`ANSWER_OK`] || the number of records (u64).
//!
//! The store and its file format build with the `nitro` or the
//! `test-server` feature (the test server keeps its log in such a file, in
//! its own process); the vsock server and the enclave's client
//! ([`HostJournal`]: one connection to the parent, CID 3, per request,
//! [`REQUEST_DEADLINE`] for the whole request) with `nitro` only.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::SealError;
use crate::journal_log::{LogStore, MAX_RECORD_BYTES};
use crate::primitives::sha3_256;

/// The vsock port on the parent the enclave reaches the store on.
pub const JOURNAL_PORT: u32 = 5005;
/// The parent instance's context ID, as seen from an enclave.
pub const PARENT_CID: u32 = 3;
/// Where the parent keeps the log.
pub const JOURNAL_FILE: &str = "/var/lib/seal/journal.log";
/// How long one request to the host may take, connection to answer.
pub const REQUEST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// A request: append counter || record.
pub const REQUEST_APPEND: u8 = 1;
/// A request: read every record.
pub const REQUEST_READ_ALL: u8 = 2;
/// An answer: done (after a read, the number of records follows).
pub const ANSWER_OK: u8 = 0;
/// An answer: refused, why follows.
pub const ANSWER_REFUSED: u8 = 1;
/// An answer to a read: one record, counter || record.
pub const ANSWER_RECORD: u8 = 2;

const HEAD_BYTES: usize = 8 + 4;
const CHECK_BYTES: usize = 32;

/// The file under the host's store: what a test replaces to make a write
/// or a flush fail.
pub trait RecordFile: Send {
    /// The whole file.
    fn read_all(&mut self) -> io::Result<Vec<u8>>;
    /// Writes `bytes` at the end.
    fn append(&mut self, bytes: &[u8]) -> io::Result<()>;
    /// Flushes the file and its directory to disk.
    fn sync(&mut self) -> io::Result<()>;
    /// Cuts the file to `length` bytes.
    fn truncate(&mut self, length: u64) -> io::Result<()>;
}

/// The store's file on disk.
pub struct DiskFile {
    file: File,
    directory: PathBuf,
}

impl DiskFile {
    /// Opens `path`, creating it mode 0600 if it is not there, and makes
    /// it 0600 if it is.
    pub fn open(path: &Path) -> io::Result<DiskFile> {
        let file = OpenOptions::new().read(true).append(true).create(true).mode(0o600).open(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        let directory = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let mut disk = DiskFile { file, directory };
        // A file just made is named in its directory only once that is
        // flushed.
        disk.sync()?;
        Ok(disk)
    }
}

impl RecordFile for DiskFile {
    fn read_all(&mut self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.file.seek(SeekFrom::Start(0))?;
        self.file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.file.write_all(bytes)
    }

    fn sync(&mut self) -> io::Result<()> {
        self.file.sync_all()?;
        File::open(&self.directory)?.sync_all()
    }

    fn truncate(&mut self, length: u64) -> io::Result<()> {
        self.file.set_len(length)
    }
}

/// Why the host's store refused an append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreRefused {
    /// The counter is not the number of records plus 1.
    WrongCounter,
    /// The record is empty or over [`MAX_RECORD_BYTES`].
    BadLength,
    /// Writing or flushing failed; nothing was kept.
    Disk,
    /// A failed write could not be undone: the store takes nothing more
    /// until it is opened again.
    Broken,
}

impl std::fmt::Display for StoreRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            StoreRefused::WrongCounter => "not the next counter",
            StoreRefused::BadLength => "a record is 1 to 4096 bytes",
            StoreRefused::Disk => "the record could not be written to disk",
            StoreRefused::Broken => "the store must be restarted",
        })
    }
}

fn check_of(head_and_record: &[u8]) -> [u8; CHECK_BYTES] {
    sha3_256(&[b"ghost-seal/v1/host-journal/file", head_and_record])
}

/// What one place in the file holds.
enum Parsed {
    /// A whole record: its counter, its bytes and how long it is on disk.
    Record(u64, Vec<u8>, usize),
    /// The rest of the file is a torn write.
    Torn,
    /// A damaged record with more after it, or a counter out of turn.
    Damaged,
}

fn parse_one(rest: &[u8], expected: u64) -> Parsed {
    if rest.len() < HEAD_BYTES {
        return Parsed::Torn;
    }
    let counter = u64::from_be_bytes(rest[..8].try_into().expect("8 bytes"));
    let length = u32::from_be_bytes(rest[8..12].try_into().expect("4 bytes")) as usize;
    if length == 0 || length > MAX_RECORD_BYTES {
        // No record boundary can be found after this: a torn tail.
        return Parsed::Torn;
    }
    let total = HEAD_BYTES + length + CHECK_BYTES;
    if rest.len() < total {
        return Parsed::Torn;
    }
    let (written, check) = rest[..total].split_at(HEAD_BYTES + length);
    if check_of(written) != check {
        return if rest.len() == total { Parsed::Torn } else { Parsed::Damaged };
    }
    if counter != expected {
        return Parsed::Damaged;
    }
    Parsed::Record(counter, written[HEAD_BYTES..].to_vec(), total)
}

/// The host's store: the records of one file, checked as described in the
/// module notes.
pub struct HostStore<F: RecordFile = DiskFile> {
    file: F,
    records: Vec<(u64, Vec<u8>)>,
    end: u64,
    broken: bool,
    dropped_torn: bool,
}

impl HostStore<DiskFile> {
    /// The store in the file at `path` (made mode 0600 if missing).
    pub fn open(path: &Path) -> io::Result<HostStore<DiskFile>> {
        HostStore::with_file(DiskFile::open(path)?)
    }
}

impl<F: RecordFile> HostStore<F> {
    /// The store in `file`: every whole record, a torn last one dropped (and
    /// cut from the file).
    pub fn with_file(mut file: F) -> io::Result<HostStore<F>> {
        let bytes = file.read_all()?;
        let mut records = Vec::new();
        let mut at = 0usize;
        let mut dropped_torn = false;
        while at < bytes.len() {
            match parse_one(&bytes[at..], records.len() as u64 + 1) {
                Parsed::Record(counter, record, used) => {
                    records.push((counter, record));
                    at += used;
                }
                Parsed::Torn => {
                    file.truncate(at as u64)?;
                    file.sync()?;
                    dropped_torn = true;
                    break;
                }
                Parsed::Damaged => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "the journal file is damaged before its end"));
                }
            }
        }
        Ok(HostStore { file, records, end: at as u64, broken: false, dropped_torn })
    }

    /// The records, in order.
    pub fn records(&self) -> &[(u64, Vec<u8>)] {
        &self.records
    }

    /// Whether a torn last record was dropped when the file was opened.
    pub fn dropped_torn_record(&self) -> bool {
        self.dropped_torn
    }

    /// Appends record `counter`: written, flushed to disk with its
    /// directory, and only then `Ok`.
    pub fn append(&mut self, counter: u64, record: &[u8]) -> Result<(), StoreRefused> {
        if self.broken {
            return Err(StoreRefused::Broken);
        }
        if counter != self.records.len() as u64 + 1 {
            return Err(StoreRefused::WrongCounter);
        }
        if record.is_empty() || record.len() > MAX_RECORD_BYTES {
            return Err(StoreRefused::BadLength);
        }
        let mut bytes = Vec::with_capacity(HEAD_BYTES + record.len() + CHECK_BYTES);
        bytes.extend_from_slice(&counter.to_be_bytes());
        bytes.extend_from_slice(&(record.len() as u32).to_be_bytes());
        bytes.extend_from_slice(record);
        let check = check_of(&bytes);
        bytes.extend_from_slice(&check);
        if self.file.append(&bytes).and_then(|()| self.file.sync()).is_err() {
            // Undo whatever reached the file, so the next append of the same
            // counter starts where this one did (its flush flushes the cut
            // too). Should the cut not reach the disk before a crash, the
            // record is either whole, a record the enclave sealed, or torn
            // and dropped at the next open.
            if self.file.truncate(self.end).is_err() {
                self.broken = true;
            }
            return Err(StoreRefused::Disk);
        }
        self.end += bytes.len() as u64;
        self.records.push((counter, record.to_vec()));
        Ok(())
    }

    /// The answer frames to one request frame.
    pub fn answer(&mut self, request: &[u8]) -> Vec<Vec<u8>> {
        let refused = |why: &str| vec![[&[ANSWER_REFUSED][..], why.as_bytes()].concat()];
        match request.split_first() {
            Some((&REQUEST_APPEND, rest)) if rest.len() > 8 => {
                let counter = u64::from_be_bytes(rest[..8].try_into().expect("8 bytes"));
                match self.append(counter, &rest[8..]) {
                    Ok(()) => vec![vec![ANSWER_OK]],
                    Err(why) => refused(&why.to_string()),
                }
            }
            Some((&REQUEST_READ_ALL, [])) => {
                let mut frames: Vec<Vec<u8>> = self
                    .records
                    .iter()
                    .map(|(counter, record)| [&[ANSWER_RECORD][..], &counter.to_be_bytes(), record].concat())
                    .collect();
                frames.push([&[ANSWER_OK][..], &(self.records.len() as u64).to_be_bytes()].concat());
                frames
            }
            _ => refused("unknown request"),
        }
    }
}

/// The store in the same process (the test server's): an append is `Ok`
/// only once it is on disk.
impl<F: RecordFile> LogStore for HostStore<F> {
    fn append(&mut self, counter: u64, record: &[u8]) -> Result<(), SealError> {
        HostStore::append(self, counter, record).map_err(|_| SealError::Journal("the journal file did not take the record"))
    }

    fn read_all(&mut self) -> Result<Vec<(u64, Vec<u8>)>, SealError> {
        Ok(self.records.clone())
    }
}

#[cfg(feature = "nitro")]
pub use self::nitro::{HostJournal, serve, serve_connection};

#[cfg(feature = "nitro")]
mod nitro {
    use std::io::{self, Read, Write};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::{
        ANSWER_OK, ANSWER_RECORD, HostStore, JOURNAL_PORT, PARENT_CID, REQUEST_APPEND, REQUEST_DEADLINE,
        REQUEST_READ_ALL, RecordFile,
    };
    use crate::error::SealError;
    use crate::journal_log::LogStore;
    use crate::key_share::{read_frame, write_frame};
    use crate::proxy::{BoundedService, Connector, DeadlineStream, ProxyListener, ServiceLimits, VsockConnector};

    /// Answers request frames on `stream` until it closes or fails, taking
    /// the store's lock for each request only.
    pub fn serve_connection<F: RecordFile, S: Read + Write>(store: &Mutex<HostStore<F>>, stream: &mut S) {
        while let Ok(request) = read_frame(stream) {
            let frames = store.lock().unwrap_or_else(|e| e.into_inner()).answer(&request);
            for frame in frames {
                if write_frame(stream, &frame).is_err() {
                    return;
                }
            }
        }
    }

    /// Serves `store` on `listener` (vsock port [`JOURNAL_PORT`] on the
    /// parent): two workers, each connection limited to `connection_time`.
    pub fn serve<L: ProxyListener, F: RecordFile + 'static>(
        listener: L,
        store: HostStore<F>,
        connection_time: Duration,
    ) -> io::Result<()> {
        let store = Arc::new(Mutex::new(store));
        let limits = ServiceLimits { workers: 2, queue: 8, connection_time };
        BoundedService::new(listener, limits)
            .serve(move |stream: &mut DeadlineStream<L::Stream>| serve_connection(&store, stream), None)
    }

    /// The enclave's side of the host's store: one connection per request,
    /// the whole request within its deadline. Any failure, a refusal or a
    /// timeout is [`SealError::Journal`].
    pub struct HostJournal<C: Connector = VsockConnector> {
        connector: C,
        deadline: Duration,
    }

    impl HostJournal<VsockConnector> {
        /// The store on the parent: CID 3, port [`JOURNAL_PORT`], with
        /// [`REQUEST_DEADLINE`].
        pub fn parent() -> HostJournal<VsockConnector> {
            HostJournal::new(VsockConnector { cid: PARENT_CID, port: JOURNAL_PORT }, REQUEST_DEADLINE)
        }
    }

    impl<C: Connector> HostJournal<C> {
        /// The store `connector` reaches, each request limited to `deadline`.
        pub fn new(connector: C, deadline: Duration) -> HostJournal<C> {
            HostJournal { connector, deadline }
        }

        fn send(&self, request: &[u8]) -> Result<DeadlineStream<C::Stream>, SealError> {
            let unreachable = SealError::Journal("the host journal cannot be reached");
            let stream = self.connector.connect_stream().map_err(|_| unreachable.clone())?;
            let mut stream = DeadlineStream::new(stream, Instant::now() + self.deadline);
            write_frame(&mut stream, request).map_err(|_| unreachable)?;
            Ok(stream)
        }
    }

    const NO_ANSWER: SealError = SealError::Journal("the host journal did not answer in time");

    impl<C: Connector> LogStore for HostJournal<C> {
        fn append(&mut self, counter: u64, record: &[u8]) -> Result<(), SealError> {
            let mut stream = self.send(&[&[REQUEST_APPEND][..], &counter.to_be_bytes(), record].concat())?;
            let answer = read_frame(&mut stream);
            stream.close();
            match answer.map_err(|_| NO_ANSWER)?.as_slice() {
                [ANSWER_OK] => Ok(()),
                _ => Err(SealError::Journal("the host journal refused the record")),
            }
        }

        fn read_all(&mut self) -> Result<Vec<(u64, Vec<u8>)>, SealError> {
            let mut stream = self.send(&[REQUEST_READ_ALL])?;
            let mut records = Vec::new();
            let result = loop {
                let frame = match read_frame(&mut stream) {
                    Ok(frame) => frame,
                    Err(_) => break Err(NO_ANSWER),
                };
                match frame.split_first() {
                    Some((&ANSWER_RECORD, rest)) if rest.len() > 8 => {
                        let counter = u64::from_be_bytes(rest[..8].try_into().expect("8 bytes"));
                        records.push((counter, rest[8..].to_vec()));
                    }
                    Some((&ANSWER_OK, count)) if count == (records.len() as u64).to_be_bytes() => break Ok(records),
                    _ => break Err(SealError::Journal("the host journal's answer is malformed")),
                }
            };
            stream.close();
            result
        }
    }
}
