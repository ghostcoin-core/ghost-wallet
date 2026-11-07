//! The journal store on the parent host and the enclave's client for it,
//! over local sockets (the sandbox has no vsock): append and read all, the
//! store's own checks (the next counter only, at most 4096 bytes), a torn
//! last record dropped at open, the file's mode, no answer before the
//! flush, a slow or silent host timing out, and both ends restarted.

mod support;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ghost_seal::host_journal::{
    self, ANSWER_OK, ANSWER_RECORD, ANSWER_REFUSED, HostJournal, HostStore, JOURNAL_FILE, JOURNAL_PORT, PARENT_CID,
    REQUEST_APPEND, REQUEST_DEADLINE, REQUEST_READ_ALL, RecordFile, StoreRefused,
};
use ghost_seal::journal_log::{JournalLog, LogStore, MAX_RECORD_BYTES, SharedLog};
use ghost_seal::key_share::{read_frame, write_frame};
use ghost_seal::proxy::{TcpConnector, UnixConnector};
use ghost_seal::{CardUid, EntryKind, Journal, SealError};
use support::UID;

const OTHER: CardUid = CardUid([0x04, 0x10, 0x20, 0x30, 0x40, 0x50, 0x61]);

/// A fresh, empty directory of the test's own.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gs-hj-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Serves the store in `file` on a Unix socket in `dir`; its path.
fn serve_file(dir: &Path, socket: &str, file: &Path) -> PathBuf {
    serve_store(dir, socket, HostStore::open(file).expect("the store opens"))
}

fn serve_store<F: RecordFile + 'static>(dir: &Path, socket: &str, store: HostStore<F>) -> PathBuf {
    let path = dir.join(socket);
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || host_journal::serve(listener, store, Duration::from_secs(5)));
    path
}

fn client(socket: &Path) -> HostJournal<UnixConnector> {
    HostJournal::new(UnixConnector(socket.to_path_buf()), Duration::from_secs(5))
}

fn record(byte: u8, length: usize) -> Vec<u8> {
    vec![byte; length]
}

#[test]
fn the_parent_store_is_on_cid_3_port_5005_with_a_10_second_deadline() {
    assert_eq!((PARENT_CID, JOURNAL_PORT), (3, 5005));
    assert_eq!(REQUEST_DEADLINE, Duration::from_secs(10));
    assert_eq!(JOURNAL_FILE, "/var/lib/seal/journal.log");
    assert_eq!((REQUEST_APPEND, REQUEST_READ_ALL), (1, 2));
    // Building the parent's client opens nothing.
    let _ = HostJournal::parent();
}

#[test]
fn append_and_read_all_over_a_local_socket() {
    let dir = scratch("append");
    let socket = serve_file(&dir, "s", &dir.join("journal.log"));
    let mut host = client(&socket);
    assert_eq!(host.read_all().unwrap(), vec![]);
    host.append(1, &record(0x11, 64)).unwrap();
    host.append(2, &record(0x22, 4096)).unwrap();
    host.append(3, &record(0x33, 1)).unwrap();
    assert_eq!(host.read_all().unwrap(), vec![(1, record(0x11, 64)), (2, record(0x22, 4096)), (3, record(0x33, 1))]);
    // What is on disk is what was answered ok.
    let store = HostStore::open(&dir.join("journal.log")).unwrap();
    assert_eq!(store.records().len(), 3);
    assert!(!store.dropped_torn_record());
}

#[test]
fn the_wire_format_is_framed_requests_and_answers() {
    let dir = scratch("wire");
    let socket = serve_file(&dir, "s", &dir.join("journal.log"));
    let mut stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write_frame(&mut stream, &[&[REQUEST_APPEND][..], &1u64.to_be_bytes(), b"record one"].concat()).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap(), vec![ANSWER_OK]);
    write_frame(&mut stream, &[&[REQUEST_APPEND][..], &5u64.to_be_bytes(), b"out of turn"].concat()).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap()[0], ANSWER_REFUSED);
    write_frame(&mut stream, &[REQUEST_READ_ALL]).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap(), [&[ANSWER_RECORD][..], &1u64.to_be_bytes(), b"record one"].concat());
    assert_eq!(read_frame(&mut stream).unwrap(), [&[ANSWER_OK][..], &1u64.to_be_bytes()].concat());
    write_frame(&mut stream, &[9]).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap()[0], ANSWER_REFUSED);
}

#[test]
fn an_append_with_the_wrong_counter_is_refused() {
    let dir = scratch("counter");
    let mut store = HostStore::open(&dir.join("journal.log")).unwrap();
    assert_eq!(store.append(0, b"zero"), Err(StoreRefused::WrongCounter));
    assert_eq!(store.append(2, b"skips one"), Err(StoreRefused::WrongCounter));
    store.append(1, b"one").unwrap();
    assert_eq!(store.append(1, b"one again"), Err(StoreRefused::WrongCounter));
    assert_eq!(store.records(), &[(1, b"one".to_vec())]);

    // Over the socket: refused, as a journal error.
    let socket = serve_store(&dir, "s", store);
    let mut host = client(&socket);
    assert!(matches!(host.append(3, b"skips one"), Err(SealError::Journal(_))));
    assert!(matches!(host.append(1, b"a repeat"), Err(SealError::Journal(_))));
    host.append(2, b"two").unwrap();
    assert_eq!(host.read_all().unwrap().len(), 2);
}

#[test]
fn a_record_over_4096_bytes_is_refused() {
    let dir = scratch("large");
    let mut store = HostStore::open(&dir.join("journal.log")).unwrap();
    assert_eq!(MAX_RECORD_BYTES, 4096);
    assert_eq!(store.append(1, &record(1, 4097)), Err(StoreRefused::BadLength));
    assert_eq!(store.append(1, &[]), Err(StoreRefused::BadLength));
    store.append(1, &record(1, 4096)).unwrap();
    let socket = serve_store(&dir, "s", store);
    let mut host = client(&socket);
    assert!(matches!(host.append(2, &record(2, 4097)), Err(SealError::Journal(_))));
    host.append(2, &record(2, 100)).unwrap();
}

fn three_records(path: &Path) -> Vec<u8> {
    let mut store = HostStore::open(path).unwrap();
    for counter in 1..=3u64 {
        store.append(counter, &record(counter as u8, 50 + counter as usize)).unwrap();
    }
    std::fs::read(path).unwrap()
}

#[test]
fn a_torn_last_record_on_disk_is_dropped_at_open() {
    let dir = scratch("torn");
    let path = dir.join("journal.log");
    let whole = three_records(&path);
    let two = 2 * (8 + 4 + 32) + 51 + 52;

    // Cut short anywhere in the last record, its head included.
    for cut in [1, 10, 40, whole.len() - two - 1] {
        std::fs::write(&path, &whole[..whole.len() - cut]).unwrap();
        let mut store = HostStore::open(&path).unwrap();
        assert!(store.dropped_torn_record(), "cut {cut}");
        assert_eq!(store.records().iter().map(|(c, _)| *c).collect::<Vec<_>>(), vec![1, 2], "cut {cut}");
        assert_eq!(std::fs::metadata(&path).unwrap().len() as usize, two, "the torn bytes are cut from the file");
        // The next append is record 3 again, written whole.
        store.append(3, b"written again").unwrap();
        let reopened = HostStore::open(&path).unwrap();
        assert_eq!(reopened.records().last().unwrap(), &(3, b"written again".to_vec()));
        assert!(!reopened.dropped_torn_record());
    }

    // The last record whole in length but failing its check (a torn write
    // of garbage), and zeros left at the end of the file.
    let mut garbled = whole.clone();
    let last = garbled.len() - 5;
    garbled[last] ^= 0xff;
    std::fs::write(&path, &garbled).unwrap();
    assert_eq!(HostStore::open(&path).unwrap().records().len(), 2);
    let mut zeros = whole.clone();
    zeros.extend_from_slice(&[0u8; 300]);
    std::fs::write(&path, &zeros).unwrap();
    let store = HostStore::open(&path).unwrap();
    assert_eq!((store.records().len(), store.dropped_torn_record()), (3, true));

    // A damaged record with whole records after it is not torn: the store
    // does not open rather than drop them.
    let mut damaged = whole.clone();
    damaged[20] ^= 0x01;
    std::fs::write(&path, &damaged).unwrap();
    assert!(HostStore::open(&path).is_err());
}

#[test]
fn the_file_is_made_mode_0600() {
    let dir = scratch("mode");
    let path = dir.join("journal.log");
    let _store = HostStore::open(&path).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    // A file found readable by others is made 0600 when opened.
    let loose = dir.join("loose.log");
    std::fs::write(&loose, b"").unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _store = HostStore::open(&loose).unwrap();
    assert_eq!(std::fs::metadata(&loose).unwrap().permissions().mode() & 0o777, 0o600);
}

/// A file in memory whose write or flush the test can make fail; it counts
/// the flushes.
#[derive(Clone, Default)]
struct FakeFile {
    state: Arc<Mutex<FakeState>>,
}

#[derive(Default)]
struct FakeState {
    bytes: Vec<u8>,
    fail_sync: bool,
    fail_write: bool,
    syncs: usize,
}

impl RecordFile for FakeFile {
    fn read_all(&mut self) -> std::io::Result<Vec<u8>> {
        Ok(self.state.lock().unwrap().bytes.clone())
    }

    fn append(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.fail_write {
            // Half of it reaches the disk.
            let half = bytes.len() / 2;
            state.bytes.extend_from_slice(&bytes[..half]);
            return Err(std::io::Error::other("the disk is full"));
        }
        state.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn sync(&mut self) -> std::io::Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.fail_sync {
            return Err(std::io::Error::other("the flush failed"));
        }
        state.syncs += 1;
        Ok(())
    }

    fn truncate(&mut self, length: u64) -> std::io::Result<()> {
        self.state.lock().unwrap().bytes.truncate(length as usize);
        Ok(())
    }
}

#[test]
fn nothing_is_acknowledged_before_the_flush() {
    let fake = FakeFile::default();
    let mut store = HostStore::with_file(fake.clone()).unwrap();
    store.append(1, b"flushed").unwrap();
    let syncs = fake.state.lock().unwrap().syncs;
    assert!(syncs >= 1, "an ok append was flushed first");

    // A flush that fails: no ok, nothing kept, the write undone.
    fake.state.lock().unwrap().fail_sync = true;
    let length = fake.state.lock().unwrap().bytes.len();
    assert_eq!(store.append(2, b"never flushed"), Err(StoreRefused::Disk));
    assert_eq!(store.records().len(), 1);
    assert_eq!(fake.state.lock().unwrap().bytes.len(), length, "the unflushed write is cut off");

    // A write that fails half way: the same.
    fake.state.lock().unwrap().fail_sync = false;
    fake.state.lock().unwrap().fail_write = true;
    assert_eq!(store.append(2, b"half written"), Err(StoreRefused::Disk));
    assert_eq!(fake.state.lock().unwrap().bytes.len(), length);
    fake.state.lock().unwrap().fail_write = false;

    // Over the socket, the enclave's client gets no ok while the flush
    // fails, then the same counter goes through.
    let dir = scratch("flush");
    let socket = serve_store(&dir, "s", store);
    let mut host = client(&socket);
    fake.state.lock().unwrap().fail_sync = true;
    assert!(matches!(host.append(2, b"never flushed"), Err(SealError::Journal(_))));
    assert_eq!(host.read_all().unwrap().len(), 1);
    fake.state.lock().unwrap().fail_sync = false;
    host.append(2, b"flushed too").unwrap();
    assert_eq!(host.read_all().unwrap().len(), 2);
    // The file as left reopens whole.
    assert_eq!(HostStore::with_file(fake.clone()).unwrap().records().len(), 2);

    // Through the log, the store in the same process (as the test server
    // runs it): a save the store does not flush fails, and the log takes it
    // as not written.
    let disk = FakeFile::default();
    let mut log = JournalLog::open(&support::master(), Box::new(HostStore::with_file(disk.clone()).unwrap())).unwrap();
    log.save(&UID, EntryKind::Fill, b"fine".to_vec()).unwrap();
    disk.state.lock().unwrap().fail_sync = true;
    assert!(matches!(log.save(&UID, EntryKind::Open, b"lost".to_vec()), Err(SealError::Journal(_))));
    assert_eq!(log.load(&UID, EntryKind::Open), None);
    disk.state.lock().unwrap().fail_sync = false;
    log.save(&UID, EntryKind::Open, b"kept".to_vec()).unwrap();
    let reopened = JournalLog::open(&support::master(), Box::new(HostStore::with_file(disk).unwrap())).unwrap();
    assert_eq!(reopened.load(&UID, EntryKind::Open), Some(b"kept".to_vec()));
}

#[test]
fn a_slow_or_silent_host_times_out_as_a_journal_error() {
    // Silent: takes the connection and never answers.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let silent_addr = silent.local_addr().unwrap();
    thread::spawn(move || {
        let mut held = Vec::new();
        for stream in silent.incoming() {
            held.push(stream);
        }
    });
    // Slow: reads the request, then answers a frame one byte at a time.
    let slow = TcpListener::bind("127.0.0.1:0").unwrap();
    let slow_addr = slow.local_addr().unwrap();
    thread::spawn(move || {
        for stream in slow.incoming() {
            let Ok(mut stream) = stream else { continue };
            thread::spawn(move || {
                let _ = read_frame(&mut stream);
                for byte in [0u8, 0, 0, 1, ANSWER_OK] {
                    thread::sleep(Duration::from_millis(250));
                    if stream.write_all(&[byte]).is_err() {
                        return;
                    }
                }
            });
        }
    });
    let deadline = Duration::from_millis(400);
    for addr in [silent_addr, slow_addr] {
        let mut host = HostJournal::new(TcpConnector(addr.to_string()), deadline);
        let started = Instant::now();
        assert!(matches!(host.append(1, b"record"), Err(SealError::Journal(_))), "{addr}");
        assert!(matches!(host.read_all(), Err(SealError::Journal(_))), "{addr}");
        assert!(started.elapsed() < Duration::from_secs(4), "{addr}: each request is cut at its deadline");
    }
    // Nobody listening at all.
    let gone = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let mut host = HostJournal::new(TcpConnector(gone.to_string()), deadline);
    assert!(matches!(host.read_all(), Err(SealError::Journal(_))));
    // A log over a silent host does not open.
    let silent_log = SharedLog::new(Box::new(HostJournal::new(TcpConnector(silent_addr.to_string()), deadline)));
    assert!(matches!(silent_log.journal(&support::master()), Err(SealError::Journal(_))));
}

#[test]
fn a_host_that_answers_garbage_is_a_journal_error() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = read_frame(&mut stream);
            // One record, then a count that does not match it.
            let _ = write_frame(&mut stream, &[&[ANSWER_RECORD][..], &1u64.to_be_bytes(), b"r"].concat());
            let _ = write_frame(&mut stream, &[&[ANSWER_OK][..], &2u64.to_be_bytes()].concat());
            let mut rest = Vec::new();
            let _ = stream.read_to_end(&mut rest);
        }
    });
    let mut host = HostJournal::new(TcpConnector(addr.to_string()), Duration::from_secs(2));
    assert!(matches!(host.read_all(), Err(SealError::Journal(_))));
    assert!(matches!(host.append(1, b"r"), Err(SealError::Journal(_))));
}

#[test]
fn a_restart_of_both_ends_gives_the_same_entries() {
    let dir = scratch("restart");
    let path = dir.join("journal.log");
    {
        let socket = serve_file(&dir, "first", &path);
        let shared = SharedLog::new(Box::new(client(&socket)));
        let mut log = shared.journal(&support::master()).unwrap();
        log.save(&UID, EntryKind::Fill, b"a fill entry".to_vec()).unwrap();
        log.save(&UID, EntryKind::Open, b"an open entry".to_vec()).unwrap();
        log.save(&OTHER, EntryKind::Fill, b"another card".to_vec()).unwrap();
        log.save(&UID, EntryKind::Fill, b"the fill entry replaced".to_vec()).unwrap();
        // A later handout checks the host's log and finds it whole.
        assert!(shared.journal(&support::master()).is_ok());
    }

    // The host restarts on the same file, and so does the enclave.
    let socket = serve_file(&dir, "second", &path);
    let shared = SharedLog::new(Box::new(client(&socket)));
    let mut log = shared.journal(&support::master()).expect("the log verifies after the restart");
    assert_eq!(log.counter(), 4);
    assert_eq!(log.load(&UID, EntryKind::Fill), Some(b"the fill entry replaced".to_vec()));
    assert_eq!(log.load(&UID, EntryKind::Open), Some(b"an open entry".to_vec()));
    assert_eq!(log.load(&OTHER, EntryKind::Fill), Some(b"another card".to_vec()));
    log.save(&OTHER, EntryKind::Open, b"after the restart".to_vec()).unwrap();
    assert_eq!(HostStore::open(&path).unwrap().records().len(), 5);

    // The file holds counters and ciphertext only.
    let bytes = std::fs::read(&path).unwrap();
    for clear in [&b"a fill entry"[..], b"an open entry", b"another card", &UID.0, &OTHER.0] {
        assert!(!support::contains(&bytes, clear));
    }
}
