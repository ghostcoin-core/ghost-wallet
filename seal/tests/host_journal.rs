//! The journal store on the parent host and the enclave's client for it,
//! over local sockets (the sandbox has no vsock): append and read all, the
//! store's own checks (the next counter only, at most 4096 bytes), a torn
//! last record dropped at open, the file's mode, no answer before the
//! flush, a slow or silent host timing out, and both ends restarted; and the
//! logs a host keeps for the peer regions (one file per origin region, on
//! the same port, ciphertext only), as a peer enclave fills and reads them.

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
    self, ANSWER_OK, ANSWER_RECORD, ANSWER_REFUSED, HostJournal, HostStore, HostStores, JOURNAL_FILE, JOURNAL_PORT,
    PARENT_CID, REQUEST_APPEND, REQUEST_DEADLINE, REQUEST_PEER, REQUEST_READ_ALL, RecordFile, StoreRefused,
    peer_log_file, peer_request,
};
use ghost_seal::journal_anchor::{Anchor, Peer, PeerLink, PeerLogs};
use ghost_seal::journal_log::{JournalLog, LogStore, MAX_RECORD_BYTES, MemoryLogStore, SharedLog};
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

const US: &str = "us-east-1";
const EU: &str = "eu-central-1";
const AP: &str = "ap-southeast-1";

/// Serves the journal in `dir` and the peer logs of `origins` beside it, on
/// one Unix socket; its path.
fn serve_with_peers(dir: &Path, socket: &str, origins: &[&str]) -> PathBuf {
    let journal = HostStore::open(&dir.join("journal.log")).unwrap();
    let peers = origins
        .iter()
        .map(|origin| (origin.to_string(), HostStore::open(&dir.join(format!("peer-{origin}.log"))).unwrap()))
        .collect();
    let stores = HostStores::new(journal, peers);
    assert_eq!(stores.origins(), origins.to_vec());
    let path = dir.join(socket);
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || host_journal::serve(listener, stores, Duration::from_secs(5)));
    path
}

#[test]
fn the_host_keeps_one_log_per_peer_region_on_the_same_port() {
    assert_eq!(REQUEST_PEER, 3);
    assert_eq!(peer_log_file(US), "/var/lib/seal/peer-us-east-1.log");
    assert_eq!(peer_log_file(AP), "/var/lib/seal/peer-ap-southeast-1.log");
    // Building the parent's client of a peer log opens nothing.
    let _ = HostJournal::parent_peer(US);

    let dir = scratch("peers");
    let socket = serve_with_peers(&dir, "s", &[US, AP]);
    let mut own = client(&socket);
    let mut us = client(&socket).peer_log(US);
    let mut ap = client(&socket).peer_log(AP);
    own.append(1, b"own record").unwrap();
    us.append(1, b"us record one").unwrap();
    us.append(2, b"us record two").unwrap();
    // Each log has its own counters and the store's checks.
    assert!(matches!(ap.append(2, b"skips one"), Err(SealError::Journal(_))));
    assert!(matches!(ap.append(1, &record(1, 4097)), Err(SealError::Journal(_))));
    ap.append(1, b"ap record one").unwrap();
    assert_eq!(own.read_all().unwrap(), vec![(1, b"own record".to_vec())]);
    assert_eq!(us.read_all().unwrap(), vec![(1, b"us record one".to_vec()), (2, b"us record two".to_vec())]);
    assert_eq!(ap.read_all().unwrap(), vec![(1, b"ap record one".to_vec())]);

    // A region the host was given no file for is refused, either way.
    let mut eu = client(&socket).peer_log(EU);
    assert!(matches!(eu.read_all(), Err(SealError::Journal(_))));
    assert!(matches!(eu.append(1, b"nowhere"), Err(SealError::Journal(_))));

    // The wire: REQUEST_PEER || origin length || origin || the request.
    let mut stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write_frame(&mut stream, &peer_request(US, &[REQUEST_READ_ALL])).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap(), [&[ANSWER_RECORD][..], &1u64.to_be_bytes(), b"us record one"].concat());
    assert_eq!(read_frame(&mut stream).unwrap(), [&[ANSWER_RECORD][..], &2u64.to_be_bytes(), b"us record two"].concat());
    assert_eq!(read_frame(&mut stream).unwrap(), [&[ANSWER_OK][..], &2u64.to_be_bytes()].concat());
    for bad in [vec![REQUEST_PEER], vec![REQUEST_PEER, 200, b'u'], peer_request("sa-east-1", &[REQUEST_READ_ALL])] {
        write_frame(&mut stream, &bad).unwrap();
        assert_eq!(read_frame(&mut stream).unwrap()[0], ANSWER_REFUSED);
    }
    drop(stream);

    // Each in its own file, which reopens with what was answered ok.
    assert_eq!(HostStore::open(&dir.join("journal.log")).unwrap().records().len(), 1);
    assert_eq!(HostStore::open(&dir.join("peer-us-east-1.log")).unwrap().records().len(), 2);
    assert_eq!(HostStore::open(&dir.join("peer-ap-southeast-1.log")).unwrap().records().len(), 1);
    assert!(!dir.join("peer-eu-central-1.log").exists());
}

/// A peer region's enclave in this process: its answers over its logs.
struct InProcess(Arc<PeerLogs>);

impl PeerLink for InProcess {
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        self.0.answer(&support::master(), request)
    }
}

/// A random source for an anchor (test only).
struct Counting(u64);

impl ghost_seal::SealRandom for Counting {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), SealError> {
        for chunk in out.chunks_mut(32) {
            self.0 += 1;
            let block = ghost_seal::primitives::sha3_256(&[b"host journal anchor test", &self.0.to_be_bytes()]);
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        Ok(())
    }
}

#[test]
fn a_peer_enclave_keeps_another_regions_log_on_its_host_and_a_replaced_host_restores_from_it() {
    // eu-central-1's host keeps the log of us-east-1 for its enclave.
    let dir = scratch("peer-enclave");
    let socket = serve_with_peers(&dir, "s", &[US, AP]);
    let peer = |socket: &Path| -> Arc<PeerLogs> {
        let stores: Vec<(String, Box<dyn LogStore>)> = vec![
            (US.to_string(), Box::new(client(socket).peer_log(US))),
            (AP.to_string(), Box::new(client(socket).peer_log(AP))),
        ];
        Arc::new(PeerLogs::new(EU, stores))
    };
    let eu = peer(&socket);
    let anchor = |logs: &Arc<PeerLogs>, seed: u64| {
        let peers = vec![Peer { region: EU.into(), link: Arc::new(InProcess(Arc::clone(logs))) as Arc<dyn PeerLink> }];
        Anchor::with_random(US, peers, Box::new(Counting(seed << 32)))
    };

    // us-east-1 writes four records; each reaches eu-central-1's host.
    let us_store = MemoryLogStore::new();
    let mut log =
        JournalLog::open_anchored(&support::master(), Box::new(us_store.clone()), Box::new(Counting(1)), Box::new(anchor(&eu, 1)))
            .unwrap();
    log.save(&UID, EntryKind::Fill, b"a fill entry".to_vec()).unwrap();
    log.save(&UID, EntryKind::Open, b"an open entry".to_vec()).unwrap();
    log.save(&OTHER, EntryKind::Fill, b"another card".to_vec()).unwrap();
    log.save(&UID, EntryKind::Fill, b"the fill entry replaced".to_vec()).unwrap();
    drop(log);
    let on_disk = HostStore::open(&dir.join("peer-us-east-1.log")).unwrap();
    assert_eq!(on_disk.records(), us_store.records().as_slice(), "the peer's host holds us-east-1's records as written");
    assert!(HostStore::open(&dir.join("peer-ap-southeast-1.log")).unwrap().records().is_empty());
    let bytes = std::fs::read(dir.join("peer-us-east-1.log")).unwrap();
    for clear in [&b"a fill entry"[..], b"an open entry", b"another card", &UID.0, &OTHER.0] {
        assert!(!support::contains(&bytes, clear), "the peer log is ciphertext only");
    }

    // eu-central-1's host and enclave restart on the same files, and
    // us-east-1's host is replaced: an empty store, restored from the peer.
    let socket = serve_with_peers(&dir, "second", &[US, AP]);
    let eu = peer(&socket);
    let replaced = MemoryLogStore::new();
    let log =
        JournalLog::open_anchored(&support::master(), Box::new(replaced.clone()), Box::new(Counting(2)), Box::new(anchor(&eu, 2)))
            .unwrap();
    assert_eq!(log.counter(), 4);
    assert_eq!(replaced.records(), us_store.records());
    assert_eq!(log.load(&UID, EntryKind::Fill), Some(b"the fill entry replaced".to_vec()));
    assert_eq!(log.load(&UID, EntryKind::Open), Some(b"an open entry".to_vec()));

    // A peer log the host changed fails the peer's own check: it answers
    // nothing about it, and the origin's log does not open.
    let path = dir.join("peer-us-east-1.log");
    let mut records = HostStore::open(&path).unwrap().records().to_vec();
    records[1].1[20] ^= 0x01;
    std::fs::remove_file(&path).unwrap();
    let mut store = HostStore::open(&path).unwrap();
    for (counter, record) in &records {
        store.append(*counter, record).unwrap();
    }
    drop(store);
    let socket = serve_with_peers(&dir, "third", &[US, AP]);
    let eu = peer(&socket);
    let empty = MemoryLogStore::new();
    let refused =
        JournalLog::open_anchored(&support::master(), Box::new(empty.clone()), Box::new(Counting(3)), Box::new(anchor(&eu, 3)));
    assert!(refused.is_err());
    assert!(empty.records().is_empty(), "nothing restored from a log that fails its checks");
}
