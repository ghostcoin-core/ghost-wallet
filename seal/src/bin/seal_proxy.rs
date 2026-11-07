//! The parent proxy, run on the enclave's parent instance. It relays bytes
//! and never reads them: see `ghost_seal::proxy`.
//!
//! ```text
//! seal_proxy inbound <listen address:port> <enclave CID> <enclave port> [--max-connections N] [--idle-secs N]
//! seal_proxy outbound <vsock port> <upstream host:port> [--max-connections N] [--idle-secs N]
//! seal_proxy start <enclave CID> genesis|join <measurements list file>
//! seal_proxy list <enclave CID> <signed measurements list file>
//! seal_proxy registry <enclave CID> <registry file>
//! seal_proxy journal <vsock port> <journal file> [<region>=<peer log file> ...]
//! ```
//!
//! `inbound` takes TCP connections from the internet (phones, and other
//! regions' enclaves asking for a key share) and relays each to the
//! enclave's service port over vsock. `outbound` takes vsock connections
//! from the enclave and relays each to one fixed upstream: a giving region's
//! inbound proxy for a key share, or a Ghost node for the chain check.
//! `start` offers the enclave the list file on its control port, which the
//! enclave takes only if the release key compiled into its image signed it,
//! and then sends its one start frame (the mode alone): a joining enclave
//! (its own region's image) trusts a giver in another region through that
//! list. `list` offers a later signed list. The host cannot make an enclave
//! trust a list: an unsigned one is refused, and the start of a join carries
//! none.
//! `registry` sends the enclave the card registry file (control frame 4),
//! after the start: the whole file each time, so a card set up since is
//! added. The enclave refuses a file that leaves out or changes a card it
//! already holds.
//! `journal` keeps the enclave's journal store (`ghost_seal::host_journal`)
//! in one file (`/var/lib/seal/journal.log`, created mode 0600) and serves
//! it to the enclave on a vsock port (5005): it appends only the next
//! counter, flushes the file and its directory to disk before it answers,
//! and drops a torn last record when it opens the file. It sees only
//! counters and records the enclave sealed; the enclave checks them. Each
//! `<region>=<file>` after it keeps, the same way, the copy of that other
//! region's log the enclave holds as its peer
//! (`/var/lib/seal/peer-<region>.log`), on the same port.
//! `outbound 5006` and `outbound 5007` carry the enclave's journal head
//! requests to the two other regions' inbound proxies.

use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ghost_seal::host_journal::{self, HostStore, HostStores};
use ghost_seal::key_share::{
    CONTROL_GENESIS, CONTROL_JOIN, CONTROL_REGISTRY, CONTROL_SIGNED_LIST, read_frame, write_control_frame,
};
use ghost_seal::proxy::{Proxy, ProxyEvent, ProxyLimits, ProxyLog, TcpConnector, VsockConnector};
use vsock::{VMADDR_CID_ANY, VsockListener, VsockStream};

/// The enclave's control port (see `seal_enclave`).
const CONTROL_PORT: u32 = 5000;

/// Writes events to standard error. Events carry no relayed bytes.
struct StderrLog;

impl ProxyLog for StderrLog {
    fn event(&self, event: ProxyEvent) {
        eprintln!("seal_proxy: {event}");
    }
}

const USAGE: &str = "usage:\n  seal_proxy inbound <listen address:port> <enclave CID> <enclave port> [--max-connections N] [--idle-secs N]\n  seal_proxy outbound <vsock port> <upstream host:port> [--max-connections N] [--idle-secs N]\n  seal_proxy start <enclave CID> genesis|join <measurements list file>\n  seal_proxy list <enclave CID> <signed measurements list file>\n  seal_proxy registry <enclave CID> <registry file>\n  seal_proxy journal <vsock port> <journal file> [<region>=<peer log file> ...]";

/// How long one journal connection may last.
const JOURNAL_CONNECTION_TIME: Duration = Duration::from_secs(30);

/// Opens the store in `file`, saying so.
fn open_store(file: &str) -> HostStore {
    let store = HostStore::open(Path::new(file)).unwrap_or_else(|e| fail(&format!("cannot open {file}: {e}")));
    if store.dropped_torn_record() {
        eprintln!("seal_proxy: dropped a torn last record of {file}");
    }
    store
}

/// Keeps the journal store in `file` and, for each `<region>=<file>` of
/// `peers`, the log of that peer region, and serves them on vsock `port`.
fn journal(port: u32, file: &str, peers: &[&str]) -> std::io::Result<()> {
    let journal = open_store(file);
    eprintln!("seal_proxy: serving the journal store {file} ({} records) on vsock port {port}", journal.records().len());
    let mut logs = Vec::new();
    for peer in peers {
        let Some((origin, path)) = peer.split_once('=') else { fail("a peer log is <region>=<file>") };
        if !ghost_seal::journal_anchor::valid_region(origin) || path.is_empty() {
            fail("a peer log is <region>=<file>, the region 1 to 32 of a-z, 0-9 and -");
        }
        let store = open_store(path);
        eprintln!("seal_proxy: serving the peer log of {origin} {path} ({} records)", store.records().len());
        logs.push((origin.to_owned(), store));
    }
    let listener = VsockListener::bind_with_cid_port(VMADDR_CID_ANY, port)
        .unwrap_or_else(|e| fail(&format!("cannot listen on vsock port {port}: {e}")));
    host_journal::serve(listener, HostStores::new(journal, logs), JOURNAL_CONNECTION_TIME)
}

/// Sends one control frame and returns the enclave's answer.
fn control(cid: u32, frame: &[u8]) -> String {
    let mut stream = VsockStream::connect_with_cid_port(cid, CONTROL_PORT)
        .unwrap_or_else(|e| fail(&format!("cannot reach the enclave's control port: {e}")));
    let _ = stream.set_read_timeout(Some(Duration::from_secs(120)));
    write_control_frame(&mut stream, frame)
        .unwrap_or_else(|e| fail(&format!("cannot send the control frame: {e}")));
    let answer = read_frame(&mut stream).unwrap_or_else(|e| fail(&format!("no answer from the enclave: {e}")));
    let answer = String::from_utf8_lossy(&answer).into_owned();
    eprintln!("seal_proxy: the enclave answered: {answer}");
    answer
}

/// Offers the enclave the list file, then starts it (the mode alone).
fn start(cid: u32, mode: &str, list_file: &str) -> ! {
    let mode = match mode {
        "genesis" => CONTROL_GENESIS,
        "join" => CONTROL_JOIN,
        _ => fail("the mode is genesis or join"),
    };
    let list = std::fs::read(list_file).unwrap_or_else(|e| fail(&format!("cannot read {list_file}: {e}")));
    // Before the start: each region runs its own image, so a joining enclave
    // trusts its giver in another region only through the release's signed
    // list. The enclave takes it only if its release key signed it; a refusal
    // leaves it on what its image trusts by itself.
    control(cid, &[&[CONTROL_SIGNED_LIST][..], &list].concat());
    if !control(cid, &[mode]).starts_with("ok") {
        std::process::exit(1);
    }
    std::process::exit(0);
}

/// Offers the enclave a later signed list.
fn list(cid: u32, list_file: &str) -> ! {
    let list = std::fs::read(list_file).unwrap_or_else(|e| fail(&format!("cannot read {list_file}: {e}")));
    let answer = control(cid, &[&[CONTROL_SIGNED_LIST][..], &list].concat());
    std::process::exit(if answer.starts_with("ok") { 0 } else { 1 });
}

/// Sends the enclave the card registry file.
fn registry(cid: u32, registry_file: &str) -> ! {
    let text = std::fs::read(registry_file).unwrap_or_else(|e| fail(&format!("cannot read {registry_file}: {e}")));
    let answer = control(cid, &[&[CONTROL_REGISTRY][..], &text].concat());
    std::process::exit(if answer.starts_with("ok") { 0 } else { 1 });
}

fn fail(why: &str) -> ! {
    eprintln!("seal_proxy: {why}\n{USAGE}");
    std::process::exit(2);
}

fn number<T: std::str::FromStr>(text: Option<&String>, what: &str) -> T {
    text.and_then(|t| t.parse().ok()).unwrap_or_else(|| fail(&format!("{what} is not a number")))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut limits = ProxyLimits::default();
    let mut positional = Vec::new();
    let mut at = 0;
    while at < args.len() {
        match args[at].as_str() {
            "--max-connections" => {
                limits.max_connections = number(args.get(at + 1), "--max-connections");
                at += 2;
            }
            "--idle-secs" => {
                limits.idle_timeout = Duration::from_secs(number(args.get(at + 1), "--idle-secs"));
                at += 2;
            }
            other => {
                positional.push(other.to_owned());
                at += 1;
            }
        }
    }
    if limits.max_connections == 0 || limits.idle_timeout.is_zero() {
        fail("limits must be more than zero");
    }
    let log: Arc<dyn ProxyLog> = Arc::new(StderrLog);
    let result = match positional.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["inbound", listen, cid, port] => {
            let listener = TcpListener::bind(listen).unwrap_or_else(|e| fail(&format!("cannot listen on {listen}: {e}")));
            let connector = VsockConnector {
                cid: number(Some(&cid.to_string()), "the enclave CID"),
                port: number(Some(&port.to_string()), "the enclave port"),
            };
            eprintln!("seal_proxy: relaying tcp {listen} to vsock {}:{}", connector.cid, connector.port);
            Proxy::new(listener, connector, limits, log).serve(None)
        }
        ["outbound", port, upstream] => {
            let port: u32 = number(Some(&port.to_string()), "the vsock port");
            let listener = VsockListener::bind_with_cid_port(VMADDR_CID_ANY, port)
                .unwrap_or_else(|e| fail(&format!("cannot listen on vsock port {port}: {e}")));
            eprintln!("seal_proxy: relaying vsock port {port} to tcp {upstream}");
            Proxy::new(listener, TcpConnector(upstream.to_string()), limits, log).serve(None)
        }
        ["start", cid, mode, list_file] => start(number(Some(&cid.to_string()), "the enclave CID"), mode, list_file),
        ["list", cid, list_file] => list(number(Some(&cid.to_string()), "the enclave CID"), list_file),
        ["registry", cid, registry_file] => {
            registry(number(Some(&cid.to_string()), "the enclave CID"), registry_file)
        }
        ["journal", port, file, peers @ ..] => journal(number(Some(&port.to_string()), "the vsock port"), file, peers),
        _ => fail("unknown command"),
    };
    if let Err(error) = result {
        fail(&format!("stopped: {error}"));
    }
}
