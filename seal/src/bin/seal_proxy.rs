//! The parent proxy, run on the enclave's parent instance. It relays bytes
//! and never reads them: see `ghost_seal::proxy`.
//!
//! ```text
//! seal_proxy inbound <listen address:port> <enclave CID> <enclave port> [--max-connections N] [--idle-secs N]
//! seal_proxy outbound <vsock port> <upstream host:port> [--max-connections N] [--idle-secs N]
//! seal_proxy start <enclave CID> genesis|join <measurements list file>
//! ```
//!
//! `inbound` takes TCP connections from the internet (phones, and other
//! regions' enclaves asking for a key share) and relays each to the
//! enclave's service port over vsock. `outbound` takes vsock connections
//! from the enclave and relays each to one fixed upstream: a giving region's
//! inbound proxy for a key share, or a Ghost node for the chain check.
//! `start` sends the enclave its one start frame on its control port (the
//! mode and the measurements list it is to enforce) and prints its answer.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use ghost_seal::key_share::{read_frame, write_frame};
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

const USAGE: &str = "usage:\n  seal_proxy inbound <listen address:port> <enclave CID> <enclave port> [--max-connections N] [--idle-secs N]\n  seal_proxy outbound <vsock port> <upstream host:port> [--max-connections N] [--idle-secs N]\n  seal_proxy start <enclave CID> genesis|join <measurements list file>";

/// Sends the start frame and prints the enclave's answer.
fn start(cid: u32, mode: &str, list_file: &str) -> ! {
    let mode = match mode {
        "genesis" => 1u8,
        "join" => 2u8,
        _ => fail("the mode is genesis or join"),
    };
    let list = std::fs::read(list_file).unwrap_or_else(|e| fail(&format!("cannot read {list_file}: {e}")));
    let mut stream = VsockStream::connect_with_cid_port(cid, CONTROL_PORT)
        .unwrap_or_else(|e| fail(&format!("cannot reach the enclave's control port: {e}")));
    let _ = stream.set_read_timeout(Some(Duration::from_secs(120)));
    let frame = [&[mode][..], &list].concat();
    write_frame(&mut stream, &frame).unwrap_or_else(|e| fail(&format!("cannot send the start frame: {e}")));
    let answer = read_frame(&mut stream).unwrap_or_else(|e| fail(&format!("no answer from the enclave: {e}")));
    let answer = String::from_utf8_lossy(&answer);
    eprintln!("seal_proxy: the enclave answered: {answer}");
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
        _ => fail("unknown command"),
    };
    if let Err(error) = result {
        fail(&format!("stopped: {error}"));
    }
}
