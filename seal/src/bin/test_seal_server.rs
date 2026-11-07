//! The development test Seal server: the relay protocol over HTTP(S),
//! running the Seal's Check against the public test M, with the card
//! registry file and the chain check over two or more real nodes. For
//! development and the phone's speed test only, never for real money. See
//! `ghost_seal::test_server` and `docs/seal-relay.md`.
//!
//! ```text
//! GHOST_DEV_TEST_SEAL=1 test_seal_server --dev-test-seal --registry FILE
//!     --node URL --node URL [--node URL ...] --journal FILE
//!     [--network CHAIN_ID:GENESIS_HEX] [--listen ADDR:PORT]
//!     [--tls-cert CERT.pem --tls-key KEY.pem] [--idle-ms N]
//!     [--total-ms N] [--max-sessions N] [--body-ms N]
//! ```
//!
//! Without the registry, with fewer than two nodes or without the journal
//! file it refuses to start, with one line; so it does for a journal file
//! that fails its checks. The journal file (created mode 0600) keeps the
//! test Seal's journal across restarts.

use ghost_seal::test_server::{DEV_ENV, Options, StartError, TestSealServer, USAGE, WARNING};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dev_env = std::env::var(DEV_ENV).ok();
    let options = Options::from_args(&args, dev_env.as_deref()).unwrap_or_else(|error| {
        match error {
            // No registry, too few nodes or no journal: one plain line.
            StartError::Missing(_) => eprintln!("test_seal_server: {error}"),
            _ => eprintln!("test_seal_server: {error}\n{USAGE}"),
        }
        std::process::exit(2);
    });
    eprintln!("{WARNING}");
    let server = TestSealServer::start(&options).unwrap_or_else(|error| {
        eprintln!("test_seal_server: {error}");
        std::process::exit(2);
    });
    eprintln!("test_seal_server: serving the relay on {}", server.url());
    server.wait();
}
