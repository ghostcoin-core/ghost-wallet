//! The development test Seal server: the relay protocol over HTTP(S),
//! running the Seal's Check against the public test M. For development and
//! the phone's speed test only, never for real money. See
//! `ghost_seal::test_server` and `docs/seal-relay.md`.
//!
//! ```text
//! GHOST_DEV_TEST_SEAL=1 test_seal_server --dev-test-seal [--listen ADDR:PORT]
//!     [--tls-cert CERT.pem --tls-key KEY.pem] [--idle-ms N] [--total-ms N] [--max-sessions N]
//! ```

use ghost_seal::test_server::{DEV_ENV, Options, TestSealServer, USAGE, WARNING};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dev_env = std::env::var(DEV_ENV).ok();
    let options = Options::from_args(&args, dev_env.as_deref()).unwrap_or_else(|error| {
        eprintln!("test_seal_server: {error}\n{USAGE}");
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
