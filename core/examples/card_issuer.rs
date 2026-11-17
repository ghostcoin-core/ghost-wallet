//! A Ghost card issuer's key and certificates, for development cards
//! (`src/java_card.rs`, "the card's certificate"). The production issuer
//! signs at its own offline loading station; this is the same signature with
//! a development key that only builds for a test network trust.
//!
//! ```text
//! cargo run --example card_issuer -- keygen <key file>
//! cargo run --example card_issuer -- public-key <key file>
//! cargo run --example card_issuer -- certify <key file> <card id> <LMS public key> <applet hash> <batch>
//! ```
//!
//! The key file holds SK.seed, SK.prf and PK.seed as 96 hex digits. Keep it
//! off any repository. `certify` prints the certificate's hex.

use ghost_client::slh_dsa::{N, SigningKey};
use ghost_wallet_core::java_card::{CARD_ID_BYTES, CERT_DOMAIN, LMS_PUBLIC_KEY_BYTES, certificate_body};
use rand::rngs::{StdRng, SysRng};
use rand::{SeedableRng, TryRng};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const L: usize>(text: &str, what: &str) -> [u8; L] {
    let text = text.trim();
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2).unwrap_or("zz"), 16).unwrap_or_else(|_| panic!("{what}: not hex")))
        .collect();
    bytes.try_into().unwrap_or_else(|_| panic!("{what}: not {L} bytes"))
}

fn key(path: &str) -> SigningKey {
    let text = std::fs::read_to_string(path).expect("read the key file");
    let all: [u8; 3 * N] = unhex(&text, "key file");
    SigningKey::from_seeds(
        all[..N].try_into().unwrap(),
        all[N..2 * N].try_into().unwrap(),
        all[2 * N..].try_into().unwrap(),
    )
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("keygen") => {
            let path = &args[1];
            assert!(std::fs::metadata(path).is_err(), "{path} exists already");
            let mut seeds = [0u8; 3 * N];
            SysRng.try_fill_bytes(&mut seeds).expect("randomness");
            std::fs::write(path, hex(&seeds)).expect("write the key file");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            println!("{}", hex(&key(path).public_key()));
        }
        Some("public-key") => println!("{}", hex(&key(&args[1]).public_key())),
        Some("certify") => {
            let signing = key(&args[1]);
            let card_id: [u8; CARD_ID_BYTES] = unhex(&args[2], "card id");
            let lms: [u8; LMS_PUBLIC_KEY_BYTES] = unhex(&args[3], "LMS public key");
            let applet: [u8; 32] = unhex(&args[4], "applet hash");
            let batch: u32 = args[5].parse().expect("batch");
            let body = certificate_body(&signing.public_key(), &card_id, &lms, &applet, batch);
            let mut rng = StdRng::try_from_rng(&mut SysRng).expect("randomness");
            let signature = signing.sign(&body, CERT_DOMAIN, &mut rng).expect("sign");
            let mut cert = body.to_vec();
            cert.extend_from_slice(&signature[..]);
            println!("{}", hex(&cert));
        }
        _ => {
            eprintln!("usage: card_issuer keygen|public-key|certify ...");
            std::process::exit(2);
        }
    }
}
