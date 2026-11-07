//! The phone's port of the Nitro document check (core/src/seal_attestation.rs)
//! on real documents made by AWS Nitro hardware: the three public test
//! vectors the Seal's tests use (seal/tests/fixtures/nitro_document_*.hex,
//! their sources noted in seal/tests/real_nitro_documents.rs). Each verifies
//! under the pinned AWS root, signature and chain included; a document that
//! is not CBOR is refused with the decoder's reason and the byte it stopped
//! at.

use ghost_wallet_core::seal_attestation::{AWS_NITRO_ROOT_SHA256, check_nitro_document};

struct RealDocument {
    name: &'static str,
    hex: &'static str,
    timestamp_ms: u64,
}

const REAL: [RealDocument; 3] = [
    RealDocument {
        name: "sui",
        hex: include_str!("../../seal/tests/fixtures/nitro_document_sui.hex"),
        timestamp_ms: 0x0000_0193_2d12_39ca,
    },
    RealDocument {
        name: "base",
        hex: include_str!("../../seal/tests/fixtures/nitro_document_base.hex"),
        timestamp_ms: 0x0000_0193_7de1_c543,
    },
    RealDocument {
        name: "nautilus",
        hex: include_str!("../../seal/tests/fixtures/nitro_document_nautilus.hex"),
        timestamp_ms: 0x0000_0196_3743_f8f0,
    },
];

fn from_hex(text: &str) -> Vec<u8> {
    let text = text.trim();
    assert!(text.len() % 2 == 0 && text.bytes().all(|c| c.is_ascii_hexdigit()), "a fixture is not hex");
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

impl RealDocument {
    fn now(&self) -> u64 {
        self.timestamp_ms / 1000 + 1
    }
}

#[test]
fn each_real_document_verifies_under_the_aws_root() {
    for real in &REAL {
        let document = from_hex(real.hex);
        assert!(document.len() > 4400, "{}", real.name);
        assert_eq!(check_nitro_document(&document, &AWS_NITRO_ROOT_SHA256, real.now()), Ok(()), "{}", real.name);
    }
}

#[test]
fn a_real_document_is_still_checked() {
    for real in &REAL {
        let document = from_hex(real.hex);
        let mut flipped = document.clone();
        *flipped.last_mut().unwrap() ^= 0x01;
        assert_eq!(
            check_nitro_document(&flipped, &AWS_NITRO_ROOT_SHA256, real.now()),
            Err("attestation document signature does not verify".to_owned()),
            "{}",
            real.name
        );
        assert_eq!(
            check_nitro_document(&document, &[7; 32], real.now()),
            Err("attestation document does not chain to the pinned root".to_owned()),
            "{}",
            real.name
        );
        assert_eq!(
            check_nitro_document(&document, &AWS_NITRO_ROOT_SHA256, real.now() + 300),
            Err("attestation document or certificate has expired".to_owned()),
            "{}",
            real.name
        );
    }
}

#[test]
fn a_document_that_is_not_cbor_says_why_and_where() {
    let real = &REAL[0];
    let document = from_hex(real.hex);
    // The payload's map head (byte 10 of the document) announces ten fields
    // where nine are: the tenth key runs off the payload's 4385 bytes.
    let mut ten = document.clone();
    assert_eq!(ten[10], 0xa9);
    ten[10] = 0xaa;
    assert_eq!(
        check_nitro_document(&ten, &AWS_NITRO_ROOT_SHA256, real.now()),
        Err("malformed attestation document: the payload is not CBOR: truncated at byte 4385 of 4385".to_owned())
    );
    // One byte short: the signature's length runs past the end.
    let short = &document[..document.len() - 1];
    assert_eq!(
        check_nitro_document(short, &AWS_NITRO_ROOT_SHA256, real.now()),
        Err(format!(
            "malformed attestation document: the document is not CBOR: a length runs past the end at byte {} of {}",
            document.len() - 98,
            short.len()
        ))
    );
}
