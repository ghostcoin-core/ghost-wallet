//! The card applet's test vectors (`card-applet/test/vectors.txt`), computed
//! with Ghost's own client: from a fixed card random, writer nonce, salt and
//! note nonce, the Phantom Key's seed bytes, F, the commitment, the marker and
//! the 430-byte commit data a card's Make must give, bit for bit. The applet's
//! tests check the card against this file.
//!
//! Run with `UPDATE_CARD_VECTORS=1` to rewrite the file.

use std::convert::Infallible;
use std::fmt::Write as _;

use ghost_client::{Amount, Capsule, KeyFormat, NoteContents, PhantomKey, Rule, encrypt_note, salted_commit_data};
use rand::{TryCryptoRng, TryRng};
use tiny_keccak::{Hasher, Sha3};

/// Gives exactly the bytes it holds, and fails the test if asked for more or
/// left with some unused.
struct Given {
    bytes: Vec<u8>,
    used: usize,
}

impl Given {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            used: 0,
        }
    }

    fn done(&self) {
        assert_eq!(self.used, self.bytes.len(), "every given byte is used");
    }
}

impl TryRng for Given {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        unreachable!("only whole byte strings are drawn")
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        unreachable!("only whole byte strings are drawn")
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let end = self.used + dst.len();
        assert!(end <= self.bytes.len(), "asked for more bytes than given");
        dst.copy_from_slice(&self.bytes[self.used..end]);
        self.used = end;
        Ok(())
    }
}

impl TryCryptoRng for Given {}

struct Case {
    card_random: [u8; 32],
    writer_nonce: [u8; 32],
    salt: [u8; 16],
    note_random: [u8; 9],
    amount: u128,
    chain_id: u64,
}

fn counting<const N: usize>(start: u8) -> [u8; N] {
    core::array::from_fn(|i| start.wrapping_add(i as u8))
}

fn mixed<const N: usize>(seed: u8) -> [u8; N] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(167).wrapping_add(seed).rotate_left(3) ^ 0x5a)
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            card_random: counting(0x00),
            writer_nonce: counting(0x20),
            salt: counting(0x40),
            note_random: counting(0x50),
            amount: 1_000_000_000_000_000_000,
            chain_id: 1,
        },
        Case {
            card_random: mixed(7),
            writer_nonce: mixed(91),
            salt: mixed(200),
            note_random: mixed(33),
            amount: (1 << 96) - 1,
            chain_id: u64::MAX,
        },
        Case {
            card_random: [0; 32],
            writer_nonce: [0; 32],
            salt: [0; 16],
            note_random: [0; 9],
            amount: 0,
            chain_id: 0,
        },
        Case {
            card_random: [0xff; 32],
            writer_nonce: mixed(1),
            salt: [0xff; 16],
            note_random: [0xff; 9],
            amount: 123_456_789_012_345_678,
            chain_id: 0x4748_4f53_5400_0001,
        },
    ]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn vectors() -> String {
    let mut out = String::new();
    out.push_str("# Ghost card applet test vectors, computed by Ghost's own client\n");
    out.push_str("# (core/tests/card_applet_vectors.rs). Inputs, then what Make must give.\n");
    for (index, case) in cases().iter().enumerate() {
        let mut seed = [0u8; 32];
        let mut sha3 = Sha3::v256();
        sha3.update(b"ghost-card-key");
        sha3.update(&case.card_random);
        sha3.update(&case.writer_nonce);
        sha3.finalize(&mut seed);

        let mut key_source = Given::new(&seed);
        let key = PhantomKey::generate(KeyFormat::Words, &mut key_source);
        key_source.done();
        let amount = Amount::new(case.amount).unwrap();
        let mut salt_source = Given::new(&case.salt);
        let commit = key
            .salted_coin_commit(0, amount, Rule::EMPTY, &mut salt_source)
            .unwrap();
        salt_source.done();
        let contents = NoteContents::salted_coin(0, amount, Rule::EMPTY, commit.salt);
        let mut note_source = Given::new(&case.note_random);
        let note = encrypt_note(
            &key.note_key(),
            case.chain_id,
            &commit.commitment,
            &contents,
            &Capsule::empty(),
            &mut note_source,
        );
        note_source.done();
        let data = salted_commit_data(&commit.fingerprint, &commit.salt, &note);

        let _ = writeln!(out, "\n[case {}]", index + 1);
        let _ = writeln!(out, "card_random = {}", hex(&case.card_random));
        let _ = writeln!(out, "writer_nonce = {}", hex(&case.writer_nonce));
        let _ = writeln!(out, "salt = {}", hex(&case.salt));
        let _ = writeln!(out, "note_random = {}", hex(&case.note_random));
        let _ = writeln!(out, "amount = {}", hex(&amount.to_bytes()[20..]));
        let _ = writeln!(out, "chain_id = {}", hex(&case.chain_id.to_be_bytes()));
        let _ = writeln!(out, "seed = {}", hex(&seed));
        let _ = writeln!(out, "fingerprint = {}", hex(commit.fingerprint.as_bytes()));
        let _ = writeln!(out, "commitment = {}", hex(commit.commitment.as_bytes()));
        let _ = writeln!(out, "marker = {}", hex(commit.marker.as_bytes()));
        let _ = writeln!(out, "commit_data = {}", hex(&data));
    }
    out
}

#[test]
fn the_card_applet_vectors_match_ghosts_client() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../card-applet/test/vectors.txt");
    let expected = vectors();
    if std::env::var_os("UPDATE_CARD_VECTORS").is_some() {
        std::fs::write(path, &expected).unwrap();
    }
    let on_disk = std::fs::read_to_string(path).unwrap_or_default();
    assert!(
        on_disk == expected,
        "card-applet/test/vectors.txt differs from what Ghost's client computes; rerun with UPDATE_CARD_VECTORS=1"
    );
}
