//! Known answers of the card-key KDF, and the properties every card's keys
//! must have.

mod support;

use ghost_seal::card_keys::{CARD_KEY_LABELS, CARD_KEYS_SALT, card_keys, card_keys_at, generation_of_version, key_version};
use ghost_seal::primitives::hkdf_sha3_256;
use ghost_seal::{CardUid, MasterKey};
use support::{UID, hex};

/// M = 00 01 02 ... 1F (a test pattern).
fn counting_master() -> MasterKey {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    MasterKey::take(&mut bytes)
}

fn all_keys(master: &MasterKey, uid: &CardUid, generation: u32) -> Vec<String> {
    let keys = card_keys_at(master, uid, generation);
    (0..5u8).map(|n| hex(keys.key(n))).collect()
}

#[test]
fn known_answers_generation_0() {
    assert_eq!(
        all_keys(&counting_master(), &UID, 0),
        vec![
            "D71D5D26BB56F814EEC9C5AF616ED0AD",
            "55CC63F9D83100BDC53AAC4C3C14A514",
            "8EC2E3EB938A867F8AA488EE08CCC12F",
            "FF47087BF4C6E959B763E92361550EB3",
            "D2A464DE5240D575F06A6CB6AC7838B0",
        ]
    );
}

#[test]
fn known_answers_generation_1() {
    assert_eq!(
        all_keys(&counting_master(), &UID, 1),
        vec![
            "189E3DE620F6D03DAE0D2CE7251A67E3",
            "C7050BD6CD56F2D26DE4E09BB8E73E89",
            "53B32B401C89D5C131E66DB6EDDE811C",
            "56008BF4F1FE19785685311546F3766A",
            "96B3667230E16B2DA33ADCD9A3257189",
        ]
    );
}

#[test]
fn card_keys_is_generation_0() {
    let master = counting_master();
    let setup = card_keys(&master, &UID);
    assert_eq!(setup.generation(), 0);
    let at_zero = card_keys_at(&master, &UID, 0);
    for n in 0..5u8 {
        assert_eq!(setup.key(n), at_zero.key(n));
    }
}

#[test]
fn each_key_is_hkdf_sha3_with_its_own_label() {
    // The KDF as docs/sealed-card.md writes it, recomputed from the primitive.
    let mut m = [0u8; 32];
    for (i, b) in m.iter_mut().enumerate() {
        *b = i as u8;
    }
    let keys = card_keys_at(&counting_master(), &UID, 7);
    for n in 0..5u8 {
        let mut expected = [0u8; 16];
        hkdf_sha3_256(CARD_KEYS_SALT, &m, &[CARD_KEY_LABELS[usize::from(n)], &[0x00], &UID.0, &7u32.to_be_bytes()], &mut expected);
        assert_eq!(keys.key(n), &expected, "key {n}");
    }
}

#[test]
fn labels_are_distinct_and_versioned() {
    assert_eq!(CARD_KEYS_SALT, b"ghost-seal/v1/card-keys");
    for (n, label) in CARD_KEY_LABELS.iter().enumerate() {
        let text = std::str::from_utf8(label).unwrap();
        assert!(text.starts_with(&format!("ghost-seal/v1/card-key/{n}/")), "{text}");
        for other in &CARD_KEY_LABELS[n + 1..] {
            assert_ne!(label, other);
        }
    }
}

#[test]
fn keys_differ_by_key_number_card_generation_and_master() {
    let master = counting_master();
    let keys = all_keys(&master, &UID, 0);
    for i in 0..5 {
        for j in i + 1..5 {
            assert_ne!(keys[i], keys[j], "keys {i} and {j}");
        }
        assert_ne!(keys[i], "00".repeat(16));
    }
    let other_card = CardUid([0x04, 0x51, 0x8d, 0xfa, 0xa9, 0x61, 0x81]);
    let next_generation = all_keys(&master, &UID, 1);
    let elsewhere = all_keys(&master, &other_card, 0);
    let other_master = all_keys(&support::master(), &UID, 0);
    for n in 0..5 {
        assert_ne!(keys[n], next_generation[n]);
        assert_ne!(keys[n], elsewhere[n]);
        assert_ne!(keys[n], other_master[n]);
    }
    // Deterministic: the Seal derives the same keys on every tap.
    assert_eq!(keys, all_keys(&counting_master(), &UID, 0));
}

#[test]
fn key_versions_never_look_like_factory_keys() {
    assert_eq!(key_version(0), 1);
    assert_eq!(key_version(1), 2);
    assert_eq!(key_version(254), 255);
    for generation in 0..300 {
        assert_ne!(key_version(generation), 0);
    }
    assert_eq!(generation_of_version(0), None);
    assert_eq!(generation_of_version(1), Some(0));
    assert_eq!(generation_of_version(2), Some(1));
}
