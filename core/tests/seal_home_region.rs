//! The home region of a Sealed card, as the phone's native relay picks it
//! (`core/src/seal_home_region.rs`): it must be the Seal's own choice
//! (`docs/sealed-card.md`, "Home region"), or a card would be sent to a
//! region that refuses it.
//!
//! The fixed vectors below were computed with an independent SHA3-256. The
//! rule is also rebuilt here as a plain loop over the rule's text, and when
//! the Seal's vector file (`seal/tests/vectors/home-region.json`, read only)
//! is present, every card in it must agree.

use ghost_wallet_core::seal_home_region::{
    HOME_NONE, HOME_NULL, HOME_REGION_LABEL, ghost_wallet_seal_home_region, home_region_index,
};
use sha3::{Digest, Sha3_256};

const REGIONS: [&str; 3] = ["us-east-1", "eu-central-1", "ap-southeast-1"];

fn regions() -> Vec<String> {
    REGIONS.iter().map(|id| (*id).to_owned()).collect()
}

fn uid(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "odd hex: {hex}");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

fn home_of(uid: &[u8], list: &[String]) -> Option<String> {
    home_region_index(uid, list).map(|index| list[index].clone())
}

/// The rule, written out as its text says it: for each region in order, hash
/// the label, the id and the UID; keep the first greatest.
fn rule(uid: &[u8], list: &[String]) -> String {
    let mut best_id = String::new();
    let mut best_hash: Option<Vec<u8>> = None;
    for id in list {
        let mut input = Vec::new();
        input.extend_from_slice(b"ghost-seal/v1/home-region");
        input.extend_from_slice(id.as_bytes());
        input.extend_from_slice(uid);
        let hash = Sha3_256::digest(&input).to_vec();
        let greater = match &best_hash {
            None => true,
            Some(top) => hash > *top,
        };
        if greater {
            best_hash = Some(hash);
            best_id = id.clone();
        }
    }
    best_id
}

/// The C bridge over `list` joined one id per line.
fn bridge(uid: &[u8], list: &[String]) -> isize {
    let ids = list.join("\n");
    // SAFETY: both pointers come from live slices of the lengths passed.
    unsafe { ghost_wallet_seal_home_region(uid.as_ptr(), uid.len(), ids.as_ptr(), ids.len()) }
}

/// A deterministic stream of card UIDs (test only): 0x04, then six bytes.
fn generated_uids(count: usize) -> Vec<Vec<u8>> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    (0..count)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let mut out = vec![0x04];
            out.extend_from_slice(&x.to_be_bytes()[..6]);
            out
        })
        .collect()
}

#[test]
fn the_label_is_the_seals() {
    assert_eq!(HOME_REGION_LABEL, b"ghost-seal/v1/home-region");
}

#[test]
fn the_fixed_vectors_give_their_home_regions() {
    let list = regions();
    for (hex, home) in [
        ("04518DFAA96180", "eu-central-1"),
        ("0412345678ABCD", "ap-southeast-1"),
        ("04FFFFFFFFFFFF", "eu-central-1"),
        ("04000000000001", "ap-southeast-1"),
        ("04A1B2C3D4E5F6", "us-east-1"),
    ] {
        let uid = uid(hex);
        assert_eq!(home_of(&uid, &list).as_deref(), Some(home), "{hex}");
        assert_eq!(rule(&uid, &list), home, "{hex}");
        let index = REGIONS.iter().position(|id| *id == home).unwrap();
        assert_eq!(bridge(&uid, &list), isize::try_from(index).unwrap(), "{hex}");
    }
}

#[test]
fn five_hundred_generated_cards_agree_with_the_rule() {
    let list = regions();
    let mut seen = std::collections::BTreeSet::new();
    for uid in generated_uids(500) {
        let home = home_of(&uid, &list).expect("a home");
        assert_eq!(home, rule(&uid, &list));
        assert_eq!(list[usize::try_from(bridge(&uid, &list)).unwrap()], home);
        seen.insert(home);
    }
    // Every region is somebody's home.
    assert_eq!(seen.len(), 3);
}

#[test]
fn the_list_order_does_not_change_the_home() {
    let orders: [[usize; 3]; 6] = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
    for uid in generated_uids(100) {
        let home = home_of(&uid, &regions()).unwrap();
        for order in orders {
            let list: Vec<String> = order.iter().map(|&i| REGIONS[i].to_owned()).collect();
            assert_eq!(home_of(&uid, &list).as_deref(), Some(home.as_str()));
        }
    }
}

#[test]
fn a_single_region_is_every_cards_home() {
    let list = vec!["eu-central-1".to_owned()];
    for uid in generated_uids(20) {
        assert_eq!(home_region_index(&uid, &list), Some(0));
    }
}

#[test]
fn there_is_no_home_for_a_bad_list_or_uid() {
    let card = uid("04518DFAA96180");
    // An empty list.
    assert_eq!(home_region_index(&card, &[]), None);
    // A UID that is not 7 bytes.
    for bad in [&card[..6], &[0u8; 8][..], &[][..]] {
        assert_eq!(home_region_index(bad, &regions()), None);
        assert_eq!(bridge(bad, &regions()), HOME_NONE);
    }
    // An empty id, anywhere in the list.
    for at in 0..=3 {
        let mut list = regions();
        list.insert(at, String::new());
        assert_eq!(home_region_index(&card, &list), None, "empty id at {at}");
    }
    // A duplicate id: its two entries hash the same, a tie that is refused,
    // whether the copy is next to the first or further on.
    for list in [
        vec!["us-east-1", "us-east-1", "eu-central-1"],
        vec!["us-east-1", "eu-central-1", "us-east-1"],
        vec!["eu-central-1", "ap-southeast-1", "eu-central-1"],
    ] {
        let list: Vec<String> = list.into_iter().map(str::to_owned).collect();
        assert_eq!(home_region_index(&card, &list), None, "{list:?}");
        assert_eq!(bridge(&card, &list), HOME_NONE, "{list:?}");
    }
}

#[test]
fn the_bridge_agrees_and_refuses_what_it_cannot_read() {
    let card = uid("04A1B2C3D4E5F6");
    let list = regions();
    assert_eq!(bridge(&card, &list), isize::try_from(home_region_index(&card, &list).unwrap()).unwrap());
    let ids = list.join("\n");
    // SAFETY: the non-null pointers come from live slices; the null ones are refused before any read.
    unsafe {
        assert_eq!(ghost_wallet_seal_home_region(core::ptr::null(), 7, ids.as_ptr(), ids.len()), HOME_NULL);
        assert_eq!(ghost_wallet_seal_home_region(card.as_ptr(), card.len(), core::ptr::null(), ids.len()), HOME_NULL);
        assert_eq!(ghost_wallet_seal_home_region(core::ptr::null(), 0, core::ptr::null(), 0), HOME_NULL);
        // No ids at all: one empty id.
        assert_eq!(ghost_wallet_seal_home_region(card.as_ptr(), card.len(), ids.as_ptr(), 0), HOME_NONE);
        // Ids that are not UTF-8.
        let bad = [0xffu8, 0xfe];
        assert_eq!(ghost_wallet_seal_home_region(card.as_ptr(), card.len(), bad.as_ptr(), bad.len()), HOME_NONE);
    }
    // A line after the last id is an empty id.
    let trailing = format!("{ids}\n");
    // SAFETY: both pointers come from live slices of the lengths passed.
    let answer = unsafe { ghost_wallet_seal_home_region(card.as_ptr(), card.len(), trailing.as_ptr(), trailing.len()) };
    assert_eq!(answer, HOME_NONE);
}

/// The quoted strings of the JSON array that follows `"key":` in `text`.
/// Enough for the vector file's flat layout; nothing else reads it.
fn string_array(text: &str, key: &str) -> Option<Vec<String>> {
    let start = text.find(&format!("\"{key}\""))?;
    let rest = &text[start..];
    let open = rest.find('[')?;
    let close = rest[open..].find(']')? + open;
    Some(
        rest[open + 1..close]
            .split(',')
            .map(|item| item.trim().trim_matches('"').to_owned())
            .filter(|item| !item.is_empty())
            .collect(),
    )
}

/// The value of `"field": "..."` in one card object.
fn field(object: &str, name: &str) -> Option<String> {
    let start = object.find(&format!("\"{name}\""))? + name.len() + 2;
    let rest = &object[start..];
    let open = rest.find('"')? + 1;
    let close = rest[open..].find('"')? + open;
    Some(rest[open..close].to_owned())
}

/// The `{ "uid", "home" }` objects of the `cards` array, or None when there is no such array.
fn cards(text: &str) -> Option<Vec<(String, String)>> {
    let start = text.find("\"cards\"")?;
    let rest = &text[start..];
    let open = rest.find('[')?;
    // A card object holds no `]`, so the first one after `[` closes the array.
    let close = rest[open..].find(']')? + open;
    let body = &rest[open + 1..close];
    let mut out = Vec::new();
    for object in body.split('}') {
        if !object.contains('{') {
            continue;
        }
        out.push((field(object, "uid")?, field(object, "home")?));
    }
    Some(out)
}

#[test]
fn the_seals_vector_file_agrees_when_present() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../seal/tests/vectors/home-region.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        // The Seal's file is not on this base; the fixed vectors above stand.
        return;
    };
    assert!(text.contains("\"version\": 1"), "a vector file of another version");
    assert!(text.contains("\"label\": \"ghost-seal/v1/home-region\""), "a vector file of another label");
    let list = string_array(&text, "regions").expect("the vector file lists its regions");
    assert!(!list.is_empty(), "the vector file lists no region");
    let cards = cards(&text).expect("the vector file has no cards");
    assert!(!cards.is_empty(), "the vector file's cards are empty");
    for (hex, home) in cards {
        assert_eq!(hex.len(), 14, "{hex}");
        assert_eq!(hex, hex.to_lowercase(), "{hex}");
        let card = uid(&hex);
        assert_eq!(home_of(&card, &list).as_deref(), Some(home.as_str()), "{hex}");
        assert_eq!(rule(&card, &list), home, "{hex}");
    }
}
