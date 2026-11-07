//! The home region of a Sealed card, chosen the way the Seal chooses it
//! (`docs/sealed-card.md`, "Home region").
//!
//! Every card is served by one region only. Of the release's ordered region
//! list, its home is the region id with the greatest
//! SHA3-256(`ghost-seal/v1/home-region` || region id || UID), compared as
//! big-endian bytes; on an equal hash the earlier id in the list wins. The
//! bytes are concatenated as they are: the label and the region id as UTF-8,
//! the UID as its 7 raw bytes, with no separator and no length prefix.
//!
//! The native relay calls this through the C bridge
//! (`ghost_wallet_seal_home_region`) once the card's UID is read, over the
//! whole listed region list, and relays to that region only. It is not
//! exported to JavaScript: JavaScript never chooses a region. Nothing here is
//! secret, and nothing here logs.

use sha3::{Digest, Sha3_256};

/// The first part of every hashed input.
pub const HOME_REGION_LABEL: &[u8] = b"ghost-seal/v1/home-region";

/// A card UID's length in bytes (NTAG 424 DNA).
pub const UID_BYTES: usize = 7;

/// The bridge's answer for no home region (an empty list, a bad UID or id, a bad buffer).
pub const HOME_NONE: isize = -1;
/// The bridge's answer for a null pointer.
pub const HOME_NULL: isize = -3;

fn score(region_id: &str, uid: &[u8]) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update(HOME_REGION_LABEL);
    hash.update(region_id.as_bytes());
    hash.update(uid);
    hash.finalize().into()
}

/// The index in `region_ids` of the card's home region.
///
/// None for an empty list, a UID that is not 7 bytes, an empty id or an id
/// listed twice. On an equal hash the earlier id in the list wins.
pub fn home_region_index(uid: &[u8], region_ids: &[String]) -> Option<usize> {
    if uid.len() != UID_BYTES || region_ids.is_empty() {
        return None;
    }
    for (index, id) in region_ids.iter().enumerate() {
        if id.is_empty() || region_ids[..index].contains(id) {
            return None;
        }
    }
    let mut best: Option<(usize, [u8; 32])> = None;
    for (index, id) in region_ids.iter().enumerate() {
        let hashed = score(id, uid);
        if best.is_none_or(|(_, top)| hashed > top) {
            best = Some((index, hashed));
        }
    }
    best.map(|(index, _)| index)
}

/// The native relay's choice of a card's home region.
///
/// `uid` is the card's UID (`uid_len` bytes, 7 for a card), `ids` the ordered
/// region ids as one UTF-8 buffer of `ids_len` bytes, one id per line (joined
/// with `\n`, no line after the last). Returns the home region's index in that
/// list, [`HOME_NONE`] (-1) when there is none (see [`home_region_index`],
/// or `ids` is not UTF-8) or [`HOME_NULL`] (-3) for a null pointer.
///
/// # Safety
///
/// `uid` must be valid for reads of `uid_len` bytes and `ids` for reads of
/// `ids_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_wallet_seal_home_region(
    uid: *const u8,
    uid_len: usize,
    ids: *const u8,
    ids_len: usize,
) -> isize {
    if uid.is_null() || ids.is_null() {
        return HOME_NULL;
    }
    // SAFETY: the caller guarantees `uid` holds `uid_len` bytes and `ids` holds `ids_len` bytes.
    let (uid, ids) = unsafe { (core::slice::from_raw_parts(uid, uid_len), core::slice::from_raw_parts(ids, ids_len)) };
    let Ok(text) = core::str::from_utf8(ids) else {
        return HOME_NONE;
    };
    let list: Vec<String> = text.split('\n').map(str::to_owned).collect();
    match home_region_index(uid, &list) {
        Some(index) => isize::try_from(index).unwrap_or(HOME_NONE),
        None => HOME_NONE,
    }
}
