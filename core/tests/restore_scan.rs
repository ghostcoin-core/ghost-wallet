//! The restore scan of `restore_scan`, from Ghost's counting-bytes test seed,
//! over a synthetic chain of 30 blocks built here. Every header is first
//! accepted by one `HeaderSync` (as in `tests/header_sync.rs`, at difficulty
//! 1 so every seal passes at nonce 0); only those headers are fed, and the
//! sync gives the scan its tip.
//!
//! Activity on accounts 0, 3 and 7 is found with the right indexes, addresses
//! and balances; the result is `Incomplete` at every height before the tip;
//! more than 20 unused accounts end the scan; a passed-over or repeated height, a
//! header off the checked chain and malformed words are refused, the words
//! never echoed; two scans of the same words agree.

use std::sync::{Arc, OnceLock};

use ghost_client::account::WalletSeed;
use ghost_client::seal::header_fields;
use ghost_wallet_core::{
    GAP_LIMIT, HeaderChainConstants, HeaderSync, RestoreResult, RestoreScan, RestoreScanError, RestoredAccount,
    TouchedAddress,
};

/// Ghost's internal network test constants.
const TEST_CHAIN: HeaderChainConstants =
    HeaderChainConstants { block_time: 30, half_life: 3600, start_difficulty: 1, min_difficulty: 1, future_drift: 30 };
const GENESIS_TIME: u64 = 0x6abd_a280;
const LATER: u64 = GENESIS_TIME + 1_000_000_000;
/// Blocks after genesis; the scan starts at block 1.
const TIP: u64 = 30;

/// Ghost's counting-bytes test seed: the bytes 0 to 31.
const COUNTING: [u8; 32] = {
    let mut bytes = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        bytes[i] = i as u8;
        i += 1;
    }
    bytes
};

/// An address of nobody in this wallet.
const STRANGER: [u8; 20] = [0xab; 20];

fn counting_words() -> String {
    WalletSeed::from_bytes(COUNTING).to_words().as_str().to_owned()
}

fn address(index: u32) -> [u8; 20] {
    *WalletSeed::from_bytes(COUNTING).rescue_account(index).address()
}

fn hex(address: &[u8; 20]) -> String {
    address.iter().fold(String::from("0x"), |mut out, byte| {
        out.push_str(&format!("{byte:02x}"));
        out
    })
}

/// A test-side RLP encoder, written apart from the client's decoder.
fn int(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    bytes[first..].to_vec()
}

fn rlp_length(len: usize, base: u8) -> Vec<u8> {
    if len < 56 {
        return vec![base + len as u8];
    }
    let digits = int(len as u64);
    let mut out = vec![base + 55 + digits.len() as u8];
    out.extend(digits);
    out
}

fn rlp_list(fields: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::new();
    for field in fields {
        if field.len() == 1 && field[0] < 0x80 {
            payload.push(field[0]);
        } else {
            payload.extend(rlp_length(field.len(), 0x80));
            payload.extend(field);
        }
    }
    let mut out = rlp_length(payload.len(), 0xc0);
    out.extend(payload);
    out
}

/// The 19-field header at `number` on top of `parent`, at difficulty 1,
/// 30 seconds per block. `marker` changes the data marker root, to make a
/// header off the chain.
fn header(parent: [u8; 32], number: u64, marker: u8) -> Vec<u8> {
    rlp_list(&[
        parent.to_vec(),
        vec![0x1d; 32],
        vec![0; 20],
        vec![0x11; 32],
        vec![0x22; 32],
        vec![0x33; 32],
        vec![0; 256],
        int(1),
        int(number),
        int(30_000_000),
        int(0),
        int(GENESIS_TIME + 30 * number),
        vec![],
        vec![0; 32],
        vec![0; 8],
        int(1_000_000_000),
        vec![0x44; 32],
        vec![0x55; 32],
        vec![marker; 32],
    ])
}

fn hash(rlp: &[u8]) -> [u8; 32] {
    header_fields(rlp).unwrap().hash
}

struct Chain {
    sync: Arc<HeaderSync>,
    /// The headers of blocks 1 to `TIP`, each accepted by `sync`.
    headers: Vec<Vec<u8>>,
}

/// One checked chain for every test: building its RandomX cache takes
/// 256 MiB, so it is built once.
fn chain() -> &'static Chain {
    static CHAIN: OnceLock<Chain> = OnceLock::new();
    CHAIN.get_or_init(|| {
        let genesis = header([0; 32], 0, 0x66);
        let sync = HeaderSync::from_genesis(genesis.clone(), TEST_CHAIN).unwrap();
        let mut headers: Vec<Vec<u8>> = Vec::new();
        for number in 1..=TIP {
            let parent = hash(headers.last().unwrap_or(&genesis));
            headers.push(header(parent, number, 0x66));
        }
        let progress = sync.add_headers(headers.clone(), LATER);
        assert_eq!(progress.accepted, TIP);
        assert_eq!(progress.refused_index, None);
        assert_eq!(sync.best_height(), TIP);
        Chain { sync, headers }
    })
}

/// A checked header, by height.
fn checked(height: u64) -> Vec<u8> {
    let chain = chain();
    assert!((1..=chain.sync.best_height()).contains(&height), "only headers the sync accepted are fed");
    chain.headers[height as usize - 1].clone()
}

fn touch(address: [u8; 20], balance: u128) -> TouchedAddress {
    let bytes = balance.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(16);
    TouchedAddress { address: address.to_vec(), balance: bytes[first..].to_vec() }
}

/// The activity of the 30 blocks: (height, account index or `None` for a
/// stranger, balance after).
type Activity = [(u64, Option<u32>, u128)];

/// Accounts 0, 3 and 7 used early, midway and late; account 0 twice.
const SPREAD: &Activity = &[
    (2, Some(0), 5_000),
    (4, None, 77),
    (11, Some(3), 1_000_000_000_000_000_000),
    (19, Some(0), 3_500),
    (19, None, 12),
    (28, Some(7), 1),
];

fn touched_at(activity: &Activity, height: u64) -> Vec<TouchedAddress> {
    activity
        .iter()
        .filter(|(at, _, _)| *at == height)
        .map(|&(_, index, balance)| touch(index.map_or(STRANGER, address), balance))
        .collect()
}

fn new_scan() -> Arc<RestoreScan> {
    RestoreScan::new(counting_words(), 1).unwrap()
}

/// Feeds every block from 1 to the tip, then returns the result.
fn scan_all(activity: &Activity) -> RestoreResult {
    let scan = new_scan();
    scan.set_tip(chain().sync.clone()).unwrap();
    for height in 1..=TIP {
        scan.feed_block(height, checked(height), touched_at(activity, height)).unwrap();
    }
    scan.result()
}

fn complete(result: RestoreResult) -> Vec<RestoredAccount> {
    match result {
        RestoreResult::Complete { accounts, note } => {
            assert!(note.contains("unverified"));
            accounts
        }
        other => panic!("the scan is not complete: {other:?}"),
    }
}

fn used(accounts: &[RestoredAccount]) -> Vec<(u32, String, String)> {
    accounts.iter().filter(|a| a.used).map(|a| (a.index, a.address.clone(), a.balance.clone())).collect()
}

#[test]
fn activity_on_accounts_0_3_and_7_is_found() {
    let accounts = complete(scan_all(SPREAD));
    assert_eq!(
        used(&accounts),
        vec![
            (0, hex(&address(0)), "3500".to_owned()),
            (3, hex(&address(3)), "1000000000000000000".to_owned()),
            (7, hex(&address(7)), "1".to_owned()),
        ]
    );
    // Every account up to the gap limit past account 7, in index order.
    assert_eq!(accounts.len(), 8 + GAP_LIMIT as usize);
    for (i, account) in accounts.iter().enumerate() {
        assert_eq!(account.index, i as u32);
        assert_eq!(account.address, hex(&address(i as u32)));
        assert!(account.unverified, "no balance is proved yet");
        if !account.used {
            assert_eq!(account.balance, "0");
        }
    }
    // The stranger's address is not one of the wallet's.
    assert!(accounts.iter().all(|a| a.address != hex(&STRANGER)));
}

#[test]
fn derived_accounts_hold_public_data_only() {
    let scan = new_scan();
    let derived = scan.accounts();
    assert_eq!(derived.len(), GAP_LIMIT as usize);
    let seed = WalletSeed::from_bytes(COUNTING);
    for account in &derived {
        let key = seed.rescue_account(account.index);
        assert_eq!(account.address, hex(key.address()));
        assert_eq!(account.rescue_public_key, key.public_key().to_vec());
    }
    assert_eq!(derived[0].address, "0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd");
}

#[test]
fn incomplete_at_every_height_before_the_tip() {
    let scan = new_scan();
    assert_eq!(scan.result(), RestoreResult::Incomplete { next_height: 1, tip: None });
    // Without a tip, nothing can be fed.
    assert_eq!(
        scan.feed_block(1, checked(1), vec![]),
        Err(RestoreScanError::AboveTip { height: 1, tip: None })
    );
    scan.set_tip(chain().sync.clone()).unwrap();
    for height in 1..=TIP {
        assert_eq!(scan.result(), RestoreResult::Incomplete { next_height: height, tip: Some(TIP) });
        scan.feed_block(height, checked(height), touched_at(SPREAD, height)).unwrap();
    }
    assert_eq!(used(&complete(scan.result())).len(), 3);
    // Nothing above the tip.
    assert_eq!(
        scan.feed_block(TIP + 1, checked(TIP), vec![]),
        Err(RestoreScanError::AboveTip { height: TIP + 1, tip: Some(TIP) })
    );
}

#[test]
fn more_than_20_unused_accounts_end_the_scan() {
    // 7, then 21 unused (8 to 28), then 29: 29 is not found.
    let far = &[(3, Some(7), 10), (9, Some(29), 20)];
    let accounts = complete(scan_all(far));
    assert_eq!(used(&accounts), vec![(7, hex(&address(7)), "10".to_owned())]);
    assert_eq!(accounts.len(), 8 + GAP_LIMIT as usize);

    // 7, then 19 unused (8 to 26), then 27: found, and the list extends past
    // it, so 45 (17 unused after 27) is found too.
    let near = &[(3, Some(7), 10), (9, Some(27), 20), (25, Some(45), 30)];
    let accounts = complete(scan_all(near));
    assert_eq!(
        used(&accounts),
        vec![
            (7, hex(&address(7)), "10".to_owned()),
            (27, hex(&address(27)), "20".to_owned()),
            (45, hex(&address(45)), "30".to_owned()),
        ]
    );
    assert_eq!(accounts.len(), 46 + GAP_LIMIT as usize);

    // An account touched before an earlier one brought it into the gap is
    // still found.
    let backwards = &[(2, Some(27), 20), (20, Some(7), 10)];
    let accounts = complete(scan_all(backwards));
    assert_eq!(
        used(&accounts),
        vec![(7, hex(&address(7)), "10".to_owned()), (27, hex(&address(27)), "20".to_owned())]
    );
}

#[test]
fn passed_over_or_repeated_height_is_refused() {
    let scan = new_scan();
    scan.set_tip(chain().sync.clone()).unwrap();
    scan.feed_block(1, checked(1), vec![]).unwrap();
    assert_eq!(
        scan.feed_block(3, checked(3), vec![]),
        Err(RestoreScanError::HeightPassedOver { expected: 2, got: 3 })
    );
    assert_eq!(
        scan.feed_block(1, checked(1), vec![]),
        Err(RestoreScanError::RepeatedHeight { expected: 2, got: 1 })
    );
    assert_eq!(scan.result(), RestoreResult::Incomplete { next_height: 2, tip: Some(TIP) });
    // The refusals changed nothing: the scan goes on from block 2.
    for height in 2..=TIP {
        scan.feed_block(height, checked(height), touched_at(SPREAD, height)).unwrap();
    }
    assert_eq!(used(&complete(scan.result())).len(), 3);
}

#[test]
fn header_off_the_checked_chain_is_refused() {
    let scan = new_scan();
    scan.set_tip(chain().sync.clone()).unwrap();
    // The header of another block at height 1.
    let off = header(hash(&header([0; 32], 0, 0x66)), 1, 0x99);
    assert!(matches!(scan.feed_block(1, off, vec![]), Ok(())));
    // Block 2 of the checked chain does not link to it.
    assert!(matches!(
        scan.feed_block(2, checked(2), vec![]),
        Err(RestoreScanError::NotTheCheckedChain { height: 2, .. })
    ));

    let scan = new_scan();
    scan.set_tip(chain().sync.clone()).unwrap();
    for height in 1..TIP {
        scan.feed_block(height, checked(height), vec![]).unwrap();
    }
    // A header that links but is not the checked tip.
    let fake_tip = header(hash(&checked(TIP - 1)), TIP, 0x99);
    assert!(matches!(
        scan.feed_block(TIP, fake_tip, vec![]),
        Err(RestoreScanError::NotTheCheckedChain { height: TIP, .. })
    ));
    // A header with the wrong height, and bytes that are no header.
    assert!(matches!(
        scan.feed_block(TIP, checked(TIP - 1), vec![]),
        Err(RestoreScanError::NotTheCheckedChain { height: TIP, .. })
    ));
    assert!(matches!(
        scan.feed_block(TIP, vec![0xc0], vec![]),
        Err(RestoreScanError::NotTheCheckedChain { height: TIP, .. })
    ));
    // A malformed address.
    let short = TouchedAddress { address: vec![1; 19], balance: vec![1] };
    assert!(matches!(
        scan.feed_block(TIP, checked(TIP), vec![short]),
        Err(RestoreScanError::BadTouched { height: TIP, .. })
    ));
    assert_eq!(scan.result(), RestoreResult::Incomplete { next_height: TIP, tip: Some(TIP) });
    scan.feed_block(TIP, checked(TIP), vec![]).unwrap();
    assert!(used(&complete(scan.result())).is_empty());
}

#[test]
fn short_or_invalid_words_are_refused_without_echoing_them() {
    let words = counting_words();
    let list: Vec<&str> = words.split(' ').collect();

    let short = list[..23].join(" ");
    let mut unknown = list.clone();
    unknown[5] = "notaword";
    let unknown = unknown.join(" ");
    let mut swapped = list.clone();
    swapped.swap(0, 1);
    let swapped = swapped.join(" ");

    for bad in [short, unknown, swapped, String::new()] {
        let error = RestoreScan::new(bad.clone(), 1).err().expect("the words are refused");
        let RestoreScanError::Words { reason } = &error else { panic!("not a words error: {error:?}") };
        assert!(!reason.is_empty());
        let shown = format!("{error} {error:?}");
        for word in bad.split(' ').filter(|w| w.len() > 2) {
            assert!(!shown.contains(word), "the error repeats a word");
        }
    }
}

#[test]
fn two_scans_of_the_same_words_agree() {
    let first = scan_all(SPREAD);
    let second = scan_all(SPREAD);
    assert_eq!(first, second);
    assert_ne!(first, scan_all(&[(2, Some(1), 5)]));
}
