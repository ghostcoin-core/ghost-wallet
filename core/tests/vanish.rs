//! Vanish, Summon and Claim by a typed Phantom Key, through the native core:
//! the key and wallet field rules, the fee of a reveal and its window, the
//! Vanish commit and its signed account transaction, the coin tree rebuilt
//! from public chain data, and reveals proved here and checked with Ghost's
//! own verifier.

use ghost_client::account::{SeedError, WalletSeed, verify_envelope};
use ghost_client::{KeyFormat, PhantomKey};
use ghost_proofs::verify_salted_coin_reveal;
use ghost_wallet_core::{
    CHECKED_KEY_WORDS, COMMIT_DATA_BYTES, COMMIT_ENTRY, CoinLeaf, ENVELOPE_BYTES, FeeWindow, KeyVault, PRIVATE_TX_TYPE, RevealRequest,
    TEST_CHAIN_ID, VANISH_GAS_LIMIT, VANISH_MIN_GAS, VanishError, VanishSend, check_key_words, classify_words,
    commit_leaf, fee_window, find_coins, find_key_coins, min_vanish_wei, prove_reveal_with, reveal_fee,
    reveal_fee_wei, reveal_leaf, sign_vanish_with, transaction_hash, vanish_commit_with,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

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
/// A stand-in genesis hash: the proofs' domain and the signatures' chain.
const GENESIS: [u8; 32] = [0x47; 32];
/// Account 0 of the counting-bytes words.
const ACCOUNT: [u8; 20] = [
    0xe5, 0xfb, 0xe4, 0xd8, 0x25, 0x67, 0x44, 0xec, 0x6f, 0xd5, 0x5f, 0x2c, 0xe5, 0xbd, 0xfa, 0xe7, 0xcb, 0xf3, 0x55,
    0xfd,
];
const ONE_GHOST: u128 = 1_000_000_000_000_000_000;
/// A small reference base fee, so a test coin pays a small fee.
const B_REF: &str = "1000";

fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

fn account_words() -> String {
    WalletSeed::from_bytes(COUNTING).to_words().as_str().to_owned()
}

fn key(seed: u64) -> PhantomKey {
    PhantomKey::generate(KeyFormat::Words, &mut rng(seed))
}

fn words_of(key: &PhantomKey) -> String {
    key.format_words().expect("a words key").as_str().to_owned()
}

/// A coin tree holding another key's Vanish, then `key`'s Vanish of `wei`.
fn tree_with(key: &PhantomKey, wei: u128) -> Vec<CoinLeaf> {
    let other = vanish_commit_with(&self::key(900), TEST_CHAIN_ID, 5 * ONE_GHOST, &mut rng(901)).unwrap();
    let ours = vanish_commit_with(key, TEST_CHAIN_ID, wei, &mut rng(902)).unwrap();
    vec![
        commit_leaf(other.commit_data, other.amount_wei).unwrap(),
        commit_leaf(ours.commit_data, ours.amount_wei).unwrap(),
    ]
}

fn request(out_wei: Option<String>) -> RevealRequest {
    RevealRequest {
        chain_id: TEST_CHAIN_ID,
        genesis_hash: GENESIS.to_vec(),
        recipient: ACCOUNT.to_vec(),
        base_fee_ref_wei: B_REF.to_owned(),
        out_wei,
    }
}

// --- Fees ----------------------------------------------------------------

#[test]
fn the_reveal_fee_and_the_smallest_vanish_match_spec_07() {
    // Spec 07: at b_ref = 1,000,000,000 the smallest Vanish (four Summon
    // fees) is 104,401,981,374,637,640 wei.
    assert_eq!(reveal_fee(1_000_000_000), Some(26_100_495_343_659_410));
    assert_eq!(reveal_fee_wei("1000000000".to_owned()).unwrap(), "26100495343659410");
    assert_eq!(min_vanish_wei("1000000000".to_owned()).unwrap(), "104401981374637640");
    // b_ref 0 still prices one wei of gas: G_PRIV plus a tenth, rounded up.
    assert_eq!(reveal_fee(0), Some(21_090_372 + 2_109_038));
    assert!(reveal_fee(u128::MAX).is_none());
    assert!(matches!(reveal_fee_wei("1e9".to_owned()), Err(VanishError::Amount { .. })));
    assert!(matches!(reveal_fee_wei(String::new()), Err(VanishError::Amount { .. })));
}

#[test]
fn a_reveal_lives_through_its_window_and_the_next() {
    assert_eq!(fee_window(0), FeeWindow { reference_height: 0, valid_until: 7 });
    assert_eq!(fee_window(5), FeeWindow { reference_height: 4, valid_until: 11 });
    assert_eq!(fee_window(7), FeeWindow { reference_height: 4, valid_until: 11 });
    assert_eq!(fee_window(8), FeeWindow { reference_height: 8, valid_until: 15 });
}

// --- The key field and the wallet field -----------------------------------

#[test]
fn account_words_are_never_a_key_and_a_key_is_never_account_words() {
    assert_eq!(classify_words(&account_words()).verdict, "account-words");
    for seed in 0..200 {
        let key = key(seed);
        let words = words_of(&key);
        assert_eq!(classify_words(&words).verdict, "phantom-key", "key {seed}");
        assert_eq!(classify_words(key.format_groups().as_str()).verdict, "phantom-key", "digits of key {seed}");
        // Ghost's own wallet parser refuses it as a wallet.
        assert_eq!(WalletSeed::from_words(&words).err(), Some(SeedError::PhantomKey), "key {seed}");

        let mut bytes = [0u8; 32];
        rng(10_000 + seed).fill_bytes(&mut bytes);
        let seed_words = WalletSeed::from_bytes(bytes).to_words().as_str().to_owned();
        if WalletSeed::from_words(&seed_words).is_ok() {
            assert_eq!(classify_words(&seed_words).verdict, "account-words", "seed {seed}");
        }
    }
}

#[test]
fn a_mistyped_key_is_named_without_echoing_it() {
    let words = words_of(&key(1));
    let list: Vec<&str> = words.split_whitespace().collect();

    let mut swapped = list.clone();
    swapped.swap(3, 4);
    if swapped != list {
        assert_eq!(classify_words(&swapped.join(" ")).verdict, "word-check");
    }

    let mut misspelt = list.clone();
    misspelt[6] = "ghostly";
    let check = classify_words(&misspelt.join(" "));
    assert_eq!((check.verdict.as_str(), check.position), ("unknown-word", 7));

    assert_eq!(classify_words(&list[..23].join(" ")).verdict, "wrong-format");
    assert_eq!(classify_words("   ").verdict, "empty");
    assert_eq!(classify_words("1234 5678").verdict, "wrong-format");

    let digits = key(1).format_groups().as_str().to_owned();
    let last = digits.chars().last().unwrap();
    let changed = format!("{}{}", &digits[..digits.len() - 1], if last == '0' { '1' } else { '0' });
    assert_eq!(classify_words(&changed).verdict, "digit-check");

    // Upper case and extra spaces are the same key.
    assert_eq!(check_key_words(format!("  {}  ", words.to_uppercase())).verdict, "phantom-key");
}

#[test]
fn the_key_field_refuses_account_words_by_name() {
    let error = find_key_coins(account_words(), TEST_CHAIN_ID, Vec::new(), Vec::new()).unwrap_err();
    match error {
        VanishError::NotAKey { reason } => assert!(reason.contains("account words"), "{reason}"),
        other => panic!("expected NotAKey, got {other:?}"),
    }
}

// --- Vanish ----------------------------------------------------------------

#[test]
fn a_vanish_commit_is_the_206_bytes_of_ghosts_web_app() {
    let key = key(2);
    let commit = vanish_commit_with(&key, TEST_CHAIN_ID, ONE_GHOST, &mut rng(3)).unwrap();
    assert_eq!(COMMIT_DATA_BYTES, 206);
    assert_eq!(commit.commit_data.len(), 206);
    assert_eq!(&commit.commit_data[..2], &[0x00, 0x02]);
    assert_eq!(commit.amount_wei, ONE_GHOST.to_string());

    // The chain's leaf, rebuilt from the data and the amount paid, is the commit's.
    let leaf = commit_leaf(commit.commit_data.clone(), commit.amount_wei.clone()).unwrap();
    assert_eq!(leaf.commitment, commit.commitment);
    assert_eq!(leaf.salt.as_deref(), Some(&commit.commit_data[34..50]));
    assert_eq!(leaf.note, commit.commit_data[50..].to_vec());

    // Another amount makes another leaf: the amount is bound in.
    let other = commit_leaf(commit.commit_data.clone(), (ONE_GHOST - 1).to_string()).unwrap();
    assert_ne!(other.commitment, commit.commitment);

    assert!(matches!(vanish_commit_with(&key, TEST_CHAIN_ID, 0, &mut rng(3)), Err(VanishError::Amount { .. })));
    assert!(matches!(vanish_commit_with(&key, TEST_CHAIN_ID, 1 << 96, &mut rng(3)), Err(VanishError::Amount { .. })));
    let mut wrong_version = commit.commit_data.clone();
    wrong_version[1] = 1;
    assert!(matches!(commit_leaf(wrong_version, commit.amount_wei.clone()), Err(VanishError::Malformed { .. })));
    assert!(matches!(commit_leaf(commit.commit_data[..205].to_vec(), commit.amount_wei), Err(VanishError::Malformed { .. })));
}

#[test]
fn the_new_key_is_shown_once_checked_then_dropped_and_finds_its_coin() {
    let vault = KeyVault::new();
    assert!(matches!(vault.take_words(), Err(VanishError::NoKeyHeld)));
    let commit = vault.prepare_with(TEST_CHAIN_ID, 2 * ONE_GHOST, &mut rng(4)).unwrap();
    assert!(vault.holds_key());
    // Not saved before it was even shown.
    assert_eq!(vault.confirm_saved().unwrap_err(), VanishError::NotChecked { checked: 0, needed: CHECKED_KEY_WORDS });
    let words = vault.take_words().unwrap();
    assert_eq!(words.len(), 24);
    // Shown once.
    assert_eq!(vault.take_words().unwrap_err(), VanishError::AlreadyShown);

    // Three different words typed back, in any case, before the key is dropped.
    assert!(!vault.check_word(2, "ghostly").unwrap());
    assert!(vault.check_word(2, &format!(" {} ", words[1].to_uppercase())).unwrap());
    assert!(vault.check_word(2, &words[1]).unwrap());
    assert!(matches!(vault.check_word(0, &words[0]), Err(VanishError::Malformed { .. })));
    assert!(matches!(vault.check_word(25, &words[0]), Err(VanishError::Malformed { .. })));
    assert_eq!(vault.confirm_saved().unwrap_err(), VanishError::NotChecked { checked: 1, needed: 3 });
    assert!(vault.check_word(9, &words[8]).unwrap());
    assert!(vault.check_word(24, &words[23]).unwrap());
    vault.confirm_saved().unwrap();
    // The phone keeps nothing.
    assert!(!vault.holds_key());
    assert!(matches!(vault.take_words(), Err(VanishError::NoKeyHeld)));
    assert!(matches!(vault.check_word(2, &words[1]), Err(VanishError::NoKeyHeld)));

    let typed = words.join(" ");
    assert_eq!(classify_words(&typed).verdict, "phantom-key");
    let leaves = vec![commit_leaf(commit.commit_data, commit.amount_wei).unwrap()];
    let found = find_key_coins(typed, TEST_CHAIN_ID, leaves, Vec::new()).unwrap();
    assert_eq!((found.status.as_str(), found.amount_wei), ("found", (2 * ONE_GHOST).to_string()));

    vault.prepare_with(TEST_CHAIN_ID, ONE_GHOST, &mut rng(5)).unwrap();
    vault.forget();
    assert!(!vault.holds_key());
}

fn vanish_send(commit_data: Vec<u8>) -> VanishSend {
    VanishSend {
        chain_id: TEST_CHAIN_ID,
        genesis_hash: GENESIS.to_vec(),
        nonce: 7,
        commit_data,
        amount_wei: ONE_GHOST.to_string(),
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 3_000_000_000,
        gas_limit: VANISH_GAS_LIMIT,
    }
}

#[test]
fn a_vanish_is_an_account_transaction_to_the_commit_entry() {
    let commit = vanish_commit_with(&key(6), TEST_CHAIN_ID, ONE_GHOST, &mut rng(7)).unwrap();
    let seed = WalletSeed::from_bytes(COUNTING);
    let signed = sign_vanish_with(&seed, 0, &vanish_send(commit.commit_data.clone()), &mut rng(8)).unwrap();

    let verified = verify_envelope(&signed.envelope, TEST_CHAIN_ID, &GENESIS).expect("Ghost accepts the Vanish");
    assert_eq!(verified.sender, ACCOUNT);
    assert_eq!(signed.sender, ACCOUNT.to_vec());
    assert_eq!(verified.hash.to_vec(), signed.transaction_hash);
    assert_eq!(transaction_hash(signed.envelope.clone()), signed.transaction_hash);
    let tx = verified.tx;
    assert_eq!(tx.to, Some(COMMIT_ENTRY));
    assert_eq!(COMMIT_ENTRY[..5], *b"ghost");
    assert_eq!(tx.value, ONE_GHOST);
    assert_eq!(tx.nonce, 7);
    assert_eq!(tx.data, commit.commit_data);
    assert_eq!(tx.gas_limit, VANISH_GAS_LIMIT);
}

#[test]
fn a_vanish_is_signed_for_the_test_chain_only_and_well_formed_only() {
    let commit = vanish_commit_with(&key(6), TEST_CHAIN_ID, ONE_GHOST, &mut rng(7)).unwrap();
    let seed = WalletSeed::from_bytes(COUNTING);
    let sign = |send: VanishSend| sign_vanish_with(&seed, 0, &send, &mut rng(8));

    let mut other_chain = vanish_send(commit.commit_data.clone());
    other_chain.chain_id = 1;
    assert_eq!(sign(other_chain).unwrap_err(), VanishError::WrongChain { expected: TEST_CHAIN_ID, found: 1 });

    let mut short = vanish_send(commit.commit_data.clone());
    short.commit_data.pop();
    assert!(matches!(sign(short), Err(VanishError::Malformed { .. })));

    let mut low_gas = vanish_send(commit.commit_data.clone());
    low_gas.gas_limit = VANISH_MIN_GAS - 1;
    assert!(matches!(sign(low_gas), Err(VanishError::Malformed { .. })));

    let mut nothing = vanish_send(commit.commit_data.clone());
    nothing.amount_wei = "0".to_owned();
    assert!(matches!(sign(nothing), Err(VanishError::Amount { .. })));

    let mut caps = vanish_send(commit.commit_data);
    caps.max_fee_per_gas = caps.max_priority_fee_per_gas - 1;
    assert!(matches!(sign(caps), Err(VanishError::Malformed { .. })));
}

// --- Finding a key's coins ---------------------------------------------------

#[test]
fn a_key_this_phone_cannot_find_is_not_found_rather_than_zero() {
    let leaves = tree_with(&key(10), ONE_GHOST);
    let stranger = key(11);
    let found = find_coins(&stranger, TEST_CHAIN_ID, &leaves, &[]).unwrap();
    assert_eq!((found.status.as_str(), found.amount_wei.as_str()), ("not-found", "0"));
    let empty = find_coins(&stranger, TEST_CHAIN_ID, &[], &[]).unwrap();
    assert_eq!(empty.status, "not-found");
    assert!(matches!(
        prove_reveal_with(&stranger, &request(None), &leaves, &[], &mut rng(12)),
        Err(VanishError::NotFound)
    ));
}

#[test]
fn a_reveal_needs_a_coin_worth_more_than_its_fee() {
    let key = key(13);
    let fee: u128 = reveal_fee_wei(B_REF.to_owned()).unwrap().parse().unwrap();
    let leaves = tree_with(&key, fee);
    assert!(matches!(prove_reveal_with(&key, &request(None), &leaves, &[], &mut rng(14)), Err(VanishError::Amount { .. })));
    let leaves = tree_with(&key, ONE_GHOST);
    let too_much = Some(ONE_GHOST.to_string());
    assert!(matches!(prove_reveal_with(&key, &request(too_much), &leaves, &[], &mut rng(14)), Err(VanishError::Amount { .. })));
    let mut zero = request(None);
    zero.recipient = vec![0; 20];
    assert!(matches!(prove_reveal_with(&key, &zero, &leaves, &[], &mut rng(14)), Err(VanishError::Malformed { .. })));
    let mut chain = request(None);
    chain.chain_id = 1234;
    assert!(matches!(prove_reveal_with(&key, &chain, &leaves, &[], &mut rng(14)), Err(VanishError::WrongChain { .. })));
}

// --- Claim, then Summon, proved on the phone ---------------------------------

#[test]
fn claim_part_then_summon_the_rest_back_to_the_account() {
    let key = key(20);
    let fee: u128 = reveal_fee_wei(B_REF.to_owned()).unwrap().parse().unwrap();
    let mut leaves = tree_with(&key, ONE_GHOST);
    let mut spent: Vec<Vec<u8>> = Vec::new();

    // Claim a third: proved here, checked by Ghost's verifier.
    let third = ONE_GHOST / 3;
    let claim = prove_reveal_with(&key, &request(Some(third.to_string())), &leaves, &spent, &mut rng(21)).unwrap();
    verify_salted_coin_reveal(&claim.params, &claim.reveal, &claim.proof).expect("Ghost verifies the Claim");
    assert_eq!(claim.params.domain, GENESIS);
    assert_eq!(claim.reveal.recipient, ACCOUNT);
    let proved = &claim.proved;
    assert_eq!(proved.out_wei, third.to_string());
    assert_eq!(proved.fee_wei, fee.to_string());
    assert_eq!(proved.remainder_wei, (ONE_GHOST - third - fee).to_string());

    // Spec 07's envelope.
    assert_eq!(proved.envelope.len(), ENVELOPE_BYTES);
    assert_eq!(ENVELOPE_BYTES, 1_311_067);
    assert_eq!(proved.envelope[0], PRIVATE_TX_TYPE);
    assert_eq!(&proved.envelope[1..3], &[0x00, 0x01]);
    assert_eq!(&proved.envelope[3..11], &TEST_CHAIN_ID.to_be_bytes());
    assert_eq!(&proved.envelope[11..43], &claim.reveal.marker);
    assert_eq!(&proved.envelope[43..75], &claim.reveal.root);
    assert_eq!(&proved.envelope[107..127], &ACCOUNT);
    assert_eq!(&proved.envelope[127..159], &claim.reveal.out);
    assert_eq!(&proved.envelope[159..191], &claim.reveal.fee);
    let proof = claim.proof.as_bytes();
    assert_eq!(&proved.envelope[191..191 + proof.len()], proof);
    assert!(proved.envelope[191 + proof.len()..ENVELOPE_BYTES - 156].iter().all(|byte| *byte == 0));
    assert_eq!(transaction_hash(proved.envelope.clone()), proved.transaction_hash);
    assert_eq!(proved.marker, claim.reveal.marker.to_vec());

    // The chain shows the Claim: its marker is spent, its remainder is a leaf.
    let shown = reveal_leaf(proved.envelope.clone()).unwrap();
    assert_eq!(shown.marker, proved.marker);
    assert_eq!(shown.leaf.commitment, claim.reveal.remainder.to_vec());
    assert_eq!(shown.leaf.salt, None);
    spent.push(shown.marker);
    leaves.push(shown.leaf);

    // The key now holds the rest, in its next coin.
    let found = find_coins(&key, TEST_CHAIN_ID, &leaves, &spent).unwrap();
    assert_eq!((found.status.as_str(), found.amount_wei), ("found", (ONE_GHOST - third - fee).to_string()));

    // Summon the rest: everything less the fee comes back to the account.
    let summon = prove_reveal_with(&key, &request(None), &leaves, &spent, &mut rng(22)).unwrap();
    verify_salted_coin_reveal(&summon.params, &summon.reveal, &summon.proof).expect("Ghost verifies the Summon");
    assert_eq!(summon.proved.out_wei, (ONE_GHOST - third - 2 * fee).to_string());
    assert_eq!(summon.proved.remainder_wei, "0");
    assert_ne!(summon.proved.marker, proved.marker);

    let shown = reveal_leaf(summon.proved.envelope.clone()).unwrap();
    spent.push(shown.marker);
    leaves.push(shown.leaf);
    let after = find_coins(&key, TEST_CHAIN_ID, &leaves, &spent).unwrap();
    // Spent, not "not found": the phone knows the key, its coins came back.
    assert_eq!((after.status.as_str(), after.amount_wei.as_str()), ("spent", "0"));
    assert!(matches!(prove_reveal_with(&key, &request(None), &leaves, &spent, &mut rng(23)), Err(VanishError::Spent)));
}

#[test]
fn reveal_leaf_refuses_what_is_not_a_private_transaction() {
    assert!(matches!(reveal_leaf(vec![PRIVATE_TX_TYPE; 10]), Err(VanishError::Malformed { .. })));
    let mut wrong_type = vec![0u8; ENVELOPE_BYTES];
    wrong_type[0] = 0x52;
    assert!(matches!(reveal_leaf(wrong_type), Err(VanishError::Malformed { .. })));
    let mut wrong_version = vec![0u8; ENVELOPE_BYTES];
    wrong_version[0] = PRIVATE_TX_TYPE;
    wrong_version[2] = 2;
    assert!(matches!(reveal_leaf(wrong_version), Err(VanishError::Malformed { .. })));
}

#[test]
fn nothing_formatted_holds_a_key_or_a_signature() {
    let key = key(30);
    let commit = vanish_commit_with(&key, TEST_CHAIN_ID, ONE_GHOST, &mut rng(31)).unwrap();
    let seed = WalletSeed::from_bytes(COUNTING);
    let signed = sign_vanish_with(&seed, 0, &vanish_send(commit.commit_data), &mut rng(32)).unwrap();
    let shown = format!("{signed:?}");
    let hex: String = signed.envelope[200..216].iter().map(|b| format!("{b:02x}")).collect();
    assert!(!shown.contains(&hex), "{shown}");

    let words = words_of(&key);
    let errors = [
        find_key_coins(words.clone(), 1, Vec::new(), Vec::new()).map(|_| ()).err(),
        find_key_coins(format!("{words} extra"), TEST_CHAIN_ID, Vec::new(), Vec::new()).map(|_| ()).err(),
    ];
    for error in errors.into_iter().flatten() {
        let text = format!("{error} {error:?}");
        for word in words.split_whitespace() {
            assert!(!text.split(|c: char| !c.is_alphanumeric()).any(|part| part == word), "{text}");
        }
    }
}
