//! The phone's checks of a Ghost Java Card (`src/java_card.rs`), against one
//! card's real answers on jcardsim (`card-applet/test/phone-vectors.txt`):
//! certificates, LMS seal statements, commit data, open codes and Open.

use std::collections::HashMap;

use ghost_client::slh_dsa::SigningKey;
use ghost_wallet_core::java_card::{
    APPLET_HASHES, CERT_BYTES, CERT_DOMAIN, CardState, CheckParts, OpenExpect, OpenRefusal, PinnedIssuer, Refusal,
    Trust, certificate_body, check_card, check_certificate, code_confirmation, code_hash, finish_open, forget_release,
    lms_verify, open_code_from_text, open_code_text, open_release, parse_statement, pinned_trust, take_open,
};
use ghost_wallet_core::card::{forget_card_key, has_card_key};
use ghost_wallet_core::{
    JavaCardCheckInput, finish_java_card_open_unchecked, java_card_identity, java_card_number, java_card_open_code,
    verify_java_card_check,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

fn vectors() -> HashMap<String, Vec<u8>> {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../card-applet/test/phone-vectors.txt"))
        .expect("the phone vectors");
    text.lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (key, value) = line.split_once('=').expect("key = value");
            let value = value.trim();
            let bytes = (0..value.len()).step_by(2).map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap()).collect();
            (key.trim().to_owned(), bytes)
        })
        .collect()
}

fn get<'a>(v: &'a HashMap<String, Vec<u8>>, key: &str) -> &'a [u8] {
    v.get(key).unwrap_or_else(|| panic!("{key} in the vectors"))
}

fn fixed<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().unwrap()
}

const CHAIN: u64 = 1;
const BATCH: u32 = 7;

fn test_issuer(seed: u8) -> SigningKey {
    SigningKey::from_seeds(&[seed; 16], &[seed.wrapping_add(1); 16], &[seed.wrapping_add(2); 16])
}

fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

/// Trust in one test issuer (dev or not), batch 7, the published applet.
fn trust(issuer: &SigningKey, dev: bool, allow_dev: bool) -> Trust {
    let issuers = leak([PinnedIssuer { public_key: issuer.public_key(), dev, batches: &[BATCH] }]);
    Trust { issuers, applet_hashes: APPLET_HASHES, revoked_cards: &[], allow_dev }
}

fn certify(issuer: &SigningKey, card_id: &[u8], lms: &[u8], applet: &[u8; 32], batch: u32) -> Vec<u8> {
    let body = certificate_body(&issuer.public_key(), &fixed(card_id), &fixed(lms), applet, batch);
    let signature = issuer.sign(&body, CERT_DOMAIN, &mut StdRng::seed_from_u64(9)).unwrap();
    let mut cert = body.to_vec();
    cert.extend_from_slice(&signature[..]);
    cert
}

fn card_cert(v: &HashMap<String, Vec<u8>>, issuer: &SigningKey) -> Vec<u8> {
    certify(issuer, get(v, "card_id"), get(v, "lms_public_key"), &APPLET_HASHES[0], BATCH)
}

fn parts<'a>(cert: &'a [u8], v: &'a HashMap<String, Vec<u8>>, name: &str, commit: Option<&'a [u8]>) -> CheckParts<'a> {
    CheckParts {
        certificate: cert,
        statement: get(v, &format!("{name}_statement")),
        signature: get(v, &format!("{name}_signature")),
        challenge: get(v, &format!("{name}_challenge")),
        commit_data: commit,
    }
}

#[test]
fn every_recorded_statement_verifies_and_only_its_own() {
    let v = vectors();
    let key = get(&v, "lms_public_key");
    for name in ["blank", "sealed", "wrong_code", "opened"] {
        let statement = get(&v, &format!("{name}_statement"));
        let signature = get(&v, &format!("{name}_signature"));
        assert!(lms_verify(key, statement, signature), "{name}");
        let mut other = statement.to_vec();
        other[60] ^= 1;
        assert!(!lms_verify(key, &other, signature), "{name}: another statement");
        let mut bad = signature.to_vec();
        bad[100] ^= 1;
        assert!(!lms_verify(key, statement, &bad), "{name}: an altered signature");
        let mut other_key = key.to_vec();
        other_key[30] ^= 1;
        assert!(!lms_verify(&other_key, statement, signature), "{name}: another key");
        assert!(!lms_verify(key, statement, &signature[..2507]), "{name}: a short signature");
    }
    // A signature of one statement does not pass for another.
    assert!(!lms_verify(key, get(&v, "sealed_statement"), get(&v, "blank_signature")));
}

#[test]
fn statements_read_as_recorded() {
    let v = vectors();
    let blank = parse_statement(get(&v, "blank_statement")).unwrap();
    assert_eq!(blank.state, CardState::Blank);
    assert_eq!((blank.fill, blank.checks_left, blank.leaf, blank.code), (0, 1023, 0, 0));
    assert_eq!(blank.commitment, [0; 32]);
    let sealed = parse_statement(get(&v, "sealed_statement")).unwrap();
    assert_eq!(sealed.state, CardState::Sealed);
    assert_eq!((sealed.fill, sealed.checks_left, sealed.leaf, sealed.code), (1, 1022, 1, 1));
    assert_eq!(sealed.amount, 1_000_000_000_000_000_000);
    assert_eq!(sealed.chain_id, CHAIN);
    assert_eq!(&sealed.commitment[..], &get(&v, "make_answer")[4..36]);
    assert_eq!(parse_statement(get(&v, "wrong_code_statement")).unwrap().code, 2);
    assert_eq!(parse_statement(get(&v, "opened_statement")).unwrap().state, CardState::Opened);
    assert!(parse_statement(&get(&v, "blank_statement")[..193]).is_none());
    let mut bad = get(&v, "blank_statement").to_vec();
    bad[34] = 3;
    assert!(parse_statement(&bad).is_none(), "an unknown state");
}

#[test]
fn a_genuine_sealed_card_passes_with_its_commit_data() {
    let v = vectors();
    let issuer = test_issuer(1);
    let cert = card_cert(&v, &issuer);
    assert_eq!(cert.len(), CERT_BYTES);
    let make = get(&v, "make_answer");
    let card = check_card(&parts(&cert, &v, "sealed", Some(&make[36..])), &trust(&issuer, false, false), CHAIN).unwrap();
    assert_eq!(card.statement.fill, 1);
    assert_eq!(card.certificate.batch, BATCH);
    let leaf = card.leaf.unwrap();
    assert_eq!(&leaf.commitment[..], &make[4..36]);
    assert_eq!(leaf.salt.as_deref(), Some(&make[36 + 34..36 + 50]));
    assert_eq!(&leaf.note[..], &make[36 + 50..]);
    // Every other recorded Check passes too, with no commit data.
    for name in ["blank", "wrong_code", "opened"] {
        check_card(&parts(&cert, &v, name, None), &trust(&issuer, false, false), CHAIN).unwrap();
    }
}

#[test]
fn certificates_are_refused_for_each_reason() {
    let v = vectors();
    let issuer = test_issuer(1);
    let cert = card_cert(&v, &issuer);
    let pinned = trust(&issuer, false, false);
    assert!(check_certificate(&cert, &pinned).is_ok());

    assert_eq!(check_certificate(&cert[..CERT_BYTES - 1], &pinned), Err(Refusal::CertificateMalformed));
    let mut wrong_domain = cert.clone();
    wrong_domain[0] ^= 1;
    assert_eq!(check_certificate(&wrong_domain, &pinned), Err(Refusal::CertificateMalformed));

    assert_eq!(check_certificate(&cert, &trust(&test_issuer(2), false, false)), Err(Refusal::UnknownIssuer));
    assert_eq!(check_certificate(&cert, &trust(&issuer, true, false)), Err(Refusal::DevIssuer));
    assert!(check_certificate(&cert, &trust(&issuer, true, true)).unwrap().dev);

    for at in [30, 50, 120, 140, 5000, CERT_BYTES - 1] {
        let mut altered = cert.clone();
        altered[at] ^= 1;
        assert_eq!(check_certificate(&altered, &pinned), Err(Refusal::IssuerSignature), "byte {at}");
    }

    let other_batch = certify(&issuer, get(&v, "card_id"), get(&v, "lms_public_key"), &APPLET_HASHES[0], BATCH + 1);
    assert_eq!(check_certificate(&other_batch, &pinned), Err(Refusal::UnknownBatch));
    let other_applet = certify(&issuer, get(&v, "card_id"), get(&v, "lms_public_key"), &[7; 32], BATCH);
    assert_eq!(check_certificate(&other_applet, &pinned), Err(Refusal::UnknownApplet));
    let revoked = Trust { revoked_cards: leak([fixed::<16>(get(&v, "card_id"))]), ..pinned };
    assert_eq!(check_certificate(&cert, &revoked), Err(Refusal::Revoked));

    // A certificate signed by an issuer for another issuer's id.
    let other = test_issuer(3);
    let mut forged = certificate_body(&issuer.public_key(), &fixed(get(&v, "card_id")), &fixed(get(&v, "lms_public_key")), &APPLET_HASHES[0], BATCH).to_vec();
    forged.extend_from_slice(&other.sign(&forged.clone(), CERT_DOMAIN, &mut StdRng::seed_from_u64(1)).unwrap()[..]);
    assert_eq!(check_certificate(&forged, &pinned), Err(Refusal::IssuerSignature));
}

#[test]
fn checks_are_refused_for_each_reason() {
    let v = vectors();
    let issuer = test_issuer(1);
    let pinned = trust(&issuer, false, false);
    let cert = card_cert(&v, &issuer);
    let make = get(&v, "make_answer");
    let commit = &make[36..];

    // A card whose certificate names another LMS key, or another card.
    let mut other_key = get(&v, "lms_public_key").to_vec();
    other_key[40] ^= 1;
    let wrong_key = certify(&issuer, get(&v, "card_id"), &other_key, &APPLET_HASHES[0], BATCH);
    assert_eq!(check_card(&parts(&wrong_key, &v, "sealed", None), &pinned, CHAIN), Err(Refusal::StatementSignature));
    let mut other_card = get(&v, "card_id").to_vec();
    other_card[0] ^= 1;
    let wrong_card = certify(&issuer, &other_card, get(&v, "lms_public_key"), &APPLET_HASHES[0], BATCH);
    assert_eq!(check_card(&parts(&wrong_card, &v, "sealed", None), &pinned, CHAIN), Err(Refusal::WrongCard));

    // An old answer replayed: not over this tap's challenge.
    let mut replay = parts(&cert, &v, "sealed", None);
    replay.challenge = get(&v, "blank_challenge");
    assert_eq!(check_card(&replay, &pinned, CHAIN), Err(Refusal::WrongChallenge));

    // A coin on another chain.
    assert_eq!(check_card(&parts(&cert, &v, "sealed", None), &pinned, CHAIN + 1), Err(Refusal::WrongChain));
    // A blank card has no chain.
    assert!(check_card(&parts(&cert, &v, "blank", None), &pinned, CHAIN + 1).is_ok());

    // Commit data altered between the card and the app.
    for at in [2, 40, 60, 429] {
        let mut altered = commit.to_vec();
        altered[at] ^= 1;
        assert_eq!(
            check_card(&parts(&cert, &v, "sealed", Some(&altered)), &pinned, CHAIN),
            Err(Refusal::CommitDataDigest),
            "byte {at}"
        );
    }
    assert_eq!(
        check_card(&parts(&cert, &v, "sealed", Some(&commit[..429])), &pinned, CHAIN),
        Err(Refusal::CommitDataMalformed)
    );
    assert_eq!(
        check_card(&parts(&cert, &v, "blank", Some(commit)), &pinned, CHAIN),
        Err(Refusal::CommitDataMalformed)
    );
}

#[test]
fn the_pinned_trust_knows_no_test_issuer() {
    let v = vectors();
    let cert = card_cert(&v, &test_issuer(1));
    let verdict = verify_java_card_check(JavaCardCheckInput {
        certificate: cert,
        statement: get(&v, "sealed_statement").to_vec(),
        signature: get(&v, "sealed_signature").to_vec(),
        challenge: get(&v, "sealed_challenge").to_vec(),
        commit_data: None,
        chain_id: ghost_wallet_core::TEST_CHAIN_ID,
    });
    assert_eq!(verdict.refusal, "unknown-issuer");
    assert!(verdict.statement.is_none());
    assert!(pinned_trust(ghost_wallet_core::TEST_CHAIN_ID).allow_dev);
    assert!(!pinned_trust(1).allow_dev, "only test networks trust the development issuer");
}

#[test]
fn open_codes() {
    let v = vectors();
    let code: [u8; 20] = fixed(get(&v, "open_code"));
    let text = open_code_text(&code);
    assert_eq!(text.len(), 32);
    assert_eq!(*open_code_from_text(&text).unwrap(), code);
    let spaced: String = text.to_lowercase().chars().enumerate().flat_map(|(i, c)| {
        if i > 0 && i % 4 == 0 { vec![' ', c] } else { vec![c] }
    }).collect();
    assert_eq!(*open_code_from_text(&spaced).unwrap(), code);
    assert_eq!(java_card_open_code(spaced).unwrap(), code.to_vec());
    assert!(open_code_from_text(&text[..31]).is_none());
    assert!(open_code_from_text(&format!("{text}A")).is_none());
    assert!(open_code_from_text(&text.replace(text.chars().next().unwrap(), "1")).is_none());
    // The confirmation the card checked, recorded with the sealed Check.
    assert_eq!(
        code_confirmation(&code, get(&v, "sealed_challenge")).to_vec(),
        get(&v, "sealed_confirmation")
    );
    assert_eq!(code_hash(&code).len(), 32);
}

#[test]
fn card_numbers_and_identify() {
    let number = java_card_number(vec![0; 16]);
    assert_eq!(number, "AAAA AAAA AAAA AAAA AAAA AAAA AA");
    let mut identify = vec![1, 1, 1];
    identify.extend_from_slice(&[0xab; 16]);
    identify.extend_from_slice(&5u32.to_be_bytes());
    identify.extend_from_slice(&1000u16.to_be_bytes());
    identify.extend_from_slice(&1024u16.to_be_bytes());
    identify.extend_from_slice(&7990u16.to_be_bytes());
    let id = java_card_identity(identify.clone()).unwrap();
    assert_eq!((id.phase, id.state.as_str(), id.fill, id.checks_left, id.certificate_bytes), (1, "sealed", 5, 1000, 7990));
    assert_eq!(id.card_number, java_card_number(vec![0xab; 16]));
    assert!(java_card_identity(identify[..28].to_vec()).is_err());
}

/// The Open tests share the core's held release and card key, so they run
/// in one test, in order.
#[test]
fn open_releases_the_key_of_exactly_the_sealed_coin() {
    let v = vectors();
    let card_id: [u8; 16] = fixed(get(&v, "card_id"));
    let code: [u8; 20] = fixed(get(&v, "open_code"));
    let challenge: [u8; 32] = fixed(get(&v, "open_challenge"));
    let answer = get(&v, "open_answer");

    let (fill, release) = open_release(&card_id, &code, &challenge, answer).unwrap();
    assert_eq!(fill, 1);
    assert_eq!(&release[..32], get(&v, "card_random"));
    assert_eq!(&release[32..], get(&v, "writer_nonce"));

    // Anything altered, or another code, challenge or card: the tag fails first.
    for at in [0, 3, 4, 19, 20, 83, 84, 99] {
        let mut altered = answer.to_vec();
        altered[at] ^= 1;
        assert_eq!(open_release(&card_id, &code, &challenge, &altered).err(), Some(OpenRefusal::BadTag), "byte {at}");
    }
    let wrong: [u8; 20] = fixed(get(&v, "wrong_open_code"));
    assert_eq!(open_release(&card_id, &wrong, &challenge, answer).err(), Some(OpenRefusal::BadTag));
    assert_eq!(open_release(&card_id, &code, &[0; 32], answer).err(), Some(OpenRefusal::BadTag));
    let mut other_card = card_id;
    other_card[5] ^= 1;
    assert_eq!(open_release(&other_card, &code, &challenge, answer).err(), Some(OpenRefusal::BadTag));
    assert_eq!(open_release(&card_id, &code, &challenge, &answer[..99]).err(), Some(OpenRefusal::Malformed));

    let sealed = parse_statement(get(&v, "sealed_statement")).unwrap();
    let make = get(&v, "make_answer");
    let commit = &make[36..];
    let salt: [u8; 16] = fixed(&commit[34..50]);
    let expect = |commitment: [u8; 32], fill: u32| OpenExpect {
        card_id,
        fill,
        amount: sealed.amount,
        commitment,
        marker: sealed.marker,
        digest: sealed.digest,
        salt: &salt,
        note: &commit[50..],
    };

    forget_card_key();
    assert_eq!(finish_open(&expect(sealed.commitment, 1)), Err(OpenRefusal::NothingHeld));

    // Another coin than the release makes: refused, and nothing is held.
    take_open(&card_id, &code, &challenge, answer).unwrap();
    let mut other = sealed.commitment;
    other[0] ^= 1;
    assert_eq!(finish_open(&expect(other, 1)), Err(OpenRefusal::NotTheCoin));
    assert!(!has_card_key());
    assert_eq!(finish_open(&expect(sealed.commitment, 1)), Err(OpenRefusal::NothingHeld), "the release was wiped");

    take_open(&card_id, &code, &challenge, answer).unwrap();
    assert_eq!(finish_open(&expect(sealed.commitment, 2)), Err(OpenRefusal::OtherFill));

    // The right coin: the key is held for the Summon.
    take_open(&card_id, &code, &challenge, answer).unwrap();
    assert_eq!(finish_open(&expect(sealed.commitment, 1)), Ok(()));
    assert!(has_card_key());
    forget_card_key();

    // A card with no seal checks left: the key is held with no statement, for
    // the card and fill its Identify gave; the chain then decides.
    take_open(&card_id, &code, &challenge, answer).unwrap();
    assert_eq!(finish_java_card_open_unchecked(card_id.to_vec(), 2), "open-other-fill");
    assert!(!has_card_key());
    take_open(&card_id, &code, &challenge, answer).unwrap();
    assert_eq!(finish_java_card_open_unchecked(card_id.to_vec(), 1), "");
    assert!(has_card_key());
    forget_card_key();
    forget_release();
}
