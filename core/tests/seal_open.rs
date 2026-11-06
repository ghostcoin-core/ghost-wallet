//! The phone's side of a Sealed card's Open: its ML-KEM-768 key, the release
//! package (made here exactly as `seal_release` in `seal/src/release.rs` makes
//! it), the check of the signed Open answer, and the card key handed to the
//! core's card-key slot for the Claim.
//!
//! The Open and card-key slots are process-wide, so the tests take turns.

use std::sync::{Mutex, MutexGuard, PoisonError};

use aes::Aes256;
use aes::cipher::{BlockModeEncrypt, KeyInit, KeyIvInit};
use ghost_client::{KeyFormat, PhantomKey};
use ghost_wallet_core::card::{forget_card_key, has_card_key};
use ghost_wallet_core::seal_answer::{ANSWER_CONTEXT, ANSWER_DOMAIN, SealAnswerCheck, sha3_256};
use ghost_wallet_core::seal_open::{
    KEY_FORMAT_CODE, PHONE_KEY_BYTES, RELEASE_LABEL, finish_seal_open, forget_seal_open_key,
    ghost_wallet_seal_open_copy_seed, ghost_wallet_seal_open_restore_seed, ghost_wallet_seal_open_take_release,
    has_seal_open_key, open_release, phantom_key_from_bytes, phone_key_of, seal_open_phone_key,
};
use hkdf::SimpleHkdf;
use hmac::{Mac, SimpleHmac};
use ml_dsa::{ExpandedSigningKey, MlDsa65, Seed};
use ml_kem::{Encapsulate, EncapsulationKey, MlKem768, TryKeyInit};
use rand::rngs::StdRng;
use rand::{SeedableRng, TryCryptoRng, TryRng};
use sha3::Sha3_256;

const UID: [u8; 7] = [0x04, 0x51, 0x8d, 0xfa, 0xa9, 0x61, 0x80];
const MEASUREMENT: [u8; 48] = [0x5e; 48];
const NOW: u64 = 1_800_000_000;
const AMOUNT: u128 = 5_000_000_000_000_000_000;
/// The card's generation after the Open: the release is keyed to it.
const NEW_GENERATION: u32 = 1;

static TURN: Mutex<()> = Mutex::new(());

fn turn() -> MutexGuard<'static, ()> {
    let guard = TURN.lock().unwrap_or_else(PoisonError::into_inner);
    forget_seal_open_key();
    forget_card_key();
    guard
}

/// A source that records the bytes it gives.
struct Recording {
    inner: StdRng,
    given: Vec<u8>,
}

impl TryRng for Recording {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.inner.try_fill_bytes(dst)?;
        self.given.extend_from_slice(dst);
        Ok(())
    }
}

impl TryCryptoRng for Recording {}

/// A test Phantom Key and its key bytes, the way the Seal holds them: the
/// format code, then the 32 secret bytes the key was made from.
fn test_key(seed: u64) -> (PhantomKey, Vec<u8>) {
    let mut source = Recording { inner: StdRng::seed_from_u64(seed), given: Vec::new() };
    let key = PhantomKey::generate(KeyFormat::Words, &mut source);
    assert_eq!(source.given.len(), 32, "a key is made from 32 bytes");
    let mut bytes = vec![KEY_FORMAT_CODE];
    bytes.extend_from_slice(&source.given);
    (key, bytes)
}

fn words(key: &PhantomKey) -> String {
    key.format_words().expect("a words key").as_str().to_owned()
}

/// The release package, as the Seal makes it for `phone_key`.
fn release_to(phone_key: &[u8], key_bytes: &[u8], uid: &[u8], generation: u32) -> Vec<u8> {
    let phone = <EncapsulationKey<MlKem768> as TryKeyInit>::new_from_slice(phone_key).expect("a phone key");
    let mut rng = StdRng::seed_from_u64(99);
    let (ciphertext, shared) = phone.encapsulate_with_rng(&mut rng);
    let mut okm = [0u8; 64];
    SimpleHkdf::<Sha3_256>::new(Some(RELEASE_LABEL), &shared[..])
        .expand_multi_info(&[uid, &generation.to_be_bytes()], &mut okm)
        .expect("hkdf");
    let iv = [0x4c; 16];
    let length = (key_bytes.len() / 16 + 1) * 16;
    let mut padded = vec![0u8; length];
    padded[..key_bytes.len()].copy_from_slice(key_bytes);
    padded[key_bytes.len()] = 0x80;
    let mut mode = cbc::Encryptor::<Aes256>::new_from_slices(&okm[..32], &iv).expect("sizes");
    for chunk in padded.chunks_exact_mut(16) {
        let mut block = aes::Block::default();
        block.copy_from_slice(chunk);
        mode.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
    let mut package = b"GSR1".to_vec();
    package.extend_from_slice(&ciphertext);
    package.extend_from_slice(&iv);
    package.extend_from_slice(&padded);
    let mut mac = <SimpleHmac<Sha3_256> as KeyInit>::new_from_slice(&okm[32..]).expect("hmac");
    mac.update(RELEASE_LABEL);
    mac.update(uid);
    mac.update(&generation.to_be_bytes());
    mac.update(&package);
    package.extend_from_slice(&mac.finalize().into_bytes());
    package
}

fn seal_key() -> ExpandedSigningKey<MlDsa65> {
    ExpandedSigningKey::<MlDsa65>::from_seed(&Seed::from([7u8; 32]))
}

/// The Seal's signed Open answer, binding `package`.
fn open_answer(challenge: [u8; 32], package: &[u8], state: u8) -> SealAnswerCheck {
    let mut answer = ANSWER_DOMAIN.to_vec();
    answer.push(3);
    answer.extend_from_slice(&challenge);
    answer.extend_from_slice(&UID);
    answer.extend_from_slice(&NEW_GENERATION.to_be_bytes());
    answer.extend_from_slice(&[0xc0; 32]);
    answer.extend_from_slice(&MEASUREMENT);
    answer.push(state);
    answer.extend_from_slice(&AMOUNT.to_be_bytes());
    answer.extend_from_slice(&(NOW + 120).to_be_bytes());
    answer.extend_from_slice(&sha3_256(package));
    answer.extend_from_slice(&[0, 0]);
    let key = seal_key();
    SealAnswerCheck {
        verifying_key: key.verifying_key().encode().to_vec(),
        measurement: MEASUREMENT.to_vec(),
        pinned_measurements: vec![MEASUREMENT.to_vec()],
        signature: key.sign_deterministic(&answer, ANSWER_CONTEXT).expect("signed").encode().to_vec(),
        answer,
        challenge: challenge.to_vec(),
        uid: UID.to_vec(),
        now: NOW,
        kind: "open".to_owned(),
    }
}

fn hand_over(package: &[u8]) -> isize {
    // SAFETY: `package` is a live slice of its own length.
    unsafe { ghost_wallet_seal_open_take_release(package.as_ptr(), package.len()) }
}

#[test]
fn key_bytes_give_back_the_same_phantom_key() {
    let (key, bytes) = test_key(1);
    let back = phantom_key_from_bytes(&bytes).ok().expect("key bytes");
    assert_eq!(words(&back), words(&key));
    let mut wrong_code = bytes.clone();
    wrong_code[0] = 0x21;
    assert!(phantom_key_from_bytes(&wrong_code).is_err());
    assert!(phantom_key_from_bytes(&bytes[..32]).is_err());
}

#[test]
fn the_phone_key_is_made_once_and_kept_until_forgotten() {
    let _turn = turn();
    assert!(!has_seal_open_key());
    let first = seal_open_phone_key().expect("a phone key");
    assert_eq!(first.len(), PHONE_KEY_BYTES);
    assert!(has_seal_open_key());
    // Asked again (an Open cut off and run again): the same key.
    assert_eq!(seal_open_phone_key().expect("a phone key"), first);
    forget_seal_open_key();
    assert!(!has_seal_open_key());
    assert_ne!(seal_open_phone_key().expect("a phone key"), first);
    forget_seal_open_key();
}

#[test]
fn the_seed_kept_in_the_keychain_gives_back_the_same_phone_key() {
    let _turn = turn();
    let phone_key = seal_open_phone_key().expect("a phone key");
    let mut seed = [0u8; 64];
    // SAFETY: `seed` is 64 writable bytes.
    assert_eq!(unsafe { ghost_wallet_seal_open_copy_seed(seed.as_mut_ptr(), seed.len()) }, 64);
    assert_eq!(phone_key_of(&seed), phone_key);
    forget_seal_open_key();
    // SAFETY: `seed` is 64 readable bytes.
    assert_eq!(unsafe { ghost_wallet_seal_open_restore_seed(seed.as_ptr(), seed.len()) }, 0);
    assert_eq!(seal_open_phone_key().expect("a phone key"), phone_key);
    forget_seal_open_key();
    // SAFETY: as above.
    assert_eq!(unsafe { ghost_wallet_seal_open_copy_seed(seed.as_mut_ptr(), seed.len()) }, -1);
}

#[test]
fn an_open_puts_the_card_key_in_the_core_for_the_claim() {
    let _turn = turn();
    let (key, bytes) = test_key(2);
    let phone_key = seal_open_phone_key().expect("a phone key");
    let package = release_to(&phone_key, &bytes, &UID, NEW_GENERATION);
    assert_eq!(hand_over(&package), 0);

    let challenge = [0x0e; 32];
    let verdict = finish_seal_open(open_answer(challenge, &package, 3));
    assert_eq!(verdict.refusal, "");
    let answer = verdict.answer.expect("accepted");
    assert_eq!(answer.state, "opened");
    assert_eq!(answer.amount_wei, AMOUNT.to_string());
    assert!(has_card_key());
    // The phone key stays until the Claim settles.
    assert!(has_seal_open_key());

    // The same key, as the reference opener gives it.
    let mut seed = [0u8; 64];
    // SAFETY: `seed` is 64 writable bytes.
    assert_eq!(unsafe { ghost_wallet_seal_open_copy_seed(seed.as_mut_ptr(), seed.len()) }, 64);
    let opened = open_release(&seed, &package, &UID, NEW_GENERATION).ok().expect("opens");
    assert_eq!(words(&phantom_key_from_bytes(&opened).ok().expect("key")), words(&key));

    // The release is used once: a second finish has nothing to open.
    assert_eq!(finish_seal_open(open_answer(challenge, &package, 3)).refusal, "no-release");
    forget_seal_open_key();
    forget_card_key();
}

#[test]
fn a_release_for_another_phone_key_is_refused() {
    let _turn = turn();
    let (_, bytes) = test_key(3);
    seal_open_phone_key().expect("a phone key");
    let mut other_seed = [0x42u8; 64];
    let other = phone_key_of(&other_seed);
    other_seed.fill(0);
    let package = release_to(&other, &bytes, &UID, NEW_GENERATION);
    assert_eq!(hand_over(&package), 0);
    assert_eq!(finish_seal_open(open_answer([0x0f; 32], &package, 3)).refusal, "bad-release");
    assert!(!has_card_key());
}

#[test]
fn a_package_too_long_to_be_a_release_is_not_held() {
    let _turn = turn();
    seal_open_phone_key().expect("a phone key");
    assert_eq!(hand_over(&[0u8; 1300]), -2);
    assert_eq!(finish_seal_open(open_answer([0x18; 32], &[0u8; 1300], 3)).refusal, "no-release");
    forget_seal_open_key();
}

#[test]
fn a_release_for_another_card_or_generation_is_refused() {
    let _turn = turn();
    let (_, bytes) = test_key(4);
    let phone_key = seal_open_phone_key().expect("a phone key");
    let package = release_to(&phone_key, &bytes, &UID, NEW_GENERATION + 1);
    assert_eq!(hand_over(&package), 0);
    assert_eq!(finish_seal_open(open_answer([0x10; 32], &package, 3)).refusal, "bad-release");
    assert!(!has_card_key());
}

#[test]
fn an_answer_that_binds_another_package_or_is_badly_signed_releases_nothing() {
    let _turn = turn();
    let (_, bytes) = test_key(5);
    let phone_key = seal_open_phone_key().expect("a phone key");
    let package = release_to(&phone_key, &bytes, &UID, NEW_GENERATION);

    assert_eq!(hand_over(&package), 0);
    let mut other = package.clone();
    other[10] ^= 1;
    assert_eq!(finish_seal_open(open_answer([0x11; 32], &other, 3)).refusal, "wrong-binding");
    assert!(!has_card_key());

    assert_eq!(hand_over(&package), 0);
    let mut forged = open_answer([0x12; 32], &package, 3);
    forged.signature[5] ^= 1;
    assert_eq!(finish_seal_open(forged).refusal, "bad-signature");
    assert!(!has_card_key());

    assert_eq!(hand_over(&package), 0);
    let mut replayed = open_answer([0x13; 32], &package, 3);
    replayed.challenge = vec![0x14; 32];
    assert_eq!(finish_seal_open(replayed).refusal, "wrong-challenge");
    assert!(!has_card_key());

    assert_eq!(hand_over(&package), 0);
    let mut expired = open_answer([0x15; 32], &package, 3);
    expired.now = NOW + 120;
    assert_eq!(finish_seal_open(expired).refusal, "expired");
    assert!(!has_card_key());

    // An answer that is not Opened releases nothing either.
    assert_eq!(hand_over(&package), 0);
    assert_eq!(finish_seal_open(open_answer([0x16; 32], &package, 2)).refusal, "wrong-kind");
    assert!(!has_card_key());
    forget_seal_open_key();
}

#[test]
fn nothing_is_held_without_a_phone_key() {
    let _turn = turn();
    assert_eq!(hand_over(&[0u8; 1172]), -1);
    let mut check = open_answer([0x17; 32], &[0u8; 1172], 3);
    assert_eq!(finish_seal_open(check.clone()).refusal, "no-phone-key");
    check.kind = "check".to_owned();
    assert_eq!(finish_seal_open(check).refusal, "wrong-kind");
    assert!(!has_card_key());
}
