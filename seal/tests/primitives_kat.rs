//! The primitives against published vectors (FIPS 197, SP 800-38A, RFC 4493,
//! FIPS 202), and the lattice schemes' sizes, round trips and known answers
//! from fixed seeds.

mod support;

use ghost_seal::answer::{ANSWER_BYTES, AnswerBody, AnswerKind};
use ghost_seal::primitives::{
    aes128_cbc_decrypt, aes128_cbc_encrypt, aes128_encrypt_block, aes256_encrypt_block, cmac_aes128, crc32_new_key,
    ct_eq, hkdf_sha3_256, hmac_sha3_256, rotate_left, sha3_256,
};
use ghost_seal::record::{FRAME_BYTES, frames};
use ghost_seal::{AnswerVerifier, CardState, MemoryJournal, PhantomKey, Pin, SealError};
use ml_dsa::{ExpandedSigningKey, MlDsa65, Seed};
use ml_kem::{Decapsulate, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768, TryKeyInit};
use support::{MEASUREMENT, START_TIME, TestClock, UID, array, hex, phone, unhex};

const NIST_KEY: &str = "2B7E151628AED2A6ABF7158809CF4F3C";
const NIST_BLOCKS: &str = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";

#[test]
fn aes_fips_197() {
    let plain: [u8; 16] = array("00112233445566778899AABBCCDDEEFF");
    assert_eq!(hex(&aes128_encrypt_block(&array("000102030405060708090A0B0C0D0E0F"), &plain)), "69C4E0D86A7B0430D8CDB78070B4C55A");
    assert_eq!(
        hex(&aes256_encrypt_block(&array("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"), &plain)),
        "8EA2B7CA516745BFEAFC49904B496089"
    );
}

#[test]
fn cbc_sp_800_38a() {
    let iv: [u8; 16] = array("000102030405060708090A0B0C0D0E0F");
    let plain = unhex(&NIST_BLOCKS[..64]);
    let cipher = aes128_cbc_encrypt(&array(NIST_KEY), &iv, &plain).unwrap();
    assert_eq!(hex(&cipher), "7649ABAC8119B246CEE98E9B12E9197D5086CB9B507219EE95DB113A917678B2");
    assert_eq!(&aes128_cbc_decrypt(&array(NIST_KEY), &iv, &cipher).unwrap()[..], &plain[..]);
    assert!(aes128_cbc_encrypt(&array(NIST_KEY), &iv, &plain[..15]).is_err());
}

#[test]
fn cmac_rfc_4493() {
    let key: [u8; 16] = array(NIST_KEY);
    let message = unhex(NIST_BLOCKS);
    assert_eq!(hex(&cmac_aes128(&key, &[])), "BB1D6929E95937287FA37D129B756746");
    assert_eq!(hex(&cmac_aes128(&key, &message[..16])), "070A16B46B4D4144F79BDD9DD04A287C");
    assert_eq!(hex(&cmac_aes128(&key, &message[..40])), "DFA66747DE9AE63030CA32611497C827");
    assert_eq!(hex(&cmac_aes128(&key, &message)), "51F0BEBF7E3B9D92FC49741779363CFE");
}

#[test]
fn sha3_fips_202() {
    assert_eq!(hex(&sha3_256(&[])), "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A");
    assert_eq!(hex(&sha3_256(&[b"abc"])), "3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532");
    assert_eq!(sha3_256(&[b"a", b"bc"]), sha3_256(&[b"abc"]));
}

#[test]
fn hmac_and_hkdf_sha3_known_answers() {
    // NIST's HMAC-SHA3-256 example: key 00..1F, "Sample message for keylen<blocklen".
    let nist_key: Vec<u8> = (0u8..32).collect();
    assert_eq!(
        hex(&hmac_sha3_256(&nist_key, &[b"Sample message for keylen<blocklen"])),
        "4FE8E202C4F058E8DDDC23D8C34E467343E23555E24FC2F025D598F558F67205"
    );
    // Pinned from this build so any change of construction shows up.
    assert_eq!(
        hex(&hmac_sha3_256(b"key", &[b"The quick brown fox jumps over the lazy dog"])),
        "8C6E0683409427F8931711B10CA92A506EB1FAFA48FADD66D76126F47AC2C333"
    );
    let mut okm = [0u8; 42];
    hkdf_sha3_256(&unhex("000102030405060708090A0B0C"), &[0x0b; 22], &[&unhex("F0F1F2F3F4F5F6F7F8F9")], &mut okm);
    assert_eq!(hex(&okm), "0C5160501D65021DEAF2C14F5ABCE04C5BD2635ABCEEBA61C2EDB6E8ED72674900557728F2C9F2C4C179");
    // HKDF expands over several info parts as over their concatenation.
    let mut split = [0u8; 42];
    hkdf_sha3_256(&unhex("000102030405060708090A0B0C"), &[0x0b; 22], &[&unhex("F0F1F2F3F4"), &unhex("F5F6F7F8F9")], &mut split);
    assert_eq!(okm, split);
}

#[test]
fn crc32_of_a_new_key_is_jamcrc() {
    // CRC-32 of "123456789" is CBF43926; the chip's is not inverted: 340BC6D9, little endian.
    assert_eq!(hex(&crc32_new_key(b"123456789")), "D9C60B34");
}

#[test]
fn small_helpers() {
    assert!(ct_eq(b"abc", b"abc"));
    assert!(!ct_eq(b"abc", b"abd"));
    assert!(!ct_eq(b"abc", b"ab"));
    assert_eq!(hex(&rotate_left(&array("000102030405060708090A0B0C0D0E0F"))), "0102030405060708090A0B0C0D0E0F00");
}

#[test]
fn frames_are_128_bytes_or_less() {
    assert_eq!(FRAME_BYTES, 128);
    let data = vec![7u8; 300];
    let split = frames(0, &data);
    assert_eq!(split.iter().map(|(at, frame)| (*at, frame.len())).collect::<Vec<_>>(), vec![(0, 128), (128, 128), (256, 44)]);
    for (_, frame) in frames(128, &data[..129]) {
        assert!(frame.len() <= FRAME_BYTES);
    }
}

#[test]
fn ml_dsa_65_signs_and_verifies() {
    let seed = Seed::from([0x11u8; 32]);
    let key = ExpandedSigningKey::<MlDsa65>::from_seed(&seed);
    let verifying = key.verifying_key().encode();
    assert_eq!(verifying.len(), 1952);
    assert_eq!(hex(&sha3_256(&[&verifying])), "A163C1528E20DE91F7C41AED6C0EC7F3C3A6BC387786CE2196FAE49EDD93F6C1");
    let signature = key.sign_deterministic(b"message", b"ctx").unwrap();
    let encoded = signature.encode();
    assert_eq!(encoded.len(), 3309);
    // Deterministic signing: the same bytes every time.
    assert_eq!(key.sign_deterministic(b"message", b"ctx").unwrap().encode(), encoded);
    assert!(key.verifying_key().verify_with_context(b"message", b"ctx", &signature));
    assert!(!key.verifying_key().verify_with_context(b"messagf", b"ctx", &signature));
    assert!(!key.verifying_key().verify_with_context(b"message", b"other", &signature));
}

#[test]
fn ml_kem_768_encapsulates_and_decapsulates() {
    let phone = phone(0x22);
    let public = phone.public_key();
    assert_eq!(public.len(), 1184);
    assert_eq!(hex(&sha3_256(&[&public])), "507D6AD678A602E2067DB3A9E9B5FF57E1705581477246F7321ADAC93555BD18");

    let decapsulation = DecapsulationKey::<MlKem768>::from_seed(ml_kem::Seed::from([0x22u8; 64]));
    assert_eq!(decapsulation.encapsulation_key().to_bytes().to_vec(), public);
    let encapsulation = <EncapsulationKey<MlKem768> as TryKeyInit>::new_from_slice(&public).unwrap();
    let (ciphertext, shared) = encapsulation.encapsulate_deterministic(&ml_kem::B32::from([0x09u8; 32]));
    assert_eq!(ciphertext.len(), 1088);
    assert_eq!(hex(&sha3_256(&[&ciphertext, &shared])), "69F677AC02470E450B885B1466111A4248A9969EE411460C47954DD64E66E5D8");
    assert_eq!(decapsulation.decapsulate(&ciphertext), shared);
    let mut tampered = ciphertext;
    tampered[0] ^= 1;
    assert_ne!(decapsulation.decapsulate(&tampered), shared);
}

#[test]
fn answers_encode_and_verify() {
    let journal = MemoryJournal::new();
    let clock = TestClock::new();
    let seal = support::seal(&journal, &clock, 9);
    let body = AnswerBody {
        kind: AnswerKind::Check,
        challenge: [3u8; 32],
        uid: UID,
        generation: 2,
        coin: [4u8; 32],
        measurement: MEASUREMENT,
        state: CardState::Sealed,
        amount_wei: 5,
        expires_at: START_TIME + 60,
        binding: [6u8; 32],
    };
    let bytes = body.encode();
    assert_eq!(bytes.len(), ANSWER_BYTES);
    assert_eq!(&bytes[..20], b"ghost-seal/v1/answer");
    assert_eq!(AnswerBody::decode(&bytes), Some(body));
    assert_eq!(seal.answer_verifying_key().len(), 1952);
    assert!(AnswerVerifier::new(&seal.answer_verifying_key(), MEASUREMENT).is_ok());
    assert!(AnswerVerifier::new(&[0u8; 10], MEASUREMENT).is_err());
}

#[test]
fn secrets_refuse_bad_shapes() {
    assert!(matches!(PhantomKey::new(vec![]), Err(SealError::BadPhantomKey)));
    assert!(matches!(PhantomKey::new(vec![1u8; 65]), Err(SealError::BadPhantomKey)));
    assert!(PhantomKey::new(vec![1u8; 64]).is_ok());
    assert!(matches!(Pin::new("123"), Err(SealError::BadPin)));
    assert!(matches!(Pin::new("12a4"), Err(SealError::BadPin)));
    assert!(matches!(Pin::new("1234567890123"), Err(SealError::BadPin)));
    assert!(Pin::new("4831").is_ok());
}
