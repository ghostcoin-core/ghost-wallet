//! Thin wrappers over the audited RustCrypto crates, in the shapes the card
//! protocol and the Seal use. No cipher, MAC, hash or KDF is written here:
//! AES is `aes`, CBC is `cbc`, CMAC is `cmac`, SHA3-256 is `sha3`, HMAC is
//! `hmac` and HKDF is `hkdf`. The only arithmetic of our own is the chip's
//! CRC32 over a new key (a checksum the datasheet asks for, not a MAC), the
//! ISO/IEC 9797-1 padding and the MAC truncation.

use aes::cipher::{BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit};
use aes::{Aes128, Aes256, Block};
use cmac::{Cmac, Mac};
use hkdf::SimpleHkdf;
use hmac::SimpleHmac;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::error::SealError;

/// AES-128 of one block (ECB, one block only), as the IV of EV2 secure
/// messaging is made.
pub fn aes128_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new_from_slice(key).expect("an AES-128 key is 16 bytes");
    let mut b = Block::from(*block);
    cipher.encrypt_block(&mut b);
    b.into()
}

/// AES-256 of one block (ECB, one block only), for the known-answer tests.
pub fn aes256_encrypt_block(key: &[u8; 32], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes256::new_from_slice(key).expect("an AES-256 key is 32 bytes");
    let mut b = Block::from(*block);
    cipher.encrypt_block(&mut b);
    b.into()
}

macro_rules! cbc_pair {
    ($enc:ident, $dec:ident, $cipher:ty, $key_bytes:expr, $what:expr) => {
        #[doc = concat!("AES-", $what, "-CBC encryption of whole blocks, no padding added.")]
        pub fn $enc(key: &[u8; $key_bytes], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, SealError> {
            if data.len() % 16 != 0 {
                return Err(SealError::Integrity("CBC data is not whole blocks"));
            }
            let mut mode =
                cbc::Encryptor::<$cipher>::new_from_slices(key, iv).expect("key and IV sizes are fixed");
            let mut out = data.to_vec();
            for chunk in out.chunks_exact_mut(16) {
                let mut block = Block::default();
                block.copy_from_slice(chunk);
                mode.encrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
            Ok(out)
        }

        #[doc = concat!("AES-", $what, "-CBC decryption of whole blocks; padding is left on.")]
        pub fn $dec(key: &[u8; $key_bytes], iv: &[u8; 16], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
            if data.len() % 16 != 0 {
                return Err(SealError::Integrity("CBC data is not whole blocks"));
            }
            let mut mode =
                cbc::Decryptor::<$cipher>::new_from_slices(key, iv).expect("key and IV sizes are fixed");
            let mut out = Zeroizing::new(data.to_vec());
            for chunk in out.chunks_exact_mut(16) {
                let mut block = Block::default();
                block.copy_from_slice(chunk);
                mode.decrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
            Ok(out)
        }
    };
}

cbc_pair!(aes128_cbc_encrypt, aes128_cbc_decrypt, Aes128, 16, "128");
cbc_pair!(aes256_cbc_encrypt, aes256_cbc_decrypt, Aes256, 32, "256");

/// AES-128-CMAC (NIST SP 800-38B, RFC 4493).
pub fn cmac_aes128(key: &[u8; 16], message: &[u8]) -> [u8; 16] {
    let mut mac = <Cmac<Aes128> as KeyInit>::new_from_slice(key).expect("an AES-128 key is 16 bytes");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// The 8-byte MAC the chip uses: bytes 1, 3, 5, ... 15 of the 16-byte CMAC.
pub fn truncate_mac(full: &[u8; 16]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = full[2 * i + 1];
    }
    out
}

/// SHA3-256 of the concatenation of `parts`.
pub fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

/// HKDF (RFC 5869) with HMAC-SHA3-256: extract with `salt`, expand `info`
/// into `out`.
pub fn hkdf_sha3_256(salt: &[u8], ikm: &[u8], info: &[&[u8]], out: &mut [u8]) {
    SimpleHkdf::<Sha3_256>::new(Some(salt), ikm)
        .expand_multi_info(info, out)
        .expect("the Seal never asks HKDF for more than 255 blocks");
}

/// HMAC-SHA3-256 of the concatenation of `parts`.
pub fn hmac_sha3_256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <SimpleHmac<Sha3_256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// Compares two byte strings in time that depends only on their lengths.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b) {
        difference |= x ^ y;
    }
    core::hint::black_box(difference) == 0
}

/// ISO/IEC 9797-1 padding method 2: 0x80, then zeros up to a whole block.
/// Always adds at least one byte.
pub fn pad(data: &[u8]) -> Zeroizing<Vec<u8>> {
    let length = (data.len() / 16 + 1) * 16;
    let mut out = Zeroizing::new(vec![0u8; length]);
    out[..data.len()].copy_from_slice(data);
    out[data.len()] = 0x80;
    out
}

/// Removes ISO/IEC 9797-1 method 2 padding.
pub fn unpad(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let mut end = data.len();
    while end > 0 && data[end - 1] == 0x00 {
        end -= 1;
    }
    if end == 0 || data[end - 1] != 0x80 || data.len() - (end - 1) > 16 {
        return Err(SealError::Integrity("the decrypted data is not padded"));
    }
    Ok(Zeroizing::new(data[..end - 1].to_vec()))
}

/// The chip's CRC32 of a new key: the IEEE polynomial, reflected, started at
/// all ones and not inverted at the end (JAMCRC), little endian.
pub fn crc32_new_key(data: &[u8]) -> [u8; 4] {
    let mut crc: u32 = 0xffff_ffff;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    crc.to_le_bytes()
}

/// `block` rotated left by one byte (RndA' and RndB').
pub fn rotate_left(block: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..15].copy_from_slice(&block[1..]);
    out[15] = block[0];
    out
}
