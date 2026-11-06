//! AuthenticateEV2First and EV2 secure messaging (CommMode.Full and
//! CommMode.MAC), host side, as the NTAG 424 DNA datasheet and AN12196 frame
//! them.
//!
//! - the session keys: SesAuthENCKey = CMAC(K, SV1), SesAuthMACKey =
//!   CMAC(K, SV2), SV = label || 00 01 00 80 || RndA[0..2] ||
//!   (RndA[2..8] XOR RndB[0..6]) || RndB[6..16] || RndA[8..16], label A5 5A
//!   for SV1 and 5A A5 for SV2;
//! - the command MAC input: Cmd || CmdCtr || TI || CmdHeader || EncData;
//! - the response MAC input: RC || CmdCtr + 1 || TI || RespData;
//! - the IVs: E(SesAuthENCKey, A5 5A || TI || CmdCtr || 0^8) for a command,
//!   E(SesAuthENCKey, 5A A5 || TI || CmdCtr + 1 || 0^8) for a response;
//! - the 8-byte MAC: the CMAC's odd bytes;
//! - CmdCtr, little endian, one more after every command and its answer.
//!
//! Nothing here sends anything: each step builds the raw APDU the phone
//! relays and checks the raw answer that comes back.

use zeroize::Zeroizing;

use crate::apdu::{command, expect_native, split_response, status, wrap_native};
use crate::error::SealError;
use crate::primitives::{
    aes128_cbc_decrypt, aes128_cbc_encrypt, aes128_encrypt_block, cmac_aes128, crc32_new_key, ct_eq, pad,
    rotate_left, truncate_mac, unpad,
};

const ZERO_IV: [u8; 16] = [0u8; 16];
const MAC_BYTES: usize = 8;

/// SV1 (label A5 5A) or SV2 (label 5A A5) of AuthenticateEV2First.
pub fn session_vector(label: [u8; 2], rnd_a: &[u8; 16], rnd_b: &[u8; 16]) -> [u8; 32] {
    let mut sv = [0u8; 32];
    sv[0..2].copy_from_slice(&label);
    sv[2..6].copy_from_slice(&[0x00, 0x01, 0x00, 0x80]);
    sv[6..8].copy_from_slice(&rnd_a[0..2]);
    for i in 0..6 {
        sv[8 + i] = rnd_a[2 + i] ^ rnd_b[i];
    }
    sv[14..24].copy_from_slice(&rnd_b[6..16]);
    sv[24..32].copy_from_slice(&rnd_a[8..16]);
    sv
}

/// The session ENC and MAC keys of an authentication with `key`.
pub fn session_keys(key: &[u8; 16], rnd_a: &[u8; 16], rnd_b: &[u8; 16]) -> (Zeroizing<[u8; 16]>, Zeroizing<[u8; 16]>) {
    let enc = Zeroizing::new(cmac_aes128(key, &session_vector([0xa5, 0x5a], rnd_a, rnd_b)));
    let mac = Zeroizing::new(cmac_aes128(key, &session_vector([0x5a, 0xa5], rnd_a, rnd_b)));
    (enc, mac)
}

/// AuthenticateEV2First part 1 for key `key_no` (no capabilities sent).
pub fn authenticate_first_command(key_no: u8) -> Vec<u8> {
    wrap_native(command::AUTHENTICATE_EV2_FIRST, &[key_no, 0x00]).expect("two bytes fit")
}

/// An AuthenticateEV2First between its two parts: the host's RndA, the
/// chip's RndB and the key, all wiped when dropped.
pub struct PendingAuthentication {
    key_no: u8,
    key: Zeroizing<[u8; 16]>,
    rnd_a: Zeroizing<[u8; 16]>,
    rnd_b: Zeroizing<[u8; 16]>,
}

/// Reads the chip's E(K, RndB) from its answer to part 1 and builds part 2:
/// E(K, RndA || RndB <<< 8), with IV zero.
pub fn authenticate_second_command(
    key_no: u8,
    key: &[u8; 16],
    first_answer: &[u8],
    rnd_a: [u8; 16],
) -> Result<(Vec<u8>, PendingAuthentication), SealError> {
    let encrypted_rnd_b = expect_native(command::AUTHENTICATE_EV2_FIRST, first_answer, status::MORE)?;
    if encrypted_rnd_b.len() != 16 {
        return Err(SealError::Integrity("AuthenticateEV2First sent a wrong-sized challenge"));
    }
    let plain = aes128_cbc_decrypt(key, &ZERO_IV, &encrypted_rnd_b)?;
    let mut rnd_b = Zeroizing::new([0u8; 16]);
    rnd_b.copy_from_slice(&plain);
    let rnd_a = Zeroizing::new(rnd_a);
    let mut message = Zeroizing::new([0u8; 32]);
    message[..16].copy_from_slice(&*rnd_a);
    message[16..].copy_from_slice(&rotate_left(&rnd_b));
    let cryptogram = aes128_cbc_encrypt(key, &ZERO_IV, &*message)?;
    let apdu = wrap_native(command::ADDITIONAL_FRAME, &cryptogram)?;
    Ok((apdu, PendingAuthentication { key_no, key: Zeroizing::new(*key), rnd_a, rnd_b }))
}

impl PendingAuthentication {
    /// Checks the chip's E(K, TI || RndA <<< 8 || PDcap2 || PCDcap2) and
    /// opens the session. Fails unless the chip proved it holds the key.
    pub fn finish(self, second_answer: &[u8]) -> Result<Session, SealError> {
        let response = split_response(second_answer)?;
        if response.sw1 != 0x91 || response.sw2 != status::OK {
            return Err(SealError::Chip {
                command: command::AUTHENTICATE_EV2_FIRST,
                sw1: response.sw1,
                sw2: response.sw2,
            });
        }
        if response.data.len() != 32 {
            return Err(SealError::Integrity("AuthenticateEV2First sent a wrong-sized answer"));
        }
        let plain = aes128_cbc_decrypt(&self.key, &ZERO_IV, &response.data)?;
        if !ct_eq(&plain[4..20], &rotate_left(&self.rnd_a)) {
            return Err(SealError::Integrity("the card did not prove it holds the key"));
        }
        let mut ti = [0u8; 4];
        ti.copy_from_slice(&plain[0..4]);
        let (enc, mac) = session_keys(&self.key, &self.rnd_a, &self.rnd_b);
        Ok(Session { enc, mac, ti, counter: 0, key_no: self.key_no, open: true })
    }
}

/// How a command's answer comes back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerMode {
    /// Data (if any) in plain, then an 8-byte MAC.
    Mac,
    /// Data encrypted under the session ENC key, then an 8-byte MAC.
    Full,
    /// No MAC: the command changed the key the session runs on, which ends
    /// the session.
    NoMac,
}

/// One authenticated session with the card. Its keys are wiped when dropped.
pub struct Session {
    enc: Zeroizing<[u8; 16]>,
    mac: Zeroizing<[u8; 16]>,
    ti: [u8; 4],
    counter: u16,
    key_no: u8,
    open: bool,
}

impl Session {
    /// A session on preset keys and TI, for the AN12196 secure-messaging
    /// vectors, which give the keys instead of a key exchange.
    pub fn from_session_keys(enc: [u8; 16], mac: [u8; 16], ti: [u8; 4], key_no: u8) -> Session {
        Session { enc: Zeroizing::new(enc), mac: Zeroizing::new(mac), ti, counter: 0, key_no, open: true }
    }

    /// The transaction identifier the chip chose.
    pub fn ti(&self) -> [u8; 4] {
        self.ti
    }

    /// CmdCtr.
    pub fn counter(&self) -> u16 {
        self.counter
    }

    /// The key number the session was opened with.
    pub fn key_no(&self) -> u8 {
        self.key_no
    }

    /// Whether the session can still send commands.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// A5 5A || TI || CmdCtr || 0^8 for a command; 5A A5 || TI || CmdCtr || 0^8
    /// for a response (after the counter moved on).
    pub fn iv_input(&self, response: bool) -> [u8; 16] {
        let mut input = [0u8; 16];
        input[0..2].copy_from_slice(if response { &[0x5a, 0xa5] } else { &[0xa5, 0x5a] });
        input[2..6].copy_from_slice(&self.ti);
        input[6..8].copy_from_slice(&self.counter.to_le_bytes());
        input
    }

    /// Cmd || CmdCtr || TI || CmdHeader || EncData, the command's MAC input.
    pub fn command_mac_input(&self, cmd: u8, header: &[u8], encrypted: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(7 + header.len() + encrypted.len());
        input.push(cmd);
        input.extend_from_slice(&self.counter.to_le_bytes());
        input.extend_from_slice(&self.ti);
        input.extend_from_slice(header);
        input.extend_from_slice(encrypted);
        input
    }

    /// RC || CmdCtr || TI || RespData, the response's MAC input (after the
    /// counter moved on).
    pub fn response_mac_input(&self, rc: u8, data: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(7 + data.len());
        input.push(rc);
        input.extend_from_slice(&self.counter.to_le_bytes());
        input.extend_from_slice(&self.ti);
        input.extend_from_slice(data);
        input
    }

    fn ensure_open(&self) -> Result<(), SealError> {
        if self.open { Ok(()) } else { Err(SealError::Integrity("the card session is closed")) }
    }

    /// A command in CommMode.Full: `plaintext` (if any) padded and encrypted,
    /// then the MAC over the header and the ciphertext.
    pub fn full_command(&self, cmd: u8, header: &[u8], plaintext: Option<&[u8]>) -> Result<Vec<u8>, SealError> {
        self.ensure_open()?;
        let encrypted = match plaintext {
            Some(data) => {
                let iv = aes128_encrypt_block(&self.enc, &self.iv_input(false));
                aes128_cbc_encrypt(&self.enc, &iv, &pad(data))?
            }
            None => Vec::new(),
        };
        let mac = truncate_mac(&cmac_aes128(&self.mac, &self.command_mac_input(cmd, header, &encrypted)));
        let mut data = Vec::with_capacity(header.len() + encrypted.len() + MAC_BYTES);
        data.extend_from_slice(header);
        data.extend_from_slice(&encrypted);
        data.extend_from_slice(&mac);
        wrap_native(cmd, &data)
    }

    /// A command in CommMode.MAC: the header in plain, then its MAC.
    pub fn mac_command(&self, cmd: u8, header: &[u8]) -> Result<Vec<u8>, SealError> {
        self.full_command(cmd, header, None)
    }

    /// ChangeKey of key `key_no` to `new_key` (version `version`). For the
    /// key the session runs on the cryptogram is NewKey || KeyVer; for any
    /// other key it is (NewKey XOR OldKey) || KeyVer || CRC32(NewKey).
    pub fn change_key_command(
        &self,
        key_no: u8,
        new_key: &[u8; 16],
        old_key: &[u8; 16],
        version: u8,
    ) -> Result<Vec<u8>, SealError> {
        let mut plain = Zeroizing::new(Vec::with_capacity(21));
        if key_no == self.key_no {
            plain.extend_from_slice(new_key);
            plain.push(version);
        } else {
            for (n, o) in new_key.iter().zip(old_key) {
                plain.push(n ^ o);
            }
            plain.push(version);
            plain.extend_from_slice(&crc32_new_key(new_key));
        }
        self.full_command(command::CHANGE_KEY, &[key_no], Some(&plain[..]))
    }

    /// Checks a command's raw answer and returns its data (decrypted in
    /// [`AnswerMode::Full`]). A refused command or a wrong MAC closes the
    /// session, as the chip drops its authentication then.
    pub fn read_answer(&mut self, cmd: u8, raw: &[u8], mode: AnswerMode) -> Result<Zeroizing<Vec<u8>>, SealError> {
        self.ensure_open()?;
        let response = match split_response(raw) {
            Ok(response) => response,
            Err(error) => {
                self.open = false;
                return Err(error);
            }
        };
        if response.sw1 != 0x91 || response.sw2 != status::OK {
            self.open = false;
            return Err(SealError::Chip { command: cmd, sw1: response.sw1, sw2: response.sw2 });
        }
        self.counter = self.counter.wrapping_add(1);
        if mode == AnswerMode::NoMac {
            self.open = false;
            if !response.data.is_empty() {
                return Err(SealError::Integrity("an answer without a MAC carried data"));
            }
            return Ok(Zeroizing::new(Vec::new()));
        }
        if response.data.len() < MAC_BYTES {
            self.open = false;
            return Err(SealError::Integrity("the answer has no MAC"));
        }
        let (body, mac) = response.data.split_at(response.data.len() - MAC_BYTES);
        let expected = truncate_mac(&cmac_aes128(&self.mac, &self.response_mac_input(response.sw2, body)));
        if !ct_eq(&expected, mac) {
            self.open = false;
            return Err(SealError::Integrity("the answer's MAC is wrong"));
        }
        if mode == AnswerMode::Mac || body.is_empty() {
            return Ok(Zeroizing::new(body.to_vec()));
        }
        if body.len() % 16 != 0 {
            self.open = false;
            return Err(SealError::Integrity("the answer is not whole blocks"));
        }
        let iv = aes128_encrypt_block(&self.enc, &self.iv_input(true));
        let plain = aes128_cbc_decrypt(&self.enc, &iv, body)?;
        unpad(&plain).inspect_err(|_| self.open = false)
    }
}
