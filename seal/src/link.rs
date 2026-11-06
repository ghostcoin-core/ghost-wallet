//! The commands the Seal sends a card, each one APDU out and one answer
//! back over a [`CardTransport`], with every answer checked.

use zeroize::Zeroizing;

use crate::apdu::{command, expect_native, file_range_header, select_ndef_application, split_response, status, wrap_native};
use crate::error::SealError;
use crate::primitives::ct_eq;
use crate::record::{FRAME_BYTES, RECORD_FILE, frames};
use crate::session::{AnswerMode, Session, authenticate_first_command, authenticate_second_command};
use crate::traits::{CardTransport, SealRandom};

/// A card reached through a transport.
pub struct CardLink<'a> {
    card: &'a mut dyn CardTransport,
}

impl<'a> CardLink<'a> {
    /// Drives `card`.
    pub fn new(card: &'a mut dyn CardTransport) -> CardLink<'a> {
        CardLink { card }
    }

    fn send(&mut self, apdu: &[u8]) -> Result<Vec<u8>, SealError> {
        self.card.transceive(apdu).map_err(|_| SealError::Dropped)
    }

    /// ISOSelectFile of the NDEF application (drops any authentication).
    pub fn select(&mut self) -> Result<(), SealError> {
        let raw = self.send(&select_ndef_application())?;
        let response = split_response(&raw)?;
        if response.sw1 != 0x90 || response.sw2 != 0x00 {
            return Err(SealError::Chip { command: 0xa4, sw1: response.sw1, sw2: response.sw2 });
        }
        Ok(())
    }

    /// GetKeyVersion of key `key_no`, outside any authentication.
    pub fn key_version(&mut self, key_no: u8) -> Result<u8, SealError> {
        let raw = self.send(&wrap_native(command::GET_KEY_VERSION, &[key_no])?)?;
        let data = expect_native(command::GET_KEY_VERSION, &raw, status::OK)?;
        match data.as_slice() {
            [version] => Ok(*version),
            _ => Err(SealError::Integrity("GetKeyVersion answered a wrong length")),
        }
    }

    /// AuthenticateEV2First with key `key_no`, RndA drawn from `random`. A key
    /// the chip refuses is [`SealError::UnknownKeys`].
    pub fn authenticate(
        &mut self,
        key_no: u8,
        key: &[u8; 16],
        random: &mut dyn SealRandom,
    ) -> Result<Session, SealError> {
        let first = self.send(&authenticate_first_command(key_no))?;
        let mut rnd_a = Zeroizing::new([0u8; 16]);
        random.fill(&mut rnd_a[..])?;
        let (apdu, pending) = authenticate_second_command(key_no, key, &first, *rnd_a)?;
        let second = self.send(&apdu)?;
        pending.finish(&second).map_err(|error| match error {
            SealError::Chip { sw2: status::AUTHENTICATION_ERROR, .. } => SealError::UnknownKeys,
            SealError::Integrity("the card did not prove it holds the key") => SealError::UnknownKeys,
            other => other,
        })
    }

    /// One command in a session, its answer checked in `mode`.
    pub fn exchange(
        &mut self,
        session: &mut Session,
        cmd: u8,
        header: &[u8],
        plaintext: Option<&[u8]>,
        mode: AnswerMode,
    ) -> Result<Zeroizing<Vec<u8>>, SealError> {
        let apdu = session.full_command(cmd, header, plaintext)?;
        let raw = self.send(&apdu)?;
        session.read_answer(cmd, &raw, mode)
    }

    /// GetCardUID (CommMode.Full): the UID the chip itself reports.
    pub fn card_uid(&mut self, session: &mut Session) -> Result<[u8; 7], SealError> {
        let uid = self.exchange(session, command::GET_CARD_UID, &[], None, AnswerMode::Full)?;
        uid.as_slice().try_into().map_err(|_| SealError::Integrity("GetCardUID answered a wrong length"))
    }

    /// GetFileSettings (CommMode.MAC) of `file`.
    pub fn file_settings(&mut self, session: &mut Session, file: u8) -> Result<Vec<u8>, SealError> {
        Ok(self.exchange(session, command::GET_FILE_SETTINGS, &[file], None, AnswerMode::Mac)?.to_vec())
    }

    /// ChangeFileSettings (CommMode.Full) of `file` to FileOption || AR1 || AR2.
    pub fn change_file_settings(&mut self, session: &mut Session, file: u8, settings: &[u8; 3]) -> Result<(), SealError> {
        let answer = self.exchange(session, command::CHANGE_FILE_SETTINGS, &[file], Some(&settings[..]), AnswerMode::Mac)?;
        if !answer.is_empty() {
            return Err(SealError::Integrity("ChangeFileSettings answered data"));
        }
        Ok(())
    }

    /// ChangeKey of key `key_no`. Changing the key the session runs on ends
    /// the session (its answer has no MAC).
    pub fn change_key(
        &mut self,
        session: &mut Session,
        key_no: u8,
        new_key: &[u8; 16],
        old_key: &[u8; 16],
        version: u8,
    ) -> Result<(), SealError> {
        let apdu = session.change_key_command(key_no, new_key, old_key, version)?;
        let raw = self.send(&apdu)?;
        let mode = if key_no == session.key_no() { AnswerMode::NoMac } else { AnswerMode::Mac };
        let answer = session.read_answer(command::CHANGE_KEY, &raw, mode)?;
        if !answer.is_empty() {
            return Err(SealError::Integrity("ChangeKey answered data"));
        }
        Ok(())
    }

    /// ReadData (CommMode.Full) of one frame of the record file.
    pub fn read_frame(&mut self, session: &mut Session, offset: u32, length: usize) -> Result<Zeroizing<Vec<u8>>, SealError> {
        if length > FRAME_BYTES {
            return Err(SealError::TooLong);
        }
        let header = file_range_header(RECORD_FILE, offset, length as u32)?;
        let data = self.exchange(session, command::READ_DATA, &header, None, AnswerMode::Full)?;
        if data.len() != length {
            return Err(SealError::Integrity("ReadData answered a wrong length"));
        }
        Ok(data)
    }

    /// WriteData (CommMode.Full) of one frame of the record file.
    pub fn write_frame(&mut self, session: &mut Session, offset: u32, data: &[u8]) -> Result<(), SealError> {
        if data.len() > FRAME_BYTES || data.is_empty() {
            return Err(SealError::TooLong);
        }
        let header = file_range_header(RECORD_FILE, offset, data.len() as u32)?;
        let answer = self.exchange(session, command::WRITE_DATA, &header, Some(data), AnswerMode::Mac)?;
        if !answer.is_empty() {
            return Err(SealError::Integrity("WriteData answered data"));
        }
        Ok(())
    }

    /// Writes `data` at `offset` in frames of at most [`FRAME_BYTES`] bytes,
    /// then reads every frame back and compares it.
    pub fn write_verified(&mut self, session: &mut Session, offset: u32, data: &[u8]) -> Result<(), SealError> {
        for (at, frame) in frames(offset, data) {
            self.write_frame(session, at, frame)?;
        }
        for (at, frame) in frames(offset, data) {
            let back = self.read_frame(session, at, frame.len())?;
            if !ct_eq(&back, frame) {
                return Err(SealError::VerifyFailed);
            }
        }
        Ok(())
    }
}
