//! NTAG 424 DNA command framing, from NXP's NTAG 424 DNA datasheet
//! (NT4H2421Gx) and application note AN12196.
//!
//! Native commands go in an ISO/IEC 7816-4 wrapper: CLA 0x90, the command
//! code as INS, P1 = P2 = 0, Lc and the data when there is data, Le = 0. The
//! chip answers with its data, then SW1 = 0x91 and SW2 = its status.

use crate::error::SealError;

/// Native command codes.
pub mod command {
    /// AuthenticateEV2First, part 1.
    pub const AUTHENTICATE_EV2_FIRST: u8 = 0x71;
    /// The next frame of a multi-frame exchange (AuthenticateEV2First part 2).
    pub const ADDITIONAL_FRAME: u8 = 0xaf;
    /// ChangeKey.
    pub const CHANGE_KEY: u8 = 0xc4;
    /// ChangeFileSettings.
    pub const CHANGE_FILE_SETTINGS: u8 = 0x5f;
    /// GetFileSettings.
    pub const GET_FILE_SETTINGS: u8 = 0xf5;
    /// GetKeyVersion.
    pub const GET_KEY_VERSION: u8 = 0x64;
    /// GetCardUID.
    pub const GET_CARD_UID: u8 = 0x51;
    /// ReadData.
    pub const READ_DATA: u8 = 0xad;
    /// WriteData.
    pub const WRITE_DATA: u8 = 0x8d;
}

/// Chip status codes (SW2 after SW1 = 0x91).
pub mod status {
    /// Done.
    pub const OK: u8 = 0x00;
    /// More frames follow.
    pub const MORE: u8 = 0xaf;
    /// A MAC or padding was wrong.
    pub const INTEGRITY_ERROR: u8 = 0x1e;
    /// The command length is wrong.
    pub const LENGTH_ERROR: u8 = 0x7e;
    /// The current authentication does not allow the command.
    pub const PERMISSION_DENIED: u8 = 0x9d;
    /// A parameter is wrong.
    pub const PARAMETER_ERROR: u8 = 0x9e;
    /// The key was refused, or no authentication is open.
    pub const AUTHENTICATION_ERROR: u8 = 0xae;
    /// Outside the file.
    pub const BOUNDARY_ERROR: u8 = 0xbe;
    /// No such key.
    pub const NO_SUCH_KEY: u8 = 0x40;
    /// The chip expected another frame.
    pub const COMMAND_ABORTED: u8 = 0xca;
    /// Unknown command.
    pub const ILLEGAL_COMMAND: u8 = 0x1c;
}

/// The NDEF application's DF name (ISOSelectFile by name).
pub const NDEF_APPLICATION: [u8; 7] = [0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];

/// The largest Lc of a short APDU.
pub const MAX_COMMAND_DATA: usize = 255;

/// ISOSelectFile of the NDEF application by its DF name, as AN12196 does.
/// Selecting drops any authentication.
pub fn select_ndef_application() -> Vec<u8> {
    let mut apdu = vec![0x00, 0xa4, 0x04, 0x00, NDEF_APPLICATION.len() as u8];
    apdu.extend_from_slice(&NDEF_APPLICATION);
    apdu.push(0x00);
    apdu
}

/// A native command in its ISO/IEC 7816-4 wrapper.
pub fn wrap_native(command: u8, data: &[u8]) -> Result<Vec<u8>, SealError> {
    if data.len() > MAX_COMMAND_DATA {
        return Err(SealError::TooLong);
    }
    if data.is_empty() {
        return Ok(vec![0x90, command, 0x00, 0x00, 0x00]);
    }
    let mut apdu = Vec::with_capacity(data.len() + 6);
    apdu.extend_from_slice(&[0x90, command, 0x00, 0x00, data.len() as u8]);
    apdu.extend_from_slice(data);
    apdu.push(0x00);
    Ok(apdu)
}

/// A raw answer split into its data and status words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The data before the status words.
    pub data: Vec<u8>,
    /// SW1.
    pub sw1: u8,
    /// SW2.
    pub sw2: u8,
}

/// Splits the status words from a raw answer.
pub fn split_response(raw: &[u8]) -> Result<Response, SealError> {
    if raw.len() < 2 {
        return Err(SealError::Integrity("the card answered without a status"));
    }
    let (data, sw) = raw.split_at(raw.len() - 2);
    Ok(Response { data: data.to_vec(), sw1: sw[0], sw2: sw[1] })
}

/// The data of a native answer whose status is `expected`.
pub fn expect_native(command: u8, raw: &[u8], expected: u8) -> Result<Vec<u8>, SealError> {
    let response = split_response(raw)?;
    if response.sw1 != 0x91 || response.sw2 != expected {
        return Err(SealError::Chip { command, sw1: response.sw1, sw2: response.sw2 });
    }
    Ok(response.data)
}

/// The FileNo, Offset and Length header of ReadData and WriteData (offset and
/// length little endian, 3 bytes each).
pub fn file_range_header(file_no: u8, offset: u32, length: u32) -> Result<[u8; 7], SealError> {
    if offset > 0x00ff_ffff || length > 0x00ff_ffff {
        return Err(SealError::TooLong);
    }
    let o = offset.to_le_bytes();
    let l = length.to_le_bytes();
    Ok([file_no, o[0], o[1], o[2], l[0], l[1], l[2]])
}

/// The access rights of a file: AR1 = Read&Write << 4 | Change, AR2 =
/// Read << 4 | Write. Each is a key number 0 to 4, 0xE (free) or 0xF (none).
pub fn access_rights(read_write: u8, change: u8, read: u8, write: u8) -> [u8; 2] {
    [(read_write & 0x0f) << 4 | (change & 0x0f), (read & 0x0f) << 4 | (write & 0x0f)]
}

/// The communication mode bits of a file's FileOption.
pub mod comm_mode {
    /// Plain.
    pub const PLAIN: u8 = 0x00;
    /// MACed.
    pub const MAC: u8 = 0x01;
    /// Encrypted and MACed.
    pub const FULL: u8 = 0x03;
}
