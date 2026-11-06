//! The PC/SC reader transport (feature `pcsc-reader`): a USB NFC reader on
//! the Mac Studio, through the system smart-card service.

use std::ffi::CString;

use ghost_seal::card_keys::CardUid;
use ghost_seal::{CardTransport, Dropped};

/// GET DATA of the card's UID, the PC/SC pseudo-APDU every contactless
/// reader answers itself.
const GET_UID: [u8; 5] = [0xff, 0xca, 0x00, 0x00, 0x00];

/// A card on a PC/SC reader, held exclusively while it is set up.
pub struct PcscCard {
    card: pcsc::Card,
    _context: pcsc::Context,
}

impl PcscCard {
    /// Connects to the card on `reader`, or on the only reader attached. With
    /// no name and more than one reader attached it refuses: a card is set
    /// up with exactly one reader in the room.
    pub fn connect(reader: Option<&str>) -> Result<PcscCard, String> {
        let context =
            pcsc::Context::establish(pcsc::Scope::User).map_err(|e| format!("no smart-card service: {e}"))?;
        let length = context.list_readers_len().map_err(|e| format!("cannot list the readers: {e}"))?;
        let mut buffer = vec![0u8; length];
        let names: Vec<CString> = context
            .list_readers(&mut buffer)
            .map_err(|e| format!("cannot list the readers: {e}"))?
            .map(|name| name.to_owned())
            .collect();
        let chosen = match reader {
            Some(wanted) => names
                .into_iter()
                .find(|name| name.to_str() == Ok(wanted))
                .ok_or_else(|| format!("no reader named {wanted}"))?,
            None if names.len() == 1 => names.into_iter().next().expect("one reader"),
            None => {
                return Err(format!(
                    "{} readers are attached: attach exactly one reader, or name it with --reader",
                    names.len()
                ));
            }
        };
        let card = context
            .connect(&chosen, pcsc::ShareMode::Exclusive, pcsc::Protocols::ANY)
            .map_err(|e| format!("no card on the reader: {e}"))?;
        Ok(PcscCard { card, _context: context })
    }

    /// The UID the reader reports for the card in its field.
    pub fn uid(&mut self) -> Result<CardUid, String> {
        let answer = self.transceive(&GET_UID).map_err(|_| "the card left the reader".to_owned())?;
        match answer.as_slice() {
            [uid @ .., 0x90, 0x00] if uid.len() == 7 => {
                let mut bytes = [0u8; 7];
                bytes.copy_from_slice(uid);
                Ok(CardUid(bytes))
            }
            _ => Err("the reader did not report a 7-byte UID".to_owned()),
        }
    }
}

impl CardTransport for PcscCard {
    fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Dropped> {
        let mut answer = [0u8; pcsc::MAX_BUFFER_SIZE];
        self.card.transmit(apdu, &mut answer).map(|data| data.to_vec()).map_err(|_| Dropped)
    }
}
