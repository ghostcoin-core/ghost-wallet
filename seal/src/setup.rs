//! The card setup: turns a blank NTAG 424 DNA into a Ghost card, once, in a
//! controlled room, before anyone gets the card. A card is never set up in
//! the field.
//!
//! In order:
//!
//! 1. Select the NDEF application and read the five key versions.
//! 2. Prove that every key is the one its version names (version 0 the
//!    factory key, the generation 0 version the Seal's key) by
//!    authenticating with it, then authenticate with key 0 and check the UID
//!    the chip itself reports. Nothing changes on the card before this.
//! 3. Set the record file (file 2) to CommMode.Full, the rights of
//!    [`record_file_settings`] and no SDM.
//! 4. Change keys 1 to 4, then key 0 last, to `card_keys(M, uid)` of
//!    generation 0.
//! 5. Zero the record file (both 128-byte frames) and read it back.
//! 6. Verify by a fresh authentication with each of the five new keys, the
//!    file settings in a fresh session, and every key version.
//! 7. Only then record the UID in the registry.
//!
//! A setup cut off at any step is run again from the start and carries on
//! from what the card says: all keys factory is a fresh setup; some keys
//! already the Seal's (and each authenticating as its version says) means
//! finish the rest. A key version that is neither the factory's nor
//! generation 0's, or a key the chip refuses, means the card is refused
//! ([`SealError::UnknownKeys`]): it is never guessed at. A card whose record
//! file already holds a Ghost record is never wiped. A card already in the
//! registry is only verified: a second run changes nothing.

use crate::card_keys::{CardKeys, CardUid, KEY_APPLICATION_MASTER, KEY_RECORD_WRITE, card_keys, key_version};
use crate::error::SealError;
use crate::flows::record_file_settings;
use crate::link::CardLink;
use crate::record::{FRAME_BYTES, HEADER_BYTES, Header, KEY_SLOT_BYTES, KeySlot, RECORD_FILE, RECORD_FILE_BYTES};
use crate::registry::{CardRegistry, RegistryEntry};
use crate::secrets::MasterKey;
use crate::session::Session;
use crate::traits::{CardTransport, SealRandom};

/// The version of every key of a card fresh from the factory.
pub const FACTORY_VERSION: u8 = 0;
/// The value of every key of a card fresh from the factory.
pub const FACTORY_KEY: [u8; 16] = [0u8; 16];
/// The file type byte GetFileSettings answers for a standard data file.
const STANDARD_DATA_FILE: u8 = 0x00;

/// What to set up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupRequest {
    /// The card's UID, as the reader reports it; the chip must report the
    /// same UID inside an authenticated session.
    pub uid: CardUid,
    /// The set-up date recorded in the registry, `YYYY-MM-DD`.
    pub set_up_on: String,
    /// The batch recorded in the registry.
    pub batch: String,
}

/// What a setup run did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupReport {
    /// The card was already registered: it was only verified, and nothing on
    /// it or in the registry changed.
    pub already_registered: bool,
    /// Some keys were already the Seal's when this run started: an earlier
    /// run was cut off and this one finished it.
    pub resumed: bool,
    /// How many keys this run changed.
    pub keys_changed: u8,
    /// Whether this run changed the record file's settings.
    pub settings_changed: bool,
}

/// Sets up card `request.uid` with the keys M derives for it, then records
/// it in `registry`. Run it again after any failure: it carries on from what
/// the card says, or refuses a card it cannot finish.
pub fn set_up_card(
    card: &mut dyn CardTransport,
    master: &MasterKey,
    request: &SetupRequest,
    random: &mut dyn SealRandom,
    registry: &mut dyn CardRegistry,
) -> Result<SetupReport, SealError> {
    let entry = RegistryEntry::new(request.uid, &request.set_up_on, &request.batch)?;
    let uid = request.uid;
    let keys = card_keys(master, &uid);
    let mut link = CardLink::new(card);

    if registry.contains(&uid) {
        verify(&mut link, &uid, &keys, random)?;
        return Ok(SetupReport { already_registered: true, resumed: false, keys_changed: 0, settings_changed: false });
    }

    // 1. What the card says.
    link.select()?;
    let versions = read_versions(&mut link)?;
    let set_up = key_version(0);
    if versions.iter().any(|v| *v != FACTORY_VERSION && *v != set_up) {
        return Err(SealError::UnknownKeys);
    }
    // 2. Every key is the one its version names, before anything changes.
    for key_no in 1..5u8 {
        link.authenticate(key_no, current_key(&versions, &keys, key_no), random)?;
    }
    let master_key = current_key(&versions, &keys, KEY_APPLICATION_MASTER);
    let mut session = authenticated(&mut link, &uid, KEY_APPLICATION_MASTER, master_key, random)?;
    let settings = link.file_settings(&mut session, RECORD_FILE)?;
    if settings.len() < 7 || settings[0] != STANDARD_DATA_FILE || file_size(&settings) < RECORD_FILE_BYTES {
        return Err(SealError::NotSetUp);
    }

    // 3. The record file: CommMode.Full, the Seal's rights, SDM off.
    let intended = record_file_settings();
    let settings_changed = settings[1..4] != intended;
    if settings_changed {
        link.change_file_settings(&mut session, RECORD_FILE, &intended)?;
    }

    // 4. Keys 1 to 4, then key 0 last (which ends the session).
    let mut keys_changed = 0u8;
    for key_no in [1u8, 2, 3, 4, KEY_APPLICATION_MASTER] {
        if versions[usize::from(key_no)] == FACTORY_VERSION {
            link.change_key(&mut session, key_no, keys.key(key_no), &FACTORY_KEY, set_up)?;
            keys_changed += 1;
        }
    }
    drop(session);

    // 5. A blank record, never over a Ghost record already on the card.
    let mut session = authenticated(&mut link, &uid, KEY_RECORD_WRITE, keys.key(KEY_RECORD_WRITE), random)?;
    let header = link.read_frame(&mut session, 0, FRAME_BYTES)?;
    if let Ok(Some(header)) = Header::decode(&header[..HEADER_BYTES], &uid) {
        return Err(SealError::WrongState(header.state));
    }
    let slot = link.read_frame(&mut session, FRAME_BYTES as u32, FRAME_BYTES)?;
    if let Ok(Some(_)) = KeySlot::decode(&slot[..KEY_SLOT_BYTES], &uid) {
        return Err(SealError::FillPending);
    }
    link.write_verified(&mut session, 0, &[0u8; RECORD_FILE_BYTES as usize])?;
    drop(session);

    // 6. Every key, the file settings and the key versions, afresh.
    verify(&mut link, &uid, &keys, random)?;

    // 7. Only now is the card a Ghost card.
    registry.record(&entry)?;
    let resumed = versions.contains(&set_up);
    Ok(SetupReport { already_registered: false, resumed, keys_changed, settings_changed })
}

/// The key `key_no` holds, as its version names it.
fn current_key<'k>(versions: &[u8; 5], keys: &'k CardKeys, key_no: u8) -> &'k [u8; 16] {
    if versions[usize::from(key_no)] == FACTORY_VERSION { &FACTORY_KEY } else { keys.key(key_no) }
}

fn read_versions(link: &mut CardLink<'_>) -> Result<[u8; 5], SealError> {
    let mut versions = [0u8; 5];
    for (key_no, version) in versions.iter_mut().enumerate() {
        *version = link.key_version(key_no as u8)?;
    }
    Ok(versions)
}

fn file_size(settings: &[u8]) -> u32 {
    u32::from_le_bytes([settings[4], settings[5], settings[6], 0])
}

/// Selects, authenticates with `key` and checks the UID the chip reports.
fn authenticated(
    link: &mut CardLink<'_>,
    uid: &CardUid,
    key_no: u8,
    key: &[u8; 16],
    random: &mut dyn SealRandom,
) -> Result<Session, SealError> {
    link.select()?;
    let mut session = link.authenticate(key_no, key, random)?;
    if link.card_uid(&mut session)? != uid.0 {
        return Err(SealError::UnknownKeys);
    }
    Ok(session)
}

/// A fresh authentication with each of the card's five keys of generation 0
/// (each checking the UID), the record file's settings read in a fresh
/// session, and every key version.
fn verify(
    link: &mut CardLink<'_>,
    uid: &CardUid,
    keys: &CardKeys,
    random: &mut dyn SealRandom,
) -> Result<(), SealError> {
    for key_no in 0..5u8 {
        let mut session = authenticated(link, uid, key_no, keys.key(key_no), random)?;
        if key_no == KEY_APPLICATION_MASTER {
            let settings = link.file_settings(&mut session, RECORD_FILE)?;
            if settings.len() < 7
                || settings[0] != STANDARD_DATA_FILE
                || settings[1..4] != record_file_settings()
                || file_size(&settings) < RECORD_FILE_BYTES
            {
                return Err(SealError::NotSetUp);
            }
        }
    }
    link.select()?;
    let versions = read_versions(link)?;
    if versions.iter().any(|v| *v != key_version(0)) {
        return Err(SealError::VerifyFailed);
    }
    Ok(())
}
