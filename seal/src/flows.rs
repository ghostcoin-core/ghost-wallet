//! Fill, Check and Open, as a state machine the card's answers drive.
//!
//! Each flow starts from what the card and the Seal's journal say, so a flow
//! cut off at any step (the card moved away, the phone's relay dropped, the
//! Seal restarted) is run again from the start and carries on from where the
//! card and the journal are.
//!
//! - **Fill** makes a Phantom Key inside the Seal, writes it to the card's key
//!   slot, writes the record (still Empty, waiting for payment), verifies both
//!   by reading them back and returns only the public commit data, the amount
//!   and a signed answer. [`Seal::confirm_fill`] marks the card Sealed only
//!   once the chain check confirms the exact payment.
//! - **Check** authenticates the card with its check key, reads the record
//!   and returns a signed answer with its state and amount. While an Open is
//!   journaled it answers Opening (Opened once released), whatever the card
//!   still says.
//! - **Open** checks the Open PIN (the try is counted on the card before the
//!   PIN is compared), journals the Open (with the key, sealed under M) before
//!   any change to the card, marks the card Opening and binds it to the phone
//!   key, wipes the key slot, moves all five card keys to the next
//!   generation, verifies that by a fresh authentication with each new key,
//!   writes the card Opened and only then releases the key, encrypted with
//!   ML-KEM-768 to the phone key bound when the Open started.

use zeroize::Zeroizing;

use crate::answer::{AnswerBody, AnswerKind, AnswerSigner, MEASUREMENT_BYTES, SignedAnswer};
use crate::apdu::{access_rights, comm_mode};
use crate::card_keys::{
    CardKeys, CardUid, KEY_APPLICATION_MASTER, KEY_CHECK_READ, KEY_RECORD_WRITE, card_keys_at, generation_of_version,
    key_version,
};
use crate::error::SealError;
use crate::journal::{EntryKind, FillEntry, Journal, OpenEntry, OpenPhase};
use crate::link::CardLink;
use crate::primitives::{ct_eq, hkdf_sha3_256, hmac_sha3_256, sha3_256};
use crate::record::{
    CardState, HEADER_BYTES, HEADER_OFFSET, Header, KEY_SLOT_BYTES, KEY_SLOT_OFFSET, KeySlot, PIN_TRIES, RECORD_FILE,
    RECORD_FILE_BYTES,
};
use crate::release::{PhoneKey, phone_key_hash, seal_release};
use crate::secrets::{MasterKey, Pin};
use crate::session::Session;
use crate::traits::{CardTransport, ChainCheck, Clock, CoinClaim, PaymentVerdict, PhantomKeyMaker, SealRandom};

/// How long a signed answer is good for, by default.
pub const ANSWER_LIFETIME_SECS: u64 = 120;
/// The HKDF label of the Open PIN hash key.
pub const PIN_LABEL: &[u8] = b"ghost-seal/v1/open-pin";
/// The highest generation a card reaches: key versions run 1 to 255.
pub const MAX_GENERATION: u32 = 254;

/// The record file's settings: CommMode.Full; key 2 reads and writes, key 1
/// reads, key 0 changes the settings.
pub fn record_file_settings() -> [u8; 3] {
    let rights = access_rights(KEY_RECORD_WRITE, KEY_APPLICATION_MASTER, KEY_CHECK_READ, KEY_RECORD_WRITE);
    [comm_mode::FULL, rights[0], rights[1]]
}

/// The Open PIN status every answer carries, so a receiver sees before
/// accepting whether redeeming the card needs a PIN it was not given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PinStatus {
    required: bool,
    tries_left: u8,
}

impl PinStatus {
    const NONE: PinStatus = PinStatus { required: false, tries_left: 0 };

    fn of(header: &Header) -> PinStatus {
        match header.pin_hash {
            Some(_) => PinStatus { required: true, tries_left: header.pin_tries_left },
            None => PinStatus::NONE,
        }
    }
}

/// A Sealed card whose Open PIN tries are used up can never be opened: no
/// answer may call it Sealed.
fn refuse_pin_locked(header: &Header) -> Result<(), SealError> {
    if header.state == CardState::Sealed && header.pin_hash.is_some() && header.pin_tries_left == 0 {
        return Err(SealError::PinLocked);
    }
    Ok(())
}

/// What the Seal is configured with besides its traits.
#[derive(Debug, Clone)]
pub struct SealConfig {
    /// The measurement of the Seal's code, put in every answer.
    pub measurement: [u8; MEASUREMENT_BYTES],
    /// How long an answer is good for, in seconds.
    pub answer_lifetime_secs: u64,
}

/// A Check, or the confirmation of a Fill.
#[derive(Debug, Clone)]
pub struct CheckRequest {
    /// The card.
    pub uid: CardUid,
    /// The phone's random challenge.
    pub challenge: [u8; 32],
}

/// A Fill.
pub struct FillRequest {
    /// The card.
    pub uid: CardUid,
    /// The phone's random challenge.
    pub challenge: [u8; 32],
    /// The coin's amount in wei.
    pub amount_wei: u128,
    /// An Open PIN to set, if any.
    pub pin: Option<Pin>,
}

/// What a Fill hands back: public values only.
#[derive(Debug, Clone)]
pub struct FillOutcome {
    /// The coin's commit data, for the Vanish that pays it.
    pub commit_data: Vec<u8>,
    /// The amount the Vanish must pay, in wei.
    pub amount_wei: u128,
    /// The signed answer (state Empty until the payment is confirmed).
    pub answer: SignedAnswer,
}

/// An Open.
pub struct OpenRequest {
    /// The card.
    pub uid: CardUid,
    /// The phone's random challenge.
    pub challenge: [u8; 32],
    /// The phone's ML-KEM-768 encapsulation key the key is released to.
    pub phone_key: Vec<u8>,
    /// The Open PIN, when the card has one.
    pub pin: Option<Pin>,
}

/// What an Open hands back.
#[derive(Debug, Clone)]
pub struct OpenOutcome {
    /// The Phantom Key, encrypted to the phone key.
    pub release: Vec<u8>,
    /// The signed answer (state Opened, binding the release).
    pub answer: SignedAnswer,
}

/// The Seal.
pub struct Seal {
    master: MasterKey,
    signer: AnswerSigner,
    config: SealConfig,
    random: Box<dyn SealRandom>,
    clock: Box<dyn Clock>,
    journal: Box<dyn Journal>,
}

impl Seal {
    /// A Seal holding `master`.
    pub fn new(
        master: MasterKey,
        config: SealConfig,
        random: Box<dyn SealRandom>,
        clock: Box<dyn Clock>,
        journal: Box<dyn Journal>,
    ) -> Seal {
        let signer = AnswerSigner::derive(&master);
        Seal { master, signer, config, random, clock, journal }
    }

    /// The Seal's encoded ML-DSA-65 public key, which phones pin.
    pub fn answer_verifying_key(&self) -> Vec<u8> {
        self.signer.verifying_key()
    }

    fn keys(&self, uid: &CardUid, generation: u32) -> CardKeys {
        card_keys_at(&self.master, uid, generation)
    }

    fn pin_hash(&self, uid: &CardUid, generation: u32, pin: &Pin) -> [u8; 16] {
        let mut key = Zeroizing::new([0u8; 32]);
        hkdf_sha3_256(PIN_LABEL, self.master.derive_from(), &[PIN_LABEL, &uid.0, &generation.to_be_bytes()], &mut key[..]);
        let full = hmac_sha3_256(&key[..], &[PIN_LABEL, pin.digits()]);
        let mut out = [0u8; 16];
        out.copy_from_slice(&full[..16]);
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn answer(
        &self,
        kind: AnswerKind,
        challenge: &[u8; 32],
        uid: &CardUid,
        generation: u32,
        coin: [u8; 32],
        state: CardState,
        amount_wei: u128,
        binding: [u8; 32],
        pin: PinStatus,
    ) -> Result<SignedAnswer, SealError> {
        self.signer.sign(AnswerBody {
            pin_required: pin.required,
            pin_tries_left: pin.tries_left,
            kind,
            challenge: *challenge,
            uid: *uid,
            generation,
            coin,
            measurement: self.config.measurement,
            state,
            amount_wei,
            expires_at: self.clock.now_unix().saturating_add(self.config.answer_lifetime_secs),
            binding,
        })
    }

    fn load_entry(&self, uid: &CardUid) -> Result<Option<OpenEntry>, SealError> {
        match self.journal.load(uid, EntryKind::Open) {
            None => Ok(None),
            Some(sealed) => OpenEntry::unseal(&self.master, uid, &sealed).map(Some),
        }
    }

    fn save_entry(&mut self, uid: &CardUid, entry: &OpenEntry) -> Result<(), SealError> {
        let sealed = entry.seal(&self.master, uid, self.random.as_mut())?;
        self.journal.save(uid, EntryKind::Open, sealed)
    }

    fn load_fill(&self, uid: &CardUid) -> Result<Option<FillEntry>, SealError> {
        match self.journal.load(uid, EntryKind::Fill) {
            None => Ok(None),
            Some(sealed) => FillEntry::unseal(&self.master, uid, &sealed).map(Some),
        }
    }

    fn save_fill(&mut self, uid: &CardUid, entry: &FillEntry) -> Result<(), SealError> {
        let sealed = entry.seal(&self.master, uid, self.random.as_mut())?;
        self.journal.save(uid, EntryKind::Fill, sealed)
    }

    /// Selects the application, authenticates with `key` and checks that
    /// the chip itself reports `uid`.
    fn session(
        &mut self,
        link: &mut CardLink<'_>,
        uid: &CardUid,
        key_no: u8,
        key: &[u8; 16],
    ) -> Result<Session, SealError> {
        link.select()?;
        let mut session = link.authenticate(key_no, key, self.random.as_mut())?;
        if link.card_uid(&mut session)? != uid.0 {
            return Err(SealError::UnknownKeys);
        }
        Ok(session)
    }

    fn session_at(
        &mut self,
        link: &mut CardLink<'_>,
        uid: &CardUid,
        key_no: u8,
        generation: u32,
    ) -> Result<Session, SealError> {
        let keys = self.keys(uid, generation);
        self.session(link, uid, key_no, keys.key(key_no))
    }

    /// The generation key `key_no` is at, from its key version.
    fn generation_of(link: &mut CardLink<'_>, key_no: u8) -> Result<u32, SealError> {
        link.select()?;
        let generation = generation_of_version(link.key_version(key_no)?).ok_or(SealError::NotSetUp)?;
        if generation > MAX_GENERATION {
            return Err(SealError::NotSetUp);
        }
        Ok(generation)
    }

    fn read_header(
        link: &mut CardLink<'_>,
        session: &mut Session,
        uid: &CardUid,
        generation: u32,
    ) -> Result<Header, SealError> {
        let bytes = link.read_frame(session, HEADER_OFFSET, HEADER_BYTES)?;
        Ok(Header::decode(&bytes, uid)?.unwrap_or_else(|| Header::blank(generation)))
    }

    fn read_slot(
        link: &mut CardLink<'_>,
        session: &mut Session,
        uid: &CardUid,
        generation: u32,
    ) -> Result<KeySlot, SealError> {
        let bytes = link.read_frame(session, KEY_SLOT_OFFSET, KEY_SLOT_BYTES)?;
        Ok(KeySlot::decode(&bytes, uid)?.unwrap_or_else(|| KeySlot::empty(generation)))
    }

    fn write_header(
        link: &mut CardLink<'_>,
        session: &mut Session,
        uid: &CardUid,
        header: &Header,
    ) -> Result<(), SealError> {
        link.write_verified(session, HEADER_OFFSET, &header.encode(uid))
    }

    fn write_slot(link: &mut CardLink<'_>, session: &mut Session, uid: &CardUid, slot: &KeySlot) -> Result<(), SealError> {
        link.write_verified(session, KEY_SLOT_OFFSET, &slot.encode(uid))
    }

    // -----------------------------------------------------------------------
    // Check

    /// Check: authenticates the card, reads its record and answers its state
    /// and amount, signed over the phone's challenge. Never reads the key.
    ///
    /// A Sealed card whose Open PIN has no tries left can never be opened, so
    /// it is never certified: Check refuses it with [`SealError::PinLocked`].
    /// A journaled Open still comes first (Opening or Opened).
    pub fn check(&mut self, card: &mut dyn CardTransport, request: &CheckRequest) -> Result<SignedAnswer, SealError> {
        let uid = request.uid;
        let pending = self.load_entry(&uid)?;
        let mut link = CardLink::new(card);
        let generation = Self::generation_of(&mut link, KEY_CHECK_READ)?;
        let mut session = self.session_at(&mut link, &uid, KEY_CHECK_READ, generation)?;
        let header = Self::read_header(&mut link, &mut session, &uid, generation)?;
        let (state, coin, amount) = match &pending {
            Some(entry) => {
                let state = if entry.phase == OpenPhase::Finished { CardState::Opened } else { CardState::Opening };
                (state, entry.coin, entry.amount_wei)
            }
            None if header.state == CardState::Empty => (CardState::Empty, [0u8; 32], 0),
            None => {
                refuse_pin_locked(&header)?;
                (header.state, header.coin, header.amount_wei)
            }
        };
        // A pending or finished Open is bound to its phone key: no PIN stands
        // between it and the key any more.
        let pin = if pending.is_some() { PinStatus::NONE } else { PinStatus::of(&header) };
        self.answer(AnswerKind::Check, &request.challenge, &uid, header.generation, coin, state, amount, [0u8; 32], pin)
    }

    // -----------------------------------------------------------------------
    // Fill

    /// Fill: makes a Phantom Key inside the Seal, writes it and the record to
    /// an empty card, verifies both by reading them back, wipes the key from
    /// memory and returns only the public commit data and the amount. The
    /// card stays Empty until [`Seal::confirm_fill`].
    pub fn fill(
        &mut self,
        card: &mut dyn CardTransport,
        request: &FillRequest,
        maker: &mut dyn PhantomKeyMaker,
    ) -> Result<FillOutcome, SealError> {
        if request.amount_wei == 0 {
            return Err(SealError::BadAmount);
        }
        let uid = request.uid;
        if self.load_entry(&uid)?.is_some() {
            return Err(SealError::WrongState(CardState::Opening));
        }
        let mut link = CardLink::new(card);
        let generation = Self::generation_of(&mut link, KEY_RECORD_WRITE)?;
        if Self::generation_of(&mut link, KEY_APPLICATION_MASTER)? != generation {
            return Err(SealError::NotSetUp);
        }
        let mut session = self.session_at(&mut link, &uid, KEY_RECORD_WRITE, generation)?;
        let settings = link.file_settings(&mut session, RECORD_FILE)?;
        let size = settings.get(4..7).map(|s| u32::from_le_bytes([s[0], s[1], s[2], 0]));
        if settings.len() < 7
            || settings[0] != 0x00
            || settings[1..4] != record_file_settings()
            || size.is_none_or(|size| size < RECORD_FILE_BYTES)
        {
            return Err(SealError::NotSetUp);
        }
        let header = Self::read_header(&mut link, &mut session, &uid, generation)?;
        if header.state != CardState::Empty {
            return Err(SealError::WrongState(header.state));
        }
        let pin_hash = request.pin.as_ref().map(|pin| self.pin_hash(&uid, generation, pin));
        if header.key_present {
            // A Fill whose answer never arrived: hand back the same coin, never
            // a new key, so a Vanish already sent for it is not lost.
            if let Some(pending) = self.load_fill(&uid)? {
                if pending.coin == header.coin
                    && pending.generation == generation
                    && pending.amount_wei == header.amount_wei
                    && request.amount_wei == header.amount_wei
                    && pin_hash == header.pin_hash
                {
                    let answer = self.answer(
                        AnswerKind::Fill,
                        &request.challenge,
                        &uid,
                        generation,
                        pending.coin,
                        CardState::Empty,
                        pending.amount_wei,
                        pending.coin,
                        PinStatus::of(&header),
                    )?;
                    return Ok(FillOutcome { commit_data: pending.commit_data, amount_wei: pending.amount_wei, answer });
                }
            }
            return Err(SealError::FillPending);
        }

        let made = maker.make(request.amount_wei, self.random.as_mut())?;
        if made.commit_data.is_empty() {
            return Err(SealError::KeyMaker("no commit data"));
        }
        let coin = sha3_256(&[&made.commit_data]);
        // Journal the coin before the card changes.
        self.save_fill(
            &uid,
            &FillEntry { generation, coin, amount_wei: request.amount_wei, commit_data: made.commit_data.clone() },
        )?;
        let slot = KeySlot { generation, coin, key: Some(made.key) };
        Self::write_slot(&mut link, &mut session, &uid, &slot)?;
        // The key is on the card and verified; the Seal keeps no copy.
        drop(slot);

        let filled = Header {
            state: CardState::Empty,
            key_present: true,
            pin_tries_left: if pin_hash.is_some() { PIN_TRIES } else { 0 },
            pin_hash,
            generation,
            amount_wei: request.amount_wei,
            coin,
            phone_key_hash: [0u8; 32],
        };
        Self::write_header(&mut link, &mut session, &uid, &filled)?;
        let answer = self.answer(
            AnswerKind::Fill,
            &request.challenge,
            &uid,
            generation,
            coin,
            CardState::Empty,
            request.amount_wei,
            coin,
            PinStatus::of(&filled),
        )?;
        Ok(FillOutcome { commit_data: made.commit_data, amount_wei: request.amount_wei, answer })
    }

    /// Marks a filled card Sealed once `chain` confirms that its coin is paid
    /// exactly. A card already Sealed is answered as such.
    pub fn confirm_fill(
        &mut self,
        card: &mut dyn CardTransport,
        request: &CheckRequest,
        chain: &dyn ChainCheck,
    ) -> Result<SignedAnswer, SealError> {
        let uid = request.uid;
        if self.load_entry(&uid)?.is_some() {
            return Err(SealError::WrongState(CardState::Opening));
        }
        let mut link = CardLink::new(card);
        let generation = Self::generation_of(&mut link, KEY_RECORD_WRITE)?;
        let mut session = self.session_at(&mut link, &uid, KEY_RECORD_WRITE, generation)?;
        let header = Self::read_header(&mut link, &mut session, &uid, generation)?;
        match header.state {
            CardState::Sealed => {
                refuse_pin_locked(&header)?;
                return self.answer(
                    AnswerKind::Fill,
                    &request.challenge,
                    &uid,
                    header.generation,
                    header.coin,
                    CardState::Sealed,
                    header.amount_wei,
                    header.coin,
                    PinStatus::of(&header),
                );
            }
            CardState::Empty if header.key_present => {}
            state => return Err(SealError::WrongState(state)),
        }
        let slot = Self::read_slot(&mut link, &mut session, &uid, generation)?;
        if slot.key.is_none() || slot.coin != header.coin || slot.generation != header.generation {
            return Err(SealError::Integrity("the key slot does not match the record"));
        }
        drop(slot);
        let claim = CoinClaim { uid, coin: header.coin, amount_wei: header.amount_wei };
        match chain.confirm_payment(&claim) {
            PaymentVerdict::Paid => {}
            PaymentVerdict::NotYet => return Err(SealError::NotPaid),
            PaymentVerdict::Mismatch => return Err(SealError::PaymentMismatch),
        }
        let sealed = Header { state: CardState::Sealed, ..header };
        Self::write_header(&mut link, &mut session, &uid, &sealed)?;
        self.answer(
            AnswerKind::Fill,
            &request.challenge,
            &uid,
            sealed.generation,
            sealed.coin,
            CardState::Sealed,
            sealed.amount_wei,
            sealed.coin,
            PinStatus::of(&sealed),
        )
    }

    // -----------------------------------------------------------------------
    // Open

    /// Open: journals the Open, wipes the key slot, rotates all card keys,
    /// verifies them by fresh authentication and only then releases the key,
    /// encrypted to the phone key bound when the Open started. Run it again
    /// after any failure: it carries on where the card and the journal are.
    pub fn open(&mut self, card: &mut dyn CardTransport, request: &OpenRequest) -> Result<OpenOutcome, SealError> {
        let uid = request.uid;
        let phone = PhoneKey::parse(&request.phone_key)?;
        let mut link = CardLink::new(card);
        let entry = match self.load_entry(&uid)? {
            Some(entry) => {
                if !ct_eq(&phone_key_hash(&entry.phone_key), &phone_key_hash(&request.phone_key)) {
                    return Err(SealError::PhoneKeyMismatch);
                }
                entry
            }
            None => self.begin_open(&mut link, request)?,
        };
        self.run_open(&mut link, &uid, entry, &phone, &request.challenge)
    }

    /// Checks the PIN and journals the Open. Changes nothing on the card but
    /// the PIN try counter.
    fn begin_open(&mut self, link: &mut CardLink<'_>, request: &OpenRequest) -> Result<OpenEntry, SealError> {
        let uid = request.uid;
        let generation = Self::generation_of(link, KEY_RECORD_WRITE)?;
        if generation >= MAX_GENERATION {
            return Err(SealError::NotSetUp);
        }
        let mut session = self.session_at(link, &uid, KEY_RECORD_WRITE, generation)?;
        let mut header = Self::read_header(link, &mut session, &uid, generation)?;
        match header.state {
            CardState::Sealed => {}
            CardState::Opening => return Err(SealError::JournalMissing),
            state => return Err(SealError::WrongState(state)),
        }
        if header.generation != generation {
            return Err(SealError::Integrity("the record is of another generation"));
        }
        if let Some(stored) = header.pin_hash {
            let pin = request.pin.as_ref().ok_or(SealError::PinRequired)?;
            if header.pin_tries_left == 0 {
                return Err(SealError::PinLocked);
            }
            // The try is counted on the card before the PIN is compared, so
            // cutting the connection never buys a free guess.
            header.pin_tries_left -= 1;
            Self::write_header(link, &mut session, &uid, &header)?;
            if !ct_eq(&self.pin_hash(&uid, generation, pin), &stored) {
                return Err(SealError::WrongPin { tries_left: header.pin_tries_left });
            }
        }
        let slot = Self::read_slot(link, &mut session, &uid, generation)?;
        let key = match slot.key {
            Some(key) if slot.coin == header.coin && slot.generation == generation => key,
            _ => return Err(SealError::Integrity("the key slot does not match the record")),
        };
        let entry = OpenEntry {
            phase: OpenPhase::Started,
            generation,
            coin: header.coin,
            amount_wei: header.amount_wei,
            phone_key: request.phone_key.clone(),
            key,
        };
        // Journal first: nothing about the Open changes the card before this.
        self.save_entry(&uid, &entry)?;
        Ok(entry)
    }

    fn run_open(
        &mut self,
        link: &mut CardLink<'_>,
        uid: &CardUid,
        mut entry: OpenEntry,
        phone: &PhoneKey,
        challenge: &[u8; 32],
    ) -> Result<OpenOutcome, SealError> {
        loop {
            let next = match entry.phase {
                OpenPhase::Started => {
                    self.mark_opening(link, uid, &entry)?;
                    OpenPhase::CardMarked
                }
                OpenPhase::CardMarked => {
                    self.wipe_slot(link, uid, &entry)?;
                    OpenPhase::SlotWiped
                }
                OpenPhase::SlotWiped => {
                    self.rotate_keys(link, uid, entry.generation)?;
                    OpenPhase::KeysRotated
                }
                OpenPhase::KeysRotated => {
                    self.finish_opened(link, uid, &entry)?;
                    OpenPhase::Finished
                }
                OpenPhase::Finished => break,
            };
            entry.phase = next;
            self.save_entry(uid, &entry)?;
        }
        let generation = entry.generation + 1;
        let release = seal_release(phone, uid, generation, &entry.key, self.random.as_mut())?;
        drop(entry.key);
        let binding = sha3_256(&[&release]);
        let answer = self.answer(
            AnswerKind::Open,
            challenge,
            uid,
            generation,
            entry.coin,
            CardState::Opened,
            entry.amount_wei,
            binding,
            PinStatus::NONE,
        )?;
        Ok(OpenOutcome { release, answer })
    }

    /// Marks the card Opening, bound to the phone key.
    fn mark_opening(&mut self, link: &mut CardLink<'_>, uid: &CardUid, entry: &OpenEntry) -> Result<(), SealError> {
        let mut session = self.session_at(link, uid, KEY_RECORD_WRITE, entry.generation)?;
        let mut header = Self::read_header(link, &mut session, uid, entry.generation)?;
        let bound = phone_key_hash(&entry.phone_key);
        match header.state {
            CardState::Opening if header.phone_key_hash == bound => return Ok(()),
            CardState::Sealed => {}
            state => return Err(SealError::WrongState(state)),
        }
        header.state = CardState::Opening;
        header.phone_key_hash = bound;
        if header.pin_hash.is_some() {
            header.pin_tries_left = PIN_TRIES;
        }
        Self::write_header(link, &mut session, uid, &header)
    }

    /// Overwrites the key slot with an empty one and reads it back.
    fn wipe_slot(&mut self, link: &mut CardLink<'_>, uid: &CardUid, entry: &OpenEntry) -> Result<(), SealError> {
        let mut session = self.session_at(link, uid, KEY_RECORD_WRITE, entry.generation)?;
        let slot = Self::read_slot(link, &mut session, uid, entry.generation)?;
        if slot.key.is_none() {
            return Ok(());
        }
        drop(slot);
        Self::write_slot(link, &mut session, uid, &KeySlot::empty(entry.generation))
    }

    /// Moves all five card keys from `generation` to the next one: keys 1 to
    /// 4 first, the application master key last. A key already moved (an
    /// earlier try cut off) is left alone. Ends with every key version read
    /// back.
    fn rotate_keys(&mut self, link: &mut CardLink<'_>, uid: &CardUid, generation: u32) -> Result<(), SealError> {
        let old = self.keys(uid, generation);
        let new = self.keys(uid, generation + 1);
        let (old_version, new_version) = (key_version(generation), key_version(generation + 1));
        link.select()?;
        let mut versions = [0u8; 5];
        for (key_no, version) in versions.iter_mut().enumerate() {
            *version = link.key_version(key_no as u8)?;
            if *version != old_version && *version != new_version {
                return Err(SealError::UnknownKeys);
            }
        }
        if versions.iter().any(|v| *v == old_version) {
            let master_moved = versions[0] == new_version;
            let master = if master_moved { new.key(KEY_APPLICATION_MASTER) } else { old.key(KEY_APPLICATION_MASTER) };
            let mut session = self.session(link, uid, KEY_APPLICATION_MASTER, master)?;
            for key_no in 1..5u8 {
                if versions[usize::from(key_no)] == old_version {
                    link.change_key(&mut session, key_no, new.key(key_no), old.key(key_no), new_version)?;
                }
            }
            if !master_moved {
                link.change_key(
                    &mut session,
                    KEY_APPLICATION_MASTER,
                    new.key(KEY_APPLICATION_MASTER),
                    old.key(KEY_APPLICATION_MASTER),
                    new_version,
                )?;
            }
        }
        link.select()?;
        for key_no in 0..5u8 {
            if link.key_version(key_no)? != new_version {
                return Err(SealError::VerifyFailed);
            }
        }
        Ok(())
    }

    /// Authenticates afresh with each of the five new keys, then writes the
    /// card Opened at the new generation and reads it back.
    fn finish_opened(&mut self, link: &mut CardLink<'_>, uid: &CardUid, entry: &OpenEntry) -> Result<(), SealError> {
        let generation = entry.generation + 1;
        for key_no in 0..5u8 {
            self.session_at(link, uid, key_no, generation)?;
        }
        let mut session = self.session_at(link, uid, KEY_RECORD_WRITE, generation)?;
        let header = Self::read_header(link, &mut session, uid, generation)?;
        let slot = Self::read_slot(link, &mut session, uid, generation)?;
        if slot.key.is_some() {
            return Err(SealError::VerifyFailed);
        }
        let bound = phone_key_hash(&entry.phone_key);
        if header.state == CardState::Opened && header.generation == generation && header.phone_key_hash == bound {
            return Ok(());
        }
        if header.state != CardState::Opening || header.phone_key_hash != bound {
            return Err(SealError::WrongState(header.state));
        }
        let opened = Header {
            state: CardState::Opened,
            key_present: false,
            pin_hash: None,
            pin_tries_left: 0,
            generation,
            amount_wei: header.amount_wei,
            coin: header.coin,
            phone_key_hash: bound,
        };
        Self::write_header(link, &mut session, uid, &opened)
    }
}
