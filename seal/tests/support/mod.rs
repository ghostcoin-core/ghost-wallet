//! Test doubles: an NTAG 424 DNA simulated from the datasheet (select,
//! GetKeyVersion, AuthenticateEV2First, GetCardUID, GetFileSettings,
//! ChangeFileSettings, ChangeKey, ReadData, WriteData), which checks every
//! MAC and enforces the record file's access rights; and stand-ins for the
//! Seal's random source, clock, the maker of its Phantom Keys, chain check,
//! chain status check and card registry. Fake chain nodes are in `nodes`; a fake node
//! speaking JSON-RPC over TLS is in `rpc_node` (included by the tests that
//! need it).
#![allow(dead_code)]

pub mod nodes;
pub mod previous_log;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use ghost_seal::journal::{EntryKind, Journal};
use ghost_seal::{Finished, FlowStep, Relay, RelayError};

use ghost_seal::card_keys::{card_keys, key_version};
use ghost_seal::flows::record_file_settings;
use ghost_seal::primitives::{
    aes128_cbc_decrypt, aes128_cbc_encrypt, aes128_encrypt_block, cmac_aes128, crc32_new_key, ct_eq, pad, rotate_left,
    sha3_256, truncate_mac, unpad,
};
use ghost_seal::session::session_keys;
use ghost_seal::{
    CardRegistry, CardTransport, CardUid, ChainCheck, Clock, CoinClaim, CoinQuery, CoinStatus, CoinStatusCheck,
    Dropped, MadeKey, MasterKey, MemoryJournal, MemoryRegistry, PaymentVerdict, PhantomKey, PhantomKeyMaker,
    PhoneSecret, RegistryEntry, Seal, SealConfig, SealError, SealRandom,
};

pub const UID: CardUid = CardUid([0x04, 0x51, 0x8d, 0xfa, 0xa9, 0x61, 0x80]);
pub const MEASUREMENT: [u8; 48] = [0x5e; 48];
pub const START_TIME: u64 = 1_800_000_000;

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

pub fn unhex(text: &str) -> Vec<u8> {
    let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(clean.len() % 2 == 0, "odd hex");
    (0..clean.len() / 2).map(|i| u8::from_str_radix(&clean[2 * i..2 * i + 2], 16).expect("hex")).collect()
}

pub fn array<const N: usize>(text: &str) -> [u8; N] {
    unhex(text).try_into().expect("length")
}

/// A test master key (a fixed pattern: test only).
pub fn master() -> MasterKey {
    let mut bytes = master_bytes();
    MasterKey::take(&mut bytes)
}

/// The bytes of [`master`]: what the previous release's log writer
/// (`previous_log`) derives its keys from.
pub fn master_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = 0x40 + i as u8;
    }
    bytes
}

/// A deterministic random source: SHA3-256 of a label and a counter (test only).
#[derive(Clone)]
pub struct TestRandom {
    label: u64,
    counter: Rc<Cell<u64>>,
}

impl TestRandom {
    pub fn new(label: u64) -> TestRandom {
        TestRandom { label, counter: Rc::new(Cell::new(0)) }
    }
}

impl SealRandom for TestRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), SealError> {
        for chunk in out.chunks_mut(32) {
            let n = self.counter.get();
            self.counter.set(n + 1);
            let block = sha3_256(&[b"test random", &self.label.to_be_bytes(), &n.to_be_bytes()]);
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        Ok(())
    }
}

/// A clock the test moves.
#[derive(Clone)]
pub struct TestClock(pub Rc<Cell<u64>>);

impl TestClock {
    pub fn new() -> TestClock {
        TestClock(Rc::new(Cell::new(START_TIME)))
    }

    pub fn advance(&self, seconds: u64) {
        self.0.set(self.0.get() + seconds);
    }
}

impl Clock for TestClock {
    fn now_unix(&self) -> u64 {
        self.0.get()
    }
}

/// A Phantom Key maker standing in for the wallet core: a 32-byte key from the
/// Seal's random source and 430 bytes of commit data made from a hash of it.
/// It keeps a copy of every key it made, so a test can check the key an Open
/// releases.
#[derive(Clone, Default)]
pub struct StubMaker {
    /// Every key made, with its commit data.
    pub made: Rc<RefCell<Vec<(Vec<u8>, Vec<u8>)>>>,
}

impl StubMaker {
    /// The key whose coin has `commit_data`.
    pub fn key_for(&self, commit_data: &[u8]) -> Vec<u8> {
        self.made.borrow().iter().find(|(_, data)| data == commit_data).expect("a key for this coin").0.clone()
    }
}

impl PhantomKeyMaker for StubMaker {
    fn make(&mut self, amount_wei: u128, random: &mut dyn SealRandom) -> Result<MadeKey, SealError> {
        let mut key = vec![0u8; 32];
        random.fill(&mut key)?;
        let mut commit_data = Vec::with_capacity(430);
        commit_data.extend_from_slice(&[0x00, 0x03]);
        let mut n = 0u32;
        while commit_data.len() < 430 {
            let block = sha3_256(&[b"stub commit", &key, &amount_wei.to_be_bytes(), &n.to_be_bytes()]);
            commit_data.extend_from_slice(&block);
            n += 1;
        }
        commit_data.truncate(430);
        let spend_marker = stub_spend_marker(&key);
        self.made.borrow_mut().push((key.clone(), commit_data.clone()));
        Ok(MadeKey { key: PhantomKey::new(key)?, commit_data, spend_marker })
    }
}

/// The stand-in spend marker of the coin of stub key `key`.
pub fn stub_spend_marker(key: &[u8]) -> [u8; 32] {
    sha3_256(&[b"stub spend marker", key])
}

impl StubMaker {
    /// The spend marker of the coin with `commit_data`.
    pub fn marker_for(&self, commit_data: &[u8]) -> [u8; 32] {
        stub_spend_marker(&self.key_for(commit_data))
    }
}

/// A chain check that answers Paid for the coins the test marked paid.
#[derive(Default)]
pub struct StubChain {
    pub paid: RefCell<BTreeSet<([u8; 32], u128)>>,
    pub mismatch: Cell<bool>,
    pub asked: Cell<usize>,
}

impl StubChain {
    pub fn pay(&self, commit_data: &[u8], amount_wei: u128) {
        self.paid.borrow_mut().insert((sha3_256(&[commit_data]), amount_wei));
    }
}

impl ChainCheck for StubChain {
    fn confirm_payment(&self, claim: &CoinClaim) -> PaymentVerdict {
        self.asked.set(self.asked.get() + 1);
        if self.mismatch.get() {
            return PaymentVerdict::Mismatch;
        }
        if self.paid.borrow().contains(&(claim.coin, claim.amount_wei)) {
            PaymentVerdict::Paid
        } else {
            PaymentVerdict::NotYet
        }
    }
}

/// A stand-in chain status check for tests that do not care about the
/// chain: every coin is exact, settled and unspent. (The Seal still asks it
/// only with the card's Fill journal entry.)
#[derive(Clone, Copy, Default)]
pub struct SettledCheck;

impl CoinStatusCheck for SettledCheck {
    fn coin_status(&self, _query: &CoinQuery) -> CoinStatus {
        CoinStatus::ExactSettledUnspent
    }
}

/// A registry holding `uids`, set up on one test date in one test batch.
pub fn registered(uids: &[CardUid]) -> MemoryRegistry {
    let mut registry = MemoryRegistry::new();
    for uid in uids {
        registry.record(&RegistryEntry::new(*uid, "2026-11-01", "test-batch").unwrap()).unwrap();
    }
    registry
}

/// A Seal with the test master key, random source, clock and `journal`,
/// the stand-in chain status check and a registry holding [`UID`].
pub fn seal(journal: &MemoryJournal, clock: &TestClock, random_label: u64) -> Seal {
    seal_with(journal, clock, random_label, Box::new(SettledCheck), Box::new(registered(&[UID])))
}

/// A Seal with the test master key, random source, clock and `journal`,
/// and `chain_status` and `registry`.
pub fn seal_with(
    journal: &MemoryJournal,
    clock: &TestClock,
    random_label: u64,
    chain_status: Box<dyn CoinStatusCheck>,
    registry: Box<dyn CardRegistry>,
) -> Seal {
    Seal::new(
        master(),
        SealConfig { measurement: MEASUREMENT, answer_lifetime_secs: 120 },
        Box::new(TestRandom::new(random_label)),
        Box::new(clock.clone()),
        Box::new(journal.clone()),
        chain_status,
        registry,
    )
}

/// A Seal for a relay's worker threads: the test master key, the system
/// random source, a fixed clock, `journal`, the stand-in chain status check
/// and a registry holding [`UID`].
pub fn thread_seal(journal: &SharedJournal) -> Seal {
    Seal::new(
        master(),
        SealConfig { measurement: MEASUREMENT, answer_lifetime_secs: 120 },
        Box::new(ghost_seal::SystemRandom),
        Box::new(FixedClock(START_TIME)),
        Box::new(journal.clone()),
        Box::new(SettledCheck),
        Box::new(registered(&[UID])),
    )
}

/// The test phone's ML-KEM-768 key.
pub fn phone(seed_byte: u8) -> PhoneSecret {
    let mut seed = [seed_byte; 64];
    PhoneSecret::from_seed(&mut seed)
}

/// When the simulated connection drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropStyle {
    /// The command never reaches the card.
    BeforeCard,
    /// The card runs the command; its answer is lost.
    AfterCard,
}

#[derive(Clone)]
struct SimAuth {
    key_no: u8,
    enc: [u8; 16],
    mac: [u8; 16],
    ti: [u8; 4],
    counter: u16,
}

const OK: [u8; 2] = [0x91, 0x00];

fn status(code: u8) -> Vec<u8> {
    vec![0x91, code]
}

/// An NTAG 424 DNA, from its datasheet.
#[derive(Clone)]
pub struct SimCard {
    pub uid: [u8; 7],
    pub keys: [[u8; 16]; 5],
    pub versions: [u8; 5],
    /// FileOption, AR1, AR2 of file 2.
    pub settings: [u8; 3],
    pub file: Vec<u8>,
    /// Commands sent so far (counting dropped ones).
    pub sent: usize,
    /// Drop the connection from command number `.0` (counted from the
    /// card's first command) on.
    pub drop_at: Option<(usize, DropStyle)>,
    /// The plaintext length of every WriteData the card ran.
    pub write_lengths: Vec<usize>,
    /// Every APDU sent and every answer given, as the phone's relay sees them.
    pub transcript: Vec<Vec<u8>>,
    auth: Option<SimAuth>,
    challenge: Option<(u8, [u8; 16])>,
    random_counter: u64,
}

impl SimCard {
    /// A card as it leaves the factory: all keys zero, file 2 plain and free.
    pub fn factory(uid: [u8; 7]) -> SimCard {
        SimCard {
            uid,
            keys: [[0u8; 16]; 5],
            versions: [0; 5],
            settings: [0x00, 0xe0, 0xee],
            file: vec![0u8; 256],
            sent: 0,
            drop_at: None,
            write_lengths: Vec::new(),
            transcript: Vec::new(),
            auth: None,
            challenge: None,
            random_counter: 0,
        }
    }

    /// A card as the card setup leaves it: the Seal's keys of generation 0
    /// (version 1), file 2 in CommMode.Full with the Seal's access rights,
    /// the file blank.
    pub fn set_up(uid: CardUid) -> SimCard {
        let mut card = SimCard::factory(uid.0);
        let keys = card_keys(&master(), &uid);
        for key_no in 0..5u8 {
            card.keys[usize::from(key_no)] = *keys.key(key_no);
            card.versions[usize::from(key_no)] = key_version(0);
        }
        card.settings = record_file_settings();
        card
    }

    /// Drops the connection from the `commands_from_now`-th command on
    /// (0: the next one).
    pub fn drop_from(&mut self, commands_from_now: usize, style: DropStyle) {
        self.drop_at = Some((self.sent + commands_from_now, style));
    }

    pub fn reconnect(&mut self) {
        self.drop_at = None;
    }

    fn random(&mut self, length: usize) -> Vec<u8> {
        self.random_counter += 1;
        sha3_256(&[b"sim card random", &self.uid, &self.random_counter.to_be_bytes()])[..length].to_vec()
    }

    pub fn authenticated(&self) -> bool {
        self.auth.is_some()
    }

    fn answer(&mut self, apdu: &[u8]) -> Vec<u8> {
        if apdu.len() >= 2 && apdu[0] == 0x00 && apdu[1] == 0xa4 {
            self.auth = None;
            self.challenge = None;
            let named = apdu.len() >= 5 && apdu.get(5..5 + usize::from(apdu[4])) == Some(&[0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01][..]);
            return if named { vec![0x90, 0x00] } else { vec![0x6a, 0x82] };
        }
        if apdu.len() < 5 || apdu[0] != 0x90 || apdu[2] != 0 || apdu[3] != 0 || apdu[apdu.len() - 1] != 0 {
            return vec![0x6e, 0x00];
        }
        let command = apdu[1];
        let data: Vec<u8> = if apdu.len() > 5 {
            if apdu.len() != 6 + usize::from(apdu[4]) {
                return status(0x7e);
            }
            apdu[5..5 + usize::from(apdu[4])].to_vec()
        } else {
            Vec::new()
        };
        let challenge = self.challenge.take();
        match command {
            0x64 => {
                if self.auth.is_some() {
                    // Authenticated GetKeyVersion is MACed; this double answers it outside sessions only.
                    return status(0x9d);
                }
                match data.as_slice() {
                    [key_no] if *key_no < 5 => [vec![self.versions[usize::from(*key_no)]], OK.to_vec()].concat(),
                    [_] => status(0x40),
                    _ => status(0x7e),
                }
            }
            0x71 => {
                self.auth = None;
                if data.len() < 2 {
                    return status(0x7e);
                }
                let key_no = data[0];
                if key_no > 4 {
                    return status(0x40);
                }
                let rnd_b: [u8; 16] = self.random(16).try_into().unwrap();
                self.challenge = Some((key_no, rnd_b));
                let encrypted = aes128_cbc_encrypt(&self.keys[usize::from(key_no)], &[0u8; 16], &rnd_b).unwrap();
                [encrypted, vec![0x91, 0xaf]].concat()
            }
            0xaf => {
                let Some((key_no, rnd_b)) = challenge else { return status(0xca) };
                if data.len() != 32 {
                    return status(0x7e);
                }
                let key = self.keys[usize::from(key_no)];
                let plain = aes128_cbc_decrypt(&key, &[0u8; 16], &data).unwrap();
                let rnd_a: [u8; 16] = plain[..16].try_into().unwrap();
                if !ct_eq(&plain[16..], &rotate_left(&rnd_b)) {
                    return status(0xae);
                }
                let ti: [u8; 4] = self.random(4).try_into().unwrap();
                let (enc, mac) = session_keys(&key, &rnd_a, &rnd_b);
                self.auth = Some(SimAuth { key_no, enc: *enc, mac: *mac, ti, counter: 0 });
                let mut message = Vec::with_capacity(32);
                message.extend_from_slice(&ti);
                message.extend_from_slice(&rotate_left(&rnd_a));
                message.extend_from_slice(&[0u8; 12]);
                [aes128_cbc_encrypt(&key, &[0u8; 16], &message).unwrap(), OK.to_vec()].concat()
            }
            0x51 => self.secured(command, &data, 0),
            0xf5 => self.secured(command, &data, 1),
            0x5f => self.secured(command, &data, 1),
            0xc4 => self.secured(command, &data, 1),
            0xad | 0x8d => self.secured(command, &data, 7),
            _ => status(0x1c),
        }
    }

    /// Checks a secured command's MAC and returns its header and plaintext,
    /// or the status to answer.
    fn open(&mut self, command: u8, data: &[u8], header_bytes: usize, encrypted: bool) -> Result<(Vec<u8>, Vec<u8>), Vec<u8>> {
        let Some(auth) = self.auth.clone() else { return Err(status(0xae)) };
        if data.len() < header_bytes + 8 {
            self.auth = None;
            return Err(status(0x7e));
        }
        let header = data[..header_bytes].to_vec();
        let body = &data[header_bytes..data.len() - 8];
        let mac = &data[data.len() - 8..];
        let mut input = vec![command];
        input.extend_from_slice(&auth.counter.to_le_bytes());
        input.extend_from_slice(&auth.ti);
        input.extend_from_slice(&header);
        input.extend_from_slice(body);
        if !ct_eq(&truncate_mac(&cmac_aes128(&auth.mac, &input)), mac) {
            self.auth = None;
            return Err(status(0x1e));
        }
        if !encrypted || body.is_empty() {
            return Ok((header, body.to_vec()));
        }
        let mut iv_input = [0u8; 16];
        iv_input[0..2].copy_from_slice(&[0xa5, 0x5a]);
        iv_input[2..6].copy_from_slice(&auth.ti);
        iv_input[6..8].copy_from_slice(&auth.counter.to_le_bytes());
        let iv = aes128_encrypt_block(&auth.enc, &iv_input);
        let plain = match aes128_cbc_decrypt(&auth.enc, &iv, body).ok().and_then(|p| unpad(&p).ok()) {
            Some(plain) => plain.to_vec(),
            None => {
                self.auth = None;
                return Err(status(0x1e));
            }
        };
        Ok((header, plain))
    }

    /// The answer to a secured command: the counter moves on, the data is
    /// encrypted (`encrypt`) or plain, and the MAC follows.
    fn mac_answer(&mut self, body: &[u8], encrypt: bool) -> Vec<u8> {
        let auth = self.auth.as_mut().expect("authenticated");
        auth.counter = auth.counter.wrapping_add(1);
        let out = if encrypt && !body.is_empty() {
            let mut iv_input = [0u8; 16];
            iv_input[0..2].copy_from_slice(&[0x5a, 0xa5]);
            iv_input[2..6].copy_from_slice(&auth.ti);
            iv_input[6..8].copy_from_slice(&auth.counter.to_le_bytes());
            let iv = aes128_encrypt_block(&auth.enc, &iv_input);
            aes128_cbc_encrypt(&auth.enc, &iv, &pad(body)).unwrap()
        } else {
            body.to_vec()
        };
        let mut input = vec![0x00];
        input.extend_from_slice(&auth.counter.to_le_bytes());
        input.extend_from_slice(&auth.ti);
        input.extend_from_slice(&out);
        let mac = truncate_mac(&cmac_aes128(&auth.mac, &input));
        [out, mac.to_vec(), OK.to_vec()].concat()
    }

    fn secured(&mut self, command: u8, data: &[u8], header_bytes: usize) -> Vec<u8> {
        let encrypted = matches!(command, 0x5f | 0xc4 | 0x8d);
        let (header, plain) = match self.open(command, data, header_bytes, encrypted) {
            Ok(opened) => opened,
            Err(answer) => return answer,
        };
        let auth_key = self.auth.as_ref().unwrap().key_no;
        match command {
            0x51 => {
                let uid = self.uid;
                self.mac_answer(&uid, true)
            }
            0xf5 => {
                if header[0] != 0x02 {
                    return status(0xf0);
                }
                let mut settings = vec![0x00];
                settings.extend_from_slice(&self.settings);
                settings.extend_from_slice(&(self.file.len() as u32).to_le_bytes()[..3]);
                self.mac_answer(&settings, false)
            }
            0x5f => {
                if header[0] != 0x02 || plain.len() != 3 {
                    return status(0x9e);
                }
                if auth_key != (self.settings[1] & 0x0f) {
                    return status(0x9d);
                }
                self.settings.copy_from_slice(&plain);
                self.mac_answer(&[], false)
            }
            0xc4 => {
                let key_no = header[0];
                if key_no > 4 {
                    return status(0x40);
                }
                if auth_key != 0 {
                    return status(0x9d);
                }
                if key_no == auth_key {
                    if plain.len() != 17 {
                        return status(0x7e);
                    }
                    self.keys[0].copy_from_slice(&plain[..16]);
                    self.versions[0] = plain[16];
                    self.auth = None;
                    return OK.to_vec();
                }
                if plain.len() != 21 {
                    return status(0x7e);
                }
                let mut new_key = [0u8; 16];
                for i in 0..16 {
                    new_key[i] = plain[i] ^ self.keys[usize::from(key_no)][i];
                }
                if crc32_new_key(&new_key) != plain[17..21] {
                    self.auth = None;
                    return status(0x1e);
                }
                self.keys[usize::from(key_no)] = new_key;
                self.versions[usize::from(key_no)] = plain[16];
                self.mac_answer(&[], false)
            }
            0xad | 0x8d => {
                let mode = self.settings[0] & 0x03;
                let read_write = self.settings[1] >> 4;
                let right = if command == 0xad { self.settings[2] >> 4 } else { self.settings[2] & 0x0f };
                if mode != 0x03 || (auth_key != right && auth_key != read_write) {
                    return status(0x9d);
                }
                let file_no = header[0];
                let offset = usize::from(header[1]) | usize::from(header[2]) << 8 | usize::from(header[3]) << 16;
                let length = usize::from(header[4]) | usize::from(header[5]) << 8 | usize::from(header[6]) << 16;
                if file_no != 0x02 || offset + length > self.file.len() {
                    return status(0xbe);
                }
                if command == 0x8d {
                    if plain.len() != length {
                        return status(0x7e);
                    }
                    self.file[offset..offset + length].copy_from_slice(&plain);
                    self.write_lengths.push(length);
                    self.mac_answer(&[], false)
                } else {
                    let content = self.file[offset..offset + length].to_vec();
                    self.mac_answer(&content, true)
                }
            }
            _ => status(0x1c),
        }
    }
}

impl CardTransport for SimCard {
    fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Dropped> {
        let index = self.sent;
        self.sent += 1;
        self.transcript.push(apdu.to_vec());
        if let Some((at, style)) = self.drop_at {
            if index >= at {
                if index == at && style == DropStyle::AfterCard {
                    let _ = self.answer(apdu);
                }
                // Out of the field: the chip powers down and forgets its session.
                self.auth = None;
                self.challenge = None;
                return Err(Dropped);
            }
        }
        let answer = self.answer(apdu);
        self.transcript.push(answer.clone());
        Ok(answer)
    }
}

/// Whether `needle` appears anywhere in `haystack`.
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// A filled, paid and Sealed card, the journal, the clock, the key maker and
/// the commit data, ready for Check and Open tests.
pub struct SealedCard {
    pub card: SimCard,
    pub journal: MemoryJournal,
    pub clock: TestClock,
    pub maker: StubMaker,
    pub commit_data: Vec<u8>,
    pub amount_wei: u128,
}

pub const AMOUNT: u128 = 1_500_000_000_000_000_000;

pub fn sealed_card(pin: Option<&str>) -> SealedCard {
    let journal = MemoryJournal::new();
    let clock = TestClock::new();
    let mut maker = StubMaker::default();
    let mut card = SimCard::set_up(UID);
    let mut seal = seal(&journal, &clock, 1);
    let filled = seal
        .fill(
            &mut card,
            &ghost_seal::FillRequest {
                uid: UID,
                challenge: [1u8; 32],
                amount_wei: AMOUNT,
                pin: pin.map(|p| ghost_seal::Pin::new(p).unwrap()),
            },
            &mut maker,
        )
        .expect("fill");
    let chain = StubChain::default();
    chain.pay(&filled.commit_data, AMOUNT);
    let answer = seal
        .confirm_fill(&mut card, &ghost_seal::CheckRequest { uid: UID, challenge: [2u8; 32] }, &chain)
        .expect("confirm");
    assert_eq!(answer.body.state, ghost_seal::CardState::Sealed);
    card.write_lengths.clear();
    card.transcript.clear();
    SealedCard { card, journal, clock, maker, commit_data: filled.commit_data, amount_wei: AMOUNT }
}

// ---------------------------------------------------------------------------
// Stand-ins a relay's workers can use: each session's Seal is made on its own
// thread, so what it is given must be `Send + Sync`.

/// A journal in memory that threads share: clones share the same entries, so
/// every session's Seal (and the test) sees what the others saved. Test only:
/// it is not durable.
#[derive(Clone, Default)]
pub struct SharedJournal {
    pub entries: Arc<Mutex<BTreeMap<(CardUid, EntryKind), Vec<u8>>>>,
}

impl SharedJournal {
    pub fn has_open(&self, uid: &CardUid) -> bool {
        self.entries.lock().unwrap().contains_key(&(*uid, EntryKind::Open))
    }

    /// Every sealed entry, as the store holds them.
    pub fn sealed_entries(&self) -> Vec<Vec<u8>> {
        self.entries.lock().unwrap().values().cloned().collect()
    }
}

impl Journal for SharedJournal {
    fn load(&self, uid: &CardUid, kind: EntryKind) -> Option<Vec<u8>> {
        self.entries.lock().unwrap().get(&(*uid, kind)).cloned()
    }

    fn save(&mut self, uid: &CardUid, kind: EntryKind, sealed: Vec<u8>) -> Result<(), SealError> {
        self.entries.lock().unwrap().insert((*uid, kind), sealed);
        Ok(())
    }
}

/// A clock that stays at one time.
#[derive(Clone, Copy)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

/// [`StubMaker`] for threads: the same keys and commit data, kept where the
/// test can read them.
#[derive(Clone, Default)]
pub struct SyncMaker {
    pub made: Arc<Mutex<Vec<(Vec<u8>, Vec<u8>)>>>,
}

impl SyncMaker {
    /// The key whose coin has `commit_data`.
    pub fn key_for(&self, commit_data: &[u8]) -> Vec<u8> {
        self.made.lock().unwrap().iter().find(|(_, data)| data == commit_data).expect("a key for this coin").0.clone()
    }

    /// The spend marker of the coin with `commit_data`.
    pub fn marker_for(&self, commit_data: &[u8]) -> [u8; 32] {
        stub_spend_marker(&self.key_for(commit_data))
    }
}

impl PhantomKeyMaker for SyncMaker {
    fn make(&mut self, amount_wei: u128, random: &mut dyn SealRandom) -> Result<MadeKey, SealError> {
        let mut stub = StubMaker::default();
        let made = stub.make(amount_wei, random)?;
        self.made.lock().unwrap().extend(stub.made.borrow().iter().cloned());
        Ok(made)
    }
}

/// [`StubChain`] for threads: Paid for the coins the test marked paid.
#[derive(Clone, Default)]
pub struct SyncChain {
    pub paid: Arc<Mutex<BTreeSet<([u8; 32], u128)>>>,
}

impl SyncChain {
    pub fn pay(&self, commit_data: &[u8], amount_wei: u128) {
        self.paid.lock().unwrap().insert((sha3_256(&[commit_data]), amount_wei));
    }
}

impl ChainCheck for SyncChain {
    fn confirm_payment(&self, claim: &CoinClaim) -> PaymentVerdict {
        if self.paid.lock().unwrap().contains(&(claim.coin, claim.amount_wei)) {
            PaymentVerdict::Paid
        } else {
            PaymentVerdict::NotYet
        }
    }
}

/// Carries a relayed flow round trip by round trip between `card` and
/// `relay`, as the phone does, from its `first` step: each APDU to the card,
/// each raw answer back. Returns the flow's end and the Seal round trips
/// (the start included). A card that drops ends the session with an abort.
pub fn carry(card: &mut SimCard, relay: &Relay, first: Result<FlowStep, RelayError>) -> (Result<Finished, RelayError>, usize) {
    let mut round_trips = 1;
    let mut step = first;
    loop {
        match step {
            Ok(FlowStep::Done(finished)) => return (Ok(finished), round_trips),
            Err(error) => return (Err(error), round_trips),
            Ok(FlowStep::Apdu { session, apdu }) => match card.transceive(&apdu) {
                Ok(answer) => {
                    round_trips += 1;
                    step = relay.step_flow(&session, &answer);
                }
                Err(Dropped) => {
                    relay.abort(&session).expect("the session was running");
                    return (Err(RelayError::Seal(SealError::Dropped)), round_trips);
                }
            },
        }
    }
}
