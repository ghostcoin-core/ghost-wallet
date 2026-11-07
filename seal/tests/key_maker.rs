//! The Seal's Phantom Key maker, `CoreKeyMaker`: the wallet core's own
//! derivation. A Fill through `Seal::fill` on the simulated card writes the
//! core's key bytes (`0x20` and the 32 secret bytes the Seal's random source
//! gave), an Open reads the same key back, and the core's lookup
//! (`find_coins` over the coin's `commit_leaf`) finds exactly the filled
//! amount with it, so the wallet core can Summon and Claim the coin; the
//! journaled spend marker is the coin's own. Two Fills make two keys and two
//! coins. A failing random source fails the Fill with nothing made: the card
//! stays Empty and the journal unchanged. The key's secret bytes and its 24
//! words appear in no Fill answer, no public header frame, no relayed APDU
//! or card answer, none of the journal store's bytes and (feature `nitro`)
//! no service log event. `MadeKey` has no `Debug` and no `Display`.

#[cfg(feature = "nitro")]
#[path = "fixtures/nitro_authority.rs"]
mod authority;
#[cfg(feature = "nitro")]
#[path = "support/enclave.rs"]
mod enclave;
#[cfg(feature = "nitro")]
#[path = "fixtures/test_release_key.rs"]
mod release;
mod support;

use std::cell::{Cell, RefCell};
use std::convert::Infallible;
use std::rc::Rc;

use ghost_seal::journal_log::{JournalLog, MemoryLogStore};
use ghost_seal::primitives::sha3_256;
use ghost_seal::relay::to_hex;
use ghost_seal::{
    CardState, CardUid, CheckRequest, CoinQuery, CoinStatus, CoinStatusCheck, CoreKeyMaker, FillOutcome, FillRequest,
    MadeKey, OpenRequest, PhantomKeyMaker, Seal, SealConfig, SealError, SealRandom,
};
use ghost_wallet_core::seal_open::phantom_key_from_bytes;
use ghost_wallet_core::vanish::{KeyVault, tree_leaves, unspent_coin};
use ghost_wallet_core::{COMMIT_DATA_BYTES, TEST_CHAIN_ID, commit_leaf, find_coins};
use support::{AMOUNT, MEASUREMENT, SimCard, StubChain, TestClock, UID, contains, registered};

/// A second card the registry holds.
const SECOND: CardUid = CardUid([0x04, 0x52, 0x8e, 0xfb, 0xaa, 0x62, 0x81]);
/// Where the key slot frame starts in the record file, and where its key
/// length and key bytes are in the frame (`docs/sealed-card.md`).
const SLOT_AT: usize = 128;
const SLOT_KEY_LENGTH_AT: usize = SLOT_AT + 40;
const SLOT_KEY_AT: usize = SLOT_AT + 41;
/// The header frame: the record file's first 116 bytes.
const HEADER_BYTES: usize = 116;

/// A test random source that remembers every draw it gave: SHA3-256 of a
/// label and a counter. It fails any draw of more than 32 bytes when told to
/// (the Seal draws 16-byte challenges for the card; only the key maker
/// draws more).
#[derive(Clone)]
struct WatchedRandom {
    label: u64,
    counter: Rc<Cell<u64>>,
    draws: Rc<RefCell<Vec<Vec<u8>>>>,
    fail_long: Rc<Cell<bool>>,
}

impl WatchedRandom {
    fn new(label: u64) -> WatchedRandom {
        WatchedRandom {
            label,
            counter: Rc::new(Cell::new(0)),
            draws: Rc::new(RefCell::new(Vec::new())),
            fail_long: Rc::new(Cell::new(false)),
        }
    }

    /// The draws of more than 32 bytes: the key maker's.
    fn long_draws(&self) -> Vec<Vec<u8>> {
        self.draws.borrow().iter().filter(|draw| draw.len() > 32).cloned().collect()
    }
}

impl SealRandom for WatchedRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), SealError> {
        if self.fail_long.get() && out.len() > 32 {
            return Err(SealError::Random);
        }
        for chunk in out.chunks_mut(32) {
            let n = self.counter.get();
            self.counter.set(n + 1);
            chunk.copy_from_slice(&sha3_256(&[b"key maker test random", &self.label.to_be_bytes(), &n.to_be_bytes()])[..chunk.len()]);
        }
        self.draws.borrow_mut().push(out.to_vec());
        Ok(())
    }
}

/// A random source that always fails.
struct Broken;

impl SealRandom for Broken {
    fn fill(&mut self, _out: &mut [u8]) -> Result<(), SealError> {
        Err(SealError::Random)
    }
}

/// A chain status check that finds every coin exact, settled and unspent,
/// and remembers what it was asked.
#[derive(Clone, Default)]
struct WatchedCheck(Rc<RefCell<Vec<CoinQuery>>>);

impl CoinStatusCheck for WatchedCheck {
    fn coin_status(&self, query: &CoinQuery) -> CoinStatus {
        self.0.borrow_mut().push(query.clone());
        CoinStatus::ExactSettledUnspent
    }
}

/// A Seal holding the test M, with `random`, the sealed log over `store` as
/// its journal, the watched chain status check and a registry of the two
/// cards.
struct Rig {
    seal: Seal,
    random: WatchedRandom,
    store: MemoryLogStore,
    check: WatchedCheck,
}

fn rig(label: u64) -> Rig {
    let store = MemoryLogStore::new();
    let journal = JournalLog::open(&support::master(), Box::new(store.clone())).expect("a new log");
    let random = WatchedRandom::new(label);
    let check = WatchedCheck::default();
    let seal = Seal::new(
        support::master(),
        SealConfig { measurement: MEASUREMENT, answer_lifetime_secs: 120 },
        Box::new(random.clone()),
        Box::new(TestClock::new()),
        Box::new(journal),
        Box::new(check.clone()),
        Box::new(registered(&[UID, SECOND])),
    );
    Rig { seal, random, store, check }
}

fn fill_request(uid: CardUid, challenge: u8) -> FillRequest {
    FillRequest { uid, challenge: [challenge; 32], amount_wei: AMOUNT, pin: None }
}

fn fill(rig: &mut Rig, card: &mut SimCard, uid: CardUid, challenge: u8) -> Result<FillOutcome, SealError> {
    rig.seal.fill(card, &fill_request(uid, challenge), &mut CoreKeyMaker::new(TEST_CHAIN_ID))
}

/// The key bytes the card's key slot holds.
fn slot_key(card: &SimCard) -> Vec<u8> {
    let length = usize::from(card.file[SLOT_KEY_LENGTH_AT]);
    card.file[SLOT_KEY_AT..SLOT_KEY_AT + length].to_vec()
}

/// What the core's lookup finds of `key_bytes` among the leaves of `coins`
/// (each commit data paid `AMOUNT`) on `chain_id`, with `spent` markers.
fn lookup(key_bytes: &[u8], chain_id: u64, coins: &[&[u8]], spent: &[Vec<u8>]) -> (String, String) {
    let key = phantom_key_from_bytes(key_bytes).expect("the core's key bytes");
    let leaves: Vec<_> = coins.iter().map(|data| commit_leaf(data.to_vec(), AMOUNT.to_string()).unwrap()).collect();
    let found = find_coins(&key, chain_id, &leaves, spent).expect("a lookup");
    (found.status, found.amount_wei)
}

/// The spend marker of `commit_data`'s coin, as the core's restore finds it
/// with `key_bytes`.
fn core_marker(key_bytes: &[u8], commit_data: &[u8]) -> [u8; 32] {
    let key = phantom_key_from_bytes(key_bytes).unwrap();
    let leaves = tree_leaves(&[commit_leaf(commit_data.to_vec(), AMOUNT.to_string()).unwrap()]).unwrap();
    *unspent_coin(&key, TEST_CHAIN_ID, &leaves, &[]).expect("the key's coin").marker.as_bytes()
}

/// A source that gives `bytes`, then zeros.
struct Given(Vec<u8>, usize);

impl rand_core::TryRng for Given {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for byte in dst {
            *byte = self.0.get(self.1).copied().unwrap_or(0);
            self.1 += 1;
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Given {}

/// The 24 words of the key whose secret is `secret`, as the core gives a
/// card-only key's words: here, in the test, only to look for them.
fn words_of(secret: &[u8]) -> String {
    let vault = KeyVault::new();
    vault.prepare_card_with(TEST_CHAIN_ID, AMOUNT, &mut Given(secret.to_vec(), 0)).unwrap();
    let words = vault.with_card_words(|words| Some(words.to_owned())).unwrap().unwrap();
    vault.forget();
    assert_eq!(words.split_whitespace().count(), 24);
    words
}

/// Every form a leak of the key could take: its secret bytes, as hex both
/// ways, as a byte list, and its words, as given and one space apart.
fn leak_forms(secret: &[u8]) -> Vec<Vec<u8>> {
    let words = words_of(secret);
    let spaced = words.split_whitespace().collect::<Vec<_>>().join(" ");
    vec![
        secret.to_vec(),
        to_hex(secret).into_bytes(),
        to_hex(secret).to_uppercase().into_bytes(),
        format!("{secret:?}").into_bytes(),
        words.clone().into_bytes(),
        spaced.into_bytes(),
        words.to_uppercase().into_bytes(),
    ]
}

fn assert_carries_none(what: &str, bytes: &[u8], forms: &[Vec<u8>]) {
    for form in forms {
        assert!(!contains(bytes, form), "the key leaked into {what}");
    }
}

#[test]
fn the_maker_makes_the_cores_key_bytes_and_coin_from_the_random_source_it_is_handed() {
    let random = WatchedRandom::new(1);
    let made = CoreKeyMaker::new(TEST_CHAIN_ID).make(AMOUNT, &mut random.clone()).expect("a key");

    // One draw: the 32 secret bytes, then the coin's salt and note nonce.
    let draws = random.draws.borrow().clone();
    assert_eq!(draws.len(), 1, "one draw from the source it is handed");
    assert!(draws[0].len() > 32, "the coin's salt and nonce come from the same draw");
    let key = made.key.expose_secret().to_vec();
    assert_eq!(key.len(), 33);
    assert_eq!(key[0], 0x20, "the core's key format code");
    assert_eq!(&key[1..], &draws[0][..32], "the secret is the bytes the source gave");

    // The core's coin: 430 bytes of version-3 commit data, found by the key.
    assert_eq!(made.commit_data.len(), COMMIT_DATA_BYTES);
    assert_eq!(made.commit_data[..2], [0x00, 0x03]);
    let found = lookup(&key, TEST_CHAIN_ID, &[&made.commit_data], &[]);
    assert_eq!(found, ("found".to_owned(), AMOUNT.to_string()));
    // Its spend marker is the coin's own: spent, the core finds it spent.
    assert_eq!(made.spend_marker, core_marker(&key, &made.commit_data));
    let spent = lookup(&key, TEST_CHAIN_ID, &[&made.commit_data], &[made.spend_marker.to_vec()]);
    assert_eq!(spent.0, "spent");
    // The note is sealed for the maker's chain: another chain's lookup finds nothing.
    assert_eq!(lookup(&key, TEST_CHAIN_ID + 1, &[&made.commit_data], &[]).0, "not-found");

    // Nothing but the source it is handed goes into the key and the coin.
    let again = CoreKeyMaker::new(TEST_CHAIN_ID).make(AMOUNT, &mut WatchedRandom::new(1)).unwrap();
    assert_eq!(again.key.expose_secret(), &key[..]);
    assert_eq!(again.commit_data, made.commit_data);
    let other = CoreKeyMaker::new(TEST_CHAIN_ID).make(AMOUNT, &mut WatchedRandom::new(2)).unwrap();
    assert_ne!(other.key.expose_secret(), &key[..]);
    assert_ne!(other.commit_data, made.commit_data);
}

#[test]
fn a_refused_amount_or_a_failing_source_makes_nothing() {
    let random = WatchedRandom::new(3);
    assert_eq!(CoreKeyMaker::new(TEST_CHAIN_ID).make(0, &mut random.clone()).err(), Some(SealError::BadAmount));
    assert!(random.draws.borrow().is_empty(), "nothing is drawn for a refused amount");
    assert_eq!(CoreKeyMaker::new(TEST_CHAIN_ID).make(AMOUNT, &mut Broken).err(), Some(SealError::Random));
}

#[test]
fn a_fill_writes_the_key_an_open_releases_and_the_wallet_core_finds_its_coin() {
    let mut rig = rig(10);
    let mut card = SimCard::set_up(UID);
    let filled = fill(&mut rig, &mut card, UID, 0x11).expect("a Fill");
    assert_eq!(filled.answer.body.state, CardState::Empty);
    assert_eq!(filled.commit_data.len(), COMMIT_DATA_BYTES);

    // The key slot holds the core's key bytes: 0x20 and the 32 bytes of the
    // maker's draw.
    let key = slot_key(&card);
    let draws = rig.random.long_draws();
    assert_eq!(draws.len(), 1, "one Fill, one key draw");
    assert_eq!(key.len(), 33);
    assert_eq!(key[0], 0x20);
    assert_eq!(&key[1..], &draws[0][..32]);

    // Paid and confirmed: Sealed. The Seal asked its chain status check with
    // the coin's own spend marker.
    let chain = StubChain::default();
    chain.pay(&filled.commit_data, AMOUNT);
    let sealed = rig.seal.confirm_fill(&mut card, &CheckRequest { uid: UID, challenge: [0x12; 32] }, &chain).unwrap();
    assert_eq!(sealed.body.state, CardState::Sealed);
    let asked = rig.check.0.borrow().last().cloned().expect("the status check was asked");
    assert_eq!(asked.commit_data, filled.commit_data);
    assert_eq!(asked.spend_marker, core_marker(&key, &filled.commit_data));

    // A full Open releases the same key bytes to the phone.
    let phone = support::phone(0x31);
    let opened = rig
        .seal
        .open(&mut card, &OpenRequest { uid: UID, challenge: [0x13; 32], phone_key: phone.public_key(), pin: None })
        .expect("an Open");
    assert_eq!(opened.answer.body.state, CardState::Opened);
    let released = phone.open(&opened.release, &UID, opened.answer.body.generation).expect("the release opens");
    assert_eq!(released.expose_secret(), &key[..], "the key round-trips unchanged");

    // The wallet core finds exactly the filled amount with it: its Summon
    // and Claim start from this lookup.
    let found = lookup(released.expose_secret(), TEST_CHAIN_ID, &[&filled.commit_data], &[]);
    assert_eq!(found, ("found".to_owned(), AMOUNT.to_string()));
}

#[test]
fn two_fills_make_two_keys_and_two_coins() {
    let mut rig = rig(20);
    let mut first = SimCard::set_up(UID);
    let mut second = SimCard::set_up(SECOND);
    let a = fill(&mut rig, &mut first, UID, 0x21).unwrap();
    let b = fill(&mut rig, &mut second, SECOND, 0x22).unwrap();
    assert_ne!(slot_key(&first), slot_key(&second));
    assert_ne!(a.commit_data, b.commit_data);
    // Each key finds its own coin among both, and only its own.
    let both: [&[u8]; 2] = [&a.commit_data, &b.commit_data];
    assert_eq!(lookup(&slot_key(&first), TEST_CHAIN_ID, &both, &[]).1, AMOUNT.to_string());
    assert_eq!(lookup(&slot_key(&first), TEST_CHAIN_ID, &[&b.commit_data], &[]).0, "not-found");
    assert_eq!(lookup(&slot_key(&second), TEST_CHAIN_ID, &[&a.commit_data], &[]).0, "not-found");
}

#[test]
fn a_failing_random_source_fails_the_fill_and_leaves_the_card_empty_and_the_journal_unchanged() {
    let mut rig = rig(30);
    let mut card = SimCard::set_up(UID);
    let file = card.file.clone();
    let records = rig.store.records();
    rig.random.fail_long.set(true);
    assert_eq!(fill(&mut rig, &mut card, UID, 0x31).err(), Some(SealError::Random));
    assert_eq!(card.file, file, "nothing was written to the card");
    assert!(card.write_lengths.is_empty());
    assert_eq!(rig.store.records(), records, "nothing was journaled");

    // The card is still Empty, and a Fill once the source works fills it.
    rig.random.fail_long.set(false);
    let check = rig.seal.check(&mut card, &CheckRequest { uid: UID, challenge: [0x32; 32] }).unwrap();
    assert_eq!(check.body.state, CardState::Empty);
    assert!(fill(&mut rig, &mut card, UID, 0x33).is_ok());
    assert_eq!(slot_key(&card).len(), 33);
}

#[test]
fn the_key_and_its_words_are_in_no_answer_header_relayed_frame_or_journal_byte() {
    let mut rig = rig(40);
    let mut card = SimCard::set_up(UID);
    let filled = fill(&mut rig, &mut card, UID, 0x41).unwrap();
    let key = slot_key(&card);
    let forms = leak_forms(&key[1..]);
    // The search sees the key where it is meant to be: on the card.
    assert!(contains(&card.file[SLOT_AT..], &key[1..]));

    let chain = StubChain::default();
    chain.pay(&filled.commit_data, AMOUNT);
    let sealed = rig.seal.confirm_fill(&mut card, &CheckRequest { uid: UID, challenge: [0x42; 32] }, &chain).unwrap();
    let checked = rig.seal.check(&mut card, &CheckRequest { uid: UID, challenge: [0x43; 32] }).unwrap();

    assert_carries_none("the commit data", &filled.commit_data, &forms);
    for answer in [&filled.answer, &sealed, &checked] {
        assert_carries_none("a signed answer", &answer.bytes, &forms);
        assert_carries_none("a signature", &answer.signature, &forms);
    }
    assert_carries_none("the header frame", &card.file[..HEADER_BYTES], &forms);
    for frame in &card.transcript {
        assert_carries_none("a relayed APDU or card answer", frame, &forms);
    }
    let journal = rig.store.bytes();
    assert!(!journal.is_empty(), "the Fill was journaled");
    assert_carries_none("the journal store", &journal, &forms);
}

/// Through the enclave's service, with the enclave's own key maker
/// installed: no service log event (nor any answer) carries the key.
#[cfg(feature = "nitro")]
#[test]
fn no_service_log_event_carries_the_key() {
    use std::sync::Arc;

    use ghost_seal::CardTransport;
    use ghost_seal::enclave_serve::{EnclaveService, MemoryServiceLog};
    use ghost_seal::relay::from_hex;
    use serde_json::{Value, json};

    fn post(service: &EnclaveService, path: &str, body: &Value) -> Value {
        let reply = service.routes().answer("POST", path, body.to_string().as_bytes());
        serde_json::from_str(&reply.body).expect("JSON")
    }
    fn carry(service: &EnclaveService, card: &mut SimCard, mut answer: Value, seen: &mut Vec<Value>) -> Value {
        while answer["status"] == "apdu" {
            seen.push(answer.clone());
            let card_answer = card.transceive(&from_hex(answer["apdu"].as_str().unwrap()).unwrap()).unwrap();
            let step = json!({ "session": answer["session"], "answer": to_hex(&card_answer) });
            answer = post(service, "/v1/relay/step", &step);
        }
        seen.push(answer.clone());
        answer
    }

    let (deps, fakes) = enclave::deps_with_maker(Some(enclave::core_key_maker()));
    let log = Arc::new(MemoryServiceLog::default());
    let service = enclave::service(deps, authority::allowed_old(), log.clone());
    service.install_master(support::master());
    let mut card = SimCard::set_up(UID);
    let mut seen = Vec::new();
    let uid = to_hex(&UID.0);
    let fill = json!({ "uid": uid, "challenge": to_hex(&[0x51; 32]), "amountWei": AMOUNT.to_string() });
    let done = carry(&service, &mut card, post(&service, "/v1/fill/start", &fill), &mut seen);
    assert_eq!(done["status"], "done", "{done}");
    let commit_data = from_hex(done["commitData"].as_str().unwrap()).unwrap();
    assert!(fakes.maker.made.lock().unwrap().is_empty(), "the enclave's own maker made the key");
    let key = slot_key(&card);
    assert_eq!(lookup(&key, TEST_CHAIN_ID, &[&commit_data], &[]).1, AMOUNT.to_string());
    let forms = leak_forms(&key[1..]);

    let events = log.0.lock().unwrap().clone();
    assert!(!events.is_empty());
    for event in &events {
        assert_carries_none("a service log event", event.to_string().as_bytes(), &forms);
        assert_carries_none("a service log event", format!("{event:?}").as_bytes(), &forms);
    }
    for answer in &seen {
        assert_carries_none("an answer", answer.to_string().as_bytes(), &forms);
        for field in ["answer", "signature", "commitData", "apdu"] {
            if let Some(hex) = answer[field].as_str() {
                assert_carries_none("an answer's bytes", &from_hex(hex).unwrap(), &forms);
            }
        }
    }
}

/// Whether `T` implements `Debug` or `Display`, found by method resolution:
/// the probe's own impl applies only when the trait does, the borrowed
/// probe's fallback otherwise.
struct Probe<T>(std::marker::PhantomData<T>);

trait NotDebug {
    fn is_debug(&self) -> bool {
        false
    }
}
impl<T> NotDebug for &Probe<T> {}
trait IsDebug {
    fn is_debug(&self) -> bool {
        true
    }
}
impl<T: std::fmt::Debug> IsDebug for Probe<T> {}

trait NotDisplay {
    fn is_display(&self) -> bool {
        false
    }
}
impl<T> NotDisplay for &Probe<T> {}
trait IsDisplay {
    fn is_display(&self) -> bool {
        true
    }
}
impl<T: std::fmt::Display> IsDisplay for Probe<T> {}

#[test]
fn made_key_has_no_debug_or_display() {
    let made = Probe::<MadeKey>(std::marker::PhantomData);
    assert!(!(&made).is_debug(), "MadeKey must not implement Debug");
    assert!(!(&made).is_display(), "MadeKey must not implement Display");
    // The probe does see the traits where they are.
    let shown = Probe::<String>(std::marker::PhantomData);
    assert!((&shown).is_debug() && (&shown).is_display());
}
