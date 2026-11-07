//! The journal log's head, anchored in the other regions, and the home
//! region of each card. Pure code: no socket, no file. The enclave carries
//! the requests over its service port (`enclave_serve`, service request kind
//! [`SERVICE_KIND`]); the tests use peers in the same process.
//!
//! **Home region.** Every card is served by one region only, its home: of
//! the ordered region list, the region whose SHA3-256(`ghost-seal/v1/home-region`
//! || region id || UID) is the greatest (compared as big-endian bytes; on a
//! tie, the earlier region). Every other region refuses the card's Fill,
//! Check, Fill confirmation and Open with the fixed refusal
//! [`WRONG_REGION_REASON`], naming the home region, before any session: it
//! touches no journal, no card and no log. So an Open begun in one region is
//! never finished, or certified Sealed, by another. The list is the
//! release's, compiled in ([`RELEASE_REGIONS`]); changing it moves cards.
//!
//! **Anchored head.** Each region keeps its own log (`journal_log`) on its
//! host and anchors it in every other region, its peers:
//!
//! - after each append, the record (ciphertext only) goes to every peer
//!   ([`OP_APPEND`]). A peer checks it with M (the next counter, its tag
//!   chained to the last record it holds for that region, and that it
//!   decodes), keeps it in its own host's store, in a log per origin
//!   region, and answers its head of that log. The save is `Ok` only once
//!   every peer answered a head holding the record ([`Anchor`]); a peer that
//!   is unreachable or refuses fails the save, and the Seal changes no card;
//! - when the log is opened, after M is installed and before the log is
//!   used, every peer is asked for its head of this region's log
//!   ([`OP_HEAD`]). With no peer answering, the log is refused (every flow
//!   503, tried again). A peer head ahead of the host's log (a cut tail, or
//!   an empty log on a replaced host) is restored from that peer
//!   ([`OP_FETCH`]), each record checked with M and appended to the host's
//!   store; a peer head with the same counter and another tag (a fork), a
//!   restored record that fails its check, or a restore that does not end on
//!   the peer's head is a refusal. A peer behind is sent what it lacks.
//!
//! Every answer about a head is `counter (8) || tag (32) || mac (32)`:
//!
//! ```text
//! mac = HMAC-SHA3-256(head key, ghost-seal/v1/journal-head || origin length (1) || origin
//!                     || counter (u64) || tag || the asker's nonce (32))
//! ```
//!
//! The head key is HKDF-SHA3-256 over M with the label
//! [`JOURNAL_HEAD_LABEL`] (salt and info). Only an enclave holding M can make
//! it, and every holder of M is an enclave attested when M was handed over,
//! so a good MAC is an answer from a peer enclave; the asker's fresh 32-byte
//! nonce (from `SealRandom`) means an old answer is never taken again. No
//! signature: the MAC is enough among holders of M.
//!
//! Requests (the body of service request kind [`SERVICE_KIND`]):
//!
//! ```text
//! op (1) || origin length (1) || origin || nonce (32) || rest
//! op 1 append: rest = counter (u64) || record     answer: the head after it
//! op 2 head:   rest = nothing                     answer: the head
//! op 3 fetch:  rest = first counter (u64)         answer: (counter (u64) || length (u32) || record)*
//! ```
//!
//! A fetch answers the records from the first counter on, up to the head,
//! at most [`MAX_FETCH_BYTES`] of them; the asker fetches again from where
//! it ended. Peers and their hosts hold counters and records only: no UID,
//! entry kind, card data or key, and never M.
//!
//! What this does not cover: every region lost at once, or the hosts of
//! every region cutting the log at once.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use zeroize::Zeroizing;

use crate::card_keys::CardUid;
use crate::error::SealError;
use crate::journal_log::{Chain, HeadAnchor, LogStore, MAX_RECORD_BYTES, TAG_BYTES, record_tag};
use crate::primitives::{ct_eq, hkdf_sha3_256, hmac_sha3_256, sha3_256};
use crate::secrets::MasterKey;
use crate::traits::{SealRandom, SystemRandom};

/// The label of the home rule's hash.
pub const HOME_REGION_LABEL: &[u8] = b"ghost-seal/v1/home-region";
/// The HKDF label of the head key, and the first part of every head MAC.
pub const JOURNAL_HEAD_LABEL: &[u8] = b"ghost-seal/v1/journal-head";
/// The release's ordered region list, compiled in: the order of
/// `enclave/deploy/regions.json`. Changing it moves cards to other homes.
pub const RELEASE_REGIONS: [&str; 3] = ["us-east-1", "eu-central-1", "ap-southeast-1"];
/// The vsock ports on the parent that the host carries to the other
/// regions' inbound proxies, one per peer, in the order of the region list
/// (this region left out).
pub const PEER_PORTS: [u32; 2] = [5006, 5007];
/// How long one request to a peer may take, connection to answer.
pub const PEER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
/// The service request kind of the requests below (beside key share 1 and
/// phone attestation 2).
pub const SERVICE_KIND: u8 = 3;
/// The bytes of a nonce.
pub const NONCE_BYTES: usize = 32;
/// The longest region id.
pub const MAX_REGION_BYTES: usize = 32;
/// The most record bytes one fetch answers.
pub const MAX_FETCH_BYTES: usize = 48 * 1024;
/// Request: append one record.
pub const OP_APPEND: u8 = 1;
/// Request: the head.
pub const OP_HEAD: u8 = 2;
/// Request: the records from a counter on.
pub const OP_FETCH: u8 = 3;
/// The `reason` of the refusal of a card whose home is another region.
pub const WRONG_REGION_REASON: &str = "wrong-region";
/// Its message.
pub const WRONG_REGION_MESSAGE: &str = "This card is served by its home region";

const HEAD_ANSWER_BYTES: usize = 8 + TAG_BYTES + 32;

/// No peer answered a head that verifies.
pub const NO_PEER: SealError = SealError::Journal("no peer region answered for the log's head");
/// A peer holds another record at a counter this region holds.
pub const FORKED: SealError = SealError::Journal("a peer region holds another log at the same counter");
/// A restored record fails its check, or the restore does not end on the
/// peer's head.
pub const BAD_RESTORE: SealError = SealError::Journal("a record restored from a peer region fails its check");
/// A peer did not answer a head holding the record.
pub const NOT_ACKNOWLEDGED: SealError = SealError::Journal("a peer region did not acknowledge the record");
/// A peer holds more of this region's log than this region does.
pub const PEER_AHEAD: SealError = SealError::Journal("a peer region holds more of this log than this region");

/// Whether `error` is the anchor's (the log's head could not be anchored),
/// not the host store's.
pub fn is_anchor_error(error: &SealError) -> bool {
    [NO_PEER, FORKED, BAD_RESTORE, NOT_ACKNOWLEDGED, PEER_AHEAD].contains(error)
}

/// Whether `name` can be a region id: 1 to 32 of `a`-`z`, `0`-`9` and `-`,
/// starting with a letter.
pub fn valid_region(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_REGION_BYTES
        && name.as_bytes()[0].is_ascii_lowercase()
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The home region of card `uid` over the ordered `regions` (see the module
/// notes); `None` for an empty list.
pub fn home_region<'a, S: AsRef<str>>(regions: &'a [S], uid: &CardUid) -> Option<&'a str> {
    let mut best: Option<(&str, [u8; 32])> = None;
    for region in regions {
        let region = region.as_ref();
        let score = sha3_256(&[HOME_REGION_LABEL, region.as_bytes(), &uid.0]);
        if best.is_none_or(|(_, top)| score > top) {
            best = Some((region, score));
        }
    }
    best.map(|(region, _)| region)
}

/// Why a region list was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionsRefused {
    /// Fewer than two regions.
    TooFew,
    /// A region id that is not 1 to 32 of `a-z`, `0-9` and `-`.
    BadName,
    /// A region listed twice.
    Twice,
    /// This region is not on the list.
    NotListed,
}

impl std::fmt::Display for RegionsRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RegionsRefused::TooFew => "the region list needs at least two regions",
            RegionsRefused::BadName => "a region id is 1 to 32 of a-z, 0-9 and -, starting with a letter",
            RegionsRefused::Twice => "a region is listed twice",
            RegionsRefused::NotListed => "this region is not on the region list",
        })
    }
}

impl std::error::Error for RegionsRefused {}

/// The ordered region list and this region in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Regions {
    list: Vec<String>,
    own: usize,
}

impl Regions {
    /// The ordered `list`, this region being `own`.
    pub fn new<S: AsRef<str>>(list: &[S], own: &str) -> Result<Regions, RegionsRefused> {
        let list: Vec<String> = list.iter().map(|r| r.as_ref().to_owned()).collect();
        if list.len() < 2 {
            return Err(RegionsRefused::TooFew);
        }
        if !list.iter().all(|r| valid_region(r)) {
            return Err(RegionsRefused::BadName);
        }
        if list.iter().enumerate().any(|(i, r)| list[..i].contains(r)) {
            return Err(RegionsRefused::Twice);
        }
        let own = list.iter().position(|r| r == own).ok_or(RegionsRefused::NotListed)?;
        Ok(Regions { list, own })
    }

    /// The release's list ([`RELEASE_REGIONS`]), this region being `own`.
    pub fn release(own: &str) -> Result<Regions, RegionsRefused> {
        Regions::new(&RELEASE_REGIONS, own)
    }

    /// This region.
    pub fn own(&self) -> &str {
        &self.list[self.own]
    }

    /// Every region, in order.
    pub fn list(&self) -> &[String] {
        &self.list
    }

    /// The other regions, in order.
    pub fn peers(&self) -> Vec<&str> {
        self.list.iter().enumerate().filter(|(i, _)| *i != self.own).map(|(_, r)| r.as_str()).collect()
    }

    /// The home region of card `uid`.
    pub fn home(&self, uid: &CardUid) -> &str {
        home_region(&self.list, uid).expect("the list is never empty")
    }

    /// Whether this region is card `uid`'s home.
    pub fn is_home(&self, uid: &CardUid) -> bool {
        self.home(uid) == self.own()
    }
}

/// The head key, derived from M.
struct HeadKey(Zeroizing<[u8; 32]>);

impl HeadKey {
    fn derive(master: &MasterKey) -> HeadKey {
        let mut key = Zeroizing::new([0u8; 32]);
        hkdf_sha3_256(JOURNAL_HEAD_LABEL, master.derive_from(), &[JOURNAL_HEAD_LABEL], &mut key[..]);
        HeadKey(key)
    }

    fn mac(&self, origin: &str, counter: u64, tag: &[u8; TAG_BYTES], nonce: &[u8; NONCE_BYTES]) -> [u8; 32] {
        let length = [origin.len() as u8];
        hmac_sha3_256(&self.0[..], &[JOURNAL_HEAD_LABEL, &length, origin.as_bytes(), &counter.to_be_bytes(), tag, nonce])
    }

    fn answer(&self, origin: &str, counter: u64, tag: &[u8; TAG_BYTES], nonce: &[u8; NONCE_BYTES]) -> Vec<u8> {
        [&counter.to_be_bytes()[..], tag, &self.mac(origin, counter, tag, nonce)].concat()
    }
}

/// One request, as a peer reads it.
struct Request<'a> {
    op: u8,
    origin: &'a str,
    nonce: [u8; NONCE_BYTES],
    rest: &'a [u8],
}

fn encode(op: u8, origin: &str, nonce: &[u8; NONCE_BYTES], rest: &[u8]) -> Vec<u8> {
    [&[op, origin.len() as u8][..], origin.as_bytes(), nonce, rest].concat()
}

fn decode(body: &[u8]) -> Result<Request<'_>, &'static str> {
    let malformed = "a journal head request is malformed";
    let (&op, body) = body.split_first().ok_or(malformed)?;
    let (&length, body) = body.split_first().ok_or(malformed)?;
    let length = usize::from(length);
    if body.len() < length + NONCE_BYTES {
        return Err(malformed);
    }
    let origin = std::str::from_utf8(&body[..length]).map_err(|_| malformed)?;
    if !valid_region(origin) {
        return Err(malformed);
    }
    let nonce = body[length..length + NONCE_BYTES].try_into().expect("32 bytes");
    Ok(Request { op, origin, nonce, rest: &body[length + NONCE_BYTES..] })
}

fn counter_of(bytes: &[u8]) -> Option<u64> {
    bytes.get(..8).map(|b| u64::from_be_bytes(b.try_into().expect("8 bytes")))
}

/// The records of a fetch answer.
fn decode_records(mut bytes: &[u8]) -> Option<Vec<(u64, Vec<u8>)>> {
    let mut records = Vec::new();
    while !bytes.is_empty() {
        let counter = counter_of(bytes)?;
        let length = u32::from_be_bytes(bytes.get(8..12)?.try_into().ok()?) as usize;
        if length == 0 || length > MAX_RECORD_BYTES {
            return None;
        }
        records.push((counter, bytes.get(12..12 + length)?.to_vec()));
        bytes = &bytes[12 + length..];
    }
    Some(records)
}

/// How a request reaches one peer region's enclave: in the enclave, a
/// framed service request kind [`SERVICE_KIND`] through the parent's
/// outbound proxy (`enclave_serve::ServicePeer`), within [`PEER_DEADLINE`].
pub trait PeerLink: Send + Sync {
    /// Sends one request; the peer's answer, or why it refused or could not
    /// be reached.
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, String>;
}

/// One peer region: its id and how to reach it.
#[derive(Clone)]
pub struct Peer {
    /// The peer's region id.
    pub region: String,
    /// How to reach its enclave.
    pub link: Arc<dyn PeerLink>,
}

/// The log a peer region keeps for one origin region.
struct OriginLog {
    store: Box<dyn LogStore>,
    /// The chain checked so far, once the store was read with M.
    chain: Option<Chain>,
}

/// A peer region's side: the logs it keeps for the other regions, each in
/// its own store on its host (`/var/lib/seal/peer-<region>.log` in a real
/// Seal), and its answers to their requests.
pub struct PeerLogs {
    own: String,
    logs: Mutex<BTreeMap<String, OriginLog>>,
}

impl PeerLogs {
    /// The logs of this region `own`, one in each of `stores` for the origin
    /// region it names. A request about any other region is refused.
    pub fn new(own: &str, stores: Vec<(String, Box<dyn LogStore>)>) -> PeerLogs {
        let logs = stores
            .into_iter()
            .filter(|(region, _)| region != own)
            .map(|(region, store)| (region, OriginLog { store, chain: None }))
            .collect();
        PeerLogs { own: own.to_owned(), logs: Mutex::new(logs) }
    }

    /// The origin regions whose logs this region keeps.
    pub fn origins(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, OriginLog>> {
        self.logs.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The answer to one request, checked with `master` (the M this enclave
    /// holds), or why it was refused.
    pub fn answer(&self, master: &MasterKey, body: &[u8]) -> Result<Vec<u8>, String> {
        let request = decode(body)?;
        if request.origin == self.own {
            return Err("this region keeps no peer log of itself".into());
        }
        let mut logs = self.lock();
        let log = logs.get_mut(request.origin).ok_or("this region keeps no log of that origin")?;
        if log.chain.is_none() {
            let records = log.store.read_all().map_err(|_| "the peer log cannot be read")?;
            let mut chain = Chain::new(master);
            for (counter, record) in &records {
                chain.push(*counter, record).map_err(|_| "the peer log fails its checks")?;
            }
            log.chain = Some(chain);
        }
        let key = HeadKey::derive(master);
        let chain = log.chain.as_mut().expect("opened above");
        match request.op {
            OP_HEAD if request.rest.is_empty() => {}
            OP_APPEND => {
                let counter = counter_of(request.rest).ok_or("a journal head request is malformed")?;
                let record = &request.rest[8..];
                // Only the next record is taken; for any other the head
                // answers what this region holds.
                if Some(counter) == chain.counter().checked_add(1) {
                    let mut next = chain.clone();
                    next.push(counter, record).map_err(|_| "the record does not chain onto that origin's log")?;
                    log.store.append(counter, record).map_err(|_| "the peer log store did not take the record")?;
                    *chain = next;
                }
            }
            OP_FETCH => {
                let from = counter_of(request.rest).filter(|_| request.rest.len() == 8);
                let from = from.ok_or("a journal head request is malformed")?;
                let records = log.store.read_all().map_err(|_| "the peer log cannot be read")?;
                let mut out = Vec::new();
                for (counter, record) in records.iter().filter(|(c, _)| *c >= from && *c <= chain.counter()) {
                    if !out.is_empty() && out.len() + 12 + record.len() > MAX_FETCH_BYTES {
                        break;
                    }
                    out.extend_from_slice(&counter.to_be_bytes());
                    out.extend_from_slice(&(record.len() as u32).to_be_bytes());
                    out.extend_from_slice(record);
                }
                return Ok(out);
            }
            _ => return Err("unknown journal head request".into()),
        }
        Ok(key.answer(request.origin, chain.counter(), &chain.tag(), &request.nonce))
    }
}

/// The origin region's side: anchors its log's head in every peer (see the
/// module notes). What a log is opened with (`journal_log::SharedLog::anchored`).
pub struct Anchor {
    origin: String,
    peers: Vec<Peer>,
    random: Box<dyn SealRandom + Send>,
    key: Option<HeadKey>,
}

impl Anchor {
    /// The anchor of region `origin`'s log in `peers`, its nonces from the
    /// system's random source.
    pub fn new(origin: &str, peers: Vec<Peer>) -> Anchor {
        Anchor::with_random(origin, peers, Box::new(SystemRandom))
    }

    /// [`Anchor::new`] with the random source of its nonces.
    pub fn with_random(origin: &str, peers: Vec<Peer>, random: Box<dyn SealRandom + Send>) -> Anchor {
        Anchor { origin: origin.to_owned(), peers, random, key: None }
    }

    /// The peer regions, in order.
    pub fn peers(&self) -> Vec<&str> {
        self.peers.iter().map(|peer| peer.region.as_str()).collect()
    }

    /// Asks peer `index` with a fresh nonce; its head, if its MAC verifies.
    fn ask(&mut self, index: usize, op: u8, rest: &[u8]) -> Result<(u64, [u8; TAG_BYTES]), SealError> {
        let key = self.key.as_ref().ok_or(NOT_ACKNOWLEDGED)?;
        let mut nonce = [0u8; NONCE_BYTES];
        self.random.fill(&mut nonce)?;
        let answer = self.peers[index].link.exchange(&encode(op, &self.origin, &nonce, rest)).map_err(|_| NOT_ACKNOWLEDGED)?;
        if answer.len() != HEAD_ANSWER_BYTES {
            return Err(NOT_ACKNOWLEDGED);
        }
        let counter = counter_of(&answer).expect("8 bytes");
        let tag: [u8; TAG_BYTES] = answer[8..8 + TAG_BYTES].try_into().expect("32 bytes");
        if !ct_eq(&key.mac(&self.origin, counter, &tag, &nonce), &answer[8 + TAG_BYTES..]) {
            return Err(NOT_ACKNOWLEDGED);
        }
        Ok((counter, tag))
    }

    fn fetch(&mut self, index: usize, from: u64) -> Result<Vec<(u64, Vec<u8>)>, SealError> {
        let mut nonce = [0u8; NONCE_BYTES];
        self.random.fill(&mut nonce)?;
        let answer = self.peers[index]
            .link
            .exchange(&encode(OP_FETCH, &self.origin, &nonce, &from.to_be_bytes()))
            .map_err(|_| BAD_RESTORE)?;
        decode_records(&answer).ok_or(BAD_RESTORE)
    }

    /// Has peer `index`, whose head is at `head`, take every record of `log`
    /// after it.
    fn catch_up(&mut self, index: usize, head: u64, log: &[(u64, Vec<u8>)]) -> Result<(), SealError> {
        for (counter, record) in log.iter().filter(|(c, _)| *c > head) {
            let tag = record_tag(record).ok_or(NOT_ACKNOWLEDGED)?;
            let (held, held_tag) = self.ask(index, OP_APPEND, &[&counter.to_be_bytes()[..], record].concat())?;
            if held > *counter {
                return Err(PEER_AHEAD);
            }
            if held != *counter {
                return Err(NOT_ACKNOWLEDGED);
            }
            if !ct_eq(&held_tag, &tag) {
                return Err(FORKED);
            }
        }
        Ok(())
    }
}

/// The tag of record `counter` of `log` (zeros for counter 0).
fn tag_at(log: &[(u64, Vec<u8>)], counter: u64) -> Option<[u8; TAG_BYTES]> {
    if counter == 0 {
        return Some([0u8; TAG_BYTES]);
    }
    log.get(usize::try_from(counter - 1).ok()?).and_then(|(_, record)| record_tag(record))
}

impl HeadAnchor for Anchor {
    fn restore(&mut self, master: &MasterKey, records: &[(u64, Vec<u8>)]) -> Result<Vec<(u64, Vec<u8>)>, SealError> {
        self.key = Some(HeadKey::derive(master));
        let own = records.len() as u64;
        let mut heads = Vec::new();
        for index in 0..self.peers.len() {
            if let Ok((counter, tag)) = self.ask(index, OP_HEAD, &[]) {
                heads.push((index, counter, tag));
            }
        }
        let &(best, top, top_tag) = heads.iter().max_by_key(|(_, counter, _)| *counter).ok_or(NO_PEER)?;
        // A peer at or behind the host's log must hold the same records.
        for (_, counter, tag) in heads.iter().filter(|(_, counter, _)| *counter <= own) {
            if tag_at(records, *counter).is_none_or(|own_tag| !ct_eq(&own_tag, tag)) {
                return Err(FORKED);
            }
        }
        let mut log = records.to_vec();
        let mut restored = Vec::new();
        if top > own {
            // A cut tail or an empty host: the missing records from the peer
            // that holds the most, each checked onto the host's chain.
            let mut chain = Chain::new(master);
            for (counter, record) in records {
                chain.push(*counter, record)?;
            }
            while chain.counter() < top {
                let batch = self.fetch(best, chain.counter() + 1)?;
                if batch.is_empty() {
                    return Err(BAD_RESTORE);
                }
                for (counter, record) in batch.into_iter().take_while(|(c, _)| *c <= top) {
                    chain.push(counter, &record).map_err(|_| BAD_RESTORE)?;
                    log.push((counter, record.clone()));
                    restored.push((counter, record));
                }
            }
            if !ct_eq(&chain.tag(), &top_tag) {
                return Err(BAD_RESTORE);
            }
            for (_, counter, tag) in &heads {
                if tag_at(&log, *counter).is_none_or(|held| !ct_eq(&held, tag)) {
                    return Err(FORKED);
                }
            }
        }
        // Every peer that answered holds the whole log before it is used.
        for (index, counter, _) in heads {
            if counter < log.len() as u64 {
                self.catch_up(index, counter, &log)?;
            }
        }
        Ok(restored)
    }

    fn anchor(&mut self, counter: u64, record: &[u8], store: &mut dyn LogStore) -> Result<(), SealError> {
        let tag = record_tag(record).ok_or(NOT_ACKNOWLEDGED)?;
        for index in 0..self.peers.len() {
            let (held, held_tag) = self.ask(index, OP_APPEND, &[&counter.to_be_bytes()[..], record].concat())?;
            if held > counter {
                return Err(PEER_AHEAD);
            }
            if held == counter {
                if !ct_eq(&held_tag, &tag) {
                    return Err(FORKED);
                }
                continue;
            }
            // The peer missed earlier records (it was down when they were
            // written): it is sent them first, from the host's store.
            let log = store.read_all()?;
            if tag_at(&log, held).is_none_or(|own_tag| !ct_eq(&own_tag, &held_tag)) {
                return Err(FORKED);
            }
            let upto: Vec<(u64, Vec<u8>)> = log.into_iter().filter(|(c, _)| *c <= counter).collect();
            self.catch_up(index, held, &upto)?;
        }
        Ok(())
    }
}
