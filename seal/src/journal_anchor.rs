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
//!   chained to the last record it holds for that region and bound to that
//!   region, and that it decodes), keeps it in its own host's store, in a log
//!   per origin region ([`PeerLogs`]), and answers its head of that log. The
//!   save is `Ok` only once every peer answered a head holding the record
//!   ([`Anchor`]); a peer that is unreachable or refuses fails the save, and
//!   the Seal changes no card;
//! - when an enclave starts, after M is installed and before it serves, it
//!   restores **every** log it keeps: each peer log ([`PeerLogs::restore`],
//!   from that origin region or another peer that holds it) and its own log
//!   ([`Anchor`], from its peers). Each restore asks every configured peer
//!   ([`OP_HEAD`]) and refuses (every flow 503, tried again) unless every one
//!   of them answered; a peer head ahead of the copy held (a cut tail, or an
//!   empty store on a replaced host) is restored from the first peer holding
//!   the most ([`OP_FETCH`]), each record checked with M and appended to the
//!   store; a peer head with the same counter and another tag (a fork), a
//!   restored record that fails its check, or a restore that does not end on
//!   the peer's head is a refusal. A peer behind is sent what it lacks.
//!
//! **No copy.** A peer log not restored yet, or empty, answers *no copy*
//! ([`NO_COPY_EMPTY`], [`NO_COPY_NOT_RESTORED`], [`NO_COPY_UNCONFIRMED`]:
//! not restored, but the store holds records), never a zero head; so does an
//! origin asked for its own log before that log is open. A *no copy* answer
//! is never a head and never agrees with one:
//!
//! - an origin's own restore takes heads only when every peer answered a
//!   head; with no head at all it opens an empty log only when its own store
//!   is empty and every peer answered [`NO_COPY_EMPTY`] (a log never
//!   written). A store with records that no peer holds is refused;
//! - a peer log's restore with no head at all keeps the copy it holds (checked
//!   with M), but refuses an empty copy while another holder still has
//!   records it has not confirmed, and a copy with records that another
//!   holder answers is empty.
//!
//! So a region replaced after another (a rolling replacement) restores the
//! other regions' logs before it serves, and the next replacement still
//! finds every log in two places.
//!
//! **Who answers.** Every answer, a head, a *no copy* or a fetch, comes in
//! one envelope:
//!
//! ```text
//! answer   = responder length (1) || responder || document length (u16) || document || mac (32) || body
//! mac      = HMAC-SHA3-256(head key, ghost-seal/v1/journal-head || op (1) || origin length (1) || origin
//!                          || responder length (1) || responder || the asker's nonce (32) || body)
//! document = the responder's fresh Nitro attestation document: nonce = the asker's nonce,
//!            user_data = SHA3-256(ghost-seal/v1/journal-head-answer || mac)
//! body     = 1 || counter (u64) || tag (32)       a head (op 1 append, op 2 head)
//!          | 0 || reason (1)                       no copy (op 2 head)
//!          | (counter (u64) || length (u32) || record)*   records (op 3 fetch)
//! ```
//!
//! The responder is the region id compiled into the responder's image. The
//! asker takes an answer only when that region is the one of the peer port it
//! asked and not its own, the MAC verifies under the head key, and the
//! document verifies with the attestation verifier (the AWS root in an
//! enclave), names a build on the approved list, carries the asker's nonce
//! and the MAC, and carries a parent-instance PCR (PCR4) that is not the
//! asker's own (read from its own attestation): an extra enclave started on
//! the asker's own host never answers for a peer. The answers one restore or
//! one save takes must come from distinct PCR4s, one per peer. The head key
//! is HKDF-SHA3-256 over M with the label [`JOURNAL_HEAD_LABEL`] (salt and
//! info): only an enclave holding M can make it.
//!
//! What this still does not cover: an attacker who can start new EC2
//! instances in the AWS account itself (each has its own PCR4) and route the
//! peer ports to approved enclaves on them; every region lost at once; the
//! hosts of every region cutting the log at once.
//!
//! Requests (the body of service request kind [`SERVICE_KIND`]):
//!
//! ```text
//! op (1) || origin length (1) || origin || nonce (32) || rest
//! op 1 append: rest = counter (u64) || record     answer: the head after it
//! op 2 head:   rest = nothing                     answer: the head, or no copy
//! op 3 fetch:  rest = first counter (u64)         answer: the records
//! ```
//!
//! **Origin bound.** Every record's tag binds the id of the region whose log
//! it is (`journal_log`: the origin's length and id come first under the
//! tag), and a peer checks each append against its log of the origin the
//! request names, from that origin's start. A request needs no caller
//! authentication: anyone can fetch ciphertext, but a record of region A's
//! log never verifies as region B's (not as B's record 1, not chained onto
//! any record of B's), so it cannot be planted in another origin's log; a
//! refused append leaves the peer's log as it was.
//!
//! A fetch answers the records from the first counter on, up to the head,
//! at most [`MAX_FETCH_BYTES`] of them; the asker fetches again from where
//! it ended. Peers and their hosts hold counters and records only: no UID,
//! entry kind, card data or key, and never M.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use zeroize::Zeroizing;

use crate::card_keys::CardUid;
use crate::error::SealError;
use crate::journal_log::{Chain, HeadAnchor, LogStore, MAX_RECORD_BYTES, SharedLog, TAG_BYTES, record_tag};
use crate::primitives::{ct_eq, hkdf_sha3_256, hmac_sha3_256, sha3_256};
use crate::secrets::MasterKey;
use crate::traits::{SealRandom, SystemRandom};

/// The label of the home rule's hash.
pub const HOME_REGION_LABEL: &[u8] = b"ghost-seal/v1/home-region";
/// The HKDF label of the head key, and the first part of every answer's MAC.
pub const JOURNAL_HEAD_LABEL: &[u8] = b"ghost-seal/v1/journal-head";
/// The label of the `user_data` an answer's attestation document carries.
pub const ANSWER_BINDING_LABEL: &[u8] = b"ghost-seal/v1/journal-head-answer";
/// The label of the document an enclave reads its own PCR4 from.
pub const OWN_INSTANCE_LABEL: &[u8] = b"ghost-seal/v1/journal-head-own-instance";
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
/// The most record bytes one fetch answers (with the envelope and its
/// document, an answer stays inside one 64 KiB frame).
pub const MAX_FETCH_BYTES: usize = 32 * 1024;
/// The longest attestation document an answer carries.
pub const MAX_ANSWER_DOCUMENT_BYTES: usize = 16 * 1024;
/// The bytes of a PCR (SHA-384).
pub const PCR_BYTES: usize = 48;
/// Request: append one record.
pub const OP_APPEND: u8 = 1;
/// Request: the head.
pub const OP_HEAD: u8 = 2;
/// Request: the records from a counter on.
pub const OP_FETCH: u8 = 3;
/// No copy: the log is restored (or open) and holds no record.
pub const NO_COPY_EMPTY: u8 = 1;
/// No copy: the log is not restored (or open) yet, and its store is empty.
pub const NO_COPY_NOT_RESTORED: u8 = 2;
/// No copy: the log is not restored (or open) yet, and its store holds
/// records not confirmed yet.
pub const NO_COPY_UNCONFIRMED: u8 = 3;
/// The `reason` of the refusal of a card whose home is another region.
pub const WRONG_REGION_REASON: &str = "wrong-region";
/// Its message.
pub const WRONG_REGION_MESSAGE: &str = "This card is served by its home region";

const HELD: u8 = 1;
const NOT_HELD: u8 = 0;

/// Not every peer answered (one is unreachable, or refused).
pub const NO_PEER: SealError = SealError::Journal("not every peer region answered for the log's head");
/// An answer is not from an attested enclave of that peer region on another
/// instance (or two answers came from one instance).
pub const UNATTESTED: SealError =
    SealError::Journal("a peer region's answer is not attested by that region's enclave on an instance of its own");
/// No peer holds a copy of the log while one is needed (the own store has
/// records, or a peer has not restored its copy yet).
pub const NO_COPY: SealError = SealError::Journal("no peer region holds a copy of this log that can be taken");
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
    [NO_PEER, UNATTESTED, NO_COPY, FORKED, BAD_RESTORE, NOT_ACKNOWLEDGED, PEER_AHEAD].contains(error)
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

/// A parent-instance PCR (PCR4): the hash of the EC2 instance an enclave
/// runs on.
pub type InstancePcr = [u8; PCR_BYTES];

/// What a checked attestation document says, as the anchor needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerDocument {
    /// Its PCR4: the parent instance of the enclave it attests.
    pub pcr4: InstancePcr,
    /// Its `user_data`.
    pub user_data: Vec<u8>,
    /// Its `nonce`.
    pub nonce: Vec<u8>,
}

/// How an enclave attests its answers and checks its peers': in an enclave,
/// its NSM, the attestation verifier over the pinned AWS root and the
/// approved builds (`enclave_serve`); in the tests and the test server, a
/// [`FakeAttester`].
pub trait AnswerAttester: Send + Sync {
    /// A fresh attestation document of this enclave binding `user_data` and
    /// `nonce`.
    fn attest(&self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String>;
    /// Checks `document`: its signature with the attestation verifier, its
    /// build on the approved list; what it says.
    fn check(&self, document: &[u8]) -> Result<AnswerDocument, String>;
}

const FAKE_ATTESTATION_LABEL: &[u8] = b"ghost-seal/test-only/fake-answer-attestation";

/// A stand-in attestation for tests and the test server: documents of a
/// build measurement and a PCR4, tagged with HMAC-SHA3-256 under a key the
/// test picks. It proves nothing about any enclave; the enclave program never
/// builds one. Its PCR4 can be set, as an enclave started on another (or the
/// same) instance would have it.
pub struct FakeAttester {
    key: [u8; 32],
    build: InstancePcr,
    pcr4: Mutex<InstancePcr>,
    approved: Vec<InstancePcr>,
}

impl FakeAttester {
    /// An attester signing with test key `key`, measuring as `build`, on
    /// the instance `pcr4`, that approves the builds `approved`.
    pub fn new(key: [u8; 32], build: InstancePcr, pcr4: InstancePcr, approved: Vec<InstancePcr>) -> FakeAttester {
        FakeAttester { key, build, pcr4: Mutex::new(pcr4), approved }
    }

    /// Moves this enclave to the instance `pcr4`.
    pub fn set_pcr4(&self, pcr4: InstancePcr) {
        *self.pcr4.lock().unwrap_or_else(|e| e.into_inner()) = pcr4;
    }

    /// The instance it reports.
    pub fn pcr4(&self) -> InstancePcr {
        *self.pcr4.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl AnswerAttester for FakeAttester {
    fn attest(&self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
        if user_data.len() > 1024 || nonce.len() > 1024 {
            return Err("user data or nonce is longer than 1024 bytes".into());
        }
        let body = [
            &self.build[..],
            &self.pcr4(),
            &(user_data.len() as u16).to_be_bytes(),
            user_data,
            &(nonce.len() as u16).to_be_bytes(),
            nonce,
        ]
        .concat();
        let tag = hmac_sha3_256(&self.key, &[FAKE_ATTESTATION_LABEL, &body]);
        Ok([&body[..], &tag].concat())
    }

    fn check(&self, document: &[u8]) -> Result<AnswerDocument, String> {
        let bad = || "the fake attestation document is malformed".to_owned();
        let (body, tag) = document.split_at_checked(document.len().checked_sub(32).ok_or_else(bad)?).ok_or_else(bad)?;
        if !ct_eq(&hmac_sha3_256(&self.key, &[FAKE_ATTESTATION_LABEL, body]), tag) {
            return Err("the fake attestation document's tag does not verify".into());
        }
        let build: InstancePcr = body.get(..PCR_BYTES).ok_or_else(bad)?.try_into().map_err(|_| bad())?;
        let pcr4: InstancePcr = body.get(PCR_BYTES..2 * PCR_BYTES).ok_or_else(bad)?.try_into().map_err(|_| bad())?;
        let mut rest = &body[2 * PCR_BYTES..];
        let mut field = || -> Option<Vec<u8>> {
            let length = usize::from(u16::from_be_bytes(rest.get(..2)?.try_into().ok()?));
            let value = rest.get(2..2 + length)?.to_vec();
            rest = &rest[2 + length..];
            Some(value)
        };
        let user_data = field().ok_or_else(bad)?;
        let nonce = field().ok_or_else(bad)?;
        if build == [0u8; PCR_BYTES] || !self.approved.contains(&build) {
            return Err("the fake attestation's build is not approved".into());
        }
        Ok(AnswerDocument { pcr4, user_data, nonce })
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

    fn mac(&self, op: u8, origin: &str, responder: &str, nonce: &[u8; NONCE_BYTES], body: &[u8]) -> [u8; 32] {
        hmac_sha3_256(
            &self.0[..],
            &[
                JOURNAL_HEAD_LABEL,
                &[op, origin.len() as u8],
                origin.as_bytes(),
                &[responder.len() as u8],
                responder.as_bytes(),
                nonce,
                body,
            ],
        )
    }
}

/// The `user_data` of the document that comes with an answer whose MAC is
/// `mac`.
fn answer_binding(mac: &[u8; 32]) -> [u8; 32] {
    sha3_256(&[ANSWER_BINDING_LABEL, mac])
}

/// What a log holds, as a head or no copy answers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    /// Records up to this counter (at least 1), the last with this tag.
    Copy(u64, [u8; TAG_BYTES]),
    /// No copy, and why ([`NO_COPY_EMPTY`] and the others).
    NoCopy(u8),
}

impl Held {
    fn of(chain: &Chain) -> Held {
        match chain.counter() {
            0 => Held::NoCopy(NO_COPY_EMPTY),
            counter => Held::Copy(counter, chain.tag()),
        }
    }

    fn encode(&self) -> Vec<u8> {
        match self {
            Held::Copy(counter, tag) => [&[HELD][..], &counter.to_be_bytes(), tag].concat(),
            Held::NoCopy(reason) => vec![NOT_HELD, *reason],
        }
    }

    /// A body read back; a zero head, or a reason that is none of the three,
    /// is no answer.
    fn decode(body: &[u8]) -> Option<Held> {
        match body.split_first()? {
            (&HELD, rest) if rest.len() == 8 + TAG_BYTES => {
                let counter = counter_of(rest)?;
                (counter > 0).then(|| Held::Copy(counter, rest[8..].try_into().expect("32 bytes")))
            }
            (&NOT_HELD, &[reason]) if (NO_COPY_EMPTY..=NO_COPY_UNCONFIRMED).contains(&reason) => {
                Some(Held::NoCopy(reason))
            }
            _ => None,
        }
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

/// The records of `records` from counter `from` up to `upto`, as a fetch
/// answers them.
fn encode_records(records: &[(u64, Vec<u8>)], from: u64, upto: u64) -> Vec<u8> {
    let mut out = Vec::new();
    for (counter, record) in records.iter().filter(|(c, _)| *c >= from && *c <= upto) {
        if !out.is_empty() && out.len() + 12 + record.len() > MAX_FETCH_BYTES {
            break;
        }
        out.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&(record.len() as u32).to_be_bytes());
        out.extend_from_slice(record);
    }
    out
}

/// An answer in its envelope (see the module notes).
struct Envelope<'a> {
    responder: &'a str,
    document: &'a [u8],
    mac: [u8; 32],
    body: &'a [u8],
}

impl Envelope<'_> {
    fn seal(
        key: &HeadKey,
        attester: &dyn AnswerAttester,
        request: &Request<'_>,
        responder: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mac = key.mac(request.op, request.origin, responder, &request.nonce, body);
        let document = attester.attest(&answer_binding(&mac), &request.nonce)?;
        if document.len() > MAX_ANSWER_DOCUMENT_BYTES {
            return Err("the attestation document is too long".into());
        }
        Ok([
            &[responder.len() as u8][..],
            responder.as_bytes(),
            &(document.len() as u16).to_be_bytes(),
            &document,
            &mac,
            body,
        ]
        .concat())
    }

    fn open(bytes: &[u8]) -> Option<Envelope<'_>> {
        let (&length, bytes) = bytes.split_first()?;
        let length = usize::from(length);
        let responder = std::str::from_utf8(bytes.get(..length)?).ok().filter(|r| valid_region(r))?;
        let bytes = &bytes[length..];
        let document_length = usize::from(u16::from_be_bytes(bytes.get(..2)?.try_into().ok()?));
        if document_length == 0 || document_length > MAX_ANSWER_DOCUMENT_BYTES {
            return None;
        }
        let document = bytes.get(2..2 + document_length)?;
        let bytes = &bytes[2 + document_length..];
        let mac = bytes.get(..32)?.try_into().ok()?;
        Some(Envelope { responder, document, mac, body: &bytes[32..] })
    }
}

/// How a request reaches one peer region's enclave: in the enclave, a
/// framed service request kind [`SERVICE_KIND`] through the parent's
/// outbound proxy (`enclave_serve::ServicePeer`), within [`PEER_DEADLINE`].
pub trait PeerLink: Send + Sync {
    /// Sends one request; the peer's answer, or why it refused or could not
    /// be reached.
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, String>;
}

/// One peer region: its id and how to reach it (its peer port).
#[derive(Clone)]
pub struct Peer {
    /// The peer's region id: the only region an answer on this link is taken
    /// from.
    pub region: String,
    /// How to reach its enclave.
    pub link: Arc<dyn PeerLink>,
}

/// Why one ask failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asked {
    /// Unreachable, or it refused.
    Unreachable,
    /// An answer, but not one taken (see [`Peers`]).
    Unattested,
}

impl Asked {
    /// As a restore reports it.
    fn at_restore(self) -> SealError {
        match self {
            Asked::Unreachable => NO_PEER,
            Asked::Unattested => UNATTESTED,
        }
    }

    /// As a save reports it.
    fn at_save(self) -> SealError {
        match self {
            Asked::Unreachable => NOT_ACKNOWLEDGED,
            Asked::Unattested => UNATTESTED,
        }
    }
}

/// The PCR4s one restore or one save took its answers from, one per peer:
/// a peer's answers all come from one instance, and no two peers share one.
struct Round(Vec<Option<InstancePcr>>);

impl Round {
    fn new(peers: usize) -> Round {
        Round(vec![None; peers])
    }

    fn note(&mut self, index: usize, pcr4: InstancePcr) -> bool {
        if let Some(held) = self.0[index] {
            return held == pcr4;
        }
        if self.0.iter().any(|seen| *seen == Some(pcr4)) {
            return false;
        }
        self.0[index] = Some(pcr4);
        true
    }
}

/// This region's peer regions, as it asks them: their links, the random
/// source of its nonces and the attester that checks their answers (and
/// attests this region's own). Shared by its [`Anchor`] and its
/// [`PeerLogs`].
pub struct Peers {
    own: String,
    peers: Vec<Peer>,
    random: Mutex<Box<dyn SealRandom + Send>>,
    attester: Mutex<Option<Arc<dyn AnswerAttester>>>,
    own_pcr4: Mutex<Option<InstancePcr>>,
}

impl Peers {
    /// The `peers` of region `own`, nonces from the system's random source,
    /// no attester yet (every ask is refused until one is installed).
    pub fn new(own: &str, peers: Vec<Peer>) -> Peers {
        Peers {
            own: own.to_owned(),
            peers,
            random: Mutex::new(Box::new(SystemRandom)),
            attester: Mutex::new(None),
            own_pcr4: Mutex::new(None),
        }
    }

    /// The same, its nonces from `random`.
    pub fn with_random(self, random: Box<dyn SealRandom + Send>) -> Peers {
        *self.random.lock().unwrap_or_else(|e| e.into_inner()) = random;
        self
    }

    /// The same, with `attester`.
    pub fn with_attester(self, attester: Arc<dyn AnswerAttester>) -> Peers {
        self.install_attester(attester);
        self
    }

    /// Installs the attester (the enclave's, once its service exists).
    pub fn install_attester(&self, attester: Arc<dyn AnswerAttester>) {
        *self.attester.lock().unwrap_or_else(|e| e.into_inner()) = Some(attester);
        *self.own_pcr4.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// This region.
    pub fn own(&self) -> &str {
        &self.own
    }

    /// The peer regions, in order.
    pub fn regions(&self) -> Vec<&str> {
        self.peers.iter().map(|peer| peer.region.as_str()).collect()
    }

    fn attester(&self) -> Option<Arc<dyn AnswerAttester>> {
        self.attester.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// This enclave's own PCR4, read once from its own checked document.
    fn own_pcr4(&self, attester: &dyn AnswerAttester) -> Option<InstancePcr> {
        let mut held = self.own_pcr4.lock().unwrap_or_else(|e| e.into_inner());
        if held.is_none() {
            let binding = sha3_256(&[OWN_INSTANCE_LABEL]);
            let document = attester.attest(&binding, &binding).ok()?;
            let own = attester.check(&document).ok()?;
            if own.user_data != binding || own.nonce != binding || own.pcr4 == [0u8; PCR_BYTES] {
                return None;
            }
            *held = Some(own.pcr4);
        }
        *held
    }

    fn nonce(&self) -> Result<[u8; NONCE_BYTES], SealError> {
        let mut nonce = [0u8; NONCE_BYTES];
        self.random.lock().unwrap_or_else(|e| e.into_inner()).fill(&mut nonce)?;
        Ok(nonce)
    }

    /// Asks peer `index` about `origin`'s log with a fresh nonce; the body
    /// of its answer, if the answer is taken (see the module notes).
    fn ask(
        &self,
        key: &HeadKey,
        round: &mut Round,
        index: usize,
        op: u8,
        origin: &str,
        rest: &[u8],
    ) -> Result<Vec<u8>, Asked> {
        let attester = self.attester().ok_or(Asked::Unattested)?;
        let own_pcr4 = self.own_pcr4(attester.as_ref()).ok_or(Asked::Unattested)?;
        let nonce = self.nonce().map_err(|_| Asked::Unreachable)?;
        let peer = &self.peers[index];
        let answer = peer.link.exchange(&encode(op, origin, &nonce, rest)).map_err(|_| Asked::Unreachable)?;
        let envelope = Envelope::open(&answer).ok_or(Asked::Unattested)?;
        // The responder's compiled-in region: the one this port leads to, and
        // never this region's own.
        if envelope.responder != peer.region || envelope.responder == self.own {
            return Err(Asked::Unattested);
        }
        if !ct_eq(&key.mac(op, origin, envelope.responder, &nonce, envelope.body), &envelope.mac) {
            return Err(Asked::Unattested);
        }
        let document = attester.check(envelope.document).map_err(|_| Asked::Unattested)?;
        if document.nonce != nonce || document.user_data != answer_binding(&envelope.mac) {
            return Err(Asked::Unattested);
        }
        // An enclave on this host (its own PCR4) never answers for a peer,
        // and one instance never answers for two.
        if document.pcr4 == [0u8; PCR_BYTES] || document.pcr4 == own_pcr4 || !round.note(index, document.pcr4) {
            return Err(Asked::Unattested);
        }
        Ok(envelope.body.to_vec())
    }

    /// Every peer's head of `origin`'s log; refused unless every peer
    /// answered.
    fn heads(&self, key: &HeadKey, round: &mut Round, origin: &str) -> Result<Vec<(usize, Held)>, SealError> {
        let mut answers = Vec::new();
        let mut failed = None;
        for index in 0..self.peers.len() {
            match self.ask(key, round, index, OP_HEAD, origin, &[]) {
                Ok(body) => match Held::decode(&body) {
                    Some(held) => answers.push((index, held)),
                    None => failed = Some(Asked::Unattested),
                },
                Err(why) => {
                    if failed != Some(Asked::Unattested) {
                        failed = Some(why);
                    }
                }
            }
        }
        match failed {
            Some(why) => Err(why.at_restore()),
            None => Ok(answers),
        }
    }

    fn fetch(&self, key: &HeadKey, round: &mut Round, index: usize, origin: &str, from: u64) -> Result<Vec<(u64, Vec<u8>)>, SealError> {
        let body = self.ask(key, round, index, OP_FETCH, origin, &from.to_be_bytes()).map_err(|why| match why {
            Asked::Unreachable => BAD_RESTORE,
            Asked::Unattested => UNATTESTED,
        })?;
        decode_records(&body).ok_or(BAD_RESTORE)
    }

    /// Has peer `index` take record `counter` of `origin`'s log; the head it
    /// then holds.
    fn append(
        &self,
        key: &HeadKey,
        round: &mut Round,
        index: usize,
        origin: &str,
        counter: u64,
        record: &[u8],
    ) -> Result<(u64, [u8; TAG_BYTES]), SealError> {
        let body = self
            .ask(key, round, index, OP_APPEND, origin, &[&counter.to_be_bytes()[..], record].concat())
            .map_err(Asked::at_save)?;
        match Held::decode(&body) {
            Some(Held::Copy(held, tag)) => Ok((held, tag)),
            Some(Held::NoCopy(_)) => Ok((0, [0u8; TAG_BYTES])),
            None => Err(UNATTESTED),
        }
    }

    /// Has peer `index`, whose head is at `head`, take every record of
    /// `origin`'s `log` after it.
    fn catch_up(
        &self,
        key: &HeadKey,
        round: &mut Round,
        index: usize,
        origin: &str,
        head: u64,
        log: &[(u64, Vec<u8>)],
    ) -> Result<(), SealError> {
        for (counter, record) in log.iter().filter(|(c, _)| *c > head) {
            let tag = record_tag(record).ok_or(NOT_ACKNOWLEDGED)?;
            let (held, held_tag) = self.append(key, round, index, origin, *counter, record)?;
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

    /// The records `heads` hold past `local` (a copy of `origin`'s log,
    /// already checked with `master`), fetched from the first peer that
    /// holds the most and checked onto `local`'s chain; refused on a fork, a
    /// record that fails, or a restore that does not end on that head.
    fn extend(
        &self,
        key: &HeadKey,
        round: &mut Round,
        master: &MasterKey,
        origin: &str,
        local: &[(u64, Vec<u8>)],
        heads: &[(usize, u64, [u8; TAG_BYTES])],
    ) -> Result<Vec<(u64, Vec<u8>)>, SealError> {
        let held = local.len() as u64;
        let top = heads.iter().map(|(_, counter, _)| *counter).max().unwrap_or(0);
        // A peer at or behind the copy held must hold the same records.
        for (_, counter, tag) in heads.iter().filter(|(_, counter, _)| *counter <= held) {
            if tag_at(local, *counter).is_none_or(|own_tag| !ct_eq(&own_tag, tag)) {
                return Err(FORKED);
            }
        }
        if top <= held {
            return Ok(Vec::new());
        }
        let &(best, _, top_tag) = heads.iter().find(|(_, counter, _)| *counter == top).expect("the top is a head");
        let mut chain = Chain::new(master, origin);
        for (counter, record) in local {
            chain.push(*counter, record).map_err(|_| BAD_RESTORE)?;
        }
        let mut log = local.to_vec();
        let mut restored = Vec::new();
        while chain.counter() < top {
            let batch = self.fetch(key, round, best, origin, chain.counter() + 1)?;
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
        for (_, counter, tag) in heads {
            if tag_at(&log, *counter).is_none_or(|held| !ct_eq(&held, tag)) {
                return Err(FORKED);
            }
        }
        Ok(restored)
    }
}

/// The tag of record `counter` of `log` (zeros for counter 0).
fn tag_at(log: &[(u64, Vec<u8>)], counter: u64) -> Option<[u8; TAG_BYTES]> {
    if counter == 0 {
        return Some([0u8; TAG_BYTES]);
    }
    log.get(usize::try_from(counter - 1).ok()?).and_then(|(_, record)| record_tag(record))
}

/// The heads among `answers`.
fn copies(answers: &[(usize, Held)]) -> Vec<(usize, u64, [u8; TAG_BYTES])> {
    answers
        .iter()
        .filter_map(|(index, held)| match held {
            Held::Copy(counter, tag) => Some((*index, *counter, *tag)),
            Held::NoCopy(_) => None,
        })
        .collect()
}

fn says(answers: &[(usize, Held)], reason: u8) -> bool {
    answers.iter().any(|(_, held)| *held == Held::NoCopy(reason))
}

/// The log a peer region keeps for one origin region.
struct OriginLog {
    store: Box<dyn LogStore>,
    /// The chain checked so far, once the copy was restored at the start.
    chain: Option<Chain>,
}

impl OriginLog {
    /// The no copy of a log not restored yet.
    fn unrestored(&mut self) -> Result<Held, &'static str> {
        let records = self.store.read_all().map_err(|_| "the peer log cannot be read")?;
        Ok(Held::NoCopy(if records.is_empty() { NO_COPY_NOT_RESTORED } else { NO_COPY_UNCONFIRMED }))
    }
}

/// This region's own log, as it answers its peers' restores of their copy
/// of it: the open log's head, and a handle on its host's store.
struct OwnLog {
    log: Arc<SharedLog>,
    store: Mutex<Box<dyn LogStore>>,
}

/// A region's side as a peer: the logs it keeps for the other regions, each
/// in its own store on its host (`/var/lib/seal/peer-<region>.log` in a real
/// Seal), restored at its start, and its attested answers to their
/// requests (and, with [`PeerLogs::with_own_log`], to their restores of
/// their copies of its own log).
pub struct PeerLogs {
    own: String,
    peers: Arc<Peers>,
    logs: BTreeMap<String, Mutex<OriginLog>>,
    own_log: Option<OwnLog>,
}

impl PeerLogs {
    /// The logs of region `peers.own()`, one in each of `stores` for the
    /// origin region it names, restored from `peers`. A request about any
    /// other region is refused.
    pub fn new(peers: Arc<Peers>, stores: Vec<(String, Box<dyn LogStore>)>) -> PeerLogs {
        let own = peers.own().to_owned();
        let logs = stores
            .into_iter()
            .filter(|(region, _)| *region != own)
            .map(|(region, store)| (region, Mutex::new(OriginLog { store, chain: None })))
            .collect();
        PeerLogs { own, peers, logs, own_log: None }
    }

    /// The same, answering about this region's own `log` too (its head once
    /// open, its records from `store`, a handle on the same host store).
    pub fn with_own_log(mut self, log: Arc<SharedLog>, store: Box<dyn LogStore>) -> PeerLogs {
        self.own_log = Some(OwnLog { log, store: Mutex::new(store) });
        self
    }

    /// The peers it restores from.
    pub fn peers(&self) -> &Arc<Peers> {
        &self.peers
    }

    /// The origin regions whose logs this region keeps.
    pub fn origins(&self) -> Vec<String> {
        self.logs.keys().cloned().collect()
    }

    /// Whether the copy of `origin`'s log was restored.
    pub fn is_restored(&self, origin: &str) -> bool {
        self.logs.get(origin).is_some_and(|log| lock(log).chain.is_some())
    }

    /// Whether every copy was restored.
    pub fn all_restored(&self) -> bool {
        self.logs.values().all(|log| lock(log).chain.is_some())
    }

    /// Restores every copy not restored yet, each with `master` (see the
    /// module notes); the first refusal, once every copy was tried.
    pub fn restore(&self, master: &MasterKey) -> Result<(), SealError> {
        let mut refused = None;
        for origin in self.logs.keys() {
            if let Err(error) = self.restore_origin(master, origin) {
                refused.get_or_insert(error);
            }
        }
        refused.map_or(Ok(()), Err)
    }

    fn restore_origin(&self, master: &MasterKey, origin: &str) -> Result<(), SealError> {
        let slot = &self.logs[origin];
        // No lock is held while the peers are asked: their own restores ask
        // this region in turn.
        let local = {
            let mut log = lock(slot);
            if log.chain.is_some() {
                return Ok(());
            }
            log.store.read_all()?
        };
        let mut chain = Chain::new(master, origin);
        for (counter, record) in &local {
            chain.push(*counter, record).map_err(|_| BAD_RESTORE)?;
        }
        let key = HeadKey::derive(master);
        let mut round = Round::new(self.peers.peers.len());
        let answers = self.peers.heads(&key, &mut round, origin)?;
        let heads = copies(&answers);
        let restored = if heads.is_empty() {
            // No holder has a copy to take. The copy held stays, unless a
            // holder says the log is empty while this one has records, or
            // this one is empty while a holder has records not confirmed.
            if !local.is_empty() && says(&answers, NO_COPY_EMPTY) {
                return Err(NO_COPY);
            }
            if local.is_empty() && says(&answers, NO_COPY_UNCONFIRMED) {
                return Err(NO_COPY);
            }
            Vec::new()
        } else {
            self.peers.extend(&key, &mut round, master, origin, &local, &heads)?
        };
        let mut log = lock(slot);
        if log.chain.is_some() {
            return Ok(());
        }
        if log.store.read_all()? != local {
            return Err(BAD_RESTORE);
        }
        for (counter, record) in &restored {
            chain.push(*counter, record).map_err(|_| BAD_RESTORE)?;
            log.store.append(*counter, record)?;
        }
        log.chain = Some(chain);
        Ok(())
    }

    /// The answer to one request, checked with `master` (the M this enclave
    /// holds) and attested, or why it was refused.
    pub fn answer(&self, master: &MasterKey, body: &[u8]) -> Result<Vec<u8>, String> {
        let request = decode(body)?;
        let attester = self.peers.attester().ok_or("this enclave cannot attest its answers yet")?;
        let key = HeadKey::derive(master);
        let answered = if request.origin == self.own {
            self.answer_own(master, &request)?
        } else {
            let slot = self.logs.get(request.origin).ok_or("this region keeps no log of that origin")?;
            answer_peer(&mut lock(slot), &request)?
        };
        // Attested once no log is held: the NSM may take its time.
        Envelope::seal(&key, attester.as_ref(), &request, &self.own, &answered)
    }

    /// About this region's own log: its head once open (no copy before).
    fn answer_own(&self, master: &MasterKey, request: &Request<'_>) -> Result<Vec<u8>, String> {
        let own = self.own_log.as_ref().ok_or("this region keeps no peer log of itself")?;
        let head = own.log.head();
        match request.op {
            OP_HEAD if request.rest.is_empty() => {
                let held = match head {
                    Some((0, _)) => Held::NoCopy(NO_COPY_EMPTY),
                    Some((counter, tag)) => Held::Copy(counter, tag),
                    None => {
                        let records = lock(&own.store).read_all().map_err(|_| "this region's log cannot be read")?;
                        Held::NoCopy(if records.is_empty() { NO_COPY_NOT_RESTORED } else { NO_COPY_UNCONFIRMED })
                    }
                };
                Ok(held.encode())
            }
            OP_FETCH => {
                let from = counter_of(request.rest).filter(|_| request.rest.len() == 8);
                let from = from.ok_or("a journal head request is malformed")?;
                let (upto, _) = head.ok_or("this region's log is not open yet")?;
                let records = lock(&own.store).read_all().map_err(|_| "this region's log cannot be read")?;
                // Only what the open log holds, checked as it was written.
                let mut chain = Chain::new(master, &self.own);
                for (counter, record) in records.iter().filter(|(c, _)| *c <= upto) {
                    chain.push(*counter, record).map_err(|_| "this region's log fails its checks")?;
                }
                Ok(encode_records(&records, from, chain.counter()))
            }
            OP_APPEND => Err("this region takes no record of its own log from a peer".into()),
            _ => Err("unknown journal head request".into()),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// About a peer log: its head and records once restored (no copy before),
/// and the next record appended.
fn answer_peer(log: &mut OriginLog, request: &Request<'_>) -> Result<Vec<u8>, String> {
    match request.op {
        OP_HEAD if request.rest.is_empty() => {
            let held = match &log.chain {
                Some(chain) => Held::of(chain),
                None => log.unrestored()?,
            };
            Ok(held.encode())
        }
        OP_APPEND => {
            let counter = counter_of(request.rest).ok_or("a journal head request is malformed")?;
            let record = &request.rest[8..];
            let OriginLog { store, chain } = log;
            let chain = chain.as_mut().ok_or("this region has not restored its copy of that log yet")?;
            // Only the next record is taken; for any other the head answers
            // what this region holds.
            if Some(counter) == chain.counter().checked_add(1) {
                let mut next = chain.clone();
                next.push(counter, record).map_err(|_| "the record does not chain onto that origin's log")?;
                store.append(counter, record).map_err(|_| "the peer log store did not take the record")?;
                *chain = next;
            }
            Ok(Held::of(chain).encode())
        }
        OP_FETCH => {
            let from = counter_of(request.rest).filter(|_| request.rest.len() == 8);
            let from = from.ok_or("a journal head request is malformed")?;
            let upto = log.chain.as_ref().ok_or("this region has not restored its copy of that log yet")?.counter();
            let records = log.store.read_all().map_err(|_| "the peer log cannot be read")?;
            Ok(encode_records(&records, from, upto))
        }
        _ => Err("unknown journal head request".into()),
    }
}

/// The origin region's side: anchors its log's head in every peer (see the
/// module notes). What a log is opened with (`journal_log::SharedLog::anchored`).
pub struct Anchor {
    peers: Arc<Peers>,
    key: Option<HeadKey>,
}

impl Anchor {
    /// The anchor of region `peers.own()`'s log in `peers`.
    pub fn new(peers: Arc<Peers>) -> Anchor {
        Anchor { peers, key: None }
    }

    /// The peer regions, in order.
    pub fn peers(&self) -> Vec<&str> {
        self.peers.regions()
    }
}

impl HeadAnchor for Anchor {
    fn origin(&self) -> &str {
        self.peers.own()
    }

    fn restore(&mut self, master: &MasterKey, records: &[(u64, Vec<u8>)]) -> Result<Vec<(u64, Vec<u8>)>, SealError> {
        let key = HeadKey::derive(master);
        let origin = self.peers.own().to_owned();
        let mut round = Round::new(self.peers.peers.len());
        // Every peer, not one.
        let answers = self.peers.heads(&key, &mut round, &origin)?;
        let heads = copies(&answers);
        if heads.is_empty() {
            // Nothing anywhere to take: only a log never written opens
            // empty. A store with records no peer holds, or a peer that has
            // not restored its copy yet, is refused.
            if !records.is_empty() || answers.iter().any(|(_, held)| *held != Held::NoCopy(NO_COPY_EMPTY)) {
                return Err(NO_COPY);
            }
            self.key = Some(key);
            return Ok(Vec::new());
        }
        // A no copy never agrees with a head: every peer must hold one.
        if heads.len() != answers.len() {
            return Err(NO_COPY);
        }
        let restored = self.peers.extend(&key, &mut round, master, &origin, records, &heads)?;
        let log: Vec<(u64, Vec<u8>)> = records.iter().cloned().chain(restored.iter().cloned()).collect();
        // Every peer holds the whole log before it is used.
        for (index, counter, _) in heads {
            if counter < log.len() as u64 {
                self.peers.catch_up(&key, &mut round, index, &origin, counter, &log)?;
            }
        }
        self.key = Some(key);
        Ok(restored)
    }

    fn anchor(&mut self, counter: u64, record: &[u8], store: &mut dyn LogStore) -> Result<(), SealError> {
        let key = self.key.as_ref().ok_or(NOT_ACKNOWLEDGED)?;
        let origin = self.peers.own();
        let tag = record_tag(record).ok_or(NOT_ACKNOWLEDGED)?;
        let mut round = Round::new(self.peers.peers.len());
        for index in 0..self.peers.peers.len() {
            let (held, held_tag) = self.peers.append(key, &mut round, index, origin, counter, record)?;
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
            self.peers.catch_up(key, &mut round, index, origin, held, &upto)?;
        }
        Ok(())
    }
}
