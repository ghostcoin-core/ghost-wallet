//! The relay's HTTP routes, as the enclave serves them to phones (feature
//! `nitro`): `docs/seal-relay.md` as written, plus the phone attestation.
//!
//! [`Routes::answer`] turns one request (method, path, body) into one answer
//! (HTTP status, JSON body) over a [`Relay`]; [`serve_http`] reads HTTP/1.1
//! requests off a byte stream (inside the enclave, the TLS stream of
//! `enclave_tls`), answers each and keeps the connection for the next one.
//!
//! | path | flow |
//! | --- | --- |
//! | `POST /v1/check/start` | [`Relay::start_check`] |
//! | `POST /v1/fill/start` | [`Relay::start_fill`] |
//! | `POST /v1/fill/confirm` | [`Relay::start_confirm_fill`] |
//! | `POST /v1/open/start` | [`Relay::start_open`] |
//! | `POST /v1/relay/step` | [`Relay::step_flow`] |
//! | `POST /v1/relay/abort` | [`Relay::abort`] |
//! | `POST /v1/attestation` | the `GPA2` phone attestation for a challenge |
//!
//! Without [`Flows`] (a Seal that is not ready to answer cards), every flow
//! route answers HTTP 503 `unavailable` and sends the card nothing; the
//! attestation route still answers.
//!
//! Nothing here logs: no path, header or body is ever written anywhere but
//! back to the phone, and no answer or message carries the PIN, which is
//! read only from a Fill or Open start and wiped once the request is
//! answered.

use std::io::{self, ErrorKind, Read, Write};
use std::ops::RangeInclusive;
use std::sync::Arc;

use serde_json::{Map, Value, json};
use zeroize::Zeroize;

use crate::card_keys::CardUid;
use crate::error::SealError;
use crate::phone_attestation::CHALLENGE_BYTES;
use crate::relay::{
    Finished, FlowStep, KeyMakerFactory, PaymentCheckFactory, Relay, RelayError, SessionId, Step, from_hex, to_hex,
};
use crate::release::PHONE_KEY_BYTES;
use crate::secrets::Pin;

/// The longest request body taken.
pub const MAX_BODY_BYTES: usize = 4096;
/// The longest request head taken (request line and headers).
pub const MAX_HEAD_BYTES: usize = 8 * 1024;
/// The most headers a request may have.
pub const MAX_HEADERS: usize = 32;
/// The message of every flow request a Seal that is not ready refuses.
pub const NOT_READY_MESSAGE: &str = "This Seal is not ready to answer cards";
/// The message of an attestation request the Seal cannot answer now.
pub const NOT_ATTESTING_MESSAGE: &str = "This Seal cannot attest right now";

/// A Fill's Open PIN: 4 to 8 digits.
const FILL_PIN_DIGITS: RangeInclusive<usize> = 4..=8;
/// An Open's PIN: whatever a card may hold (`Pin`: 4 to 12 digits).
const OPEN_PIN_DIGITS: RangeInclusive<usize> = 4..=12;
/// The digits of the largest amount in wei (`u128::MAX` has 39).
const MAX_AMOUNT_DIGITS: usize = 39;
/// How much is read from the stream at once.
const READ_CHUNK_BYTES: usize = 2048;

/// One answer: an HTTP status and its JSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The HTTP status.
    pub status: u16,
    /// The JSON body, as text.
    pub body: String,
}

impl Reply {
    fn ok(body: Value) -> Reply {
        Reply { status: 200, body: body.to_string() }
    }

    fn error(status: u16, code: &str, message: &str) -> Reply {
        Reply { status, body: json!({ "status": "error", "error": code, "message": message }).to_string() }
    }

    fn refused(message: &str, reason: Option<&str>) -> Reply {
        let mut body = Map::new();
        body.insert("status".into(), "error".into());
        body.insert("error".into(), "refused".into());
        body.insert("message".into(), message.into());
        if let Some(reason) = reason {
            body.insert("reason".into(), reason.into());
        }
        Reply { status: 422, body: Value::Object(body).to_string() }
    }

    fn not_ready() -> Reply {
        Reply::error(503, "unavailable", NOT_READY_MESSAGE)
    }
}

/// Why the attestation route could not answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestRefused {
    /// The Seal holds no M yet, so it has no answer key to attest.
    NotReady,
    /// The attestation could not be made now (the NSM failed).
    Failed,
}

/// What answers `POST /v1/attestation`: the `GPA2` phone attestation for a
/// challenge, binding the TLS certificate the enclave serves.
pub trait PhoneAttester: Send + Sync {
    /// The attestation for `challenge`.
    fn attest(&self, challenge: &[u8; CHALLENGE_BYTES]) -> Result<Vec<u8>, AttestRefused>;
}

/// What the flow routes run on: the relay, and what a Fill and its
/// confirmation are given besides the Seal.
pub struct Flows {
    /// The relay whose sessions run the flows.
    pub relay: Arc<Relay>,
    /// Makes a Fill's Phantom Key maker. Without one, a Fill answers
    /// `unavailable` (the other flows are served).
    pub key_maker: Option<KeyMakerFactory>,
    /// Makes a Fill confirmation's payment check.
    pub payment: PaymentCheckFactory,
}

/// The routes of `docs/seal-relay.md` and the attestation route.
pub struct Routes {
    flows: Option<Flows>,
    attester: Option<Arc<dyn PhoneAttester>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    CheckStart,
    FillStart,
    FillConfirm,
    OpenStart,
    Step,
    Abort,
    Attestation,
}

impl Route {
    fn of(path: &str) -> Option<Route> {
        match path.split('?').next().unwrap_or("") {
            "/v1/check/start" => Some(Route::CheckStart),
            "/v1/fill/start" => Some(Route::FillStart),
            "/v1/fill/confirm" => Some(Route::FillConfirm),
            "/v1/open/start" => Some(Route::OpenStart),
            "/v1/relay/step" => Some(Route::Step),
            "/v1/relay/abort" => Some(Route::Abort),
            "/v1/attestation" => Some(Route::Attestation),
            _ => None,
        }
    }
}

impl Routes {
    /// Routes serving `flows` (`None`: every flow request is refused as
    /// `unavailable`) and the attestation from `attester` (`None`: refused
    /// as `unavailable` too).
    pub fn new(flows: Option<Flows>, attester: Option<Arc<dyn PhoneAttester>>) -> Routes {
        Routes { flows, attester }
    }

    /// Whether the flow routes are served.
    pub fn serves_flows(&self) -> bool {
        self.flows.is_some()
    }

    /// The answer to one request.
    pub fn answer(&self, method: &str, path: &str, body: &[u8]) -> Reply {
        self.route(method, path, (body.len() <= MAX_BODY_BYTES).then_some(body))
    }

    /// The answer to one request whose body is `None` when it is over
    /// [`MAX_BODY_BYTES`].
    fn route(&self, method: &str, path: &str, body: Option<&[u8]>) -> Reply {
        let Some(route) = Route::of(path) else {
            return Reply::error(404, "not-found", "no such path");
        };
        if method != "POST" {
            return Reply::error(405, "method", "use POST");
        }
        let Some(body) = body else {
            return Reply::error(413, "too-large", "the request is too large");
        };
        if route == Route::Attestation {
            return self.attestation(body);
        }
        let Some(flows) = &self.flows else {
            return Reply::not_ready();
        };
        let mut fields = match serde_json::from_slice::<Value>(body) {
            Ok(fields @ Value::Object(_)) => fields,
            _ => return Reply::error(400, "bad-request", "the body is not a JSON object"),
        };
        let result = match route {
            Route::CheckStart => start_check(flows, &fields),
            Route::FillStart => start_fill(flows, &fields),
            Route::FillConfirm => start_confirm_fill(flows, &fields),
            Route::OpenStart => start_open(flows, &fields),
            Route::Step => step(flows, &fields),
            Route::Abort => abort(flows, &fields),
            Route::Attestation => return self.attestation(body),
        };
        if let Some(Value::String(pin)) = fields.get_mut("pin") {
            pin.zeroize();
        }
        result.unwrap_or_else(|error| refusal(&error))
    }

    fn attestation(&self, body: &[u8]) -> Reply {
        let Some(attester) = &self.attester else {
            return Reply::error(503, "unavailable", NOT_ATTESTING_MESSAGE);
        };
        let fields = match serde_json::from_slice::<Value>(body) {
            Ok(fields @ Value::Object(_)) => fields,
            _ => return Reply::error(400, "bad-request", "the body is not a JSON object"),
        };
        let challenge = match hex_field::<CHALLENGE_BYTES>(&fields, "challenge") {
            Ok(challenge) => challenge,
            Err(error) => return refusal(&error),
        };
        match attester.attest(&challenge) {
            Ok(attestation) => Reply::ok(json!({ "status": "ok", "attestation": to_hex(&attestation) })),
            Err(AttestRefused::NotReady) => Reply::error(503, "unavailable", "This Seal holds no master key yet"),
            Err(AttestRefused::Failed) => Reply::error(503, "unavailable", NOT_ATTESTING_MESSAGE),
        }
    }
}

fn hex_field<const N: usize>(fields: &Value, name: &'static str) -> Result<[u8; N], RelayError> {
    fields
        .get(name)
        .and_then(Value::as_str)
        .and_then(from_hex)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(RelayError::BadRequest(name))
}

fn uid_field(fields: &Value) -> Result<CardUid, RelayError> {
    hex_field::<7>(fields, "uid").map(CardUid)
}

fn session_field(fields: &Value) -> Result<SessionId, RelayError> {
    hex_field::<16>(fields, "session").map(SessionId)
}

/// `amountWei`: a string of decimal digits.
fn amount_field(fields: &Value) -> Result<u128, RelayError> {
    let text = fields.get("amountWei").and_then(Value::as_str).ok_or(RelayError::BadRequest("amountWei"))?;
    if text.is_empty() || text.len() > MAX_AMOUNT_DIGITS || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(RelayError::BadRequest("amountWei"));
    }
    text.parse::<u128>().map_err(|_| RelayError::BadRequest("amountWei"))
}

/// `pin`, left out (or null) for none. A malformed PIN is refused by its
/// field's name only; the PIN itself never goes into a message.
fn pin_field(fields: &Value, digits: RangeInclusive<usize>) -> Result<Option<Pin>, RelayError> {
    match fields.get("pin") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if digits.contains(&text.len()) => {
            Pin::new(text).map(Some).map_err(|_| RelayError::BadRequest("pin"))
        }
        Some(_) => Err(RelayError::BadRequest("pin")),
    }
}

fn flow_reply(step: FlowStep) -> Reply {
    match step {
        FlowStep::Apdu { session, apdu } => {
            Reply::ok(json!({ "status": "apdu", "session": session.to_hex(), "apdu": to_hex(&apdu) }))
        }
        FlowStep::Done(finished) => {
            let mut body = Map::new();
            body.insert("status".into(), "done".into());
            body.insert("answer".into(), to_hex(&finished.answer.bytes).into());
            body.insert("signature".into(), to_hex(&finished.answer.signature).into());
            if let Some(commit_data) = &finished.commit_data {
                body.insert("commitData".into(), to_hex(commit_data).into());
            }
            if let Some(release) = &finished.release {
                body.insert("release".into(), to_hex(release).into());
            }
            Reply::ok(Value::Object(body))
        }
    }
}

fn start_check(flows: &Flows, fields: &Value) -> Result<Reply, RelayError> {
    let uid = uid_field(fields)?;
    let challenge = hex_field::<32>(fields, "challenge")?;
    flows.relay.start_check(uid, challenge).map(|step| flow_reply(step_as_flow(step)))
}

fn step_as_flow(step: Step) -> FlowStep {
    match step {
        Step::Apdu { session, apdu } => FlowStep::Apdu { session, apdu },
        Step::Done(answer) => FlowStep::Done(Finished { answer, commit_data: None, release: None }),
    }
}

fn start_fill(flows: &Flows, fields: &Value) -> Result<Reply, RelayError> {
    let Some(maker) = &flows.key_maker else {
        return Ok(Reply::not_ready());
    };
    let uid = uid_field(fields)?;
    let challenge = hex_field::<32>(fields, "challenge")?;
    let amount_wei = amount_field(fields)?;
    let pin = pin_field(fields, FILL_PIN_DIGITS)?;
    flows.relay.start_fill(uid, challenge, amount_wei, pin, Arc::clone(maker)).map(flow_reply)
}

fn start_confirm_fill(flows: &Flows, fields: &Value) -> Result<Reply, RelayError> {
    let uid = uid_field(fields)?;
    let challenge = hex_field::<32>(fields, "challenge")?;
    flows.relay.start_confirm_fill(uid, challenge, Arc::clone(&flows.payment)).map(flow_reply)
}

fn start_open(flows: &Flows, fields: &Value) -> Result<Reply, RelayError> {
    let uid = uid_field(fields)?;
    let challenge = hex_field::<32>(fields, "challenge")?;
    let phone_key = fields
        .get("phoneKey")
        .and_then(Value::as_str)
        .and_then(from_hex)
        .filter(|key| key.len() == PHONE_KEY_BYTES)
        .ok_or(RelayError::BadRequest("phoneKey"))?;
    let pin = pin_field(fields, OPEN_PIN_DIGITS)?;
    flows.relay.start_open(uid, challenge, phone_key, pin).map(flow_reply)
}

fn step(flows: &Flows, fields: &Value) -> Result<Reply, RelayError> {
    let session = session_field(fields)?;
    let answer = fields
        .get("answer")
        .and_then(Value::as_str)
        .and_then(from_hex)
        .ok_or(RelayError::BadRequest("answer"))?;
    flows.relay.step_flow(&session, &answer).map(flow_reply)
}

fn abort(flows: &Flows, fields: &Value) -> Result<Reply, RelayError> {
    let session = session_field(fields)?;
    flows.relay.abort(&session).map(|()| Reply::ok(json!({ "status": "aborted" })))
}

/// The `reason` of a refusal, so the phone can say what the card is
/// (`docs/seal-relay.md`, "Why a card was refused").
pub fn reason(error: &SealError) -> Option<&'static str> {
    match error {
        SealError::NotAGhostCard | SealError::UnknownKeys => Some("not-a-ghost-card"),
        SealError::NotSettled => Some("filling"),
        SealError::NotPaid => Some("not-paid"),
        SealError::CantCheckNow => Some("cant-check-now"),
        SealError::CoinSpent => Some("spent"),
        SealError::PinRequired => Some("pin-required"),
        SealError::WrongPin { .. } => Some("wrong-pin"),
        SealError::PinLocked => Some("pin-locked"),
        SealError::WrongState(_) => Some("wrong-state"),
        SealError::FillPending => Some("fill-pending"),
        _ => None,
    }
}

/// The answer to a relay refusal: the error table of `docs/seal-relay.md`,
/// with the refusal's `reason` when it has one.
pub fn refusal(error: &RelayError) -> Reply {
    let message = error.to_string();
    match error {
        RelayError::UnknownSession => Reply::error(404, "unknown-session", &message),
        RelayError::Expired => Reply::error(410, "expired", &message),
        RelayError::Busy => Reply::error(503, "busy", &message),
        RelayError::BadRequest(_) => Reply::error(400, "bad-request", &message),
        RelayError::Seal(SealError::Dropped) => Reply::error(422, "card-dropped", &message),
        RelayError::Seal(seal) => Reply::refused(&message, reason(seal)),
    }
}

/// The standard reason phrase of the statuses the routes answer.
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        410 => "Gone",
        413 => "Content Too Large",
        422 => "Unprocessable Content",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

/// Writes `reply` as one HTTP/1.1 answer, with `Cache-Control: no-store`.
pub fn write_reply(out: &mut dyn Write, reply: &Reply, close: bool) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
        reply.status,
        reason_phrase(reply.status),
        reply.body.len(),
        if close { "close" } else { "keep-alive" },
    );
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(reply.body.as_bytes());
    out.write_all(&bytes)?;
    out.flush()
}

/// What the head of one request says.
struct Head {
    method: String,
    path: String,
    content_length: usize,
    close: bool,
}

/// Why a head is refused: the connection is answered 400 and closed.
struct BadHead(&'static str);

fn parse_head(bytes: &[u8]) -> Result<Head, BadHead> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(bytes) {
        Ok(httparse::Status::Complete(length)) if length == bytes.len() => {}
        _ => return Err(BadHead("the request head is malformed")),
    }
    let (Some(method), Some(path), Some(version)) = (request.method, request.path, request.version) else {
        return Err(BadHead("the request head is malformed"));
    };
    let mut content_length = None;
    let mut close = version != 1;
    for header in request.headers.iter() {
        if header.name.eq_ignore_ascii_case("content-length") {
            let value = std::str::from_utf8(header.value).map(str::trim).unwrap_or("");
            let parsed = (!value.is_empty() && value.len() <= 10 && value.bytes().all(|b| b.is_ascii_digit()))
                .then(|| value.parse::<usize>().ok())
                .flatten()
                .ok_or(BadHead("the content length is malformed"))?;
            if content_length.is_some_and(|seen| seen != parsed) {
                return Err(BadHead("the content length is given twice"));
            }
            content_length = Some(parsed);
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(BadHead("only bodies with a content length are taken"));
        } else if header.name.eq_ignore_ascii_case("connection") {
            let value = std::str::from_utf8(header.value).unwrap_or("");
            if value.split(',').any(|token| token.trim().eq_ignore_ascii_case("close")) {
                close = true;
            }
        }
    }
    Ok(Head { method: method.to_owned(), path: path.to_owned(), content_length: content_length.unwrap_or(0), close })
}

fn head_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n").map(|at| at + 4)
}

/// Reads more of `stream` into `buffer`; `false` when the stream ended or
/// failed (its deadline included).
fn read_more(stream: &mut dyn Read, buffer: &mut Vec<u8>) -> bool {
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return false,
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);
                chunk[..n].zeroize();
                return true;
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return false,
        }
    }
}

/// Serves HTTP/1.1 requests on `stream` until it closes, fails, a request
/// asks to close it, or a request is malformed (answered 400 and closed). A
/// body over [`MAX_BODY_BYTES`] is answered 413 unread and the connection
/// closed. The caller bounds the connection's time (inside the enclave, the
/// service port's connection time). Nothing read is logged; every byte read
/// is wiped once its request is answered.
pub fn serve_http(stream: &mut dyn ReadWrite, routes: &Routes) {
    let mut buffer: Vec<u8> = Vec::with_capacity(READ_CHUNK_BYTES);
    serve_requests(stream, routes, &mut buffer);
    buffer.zeroize();
}

/// A byte stream both ways.
pub trait ReadWrite: Read + Write {}

impl<T: Read + Write + ?Sized> ReadWrite for T {}

fn serve_requests(stream: &mut dyn ReadWrite, routes: &Routes, buffer: &mut Vec<u8>) {
    loop {
        let end = loop {
            if let Some(end) = head_end(buffer) {
                break end;
            }
            if buffer.len() > MAX_HEAD_BYTES {
                let _ = write_reply(stream, &Reply::error(400, "bad-request", "the request head is too large"), true);
                return;
            }
            if !read_more(stream, buffer) {
                return;
            }
        };
        if end > MAX_HEAD_BYTES {
            let _ = write_reply(stream, &Reply::error(400, "bad-request", "the request head is too large"), true);
            return;
        }
        let head = match parse_head(&buffer[..end]) {
            Ok(head) => head,
            Err(BadHead(why)) => {
                let _ = write_reply(stream, &Reply::error(400, "bad-request", why), true);
                return;
            }
        };
        if head.content_length > MAX_BODY_BYTES {
            let _ = write_reply(stream, &routes.route(&head.method, &head.path, None), true);
            return;
        }
        let whole = end + head.content_length;
        while buffer.len() < whole {
            if !read_more(stream, buffer) {
                return;
            }
        }
        let reply = routes.answer(&head.method, &head.path, &buffer[end..whole]);
        buffer[..whole].zeroize();
        buffer.drain(..whole);
        if write_reply(stream, &reply, head.close).is_err() || head.close {
            return;
        }
    }
}
