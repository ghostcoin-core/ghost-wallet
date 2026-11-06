# The Seal relay

The phone carries the Seal's card traffic. The Seal holds every card key and
runs Fill, Check and Open (`docs/sealed-card.md`); it never talks to a card
itself. Its card transport (`CardTransport` in `seal/src/traits.rs`) is one
APDU in, one raw answer out, and the phone stands behind it over the network:

```text
card  <-- NFC -->  phone  <-- HTTPS -->  Seal
          APDU, answer       the same bytes, as hex
```

The phone:

- opens the Core NFC session and the connection to the Seal;
- passes each APDU to the card and each answer back as opaque bytes: it never
  decrypts them, and it holds no card key;
- hands JavaScript only the result: the card UID, the state, the amount in
  wei, the Seal's signed answer and the time of each round trip. No function
  of the native relay returns an APDU or an answer to JavaScript.

The card's secure messaging is end to end between the chip and the Seal, so
the phone (and anyone between the phone and the Seal) sees only what the
relay sees: commands and answers encrypted and MACed under session keys the
phone never has.

The protocol is implemented in `seal/src/relay.rs`, served over HTTP by the
development test server (`seal/src/test_server.rs`), and carried on the phone
by `modules/ghost-nfc/ios/SealRelay.swift`.

## Sessions

1. The phone connects to the card and starts a Check with the card's UID and
   a fresh random 32-byte challenge.
2. The Seal starts `Seal::check` on a worker. The worker's card transport hands
   each APDU to the phone as the answer to the phone's last request, and waits
   for the card's raw answer in the phone's next request.
3. When the flow is over, the last answer is the Seal's signed answer
   (`seal/src/answer.rs`): the 203 answer bytes and their ML-DSA-65 signature.

Each session has:

| | default | |
| --- | --- | --- |
| id | 16 random bytes | in every request after the start |
| idle timeout | 10 s | how long the Seal waits for the card's answer to one command |
| total limit | 30 s | from the start; at most 45 s, well inside the iOS NFC session limit of 60 s |
| sessions at once | 32 | more are refused as busy |

A session is finished when the Seal answers `done` or refuses, when the phone
aborts it, or when it goes past either limit. An unknown or finished session
id is refused. A session past a limit is refused as `expired` once and then is
unknown. The Seal's flow then stops as a dropped connection, which Check,
Fill and Open all treat as "run again from the start".

A Check is about seven card round trips (select, read the key version,
select, two authentication steps, read the UID, read the record header), so
eight Seal round trips. The speed target is a whole Check in 2 seconds or
less over Wi-Fi and over mobile data.

## Wire format

Plain request and answer pairs: each is an HTTP `POST` with a JSON body, and
each answer is JSON. Bytes are hex (answers are lowercase; either case is
accepted). Request bodies are at most 4096 bytes. Every answer has
`Cache-Control: no-store`.

### Start a Check

`POST /v1/check/start`

```json
{ "uid": "04518dfaa96180", "challenge": "<64 hex digits>" }
```

### Carry the card's answer

`POST /v1/relay/step`

```json
{ "session": "<32 hex digits>", "answer": "<the card's raw answer: data and SW1 SW2, 2 to 258 bytes>" }
```

### End a session early

`POST /v1/relay/abort` with `{ "session": "<32 hex digits>" }` when the card
leaves the field. Answers `{ "status": "aborted" }`.

### Answers

The next command for the card (`200`):

```json
{ "status": "apdu", "session": "<32 hex digits>", "apdu": "<hex>" }
```

The end of the flow (`200`); the session is finished:

```json
{ "status": "done", "answer": "<203 bytes as hex>", "signature": "<ML-DSA-65 signature as hex>" }
```

A refusal: `{ "status": "error", "error": "<code>", "message": "<plain text>" }`

| HTTP | `error` | |
| --- | --- | --- |
| 400 | `bad-request` | a field is missing or malformed, or the body is not JSON |
| 404 | `unknown-session` | the session id is unknown or finished |
| 404 | `not-found` | no such path |
| 405 | `method` | not a `POST` |
| 410 | `expired` | the session went past its idle timeout or total limit |
| 413 | `too-large` | the body is over 4096 bytes |
| 422 | `card-dropped` | the Seal's flow stopped as a dropped connection |
| 422 | `refused` | the Seal refused the card (wrong keys, a torn record, …) |
| 503 | `busy` | too many sessions |

Messages never carry a key, a PIN or card traffic.

## What the phone checks

The state, amount and UID the phone reports come from the signed answer bytes,
never from unsigned fields: the answer's domain is `ghost-seal/v1/answer`, its
kind is Check, it carries the phone's own challenge and the UID of the card in
the field. Verifying the signature against the Seal's pinned key and
measurement is the Check screen's job (a later piece of work); the speed screen
only times the relay.

## Fill

Fill is not on the relay yet. When it is, it uses the same sessions and step
requests, started from its own path, and the speed screen times it too.

## The development test server

`seal/src/bin/test_seal_server.rs`, built only with the `test-server` cargo
feature (the default build of `seal/` has no networking and no extra crate).
It is for development and the speed test only, **never for real money**:

- it refuses to start unless it is given `--dev-test-seal` and the environment
  variable `GHOST_DEV_TEST_SEAL=1`, and prints a one-line warning when it
  starts;
- it holds only the test M: the 32 bytes SHA3-256 of the text
  `ghost-seal/dev-test-master/v1`, which is
  `d7c19145c84d99edf3c8fbe63d29dfe4e7a89e39e5454e3903a123e4cf7b6040`. Anyone can
  derive it, so a card set up with it protects nothing. Card setup uses the
  same value for its test cards;
- its answers carry an all-zero code measurement, which no real Seal build
  has, so a phone that pins a real measurement never accepts them;
- no enclave, no journal on disk and no card registry yet: it answers a Check
  for any card set up with the test M. Check only.

```sh
cargo build --manifest-path seal/Cargo.toml --release --features test-server --bin test_seal_server

# HTTPS, for the phone (a certificate the iPhone trusts, PEM files):
GHOST_DEV_TEST_SEAL=1 seal/target/release/test_seal_server --dev-test-seal \
  --listen 0.0.0.0:8443 --tls-cert cert.pem --tls-key key.pem

# Plain HTTP, loopback only (it refuses any other address without TLS):
GHOST_DEV_TEST_SEAL=1 seal/target/release/test_seal_server --dev-test-seal --listen 127.0.0.1:8787
```

`--idle-ms`, `--total-ms` and `--max-sessions` change the session limits; the
total must stay at most 45 seconds and the idle timeout within it.

## The speed screen

`app/seal-speed.tsx` (route `/seal-speed`, a bare test screen like the bench)
runs a Check through the relay against a Seal address typed in, and shows the
total time and each round trip (labelled card or Seal). It keeps the last 20
runs in memory only. It times Check only for now, and says so.

After merge, on the real iPhone with a real card set up with the test M: a
Check should take 2 seconds or less over Wi-Fi and over mobile data (mobile
data needs the test server reachable from the internet). If it is slower,
record the numbers and batch the Seal's commands.
