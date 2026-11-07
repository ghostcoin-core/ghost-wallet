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
- hands JavaScript only the result: the card UID, the challenge it sent, the
  state, the amount in wei, the Seal's signed answer, the time of each round
  trip and, for a Fill, the coin's public commit data. An Open's release
  package goes from the relay straight to the native core
  (`core/src/seal_open.rs`). No function of the native relay returns an APDU
  or a card answer to JavaScript.

The card's secure messaging is end to end between the chip and the Seal, so
the phone (and anyone between the phone and the Seal) sees only what the
relay sees: commands and answers encrypted and MACed under session keys the
phone never has.

The protocol is implemented in `seal/src/relay.rs`, served over HTTPS by the
Seal's enclave (`seal/src/relay_http.rs`, TLS ended inside the enclave; see
`docs/seal-enclave.md`, "Serving phones"), served for Check only by the
development test server (below), and carried on the phone by
`modules/ghost-nfc/ios/SealRelay.swift`.

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
| 503 | `unavailable` | the Seal is not ready to answer cards (the enclave only) |

Messages never carry a key, a PIN or card traffic.

The enclave answers every flow request (the starts, step and abort)
`unavailable` with the message "This Seal is not ready to answer cards"
until it holds M and a chain status check, a card registry (loaded by the
host) and a durable journal are installed into it, and the journal (the
sealed log the parent host keeps) has been read and verified with M; it
sends no card command before then. It installs all three. A Fill start is
still answered `unavailable` until the enclave has its Phantom Key
derivation (`KeyMakerSource`).

### The Seal's attestation (the enclave only)

`POST /v1/attestation` with `{ "challenge": "<64 hex digits>" }` answers
`{ "status": "ok", "attestation": "<GPA2 as hex>" }`: the Nitro attestation
binding the Seal's ML-DSA-65 and ML-KEM-768 keys and the SHA-256 of the TLS
certificate of this connection to its measurement and to the challenge
(`docs/seal-enclave.md`, "Attestation for phones"). The phone trusts the
certificate only when that hash equals the certificate it is connected to.
Before the enclave holds M it is refused `unavailable`.

## What the phone checks

The state, amount and UID the phone reports come from the signed answer bytes,
never from unsigned fields: the answer's domain is `ghost-seal/v1/answer`, its
kind is the flow's (Check, Fill or Open), it carries the phone's own challenge
and the UID of the card in the field. The relay hands JavaScript the challenge
it made with the answer, and the native core (`core/src/seal_answer.rs`, the
phone's side of `AnswerVerifier`) then checks the ML-DSA-65 signature under
the Seal's key, that the Seal's measurement is on the app's pinned list
(`lib/seal/pinned-measurements.ts`) and is the one in the answer, the
challenge, the card and the expiry, and for a Fill or an Open that the answer
binds the commit data or the release package that came with it. The Seal's
key and measurement come from `lib/seal/trusted-seal.ts`, which has no Seal
yet outside the tests, so every card shows "Can't verify this card" until it
has one (see `docs/sealed-card.md`, "The app"). The speed screen only times
the relay.

## Fill, its confirmation and Open

They use the same sessions, step requests, abort and answers as Check,
started from their own paths (`start_fill`, `start_confirm_fill` and
`start_open` beside `start_check` in `seal/src/relay.rs`). The Seal's enclave
serves them; the development test server answers Check only. The phone side is
`modules/ghost-nfc/ios/SealRelay.swift` and `modules/ghost-nfc/relay.ts`.

### Start a Fill

`POST /v1/fill/start`

```json
{ "uid": "04518dfaa96180", "challenge": "<64 hex digits>", "amountWei": "<decimal digits>", "pin": "<4 to 8 digits>" }
```

`pin` is left out when the card gets no Open PIN. The flow is `Seal::fill`.
Its `done` answer also carries the coin's public commit data, which the phone
pays with its Vanish:

```json
{ "status": "done", "answer": "<203 bytes as hex>", "signature": "<hex>", "commitData": "<430 bytes as hex>" }
```

The answer's kind is Fill, its state Empty, its coin and binding both
SHA3-256 of the commit data, its amount the one asked for and its PIN status
the one asked for; the phone refuses anything else.

### Confirm a Fill

`POST /v1/fill/confirm` with `{ "uid": ..., "challenge": ... }`. The flow is
`Seal::confirm_fill`: once the chain check finds the coin paid exactly and
settled, the card is written Sealed and the `done` answer (kind Fill) says
Sealed; until then it is refused with the reason `filling`.

### Start an Open

`POST /v1/open/start`

```json
{ "uid": "04518dfaa96180", "challenge": "<64 hex digits>", "phoneKey": "<1184 bytes as hex>", "pin": "<the card's Open PIN>" }
```

`phoneKey` is the native core's ML-KEM-768 encapsulation key; `pin` is left
out for a card without one. The flow is `Seal::open`. Its `done` answer also
carries the release package (`GSR1`..., `docs/sealed-card.md`, "Open
release"):

```json
{ "status": "done", "answer": "<203 bytes as hex>", "signature": "<hex>", "release": "<the package as hex>" }
```

The phone hands `release` to the native core and nowhere else; the core
accepts the answer (kind Open, state Opened) only when it binds exactly that
package.

### Why a card was refused

A `refused` answer (HTTP 422) of any flow may carry a `reason`, so the phone
can say what the card is without reading `message`:

| `reason` | | the phone shows |
| --- | --- | --- |
| `not-a-ghost-card` | not in the card registry, or keys the Seal does not derive | Not a Ghost card |
| `filling`, `not-paid` | the payment is not settled yet | Filling, waiting to settle |
| `cant-check-now` | the chain check could not reach its nodes | Can't check right now |
| `spent` | the coin is spent | Spent, empty |
| `pin-required` | an Open of this card needs its PIN | asks for the PIN |
| `wrong-pin` | the PIN was wrong; a try was counted | Wrong PIN, Check again for the tries left |
| `pin-locked` | no PIN tries left | Locked |
| `wrong-state` | the card is not in a state for this flow | asks to try again |
| `fill-pending` | a Fill with another amount or PIN waits for its payment | asks to try again |

A refusal without a `reason` is shown as Not a Ghost card. The PIN is sent
only in the start request, over HTTPS, and never comes back in any answer or
message.

The phone allows a Check 32 card round trips, a Fill or its confirmation 64
and an Open 160 (it rotates five keys and authenticates with each new one),
all inside the same 50 seconds.

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
- its Seal is built like every Seal (`Seal::new`), with the card registry and
  the chain check. It refuses to start, with one line, without `--registry
  FILE` (the registry file the card setup writes, a `FileRegistry`, read
  again for each Check so cards set up later are served without a restart)
  or with fewer than two `--node URL` (each an `RpcNode`: `https://` and any
  host, checked against ISRG Root X1 as in the enclave, or `http://` and a
  loopback address only, a development convenience). The nodes must follow
  the release network (the Ghost public test network) unless `--network
  CHAIN_ID:GENESIS_HEX` names another. A card the registry does not hold is
  refused with the reason `not-a-ghost-card` before any card command;
- no enclave, but the enclave's journal code: it refuses to start, with one
  line, without `--journal FILE`, the file it keeps the sealed, chained
  journal log in (created mode 0600; the same log as the enclave's, under
  the test M, with the host's file store in its own process). The log is read
  and verified whole at the start, and a file that fails its checks is
  refused; every session shares it, so a Fill or an Open cut off before a
  restart is finished after one on the same file. A Sealed card whose Fill
  entry is not in that file (sealed by another Seal) is refused rather than
  answered unchecked. It answers an Empty card. Check only over HTTP.

```sh
cargo build --manifest-path seal/Cargo.toml --release --features test-server --bin test_seal_server

# HTTPS, for the phone (a certificate the iPhone trusts, PEM files):
GHOST_DEV_TEST_SEAL=1 seal/target/release/test_seal_server --dev-test-seal \
  --registry registry.txt --node https://node-one.example/ghost-rpc --node https://node-two.example/ghost-rpc \
  --journal dev-journal.log --listen 0.0.0.0:8443 --tls-cert cert.pem --tls-key key.pem

# Plain HTTP, loopback only (it refuses any other address without TLS):
GHOST_DEV_TEST_SEAL=1 seal/target/release/test_seal_server --dev-test-seal \
  --registry registry.txt --node https://node-one.example/ghost-rpc --node https://node-two.example/ghost-rpc \
  --journal dev-journal.log --listen 127.0.0.1:8787
```

`--idle-ms`, `--total-ms` and `--max-sessions` change the session limits; the
total must stay at most 45 seconds and the idle timeout within it.

Every request must arrive whole and in time, or its connection is closed:

| | default | |
| --- | --- | --- |
| body deadline | 5 s | from the request's head to the end of its body, however steadily the body trickles in; `--body-ms`, at most 30 s |
| next head | 30 s | from the connection opening, or from its last answer, to the next request's head |
| connections | 128 | at once, 32 from one address; more are closed at once |

The server listens itself and carries each connection's bytes (still TLS for
HTTPS) to its HTTP library on a loopback port of its own, so it can close a
connection whose body is late; that ends the library's read of the body at
once. Each request is served on its own thread, so an unfinished body never
holds up anyone else's Check.

## The speed screen

`app/seal-speed.tsx` (route `/seal-speed`, a bare test screen like the bench)
runs a Check through the relay against a Seal address typed in, and shows the
total time and each round trip (labelled card or Seal). It keeps the last 20
runs in memory only. It times Check only for now, and says so.

After merge, on the real iPhone with a real card set up with the test M: a
Check should take 2 seconds or less over Wi-Fi and over mobile data (mobile
data needs the test server reachable from the internet). If it is slower,
record the numbers and batch the Seal's commands.
