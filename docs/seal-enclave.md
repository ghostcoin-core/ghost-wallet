# The Seal on AWS Nitro Enclaves

The Seal (the `seal/` crate, designed in `docs/sealed-card.md`) runs inside an
AWS Nitro Enclave. This document covers what runs where, how the enclave is
built and measured, how the master secret M is made and copied between
regions, the attestation phones get, the parent proxy, and what is still
trusted. Everything here is in the `seal/` crate behind the cargo feature
`nitro` (off by default, so the default build keeps its small tree and has no
networking), plus `enclave/` (image, scripts, deploy files) and
`lib/seal/pinned-measurements.ts` (the app's pinned list).

## What runs where

- **The enclave** runs `seal_enclave`, the only program in the enclave image.
  It has no disk, no network and no console; it talks only over vsock.
- **The host** (the enclave's parent EC2 instance) runs `seal_proxy`, which
  relays bytes between TCP and vsock and never reads them.
- **Regions**: one host and one enclave per region, in 2 to 3 regions
  (`enclave/deploy/regions.json`). Every enclave holds the same M.

vsock ports of the enclave: **5000** control (the host only; the proxy never
forwards to it), **5001** service (the inbound proxy forwards the internet to
it). Ports on the host, for the enclave to reach out: **5002** to a giving
region's proxy (key share), **5003** to a Ghost node (the chain check).

## Build and measurements

`enclave/Dockerfile` builds `seal_enclave` in a Rust toolchain image pinned by
digest, with `--locked`, for the fixed target `aarch64-unknown-linux-gnu`
linked statically, with `SOURCE_DATE_EPOCH` and `--remap-path-prefix` set,
under the release profile of `seal/Cargo.toml` (one codegen unit, no
incremental state, no debug info, symbols stripped). The settings live in
`enclave/build.env`, which the Dockerfile and the reproducibility check both
read. The enclave image is the program alone on `scratch`;
`nitro-cli build-enclave` adds the enclave kernel and init. The Dockerfile's
`proxy` stage builds the host's `seal_proxy` for musl (it is not measured and
looks up host names, which a static glibc program cannot do reliably).

- `enclave/scripts/check-reproducible.sh` builds the program twice from two
  different directories with those settings and fails unless both SHA-256
  hashes match. It needs neither Docker nor a Nitro tool.
- `enclave/scripts/compute-pcrs.sh`, run on a Nitro-capable builder, builds
  the image and the EIF, reads PCR0, PCR1 and PCR2 from `nitro-cli
  build-enclave` and `nitro-cli describe-eif`, checks they agree, and appends
  the build to `enclave/measurements.json`.

PCR0 measures the whole image and is the Seal's answer measurement (SHA-384,
48 bytes, `MEASUREMENT_BYTES`). PCR1 measures the kernel and boot ramdisk,
PCR2 the program.

### The published list

`enclave/measurements.json`, read by `seal/src/measurements.rs` and, in the
same format, pinned in the app by `lib/seal/pinned-measurements.ts`:

```json
{"version": 1, "builds": [{"name": "seal-2026-11-01", "released": "2026-11-01",
  "pcr0": "<96 hex>", "pcr1": "<96 hex>", "pcr2": "<96 hex>", "status": "allowed"}]}
```

A measurement is accepted only when PCR0, PCR1 and PCR2 all equal one build
whose status is `allowed`. A `revoked` build is never accepted and never given
M. Both readers are strict and refuse the whole list for any of: another
version, an unknown or missing field, a PCR that is not 96 lowercase hex
digits or is all zeros (a debug-mode enclave reports zeros), a date that does
not exist, an unknown status, a name listed twice, a PCR0 listed twice,
duplicate JSON keys or trailing data. Both read the fixture
`seal/tests/fixtures/measurements.json` in their tests.

Until the first build is published, the published list and the app's pinned
list hold no build, and every Seal is refused.

The published file also carries `"signature"`: the release key's ML-DSA-65
signature (FIPS 204, context `ghost-seal measurements`) over
`ghost-seal/v1/measurements/release` || the list's digest (SHA3-256 of the
builds in canonical form, so JSON spacing does not matter), as 6618 lowercase
hex digits. Both readers take the field and check that it is well formed; only
the enclave verifies it (below). The release key's private half is made and
kept offline by the release owner and is never in the repository, an image or
a fixture; the tests sign with test-only keys made from fixed patterns in
`seal/tests/fixtures/test_release_key.rs`. Until the release key exists the
published file has no signature, and no enclave takes it.

### The rule: an enclave enforces only a list it trusts itself

The list a giving enclave checks a receiver's attested PCR0, PCR1 and PCR2
against, and the list a joining enclave checks its giver against, never comes
from the host or from another enclave. It is a `TrustedList`
(`seal/src/measurements.rs`), made of exactly:

1. **The builds compiled into its own image** (`COMPILED_BUILDS`, empty
   today). The image's own PCRs cover them. An image cannot list itself or a
   later build, so this holds earlier builds.
2. **A list signed by the release key whose public key is compiled into its
   image** (`RELEASE_KEY_HEX`, empty until the release key is made; with no
   key, no signed list is taken). The host can carry such a list to the
   enclave but cannot write one. A signed list replaces a held one only if it
   extends it: every build held stays, with the same name, date and PCRs, and
   every revoked build stays revoked. An older signed list cannot roll back a
   newer one in a running enclave.
3. **Its own build**, read from its own attestation document at start. A copy
   of the very same image is the same code that already holds M, so regional
   copies of one build need no list at all.

A build that the compiled-in builds or the signed list mark `revoked` is
refused, whatever else names it, including the enclave's own build. A list the
host sends unsigned, or signed by any other key, is refused and changes
nothing. A join start carries no list: anything the host sends after the join
byte is ignored, and the joining enclave checks its giver against (1) and (3)
only. A debug-mode enclave (zero PCRs) is never trusted, not even as its own
build.

So a host that starts a published image with a list naming its own build
gets nothing: the list is refused, and the published image hands M only to a
build in (1), (2) or (3), even when the host's build presents a perfectly
valid attestation document.

## Attestation documents

`seal/src/attestation.rs` checks Nitro attestation documents: COSE_Sign1 with
ES384 over a CBOR payload with exactly the fields AWS documents (`module_id`,
`timestamp`, `digest`, `pcrs`, `certificate`, `cabundle`, and the optional
`public_key`, `user_data`, `nonce`). The verifier checks the structure and the
ES384 header; that `cabundle[0]` is the pinned root (its SHA-256 is the
fingerprint AWS publishes for the Nitro Enclaves Root-G1,
`64:1A:03:21:...:79:BB:5B`); that each certificate is signed by the one above
it, every issuer is a CA allowed to sign certificates within its path length,
and the names chain; that every certificate is valid now; the document's
signature; the payload's fields, sizes, digest `SHA384` and 48-byte PCRs 0, 1
and 2; and that the document is at most 300 seconds old. An unknown critical
X.509 extension or an unknown payload field refuses the document. This is
verify-only use of `p384`; nothing outside the tests signs. Tests inject their
own root and never use the AWS one.

The enclave asks the Nitro Secure Module for its own documents through
`/dev/nsm` (`NsmSource`), with the request
`{"Attestation": {"user_data": ..., "nonce": ..., "public_key": null}}`.

## The master secret M

- **Made once, inside the first enclave.** The first enclave is started in
  genesis mode and draws M from its own random source. That happens once,
  ever: every other start of any enclave, including a replacement of the first
  host, is in join mode, and join mode never makes M, not even when the
  handover fails. `deploy.sh` deploys the genesis region in join mode once its
  stack exists.
- **No way out.** There is no KMS key or decrypt grant (the host role has no
  KMS permission at all), no human share, no backup and no function that
  returns M. M lives only in enclave memory as a `MasterKey`, which has no
  `Debug`, `Display` or serialisation. The only bytes that carry M are a
  key-share package, encrypted to one attested enclave on the list.
- **Copies** come only from a running enclave, through the key-share protocol.

### The key-share protocol (`seal/src/key_share.rs`)

1. The receiving enclave makes a fresh ML-KEM-768 key pair and a fresh
   32-byte nonce, and gets a document with `user_data` = SHA3-256(
   `ghost-seal/v1/key-share/request` || encapsulation key) and `nonce` = the
   nonce. Request: `GKQ1` || encapsulation key (1184) || document length
   (u32 BE) || document.
2. The giving enclave verifies the document and accepts it only when its
   PCR0, PCR1 and PCR2 are one allowed build of its trusted list (see the rule
   above) and it binds the key.
   It encapsulates to the key and gets its own document: `user_data` =
   SHA3-256(`ghost-seal/v1/key-share/package` || the receiver document's hash
   || nonce || KEM ciphertext), `nonce` = the receiver's nonce. It checks that
   it is itself an allowed build of its list (a revoked build stops giving).
   HKDF with HMAC-SHA3-256 (salt and info prefix
   `ghost-seal/v1/key-share/package`, info also the receiver document's hash,
   the giver document's hash and the nonce) derives an AES-256 key and an
   HMAC-SHA3-256 key. M is padded (ISO/IEC 9797-1 method 2), encrypted with
   AES-256-CBC under a fresh IV and MACed (encrypt-then-MAC, the primitives
   of the Open release). Package: `GKP1` || document length (u32 BE) || giver
   document || KEM ciphertext (1088) || IV (16) || ciphertext (48) || tag
   (32), the tag over the label, both document hashes, the nonce and
   everything before it.
3. The receiver verifies the giver's document the same way, checks it is an
   allowed build of its own list, its nonce and its binding of the KEM
   ciphertext to this receiver's document, before it decapsulates or reads
   anything else; then checks the tag and decrypts.

A document hash is SHA3-256(`ghost-seal/v1/attestation-document` ||
document). A package opens only for the one receiver and nonce it was made
for; a receiver takes one package and is used up.

### Upgrades

A new build gets M the same way as a new region: once its PCRs are published
in `enclave/measurements.json`, the release owner has signed that list
offline, and the running enclaves have been given the signed list
(`seal_proxy list`). A new build compiles the builds it may take M from into
`COMPILED_BUILDS`. The app pins the list of builds it accepts.

## Attestation for phones (`seal/src/phone_attestation.rs`)

`GPA2` || document length (u32 BE) || Nitro document || the Seal's ML-DSA-65
verifying key (1952, derived from M as every answer signature is) || its
ML-KEM-768 encapsulation key (1184) || the SHA-256 of the DER of the TLS
certificate the enclave serves (32 bytes). The document's `user_data` is
SHA3-256(`ghost-seal/v2/phone-attestation` || verifying key || encapsulation
key || certificate hash || the phone's 32-byte challenge). `make` takes the
certificate hash; `verify` is the reference check: the document against the
pinned root, its PCRs against the pinned list, the binding, both keys well
formed, and the certificate hash equal to the one the caller's connection
used; it returns the hash with the keys. A phone attestation whose
certificate hash differs from the certificate of the connection it came over
is refused. (`GPA1`, without the certificate hash, is gone: nothing used it.)
The app's own check, in native code, is a later step.

A phone gets it either over TLS (`POST /v1/attestation`, below) or as a
framed request on the service port.

## The parent proxy (`seal/src/proxy.rs`, `seal_proxy`)

`seal_proxy inbound` takes TCP from the internet and relays each connection to
the enclave's service port; `seal_proxy outbound` takes vsock connections from
the enclave and relays each to one fixed upstream (a giving region's proxy, or
a Ghost node). It copies bytes both ways and never parses, logs or stores
them: its log is a fixed set of events with no field for carried bytes. It
limits open connections (256 by default), closes a connection idle for its
idle timeout (120 seconds by default), and when either side closes, closes the
other. Everything it carries is encrypted end to end to the enclave (TLS, a
key-share request or package). `seal_proxy start` sends the enclave its one
start frame (the mode alone) and then offers it the list file; `seal_proxy
list` offers a later one. The enclave takes a list only if it is signed by
its release key.

## Enclave program protocol

Frames are a u32 big-endian length and the bytes (at most 64 KiB). Control
port: a start frame, 1 (genesis) optionally followed by a signed list, or 2
(join; anything after it is ignored); after the start, 3 || a signed list.
The answer is a status text. A second start is refused, so an enclave whose
join failed stays without M until it is restarted; a list that is not signed
by the compiled-in release key is refused. Service port: kind (1 key-share
request, 2 phone attestation with a 32-byte challenge) || body; the answer is
0 || body, or 1 || why it was refused. Before it holds M, the enclave refuses
every service request.

### Bounded service

The service port runs on a fixed pool of 4 worker threads, all started at
once; no thread is made per connection. Accepted connections wait in a queue
of 8; a connection that finds the queue full is closed at once. Each
connection has 30 seconds in all from the moment it is accepted, the queue
included; every read and write waits at most until then, however slowly the
bytes come, and a connection whose time ran out in the queue is closed unread.
So clients that send a whole request and hang up, or drip bytes, can occupy
at most the pool and the queue. A failed accept (out of file descriptors, say)
waits a moment and goes on; no thread or resource failure panics the accept
loop, and a handler that panics leaves its worker running. The parent proxy
likewise closes a connection it has no thread for instead of panicking. The
handover a joining enclave makes has 60 seconds in all.

## Serving phones (`seal/src/enclave_serve.rs`)

One public port. The service port 5001 serves both phones and other
enclaves; the first byte of a connection picks the protocol:

- `0x16` (a TLS handshake record): TLS ended inside the enclave, then the
  relay's HTTP routes (`docs/seal-relay.md`);
- `0x00` (the top byte of a frame length of at most 64 KiB): the framed
  protocol above (key share, phone attestation);
- anything else: the connection is closed unanswered.

The pool of 4 workers, the queue of 8, the 30 second connection time and the
handover rules are the bounded service's above; a slow TLS handshake counts
against the same connection time. The parent proxy still carries only
ciphertext.

### TLS inside the enclave (`seal/src/enclave_tls.rs`)

`rustls` (exact-pinned, default features off, only `std` and its `ring`
provider: no TLS 1.2 code and no other provider), TLS 1.3 only, no client
certificate, no session tickets, no 0-RTT. At each start the enclave makes a
fresh ECDSA P-256 key pair and a self-signed certificate (subject name
`ghost-seal`, a fixed wide validity window so no clock is needed) with
`rcgen` (exact-pinned, `ring` backend only). Both live in enclave memory only
and are never written anywhere; a restart makes new ones. The key is
transport authentication only and holds no GHOST: card traffic is already end
to end between the chip and the Seal, and an Open's release is ML-KEM to the
phone's key. The certificate is not trusted on a name: the phone trusts it
only through `GPA2`, which binds its SHA-256 to the enclave's measurement, so
a man in the middle cannot swap the phone key of an Open. No elliptic-curve
code is written here. The `ring` crate's C and assembly are built with fixed
flags and a file-prefix map, so `enclave/scripts/check-reproducible.sh` still
gets the same binary twice.

### The routes (`seal/src/relay_http.rs`)

HTTP/1.1 heads are parsed with `httparse`, bodies (at most 4096 bytes) as
JSON. The routes are the relay's (`/v1/check/start`, `/v1/fill/start`,
`/v1/fill/confirm`, `/v1/open/start`, `/v1/relay/step`, `/v1/relay/abort`)
plus `POST /v1/attestation` with `{ "challenge": "<64 hex digits>" }`, which
answers `{ "status": "ok", "attestation": "<GPA2 as hex>" }`. No path, header
or body is logged; the service log is a fixed set of events with no field for
carried bytes.

### Fail closed

The flows are served only when the enclave holds M **and** a chain status
check, a card registry and a durable journal (not a memory-only one) have been
installed into it (`ServiceDeps`). The enclave program installs none of the
three yet, so every flow request (start, step and abort) is answered HTTP 503
`unavailable` with the message "This Seal is not ready to answer cards", and
no card traffic is sent; the attestation route still works once M is held. A
Seal built without the three is never reachable from the network. The tests
install fakes for the three to prove the flows.

## What is still trusted

- **AWS Nitro**: the enclave's isolation and the NSM's attestation, signed
  under the pinned AWS root.
- **The release key.** Whoever holds the release key's private half (offline)
  decides which later builds may receive M. The host and whoever deploys the
  stacks do not: the list they carry counts only with the release signature.
  Revocation reaches a running enclave when it is given the signed list that
  carries it; a host can delay that by not delivering it, and a freshly
  started enclave can be offered an older signed list (from before a
  revocation) that extends what it compiles in. Keep revoked builds from
  running, and start replacements from an image that compiles the revocation
  in.
- **The published code**: anyone can rebuild it and must get the published
  PCRs.

## Not yet done

The live deploy and the first real M (they need an AWS account), the first
real PCR values (they need a Nitro-capable builder), the release key (made
offline by the release owner; its public half goes into `RELEASE_KEY_HEX`
before the first image is built, and its signature into
`enclave/measurements.json` each time a build is published), the reproducibility check
in CI, the three things the enclave needs before it answers a card (the chain
check over the host's vsock port 5003, a durable sealed journal kept outside
the enclave, and the card registry loaded into the enclave), and the app's
check of the phone attestation and of the TLS certificate it binds.
