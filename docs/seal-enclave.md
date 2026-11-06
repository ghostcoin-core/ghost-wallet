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
   PCR0, PCR1 and PCR2 are one allowed build of its list and it binds the key.
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
in `enclave/measurements.json` and the list given to the running enclaves
names it as allowed. The app pins the list of builds it accepts.

## Attestation for phones (`seal/src/phone_attestation.rs`)

`GPA1` || document length (u32 BE) || Nitro document || the Seal's ML-DSA-65
verifying key (1952, derived from M as every answer signature is) || the
enclave's ML-KEM-768 encapsulation key (1184). The document's `user_data` is
SHA3-256(`ghost-seal/v1/phone-attestation` || verifying key || encapsulation
key || the phone's 32-byte challenge). `verify` is the reference check: the
document against the pinned root, its PCRs against the pinned list, the
binding, and both keys well formed. The app's own check, in native code, is a
later step.

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
start frame.

## Enclave program protocol

Frames are a u32 big-endian length and the bytes (at most 64 KiB). Control
port: one start frame, mode (1 genesis, 2 join) || the list JSON; the answer
is a status text; a second start is refused, so an enclave whose join failed
stays without M until it is restarted. Service port: kind (1 key-share
request, 2 phone attestation with a 32-byte challenge) || body; the answer is
0 || body, or 1 || why it was refused. Before it holds M, the enclave refuses
every service request.

Serving Check, Fill and Open to phones from the enclave (TLS ended inside the
enclave) is a later step.

## What is still trusted

- **AWS Nitro**: the enclave's isolation and the NSM's attestation, signed
  under the pinned AWS root.
- **The list a running enclave enforces.** An enclave image cannot hold the
  measurements of builds made after it, so the list comes in the start frame
  from the host, which takes it from the published list at a pinned SHA-256
  (a stack parameter). Whoever deploys the stacks is trusted to give only the
  published list; a list naming a build that is not published would let that
  build receive M. The list's SHA-256 is in each stack's parameters, so every
  start can be checked against the repository afterwards.
- **The published code**: anyone can rebuild it and must get the published
  PCRs.

## Not yet done

The live deploy and the first real M (they need an AWS account), the first
real PCR values (they need a Nitro-capable builder), the reproducibility check
in CI, the enclave serving phones, and the app's check of the phone
attestation.
