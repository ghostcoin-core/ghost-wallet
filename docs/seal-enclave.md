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
  relays bytes between TCP and vsock and never reads them. By default it is a
  c7g.large (2 vCPU, 4 GiB): the enclave gets 1 vCPU and 2048 MiB, the host
  keeps the other vCPU and about 2 GiB. A larger size is a redeploy that
  replaces one region's host at a time (`enclave/RUNBOOK.md`, "Needs").
- **Regions**: one host and one enclave per region, in the regions of the
  compiled-in region list (`enclave/deploy/regions.json` lists the same, in
  the same order). Every enclave holds the same M.

vsock ports of the enclave: **5000** control (the host only; the proxy never
forwards to it), **5001** service (the inbound proxy forwards the internet to
it). Ports on the host, for the enclave to reach out: **5002** to a giving
region's proxy (key share), **5003** and **5004** to the two Ghost nodes of
the compiled-in release node list (the chain check; TLS to each ends inside
the enclave), **5005** the host's journal store, and **5006** and **5007** to
the two other regions' proxies (the journal's head, anchored in the peer
regions; one port per peer, in the order of the region list).

Each card is served by its home region only (`docs/sealed-card.md`, "Home
region"). The region list is compiled into the image
(`seal/src/journal_anchor.rs`, `RELEASE_REGIONS`), and so is each image's own
region: the `SEAL_REGION` build argument of `enclave/Dockerfile`, compiled into
`seal_enclave`. One image per region, each with its own PCRs and its own
entry on the signed list; the Dockerfile refuses to build an enclave image
without a region on the compiled list, and an image built some other way
without one installs no journal and answers every card `unavailable`.

## Build and measurements

`enclave/Dockerfile` builds `seal_enclave` in a Rust toolchain image pinned by
digest, with `--locked`, for the fixed target `aarch64-unknown-linux-gnu`
linked statically, with `SOURCE_DATE_EPOCH` and `--remap-path-prefix` set,
under the release profile of `seal/Cargo.toml` (one codegen unit, no
incremental state, no debug info, symbols stripped). The settings live in
`enclave/build.env`, which the Dockerfile and the reproducibility check both
read. The enclave image is the program alone on `scratch`;
`nitro-cli build-enclave` adds the enclave kernel and init. The Dockerfile's
`proxy` stage builds the host's `seal_proxy` for musl (it is not measured,
looks up host names, which a static glibc program cannot do reliably, and is
the same for every region, so it needs no `SEAL_REGION`).

The enclave image takes the build argument `SEAL_REGION`
(`docker build --build-arg SEAL_REGION=<region>`), which `seal_enclave`
compiles in as its own region. The build stops unless it is one of the
compiled region list (`RELEASE_REGIONS`). It is never in `build.env` and
never read from the host: each region's image is its own build, measured and
listed on its own.

- `enclave/scripts/check-reproducible.sh` builds the program twice from two
  different directories with those settings, for each region of
  `enclave/deploy/regions.json` (which must be the compiled list), and fails
  unless both SHA-256 hashes of each region match and no two regions' builds
  are the same. It needs neither Docker nor a Nitro tool.
- `enclave/scripts/compute-pcrs.sh`, run on a Nitro-capable builder, builds
  the image and the EIF of each region of `regions.json`
  (`enclave/out/seal-<region>.eif`), reads PCR0, PCR1 and PCR2 from
  `nitro-cli build-enclave` and `nitro-cli describe-eif`, checks they agree
  and that no two regions share a PCR0, and appends one build per region,
  named `<build name>-<region>`, to `enclave/measurements.json`.
- `enclave/scripts/deploy.sh` takes each region's EIF URL and SHA-256
  (`--eif-url <region>=URL --eif-sha256 <region>=HEX`, one of each per
  region of `regions.json`), refuses when any region's is missing, and
  refuses one EIF given to two regions.

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
   of the very same image is the same code that already holds M: a replaced
   host in the same region, running that region's image. The regions of one
   release are different images (each compiles in its own region), so they
   trust each other through (2).

A build that the compiled-in builds or the signed list mark `revoked` is
refused, whatever else names it, including the enclave's own build. A list the
host sends unsigned, or signed by any other key, is refused and changes
nothing. A join start carries no list: anything the host sends after the join
byte is ignored. A signed list may come before the start (control frame 3,
which `seal_proxy start` sends first), under the same signature and extend
rules, and the joining enclave checks its giver against (1), (2) and (3). That
is how a region's image joins from another region's: the release's signed
list names every region's build. A debug-mode enclave (zero PCRs) is never trusted, not even as its own
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
key-share request or package). `seal_proxy start` offers the enclave the list
file and then sends its one start frame (the mode alone); `seal_proxy list`
offers a later one. The enclave takes a list only if it is signed by its
release key. The list comes before the start because each region runs its
own image: a joining enclave's own build is never its giver's (another
region's image), so it trusts the giver only as a build on the release's
signed list.

## Enclave program protocol

Frames are a u32 big-endian length and the bytes (at most 64 KiB on the
service port, 8 MiB on the control port). Control port: a start frame, 1
(genesis) optionally followed by a signed list, or 2 (join; anything after it
is ignored); before or after the start, 3 || a signed list; after the start,
4 || the card registry (below). The answer is a status text. A second start is refused, so an
enclave whose join failed stays without M until it is restarted; a list that
is not signed by the compiled-in release key is refused. Service port: kind
(1 key-share request, 2 phone attestation with a 32-byte challenge) || body;
the answer is 0 || body, or 1 || why it was refused. Before it holds M, the
enclave refuses every service request.

### The card registry in the enclave

The enclave's registry (`LoadedRegistry`, `seal/src/registry.rs`) is empty,
and counts as not loaded, until the host sends it, after the start, as
control frame 4: the text of the registry file exactly as the card setup's
`FileRegistry` writes it (`seal_proxy registry <enclave CID> <registry
file>`). The enclave keeps only whole lines that pass their check (a torn or
damaged line is left out). It refuses the whole frame, and changes nothing,
if the frame leaves out a card it already holds or gives one another entry;
otherwise it adds the new cards. The host sends the whole file each time, any
number of times, so a card set up later is served without a restart. No
flow is served until the first load; when it arrives after M, the routes are
rebuilt (`EnclaveService::refresh_flows`).

A registry line's check is unkeyed: it catches torn and damaged lines, not a
host that writes its own. So the host can add a UID or leave one out of its
first load. Adding one is harmless: the Seal still refuses a card whose keys
it does not derive from M, so a card the setup never made gets nothing.
Leaving one out only stops service to that card ("Not a Ghost card") until a
load includes it; once held, a card can never be dropped by the host.

### The chain check in the enclave

The release node list is compiled in (`seal/src/node_list.rs`): the Ghost
public test network (chain id 6777972 and the hash of its block 0, as the
node project publishes it) and two nodes mirroring the app's
`RELEASE_NODE_URLS` (`lib/network/build-network.ts`; a jest test keeps them
equal), each reached through its own vsock port on the host (5003 and 5004),
which the host's outbound proxy carries to the node's HTTPS port. The list's
reader refuses fewer than two nodes and a name, host or port listed twice,
as `NodeChainCheck` does. Both nodes are run by one operator today: the code
needs two entries that agree but does not try to prove that they are
independent.

Each node is an `RpcNode` (`seal/src/node_rpc.rs`): JSON-RPC over HTTP/1.1,
one request per connection (`Connection: close`), with the calls the wallet
already makes (`eth_chainId`, `eth_getBlockByNumber`, `eth_getBlockReceipts`,
`ghost_getPageRoots`, `ghost_getPageSet`, `ghost_getTreePage`), heads read
with `httparse` and bodies with `serde_json`. Every reply is at most 1 MiB and
every exchange has 10 seconds in all; a refused, malformed, oversized or slow
reply is "can't check right now", never a guess.

TLS 1.3 to every node ends inside the enclave, with `rustls` (`ring`
provider, no TLS 1.2 code). The only trust anchor compiled in is the ISRG
Root X1 certificate (a test checks its SHA-256 against the published
fingerprint); the server's certificate is checked by rustls's own
`WebPkiServerVerifier` over that one root, for the node entry's host name.
No other certificate check, no public CA bundle, no pinned certificate hash.

A Vanish is found by its fingerprint with a bounded scan: the node reads the
chain forward from block 1 (`eth_getBlockByNumber` and
`eth_getBlockReceipts`; a block is read again with its transactions only when
its receipts show one to the coin commit entry), at most 500 blocks per call.
What it finds in blocks more than 128 below the tip it keeps in enclave
memory, shared by every session, per node; the newer blocks are read again
on every call, so a reorganisation among them is seen (one deeper than 128
blocks starts the scan over). Until it has caught up with the tip it answers
"can't check right now", and the next Check carries on from where it
stopped. This is correct and bounded but slow on a long chain; a faster
lookup is later work. A Vanish's leaf position is found among the leaves its
block added, from the coin tree as of its block and of its parent. The
1 MiB reply limit also bounds what can be read: a block with a Vanish whose
reply passes 1 MiB, or a coin tree page whose entries do, cannot be read, and
the answer for such a coin is "can't check right now".

A Fill confirmation's payment check (`ChainCheck`) in the enclave defers to
the session Seal's own chain status check, which every Seal is built with:
the card names its coin by hash only, and only the Seal's Fill journal entry
holds its commit data and spend marker.

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
check, a card registry that has been loaded and a durable journal (not a
memory-only one) have been installed into it (`ServiceDeps`). `Seal::new` is
the only way to build a Seal and takes the chain status check and the card
registry, so no Seal anywhere answers Sealed unchecked or serves an
unregistered card.

The enclave program installs the chain status check (`NodeChainStatus`: the
`RpcNode`s of the compiled-in release node list, over vsock to the host),
the card registry the host loads (`LoadedRegistry`) and the durable
journal: the append-only sealed log (`seal/src/journal_log.rs`, a
`SharedLog`) over the parent's store (`seal/src/host_journal.rs`, below).
With M, the three and a loaded registry, `ServiceDeps::ready()` is true and
Check, Fill confirmation and Open are served. It also installs the Phantom
Key maker a Fill needs (`CoreKeyMakerSource`, a fresh `CoreKeyMaker` from
`seal/src/key_maker.rs` per Fill), on the chain of the release network the
chain check follows, so a Fill start is served too. Without a key maker a
Fill start is answered HTTP 503 `unavailable` while the other flows are
served.

The journal is opened once, with the M just installed
(`DurableJournal::journal(&master)`): the enclave reads every record from
the host and refuses the log on a counter that is not the previous one plus
1 (a gap, a repeat or a reorder), a bad tag, a tag chained to another
record, a record that does not decode, or another M. A refused or
unreachable journal leaves every flow request (start, step and abort)
answered HTTP 503 `unavailable` with the message "This Seal is not ready to
answer cards", sends no card traffic, and logs one fixed event (`the durable
journal was refused`, no bytes); the enclave tries again every minute and at
each registry load. The attestation route still works once M is held. Each
session's Seal then gets a handle to the same log, behind one lock: before
it, the host's log is read again, and a log shorter, longer or with another
tail than the one the enclave wrote is a rollback, refused for good (no save
is taken, so no card changes) and logged the same way. Loads answer from the
log as verified in enclave memory, never from the host. The tests install
the log over a store in memory they can corrupt, and fakes for the rest.

### The journal store on the host (`seal/src/host_journal.rs`, `seal_proxy journal`)

The parent keeps the log in one file, `/var/lib/seal/journal.log` (the
`seal-journal` unit's systemd state directory, created mode 0600), and serves
it to the enclave on vsock port 5005 with `seal_proxy journal 5005
/var/lib/seal/journal.log`: the deployed proxy binary, no new artifact.
Requests are frames: 1 || counter || record (append) and 2 (read all). The
host takes an append only with the next counter and a record of at most 4096
bytes, writes `counter || length || record || check`, flushes the file and
its directory (`fsync`), and only then answers ok; a torn last record is
dropped when it opens the file. The enclave connects to the parent (CID 3)
port 5005 for each request, with 10 seconds per request; any failure, refusal
or timeout is a journal error, and the Seal changes a card only after a save
succeeded. The host sees counters and ciphertext only, and is not trusted for
integrity: the enclave checks the log itself.

The same unit keeps, for each other region, the copy of its log this
enclave holds as its peer: `seal_proxy journal 5005 /var/lib/seal/journal.log
<region>=/var/lib/seal/peer-<region>.log ...`, one file per origin region,
the same store and checks, the same port; a request about a peer log is 3 ||
origin length || origin || an append or read-all request.

### The journal's head in the other regions (`seal/src/journal_anchor.rs`)

The host's log alone cannot show a tail cut while the enclave is stopped,
nor a replaced host's empty log. So each region's log is anchored in the
other two (`docs/sealed-card.md`, "Journal", has the formats):

- After each append is durable on the host, the enclave sends the record
  (ciphertext only) to both peer enclaves as a service request kind 3,
  through vsock ports 5006 and 5007 (`seal_proxy outbound`, units
  `seal-anchor` and `seal-anchor-2`) to their regions' inbound proxies, 10
  seconds each. A peer checks the record's chain with M from that origin's
  start (every record's tag binds its origin region, so a record of another
  region's log never verifies there, whoever sends it), keeps it in its
  host's peer log for that origin, and answers its head MACed under a key
  derived from M (`ghost-seal/v1/journal-head`) over the asker's fresh
  nonce and the responder's own region id, with a fresh attestation
  document (below). The save is `Ok` only once both answered a head holding
  it, so Fill and Open refuse while a peer is unreachable.
- At the start, after M is installed and before any flow, the enclave
  restores **every** log it keeps, not only its own: first its copies of
  the two other regions' logs (`/var/lib/seal/peer-<region>.log`), each
  from that region or the other peer that holds it, then its own log from
  both peers. Every restore asks **every** peer (one answering is not
  enough); a peer holding more than the host's copy has the missing records
  restored to the host's store, each checked with M: that one path covers a
  cut tail and a replaced host. With a peer silent, an answer not taken
  (below), a peer holding another record at the same counter, or a restored
  record that fails its check, it serves no flow, logs `the durable journal
  could not be anchored in a peer region` and tries again every minute.
- A peer log not restored yet, or empty, answers *no copy* (with why: empty,
  not restored and nothing stored, or not restored with records not
  confirmed yet), never a zero head; a region asked for its own log before
  that log is open answers the same. A *no copy* never counts as a head or
  as agreement: a region's own restore takes heads only when every peer
  holds one, and opens an empty log only when its host's store is empty and
  every peer answered that its copy is restored and empty (a log never
  written). A store with records that no peer holds is refused, except a
  log still in the previous format (below). A peer log's
  restore with no head anywhere keeps the copy it holds, but refuses it when
  another holder says the log is empty, and waits while it is empty and
  another holder has records not confirmed yet. So when regions are
  replaced one after another (a rolling replacement), each replacement
  restores the other regions' logs before it serves, and the next one still
  finds every log in two places.
- A peer request needs M only, not the peer's own flows, so regions that
  start together anchor each other; a region answers about its own log from
  its host's store once that log is open.
- **A log written before the anchor.** The previous release's records carry
  no origin under their tag. When the host's own log holds such records,
  the enclave checks every one once with the previous rule (a record that
  fails it, or a log mixing the two formats, is a refusal), rewrites each
  with the same counter, IV and ciphertext under the current, origin-bound
  tag as this region's record, and has every peer take the rewritten log
  first: each peer must answer, with its copy restored (empty, as no peer
  can hold a log never anchored, or with a part of it left by a try that
  failed half way), and is sent what it lacks. Only then is the host's file
  replaced at once (the whole log written to `journal.log.new`, flushed,
  renamed over `journal.log`, the directory flushed; request 4 || counter
  || record stages each record, 5 || count replaces) and read back, before
  any flow. Until then the file keeps the previous format, and the region
  answers its peers about it as about an empty store (*no copy*, not
  restored), so their copies restore empty and the upgrade can begin. Fill
  and Open entries are kept as they were. Peer logs are always in the
  current format and are never rewritten.

**Who may answer.** M alone does not prove which enclave answers: an
approved build of another region's image can join M through the key share
(which authorizes by build), and a host controller could start one on its own
instance and lead the peer ports to it. So every head, *no copy* and fetch
answer carries a fresh Nitro attestation document from the answering
enclave's NSM, whose `nonce` is the asker's fresh nonce and whose `user_data`
binds the answer's MAC. The asker checks it with the existing attestation
verifier (the pinned AWS root) and against its trusted list (the approved
builds), and takes the answer only when:

- the region id compiled into the responder, bound into the MAC, is the
  region of the peer port it asked (5006 or 5007) and not the asker's own;
- the document's parent-instance PCR (PCR4) is not the asker's own, which it
  reads from its own attestation document: an extra enclave started on the
  asker's own host never answers for a peer;
- the answers of one restore or one save come from distinct PCR4s, one per
  peer: one instance never answers for two peers.

The cost is availability: Fill and Open wait while a peer region is down,
and a restarting region waits until both peers answer; keep every region
running, and replace a lost region by a redeploy, one region at a time, each
replacement serving before the next begins, which restores from its peers
(`enclave/RUNBOOK.md`). What it still does not cover:

- **An attacker who can launch new EC2 instances in the AWS account
  itself.** Each new instance has its own PCR4, so approved enclaves started
  on two new instances, one per peer port, joined to M through the key share
  and seeded with an old copy of the log, are taken as the two peers. The
  instance PCR binds an answer to an instance, not to the deployed stack;
  the AWS account (who may start instances in it, and the routes of the
  peer ports) stays trusted for this. Closing it needs the answering
  instances bound to the deployed stacks, by a membership list of the
  regions' instances signed with the release key; that is a later change,
  not this one.
- every region lost at once, or the hosts of every region cutting the log at
  once.

## What is still trusted

- **AWS Nitro**: the enclave's isolation and the NSM's attestation, signed
  under the pinned AWS root.
- **The AWS account**, for the journal's anchor: whoever can launch new EC2
  instances in it can start approved enclaves on instances of their own and
  answer for both peer regions (see "The journal's head in the other
  regions").
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
in CI, the app and DNS sending each card to its home region, a faster Vanish lookup than the
bounded block scan, nodes of independent operators in the release node list,
and the app's check of the phone attestation and of the TLS certificate it
binds.
