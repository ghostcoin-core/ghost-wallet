# The app's check of the Seal's attestation

The card screens (Check, Fill, Open) trust a Seal only through its Nitro
attestation, checked in native code. Until a Seal verifies, every card shows
"Can't verify this card", never an amount.

The Seal runs in several regions, and each card is served by one of them
only, its home (`docs/sealed-card.md`, "Home region"). `SEAL_REGIONS`
(`lib/seal/seal-config.ts`) is the ordered list `[{ id, url }]` of live
regions, in exactly the order and with exactly the ids of the Seal's release
list. It is empty until the live Seal exists (the deploy fills it in), so
today the app fetches nothing, opens no card sheet and trusts no Seal.

## Each card's home region

The app picks a card's home region the way the Seal does: of the ordered
list, the region id with the greatest SHA3-256(`ghost-seal/v1/home-region`
|| region id || UID), the label and id as UTF-8 and the UID as its 7 raw
bytes, concatenated as they are; on an equal hash the earlier id wins. It is
computed in the native core only (`core/src/seal_home_region.rs`,
`home_region_index`), through the C bridge `ghost_wallet_seal_home_region`
(`modules/ghost-nfc/ios/GhostCardBridge.h`: the UID, the ids as one UTF-8
buffer with one id per line; the index, -1 for none, -3 for a null pointer).
JavaScript never chooses a region and holds no hash code.
`core/tests/seal_home_region.rs` checks it against fixed vectors, a plain
loop over the rule, and every card in the Seal's
`seal/tests/vectors/home-region.json`.

The UID is known only once the card is tapped, so the native relay chooses.
At the start of each card flow JavaScript hands it the list
(`setSealRegions`, kept in native memory). A relay call (`relayCheck`,
`relayFill`, `relayFillConfirm`, `relayOpen`) with an empty Seal address
reads the UID, has the core choose over the whole listed list (never only
the regions that verified, or a region that is down would move cards) and
runs the flow against that region's address only. With no list, or no pin
for that region's host, nothing is sent and the flow fails as
"seal-unreachable". The result names the region it ran in. A typed https://
address (the speed screen) still runs against that one Seal, with no region.

A Seal that is not the card's home refuses it with the reason
`wrong-region` (`docs/seal-relay.md`). The app shows "This card is served by
another Seal region than the one this iPhone chose. Update Ghost Wallet, then
try again." and nothing the Seal sent; the home region the Seal names is
ignored. Each tap makes exactly one start request, to one Seal, and nothing
after a refusal: no Check, Fill, confirmation or Open is ever sent again, to
that region or another, until the person taps again. A refusal releases no
card key, notes no Fill and never shows Secured or an amount.

## What the Seal answers

`POST /v1/attestation` over HTTPS with `{ "challenge": "<64 hex digits>" }`
(the phone's 32-byte challenge). The answer (HTTP 200, at most 32 KiB) is
either JSON `{ "attestation": "<hex>" }` or the raw bytes, which start with
`GPA2`:

`GPA2` || document length (u32 BE) || Nitro attestation document || the
Seal's ML-DSA-65 verifying key (1952 bytes) || its ML-KEM-768 encapsulation
key (1184 bytes) || the SHA-256 of the DER of the TLS certificate the Seal
serves (32 bytes).

The document's `user_data` is SHA3-256(`ghost-seal/v2/phone-attestation` ||
verifying key || encapsulation key || certificate hash || challenge). The
older `GPA1` layout, and any other magic, is refused. Serving it is the
enclave's work; the app only reads it.

## Fetching (native)

`modules/ghost-nfc/ios/SealAttestation.swift` makes that one request on its
own ephemeral `URLSession` (10 second timeout, answer capped at 32 KiB). Its
delegate takes the server's leaf certificate, hashes its DER with SHA-256 and
lets that one connection go on without trusting any name: whether the
certificate is the Seal's is decided by the attestation, not by a CA. No App
Transport Security exception is set. JavaScript gets back only the
attestation bytes and the certificate hash, as hex
(`fetchSealAttestation`, `modules/ghost-nfc/relay.ts`).

## Checking (native core)

`verify_seal_attestation` (`core/src/seal_attestation.rs`, exported through
`modules/ghost-core/index.ts`) takes the attestation, the challenge, the
measured certificate hash, every pinned build of
`lib/seal/pinned-measurements.ts` (PCR0, PCR1, PCR2 and whether it is
allowed; revoked builds included) and now. It is a verify-only port of the
Seal's `NitroVerifier` (`seal/src/attestation.rs`): the bundle starts with the
pinned AWS Nitro root (its SHA-256), each certificate is signed by the one
above it (ECDSA P-384, `p384`), each issuer is a CA allowed to sign
certificates within its path length, every certificate is valid now, an
unknown critical extension is refused, the header is ES384 alone, the
payload has exactly AWS's fields (SHA384 digest, 48-byte PCRs, PCR0 to PCR2
present), the document's signature verifies and it is at most 300 seconds
old. Then PCR0, PCR1 and PCR2 must all equal one allowed pinned build, the
document must bind these keys, this challenge and this certificate hash,
both keys must decode, and the certificate the connection presented must be
the one bound.

It answers the Seal's verifying key, its ML-KEM key, PCR0 (the measurement
its answers carry) and the build's name, or one refusal:

| refusal | why |
| --- | --- |
| `malformed` | not the `GPA2` layout, not CBOR or COSE, a field missing, unknown or of the wrong size, or an input of the wrong length |
| `bad-chain` | another root, a certificate not signed by its issuer, an issuer that may not issue |
| `bad-signature` | the document's signature does not verify (a tampered payload included) |
| `expired` | the document is older than 300 seconds, or a certificate has expired |
| `not-yet-valid` | the document or a certificate is from the future |
| `not-pinned` | PCR0, PCR1 and PCR2 do not all equal one pinned build (an empty list refuses every Seal) |
| `revoked` | the build is pinned as revoked |
| `debug-mode` | a PCR is all zeros |
| `keys-not-bound` | the document does not bind these keys, this challenge and this certificate hash, or a key does not decode |
| `tls-mismatch` | the connection presented another certificate than the one bound |

Nothing panics; any error is a refusal. The challenge comes from the core's
random source (`seal_attestation_challenge`). The code is copied from `seal/`
(which depends on the core, so the core cannot depend on it) and kept in step
by the tests on both sides; `core/tests/seal_attestation.rs` signs its
documents with a test authority (`core/tests/support/nitro_authority.rs`),
never the AWS root, and checks that the verifier's source holds no signing
call or private key type.

## The relay's pin

Only after the core accepted a region's attestation does JavaScript call
`setSealPin(sealUrl, certSha256)` for that region's address. From then on
`modules/ghost-nfc/ios/SealRelay.swift` connects to that host only when the
presented leaf certificate's SHA-256 equals the pin; with no pin, another
hash or plain `http://`, the connection is cancelled and the flow fails as
"seal-unreachable". Any failure drops that region's pin. Pins are in memory
only.

## When it runs

Attestation is per region, with the same checks for each.
`lib/seal/seal-attestation.ts` loads one region (`loadTrustedSeal`, a 10
second deadline on its fetch), and the Seal it gives carries its `region`.
`lib/seal/trusted-seal.ts` keeps one entry per region in memory:
`trustedSeal(region)` reads it synchronously, and `refreshTrustedSeals()`
(never throws) first hands the native relay the list (`setSealRegions`),
then fetches and checks, in parallel, every region whose entry has run out,
and returns the verified Seals by region id. A verified Seal is kept 5
minutes, a failure 30 seconds; one region failing never changes another.

Only the card flows (`lib/seal/flows.ts`: Check, Fill and its confirmation,
Open) await it, at their start. A flow goes on to the card only when at
least one region verified; otherwise it is "Can't verify this card" with no
card sheet. Its answer is checked with the Seal of the region that answered
(that region's key, measurement and pin only); a region with no verified
Seal, or one not listed, is "Can't verify this card". Nothing is fetched at
app start or in the background, and opening the wallet, Home and Send never
wait on it.
