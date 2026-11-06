# The app's check of the Seal's attestation

The card screens (Check, Fill, Open) trust a Seal only through its Nitro
attestation, checked in native code. Until a Seal verifies, every card shows
"Can't verify this card", never an amount. `SEAL_URL`
(`lib/seal/seal-config.ts`) is an empty string until the live Seal exists, so
today the app fetches nothing and trusts no Seal.

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

Only after the core accepted the attestation does JavaScript call
`setSealPin(sealUrl, certSha256)`. From then on
`modules/ghost-nfc/ios/SealRelay.swift` connects to that host only when the
presented leaf certificate's SHA-256 equals the pin; with no pin, another
hash or plain `http://`, the connection is cancelled and the flow fails as
"seal-unreachable". Any failure drops the pin. Pins are in memory only.

## When it runs

`lib/seal/trusted-seal.ts` keeps the result in memory: `trustedSeal()` reads
it synchronously, and `refreshTrustedSeal()` (never throws) fetches and
checks again when it has run out. A verified Seal is kept 5 minutes, a
failure 30 seconds. Only the card flows (`lib/seal/flows.ts`: Check, Fill
and its confirmation, Open) await it, at their start. Nothing is fetched at
app start or in the background, and opening the wallet, Home and Send never
wait on it.
