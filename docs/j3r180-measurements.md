# J3R180 measurements

Measured on 2026-11-16 on one J3R180 card in a USB contact reader
("Generic EMV Smartcard Reader", USB 2ce3:9563, T=1), checked against
`docs/bearer-card-spec.md` ("Card type" and the time budgets). The numbers come
from a throwaway probe applet, `tools/card-probe/` (the applet is
`src/ghostprobe/Probe.java` and the timing program is `Host.java`). The card
manager keys were read, never changed, and the probe was deleted afterwards.

## Answer

**Keep the J3R180.** The card has no native SHA-3, so Ghost's hashes run in
bytecode. With the unrolled code in the probe, a Keccak-f\[1600\] permutation
takes **0.43 s** (the first plain loop took 1.44 s). The ChaCha20-Poly1305 note
seal takes **0.60 s** (the first version took 1.60 s). At those speeds Make
fits its 10 s budget even computed live, with the spec unchanged:

| Make, over contact | Time |
| --- | --- |
| Live, spec as written | **≈ 8.4 s** |
| Live, commit-data digest on native SHA-256 | ≈ 6.7 s |
| Live, SHA-256 digest, seal statement signed at the first Check instead of at Make | **≈ 5.1 s** |
| Key work precomputed when the card is loaded or emptied, SHA-256 digest | ≈ 2.8 s (≈ 1.2 s without the signature at Make) |

The recommendation is the third row, about 5 s. It keeps the writer's nonce in
the key and needs two small changes, both to the card's own seal statement and
neither to the chain:

1. Use native SHA-256 for the commit-data digest in the seal statement.
2. Make returns the commit data unsigned. The writer's app asks for a signed
   statement with Check, as every receiver does.

Precomputing goes faster still and is the fallback if the iPhone turns out
slower than the contact reader.

A replacement card would not remove the bytecode work. Ghost's F, commitment
and marker use Keccak-256 with the original 0x01 padding. A card's SHA3-256 API
pads with 0x06 and cannot compute them, so even a card with native SHA3-256
still runs at least 4 of the 14 permutations in bytecode.

## The card

| Item | Measured |
| --- | --- |
| ATR | `3BF81300008131FE454A434F5076323431B7`. Its text says "JCOPv241", a reseller string. |
| CPLC | IC fabricator 4790 (NXP), IC type D321, OS ID 4700, fabricated 2023-02-10, batch 5547 |
| Platform | GlobalPlatform 2.3, Java Card 3 (Card Data). The card loads and runs Java Card 3.0.5 code: SHA-512, AES-CTR, AES-CMAC, TRNG and 32-bit memory queries all work. This is consistent with JCOP 4 P71. |
| Card manager | ISD `A000000151000000`, life cycle OP_READY. SCP02 only (i=15/35/55/75). |
| Card manager keys | **Factory default** `404142…4F` (key version 1, three 3DES keys). A session opened with them on the first try. They were not changed. |
| `int` type | Supported |
| RAM int arrays (`javacardx.framework.util.intx`) | **Not present.** A package that imports it is refused at LOAD (6985). Hot 32-bit state must live in local variables or in short arrays. |
| Free persistent memory | **157,504 bytes** with the probe loaded. The probe itself (a 27 KB CAP file plus its objects) is not counted, so the empty card has more. After allocating the 2,047-node LMS tree (65,504 bytes): 91,968 bytes. |
| Free RAM | **2,022 bytes** (cleared on reset) and **2,016 bytes** (cleared on deselect), measured after the probe took about 1.3 KB of RAM. That gives roughly 3.3 KB for one applet. |

### Algorithms the API accepts

| Algorithm | Native |
| --- | --- |
| SHA-256, SHA-512 | yes |
| **SHA3-256, SHA3-512** | **no** (agrees with the public JCOP 4 P71 security targets) |
| AES-256 key, AES-CBC, AES-CTR | yes |
| AES-GCM, AES-CCM (AEAD) | **no** |
| AES-CMAC | yes |
| HMAC-SHA-256 | no |
| Secure random, TRNG, key-generation random | yes |

### APDUs

- Extended-length commands work: 300, 500, 600 and 1,000 data bytes in one
  command. The card's SHA-256 of the data matched the host's. A 1,000-byte
  command took 0.36 s.
- Responses work up to 256 bytes. Any longer response fails with
  `SCARD_E_NOT_TRANSACTED` at the reader. A 1,000-byte command passes, so this
  looks like a limit of this reader, not of the card. The iPhone test settles
  it. Either way, the applet can send long answers, such as a 2.5 KB LMS
  signature, as several 256-byte responses.
- Plain no-op round trip: 8 ms.

## Timings

All timings are card-side work with the 8 ms round trip removed, measured over
contact. Each answer was checked against the host's own implementation.

| Work | Time | Check |
| --- | --- | --- |
| SHA-256, native, 55-byte input (the LMS chain input) | **2.41 ms** per call (1,000 calls: 2.41 s) | n/a |
| **Keccak-f\[1600\], bytecode, unrolled** (`keccakFast`: each round written out, no loops, modulo or table lookups inside a round, column sums in local variables, state in two 100-short RAM arrays) | **0.428 s per permutation** (10 runs: 4.28 s) | SHA3-256 built on it matches the host |
| Keccak-f\[1600\], bytecode, plain loops (`keccakS`, the first version) | 1.44 s per permutation | SHA3-256 built on it matches the host |
| **ChaCha20-Poly1305, bytecode, unrolled Poly1305**: seals a Ghost note (352-byte body plus 40-byte associated data, giving a 380-byte sealed note) | **0.60 s** | tag matches the host's JCE |
| ChaCha20 alone (7 blocks, 32-bit work in local variables) | 0.28 s | n/a |
| ChaCha20-Poly1305 with plain-loop Poly1305 (the first version) | 1.60 s | ciphertext and tag match the host's JCE |
| LMS H10/W4 sign, native SHA-256 (with the atomic leaf-index write and a 10-node path read) | **1.59 s** average, 1.50 s min, 1.73 s max over 10 signatures, 582 SHA-256 calls on average | hash count as expected |
| LMS leaf key generation (one LM-OTS public key plus its leaf) | **2.94 s** per leaf (1,074 SHA-256 calls) | n/a |
| LMS H10 key generation, extrapolated (1,024 leaves plus 1,023 inner nodes) | **about 50 minutes** per card | n/a |

The unrolled Keccak and Poly1305 are generated code: every round is written
out in full. The applet is free to carry that code, since persistent memory is
plentiful.

Contactless power from a phone can make the card slower than it is over
contact. The iPhone run is still to be done (see "Not measured here").

## How long loading GHOST onto a card takes

Make's Keccak work, counted from Ghost's client code:

| Step | Hash | Permutations |
| --- | --- | --- |
| seed = SHA3-256("ghost-card-key" ‖ card random ‖ writer nonce) | SHA3-256 | 1 |
| secrets s, r, b₀, note key, note tag | SHA3-256 | 5 |
| F (204-byte input) | Keccak-256 | 2 |
| commitment C = K(F, amount) | Keccak-256 | 1 |
| marker | Keccak-256 | 1 |
| SHA3-256 of the 430-byte commit data | SHA3-256 | 4 |
| **Total** | | **14** (15 with the note lookup tag) |

Make's other work is the note seal (0.60 s), the seal statement's LMS
signature (1.59 s), and the atomic write plus I/O (about 0.2 s, estimated).
Each permutation takes 0.428 s.

| Way | What runs at Make | Make time | Budget (≤10 s) |
| --- | --- | --- | --- |
| **Live, spec as written** | 14 permutations, seal, sign | 14 × 0.43 + 0.60 + 1.59 + 0.2 ≈ **8.4 s** (8.8 s with the lookup tag) | **pass** |
| Live, commit-data digest on native SHA-256 | 10 permutations, seal, sign | ≈ **6.7 s** | pass |
| **Live, SHA-256 digest, statement signed at the first Check** | 10 permutations, seal | ≈ **5.1 s** | **pass (recommended)** |
| Precomputed when emptied, spec digest | C (1), commit-data SHA3 (4), seal, sign | ≈ **4.5 s** | pass |
| Precomputed when emptied, SHA-256 digest | C (1), seal, sign | ≈ **2.8 s** (≈ 1.2 s without the signature) | pass |

With the plain-loop code first measured (1.44 s per permutation, 1.60 s seal),
live Make took about 23.6 s. The unrolled code is what brings it inside the
budget.

"Precomputed" means the card draws its random bytes and computes the seed, the
secrets, the salt, F, the marker and the lookup tag ahead of time: 10
permutations, about **4.3 s**. A new card does this at the loading station. A
used card does it right after Open releases its seed material, while the
opener's phone is still on it, or at the start of the next Make if it was
pulled away (that one Make then takes the live time). None of these values
depends on the amount. The commitment, the note (which holds the amount and
uses C as associated data), the commit data and the statement do, so they stay
at Make.

The cost of precomputing: the key mixes in a nonce from whoever prepared it
(the issuer for a new card, the last opener for a used one) instead of the
writer's, which only arrives at Make. Against a card maker who weakens the
random source, the key is then as safe as that preparer is honest, rather than
the writer. Live Make keeps the writer's nonce, which is why it is the
recommendation now that it fits.

## Pass/fail against the spec

| Requirement | Result |
| --- | --- |
| Java Card 3.0.5+ on a GlobalPlatform card manager | **pass** (GP 2.3, runs JC 3.0.5 code) |
| Contactless ISO 14443-A | not measured here (contact only). The card is sold as dual-interface. |
| Extended-length or chained APDUs | **pass** for commands up to 1,000 bytes. Long responses are unconfirmed through this reader (see above). |
| Native SHA-256 | **pass** |
| Native SHA3-256 | **fail** (not in the API) |
| Native AES-256 | **pass**. There is no AEAD mode: Open's "authenticated mode" must be AES-256-CTR plus AES-CMAC (both native). |
| Hardware TRNG | **pass** (`ALG_TRNG` accepted) |
| Atomic persistent writes | **pass**. The transaction API works: every LMS signature advanced its leaf index inside one. Tearing was not tested. |
| ≥ 100 KiB free persistent memory | **pass** (157,504 bytes free with the probe loaded) |
| CC EAL6+ secure element | JCOP 4 P71 is certified EAL6+. This card matches it, but a reseller card in OP_READY with default keys is not in the certified delivery state, so the certificate covers the chip, not this card's history. |
| **Make ≤ 10 s** | **pass live, ≈ 8.4 s as written** with the unrolled code; ≈ 5.1 s with the SHA-256 digest and the signature moved to Check. (The plain-loop code took 23.6 s.) |
| **Check ≤ 3 s** | **pass**, estimated 1.6–1.8 s: one LMS signature, with the statement's digest and marker stored at Make, plus about 2.5 KB of output |
| **Open ≤ 3 s** | **pass, ≈ 0.9 s as written** (two unrolled SHA3-256 permutations plus native AES). It drops under 0.1 s with native SHA-256 for the open-code hash and the open key, but that change isn't needed. |
| LMS key generation "up to about half an hour" | **fail at H10, about 50 min.** H9 takes about 25 min and H8 about 12.5 min. Alternatively, accept 50 minutes in parallel readers at the loading station. |

Does bytecode Keccak still fit the budgets? Yes, over contact, when unrolled:
live Make takes about 8.4 s as written and Open about 0.9 s. The plain-loop
version did not fit. Over NFC the card may run slower, so the iPhone run
(below) is what confirms it.

## Not measured here

- The iPhone Core NFC round trip, a long response over NFC, and contactless
  timings. This needs the card on the phone.
- A bytecode ML-DSA-44 signature. The spec already rules ML-DSA out on this
  card class, and with about 3.3 KB of RAM for an applet and no RAM int arrays
  this card is further from it than the spec assumed.

## Raw run

```
reader: Generic EMV Smartcard Reader
protocol: T=1
ATR: 3bf81300008131fe454a434f5076323431b7
select: 9000
  SHA-256 yes, SHA-512 yes, SHA3-256 no, SHA3-512 no, AES-CBC yes, AES-CTR yes,
  AES-GCM no, AES-CCM no, AES-256 key yes, AES-CMAC yes, HMAC-SHA256 no,
  SecureRandom yes, TRNG yes, KeyGen RNG yes, RAM int arrays no
  free persistent 157504 bytes, free RAM (reset) 2022 bytes, free RAM (deselect) 2016 bytes
APDU round trip (no-op): 7.99 ms
SHA-256 x1000 (55-byte input): 2412 ms total, 2.412 ms per call
SHA3-256 bytecode (16-bit limbs) matches host: true
Keccak-f[1600] bytecode, 16-bit limbs: 1443 ms per permutation (1 run 1458 ms, 10 runs 14440 ms)
SHA3-256 bytecode (unrolled) matches host: true
Keccak-f[1600] bytecode, unrolled: 428 ms per permutation (1 run 427 ms, 10 runs 4277 ms)
ChaCha20 alone, 7 blocks: 277 ms
ChaCha20-Poly1305 unrolled Poly1305 matches host: tag true
ChaCha20-Poly1305 seal, unrolled Poly1305: 598 ms
ChaCha20-Poly1305 (352-byte note body + 40-byte AAD = 380-byte sealed note) matches host: ciphertext true, tag true
ChaCha20-Poly1305 seal: 1603 ms (1 run 1613 ms)
after allocating the 2,047-node LMS tree (65,504 bytes):
  free persistent 91968 bytes, free RAM (reset) 2022 bytes, free RAM (deselect) 2016 bytes
LMS H10/W4 sign (10 signatures): avg 1588 ms, min 1497 ms, max 1734 ms, avg 582 SHA-256 calls
LMS leaf key generation: 2935 ms per leaf (1074 SHA-256 calls per leaf)
LMS H10 key generation estimate (1,024 leaves + 1,023 inner nodes): 50.2 minutes
extended APDU, 1,000 bytes in: 9000, hash matches. Response of 257+ bytes: SCARD_E_NOT_TRANSACTED at the reader.
```

## Reproducing

1. Get GlobalPlatformPro, ant-javacard, the Oracle Java Card SDKs
   (`jc310r20210706_kit` to build, `jc305u4_kit` as the target) and JDK 17.
2. Put them in `~/jc-probe/tools/`, then run `ant` in `tools/card-probe/` and
   `gp --install probe.cap`.
3. Run `java Host.java` (`java Host.java fast` runs only the unrolled
   Keccak and seal timings; on macOS, add
   `-Dsun.security.smartcardio.library=/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC`).
4. Remove it with `gp --delete A00000084750524F42 -f`.

Only use a sacrificial card with known card manager keys, and never run
`--lock`.
