# J3R180 measurements

Measured on 2026-11-16 on one J3R180 card in a USB contact reader
("Generic EMV Smartcard Reader", USB 2ce3:9563, T=1), checked against
`docs/bearer-card-spec.md` ("Card type" and the time budgets). The numbers come
from a throwaway probe applet, `tools/card-probe/` (the applet is
`src/ghostprobe/Probe.java` and the timing program is `Host.java`). The card
manager keys were read, never changed, and the probe was deleted afterwards.

## Answer

**Keep the J3R180, but change the spec.** The card has no native SHA-3. A
bytecode Keccak-f\[1600\] permutation takes **1.44 s**. Done live, Make needs
14 permutations and takes about **24 s**, against a 10 s budget, so live
bytecode Keccak does **not** fit. With three spec changes Make takes about
**5 s** and every budget is met:

1. Do the key work ahead of time. Make the key, its secrets, F and the marker
   when the card is loaded or emptied, not at Make.
2. Use native SHA-256 for the commit-data digest in the seal statement.
3. Use native SHA-256 for the open-code hash and the open key.

A replacement card would not remove the problem. Ghost's F, commitment and
marker use Keccak-256 with the original 0x01 padding. A card's SHA3-256 API
pads with 0x06 and cannot compute them. So even a card with native SHA3-256
still runs at least 4 of the 14 permutations in bytecode. The fix belongs in
the spec, not in a different chip.

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
| **Keccak-f\[1600\], bytecode** (25 lanes as 4×16-bit limbs, all in RAM) | **1.44 s per permutation** (10 runs: 14.4 s) | SHA3-256 built on it matches the host |
| ChaCha20-Poly1305, bytecode: seals a Ghost note (352-byte body plus 40-byte associated data, giving a 380-byte sealed note) | **1.60 s** | ciphertext and tag match the host's JCE |
| LMS H10/W4 sign, native SHA-256 (with the atomic leaf-index write and a 10-node path read) | **1.59 s** average, 1.50 s min, 1.73 s max over 10 signatures, 582 SHA-256 calls on average | hash count as expected |
| LMS leaf key generation (one LM-OTS public key plus its leaf) | **2.94 s** per leaf (1,074 SHA-256 calls) | n/a |
| LMS H10 key generation, extrapolated (1,024 leaves plus 1,023 inner nodes) | **about 50 minutes** per card | n/a |

The Keccak is a plain loop implementation. Unrolling might make it somewhat
faster, but live Make would need about 0.5 s per permutation, three times
faster than measured. That speedup was not measured and is not assumed below.

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

Make's other work is the note seal (1.60 s), the seal statement's LMS
signature (1.59 s), and the atomic write plus I/O (about 0.2 s, estimated).

| Way | What runs at Make | Make time | Budget (≤10 s) |
| --- | --- | --- | --- |
| **Live, spec as written** | 14 permutations, seal, sign | 14 × 1.44 + 1.60 + 1.59 + 0.2 ≈ **23.6 s** (25.0 s with the lookup tag) | **fail** |
| Live, commit-data digest on native SHA-256 | 10 permutations, seal, sign | ≈ **17.8 s** | fail |
| **Precomputed when emptied**, spec digest | C (1), commit-data SHA3 (4), seal, sign | 5 × 1.44 + 1.60 + 1.59 + 0.2 ≈ **10.6 s** | fail (just over) |
| **Precomputed when emptied, commit-data digest on native SHA-256** | C (1), seal, sign | 1.44 + 1.60 + 1.59 + 0.2 ≈ **4.8 s** | **pass** |

"Precomputed" means the card draws its random bytes and computes the seed, the
secrets, the salt, F, the marker and the lookup tag ahead of time: 10
permutations, about **14.4 s**. A new card does this at the loading station. A
used card does it right after Open releases its seed material, while the
opener's phone is still on it, or at the start of the next Make if it was
pulled away (that one Make then takes the live time). None of these values
depends on the amount. The commitment, the note (which holds the amount and
uses C as associated data), the commit data and the statement do, so they stay
at Make.

The cost of precomputing: the key can no longer mix in the **writer's** nonce,
which only arrives at Make. It mixes in a nonce from whoever prepared it: the
issuer for a new card, the last opener for a used one. Against a card maker who
weakens the random source, the protection then rests on that party instead of
the writer. The spec has to accept this trade-off or keep live Make and raise
its budget to about 25 s (phone held on the card).

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
| **Make ≤ 10 s** | **fail live (23.6 s)**. **Pass at 4.8 s** with precompute plus a native SHA-256 commit-data digest. |
| **Check ≤ 3 s** | **pass**, estimated 1.6–1.8 s: one LMS signature, with the statement's digest and marker stored at Make, plus about 2.5 KB of output |
| **Open ≤ 3 s** | **fail as written, ≈ 3.0 s** (two bytecode SHA3-256 permutations, 2.9 s, plus AES). **Pass at under 0.1 s** with native SHA-256 for the open-code hash and the open key. |
| LMS key generation "up to about half an hour" | **fail at H10, about 50 min.** H9 takes about 25 min and H8 about 12.5 min. Alternatively, accept 50 minutes in parallel readers at the loading station. |

Does bytecode Keccak still fit the budgets? Only for the one amount-dependent
permutation (the commitment) at Make, plus the precompute done ahead of time.
It does not fit when the whole key derivation runs live at Make.

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
3. Run `java Host.java` (on macOS, add
   `-Dsun.security.smartcardio.library=/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC`).
4. Remove it with `gp --delete A00000084750524F42 -f`.

Only use a sacrificial card with known card manager keys, and never run
`--lock`.
