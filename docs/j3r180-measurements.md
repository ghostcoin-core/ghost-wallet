# J3R180 measurements

Measured on 2026-11-16 on one J3R180 card in a USB contact reader
("Generic EMV Smartcard Reader", USB 2ce3:9563, T=1), checked against
`docs/bearer-card-spec.md` ("Card type" and the time budgets). The numbers come
from a throwaway probe applet, `tools/card-probe/` (the applet is
`src/ghostprobe/Probe.java` and the timing program is `Host.java`). The card
manager keys were read, never changed, and the probe was deleted afterwards.
The Keccak and seal code was rewritten and measured again on 2026-11-17, on
the same card and reader.

## Answer

**Keep the J3R180.** The card has no native SHA-3, so Ghost's hashes run in
bytecode. With the generated code in the probe, a Keccak-f\[1600\] permutation
takes **0.139 s** and the ChaCha20-Poly1305 note seal takes **0.35 s**:

| Code | Keccak-f\[1600\] | Note seal |
| --- | --- | --- |
| Plain loops (first version) | 1.44 s | 1.60 s |
| Unrolled, 16-bit limbs in RAM arrays (second version) | 0.428 s | 0.60 s |
| **32-bit halves in local variables (now)** | **0.139 s** | **0.35 s** |

At those speeds Make fits its 10 s budget with a wide margin, computed live
and with the spec unchanged:

| Make, over contact | Time | With the second version |
| --- | --- | --- |
| Live, spec as written | **≈ 4.1 s** | 8.4 s |
| Live, commit-data digest on native SHA-256 | ≈ 3.5 s | 6.7 s |
| Live, SHA-256 digest, seal statement signed at the first Check instead of at Make | **≈ 1.9 s** | 5.1 s |
| Key work precomputed when the card is loaded or emptied, SHA-256 digest | ≈ 2.3 s (≈ 0.7 s without the signature at Make) | 2.8 s (1.2 s) |

The spec as written no longer needs any change to fit. The third row is still
the fastest live design, about 1.9 s. It keeps the writer's nonce in the key
and needs two small changes, both to the card's own seal statement and neither
to the chain:

1. Use native SHA-256 for the commit-data digest in the seal statement.
2. Make returns the commit data unsigned. The writer's app asks for a signed
   statement with Check, as every receiver does.

In the spec as written the LMS signature (1.57 s) is now the largest single
part of Make, which is why the second change is worth more than it was.
Precomputing no longer beats live Make unless the signature also moves; it
stays the fallback if the iPhone turns out much slower than the contact
reader.

A replacement card would not remove the bytecode work. Ghost's F, commitment
and marker use Keccak-256 with the original 0x01 padding. A card's SHA3-256 API
pads with 0x06 and cannot compute them, so even a card with native SHA3-256
still runs at least 4 of the 14 permutations in bytecode.

## Over iPhone NFC

Measured on 2026-11-17 with the card held to an iPhone, running TestFlight
build 132's Card probe screen against the probe from main (commit 0dcf579).
**Over NFC the card is about 5% slower than over contact, and every budget
passes with room to spare.**

| Work | Contact | iPhone NFC |
| --- | --- | --- |
| No-op round trip | 7.9 ms | 7.1 ms |
| SHA-256, native, per call | 2.41 ms | 2.53 ms |
| **Keccak-f\[1600\], generated code** | 139 ms | **146 ms** (SHA3-256 right) |
| Keccak-f\[1600\], plain loop | 1.44 s | 1.53 s |
| **Note seal** | 346 ms | **362 ms** (tag right) |
| **LMS H10/W4 sign** | 1.57–1.59 s | **1.62 s** (568 SHA-256 calls) |
| Extended command, 1,000 bytes | 0.36 s, hash right | 128 ms, hash right |
| Answer of 256 bytes | yes | yes, 36 ms |
| Answer of 257 bytes | no (USB reader) | **yes, 37 ms**, all bytes right |
| Answer of 1,000 bytes | no (USB reader) | **yes, 106 ms**, all bytes right |

Answers longer than 256 bytes work over the iPhone, so the failure over
contact was the USB reader's limit, not the card's. A Check's 2.5 KB answer
can go back in a few long answers.

| Budget, over iPhone NFC | Estimate | Result |
| --- | --- | --- |
| Make, spec as written | 4.23 s | **pass** (≤ 10 s) |
| Make, recommended (SHA-256 digest, statement signed at Check) | 2.02 s | **pass** |
| Make, precomputed (signature at Make) | 2.33 s | **pass** |
| Check | 1.88 s | **pass** (≤ 3 s) |
| Open, spec as written | 0.39 s | **pass** (≤ 3 s) |

The estimates add up the measured parts as the tables above do: permutations,
seal and signature, plus 0.2 s for the atomic write and I/O at Make, and for
Check the signature plus 2.6 KB of answer at the measured rate. They are not a
timed Make, which needs the real applet.

## Where the time goes, and what is left to try

This is the fastest live design: live Make, a native SHA-256 commit-data
digest, and the statement signed at Check. It took about 5.1 s with the second
version of the code.

| Part | Time | Share |
| --- | --- | --- |
| 10 Keccak-f\[1600\] permutations: seed (1), s, r, b₀, note key, note tag (5), F (2), C (1), marker (1) | 10 × 0.139 = 1.39 s | 72% |
| Note seal (ChaCha20 0.20 s, Poly1305 and the rest about 0.15 s) | 0.35 s | 18% |
| Atomic write, SHA-256 digest, I/O (estimated) | about 0.2 s | 10% |
| **Total** | **about 1.9 s** | |

Fixed constraints:

- The chain does not change: F, C and the marker use Keccak-256 with 0x01
  padding.
- The secrets and note key are derived as Ghost's client derives them.
- No elliptic-curve keys anywhere.
- About 3.7 KB of RAM for an applet, no RAM int arrays, and `int` is
  supported.

What made the difference:

- **The card runs about 200,000 bytecodes a second, and an `int` bytecode
  costs the same as a `short` one.** Both versions of Keccak come out at about
  5 µs per bytecode. So the work is to count bytecodes, and 32-bit values
  halve the count against 16-bit limbs.
- **Keccak keeps its whole state in 50 `int` local variables** (two per lane),
  so a round reads and writes no array. Each round writes its results back
  into the lanes it just read. That moves the lanes around, and after four
  rounds they are all home again, so the loop body is four rounds, run six
  times. A round is about 1,180 bytecodes (the second version took about
  3,500). The state is copied in from one 100-short RAM array and back out,
  which costs about 4% of a permutation. The second state array is gone, which
  frees 200 bytes of RAM.
- **Poly1305 uses ten 13-bit limbs**, as poly1305-donna's 16-bit version does:
  100 multiplications per block where the 8-bit limbs needed 289. Sums are
  unsigned 32-bit values, carried after every five products.
- **ChaCha20 writes its rotations inline** (the second version called a
  method for each, 320 calls per block) and XORs the key stream straight into
  the note.

Ideas not yet tried, with what each should save:

- **Keccak, lane-complementing transform:** chi needs 5 NOTs per round where
  it now does 25. About 80 of the 1,180 bytecodes in a round, so about 9 ms
  per permutation.
- **Keccak, absorb into the local variables directly** when the input is one
  short block, instead of through the short array: up to 6 ms per permutation.
- **Fewer permutations:** the seed hash is the card's own construction, so it
  could be native SHA-256 (saves 0.14 s). The other nine are fixed by Ghost.
- **ChaCha20:** three of the first four quarter-rounds do not depend on the
  block counter and could be computed once for all seven blocks, about 7 ms.

None of these moves Make by more than 0.1 to 0.2 s. With the spec as written,
the LMS signature and the four extra SHA3-256 permutations over the commit
data are 2.1 s of the 4.1 s, so the two spec changes above are the larger
lever now.

The generated methods come from `tools/card-probe/gen/`: `keccak.py`
(`keccakFast`), `poly1305.py` (`polyFast`) and `chacha.py` (`chachaFast`).
`python3 gen/apply.py` writes all three into `Probe.java`. Measure any change
on the card with `java Host.java fast`, and check that SHA3-256 and the seal
still match the host.

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
| Free persistent memory | **143,412 bytes** with the probe loaded. The probe itself (a 61 KB CAP file plus its objects) is not counted, so the empty card has more. With the first, 27 KB probe it was 157,504 bytes. After allocating the 2,047-node LMS tree (65,504 bytes): 77,876 bytes. |
| Free RAM | **2,470 bytes** (cleared on reset) and **2,464 bytes** (cleared on deselect), measured after the probe took about 1.3 KB of RAM. That gives roughly 3.7 KB for one applet. The first report said 2,022 bytes: it was read after the probe's own algorithm checks had created 448 bytes of objects. The probe now reads memory first and asks the card to reclaim those objects. Running the generated code does not change these numbers, so its local variables (about 80 `int`s in `keccakFast`) come out of the card's stack, not out of this RAM. |

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
- Over the USB reader, responses work up to 256 bytes and any longer one fails
  with `SCARD_E_NOT_TRANSACTED`. Over the iPhone, answers of 257 and 1,000
  bytes come back whole (see "Over iPhone NFC"), so that limit belongs to the
  reader, not the card.
- Plain no-op round trip: 8 ms.

## Timings

All timings are card-side work with the 8 ms round trip removed, measured over
contact. Each answer was checked against the host's own implementation.

| Work | Time | Check |
| --- | --- | --- |
| SHA-256, native, 55-byte input (the LMS chain input) | **2.41 ms** per call (1,000 calls: 2.41 s) | n/a |
| **Keccak-f\[1600\], bytecode, 32-bit halves in local variables** (`keccakFast`: the state in 50 `int` locals, each round written out with constant shifts, results written back in place, four rounds per loop pass) | **0.139 s per permutation** (10 runs: 1.39 s) | SHA3-256 built on it matches the host |
| Keccak-f\[1600\], bytecode, unrolled on 16-bit limbs in two RAM arrays (the second version) | 0.428 s per permutation | SHA3-256 built on it matched the host |
| Keccak-f\[1600\], bytecode, plain loops (`keccakS`, the first version) | 1.44 s per permutation | SHA3-256 built on it matches the host |
| **ChaCha20-Poly1305, bytecode, generated code** (`chachaFast` and `polyFast`): seals a Ghost note (352-byte body plus 40-byte associated data, giving a 380-byte sealed note) | **0.35 s** | tag and ciphertext match the host's JCE |
| ChaCha20 alone (7 blocks, rotations inline) | 0.20 s | n/a |
| ChaCha20-Poly1305 with 8-bit-limb unrolled Poly1305 and a method call per rotation (the second version) | 0.60 s (ChaCha20 alone 0.28 s) | tag matched the host's JCE |
| ChaCha20-Poly1305 with plain-loop Poly1305 (the first version) | 1.60 s | ciphertext and tag match the host's JCE |
| LMS H10/W4 sign, native SHA-256 (with the atomic leaf-index write and a 10-node path read) | **1.57 s** average, 1.38 s min, 1.77 s max over 10 signatures, 573 SHA-256 calls on average | hash count as expected |
| LMS leaf key generation (one LM-OTS public key plus its leaf) | **2.94 s** per leaf (1,074 SHA-256 calls) | n/a |
| LMS H10 key generation, extrapolated (1,024 leaves plus 1,023 inner nodes) | **about 50 minutes** per card | n/a |

The fast Keccak, Poly1305 and ChaCha20 are generated code: every round is
written out in full. The applet is free to carry that code, since persistent
memory is plentiful. Before it went on the card, the generated Java was run
on a desktop JVM against a reference Keccak-f (2,000 random states), a
big-number Poly1305 (20,000 keys and messages, including all-ones) and the
JCE seal, with no mismatch.

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

Make's other work is the note seal (0.35 s), the seal statement's LMS
signature (1.57 s), and the atomic write plus I/O (about 0.2 s, estimated).
Each permutation takes 0.139 s. The Make times below are these measured parts
added up; a whole Make has not been run on the card, because the applet does
not exist yet.

| Way | What runs at Make | Make time | Budget (≤10 s) |
| --- | --- | --- | --- |
| **Live, spec as written** | 14 permutations, seal, sign | 14 × 0.139 + 0.35 + 1.57 + 0.2 ≈ **4.1 s** (4.2 s with the lookup tag) | **pass** |
| Live, commit-data digest on native SHA-256 | 10 permutations, seal, sign | ≈ **3.5 s** | pass |
| **Live, SHA-256 digest, statement signed at the first Check** | 10 permutations, seal | 10 × 0.139 + 0.35 + 0.2 ≈ **1.9 s** | **pass (fastest live)** |
| Precomputed when emptied, spec digest | C (1), commit-data SHA3 (4), seal, sign | ≈ **2.8 s** | pass |
| Precomputed when emptied, SHA-256 digest | C (1), seal, sign | ≈ **2.3 s** (≈ 0.7 s without the signature) | pass |

With the plain-loop code first measured (1.44 s per permutation, 1.60 s seal),
live Make took about 23.6 s, and with the second version (0.428 s, 0.60 s)
about 8.4 s.

"Precomputed" means the card draws its random bytes and computes the seed, the
secrets, the salt, F, the marker and the lookup tag ahead of time: 10
permutations, about **1.4 s**. A new card does this at the loading station. A
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
recommendation now that it fits. Precomputing now saves only that 1.4 s.

## Pass/fail against the spec

| Requirement | Result |
| --- | --- |
| Java Card 3.0.5+ on a GlobalPlatform card manager | **pass** (GP 2.3, runs JC 3.0.5 code) |
| Contactless ISO 14443-A | **pass**: every test ran over iPhone Core NFC (`NFCISO7816Tag`), about 5% slower than contact |
| Extended-length or chained APDUs | **pass**: 1,000-byte commands, and answers of 257 and 1,000 bytes over the iPhone |
| Native SHA-256 | **pass** |
| Native SHA3-256 | **fail** (not in the API) |
| Native AES-256 | **pass**. There is no AEAD mode: Open's "authenticated mode" must be AES-256-CTR plus AES-CMAC (both native). |
| Hardware TRNG | **pass** (`ALG_TRNG` accepted) |
| Atomic persistent writes | **pass**. The transaction API works: every LMS signature advanced its leaf index inside one. Tearing was not tested. |
| ≥ 100 KiB free persistent memory | **pass** (143,412 bytes free with the 61 KB probe loaded) |
| CC EAL6+ secure element | JCOP 4 P71 is certified EAL6+. This card matches it, but a reseller card in OP_READY with default keys is not in the certified delivery state, so the certificate covers the chip, not this card's history. |
| **Make ≤ 10 s** | **pass over iPhone NFC, ≈ 4.2 s as written**, ≈ 2.0 s recommended (contact: 4.1 s and 1.9 s) with the generated code; ≈ 1.9 s with the SHA-256 digest and the signature moved to Check. (The plain-loop code took 23.6 s and the second version 8.4 s.) |
| **Check ≤ 3 s** | **pass, ≈ 1.9 s over iPhone NFC**: one LMS signature (1.62 s), with the statement's digest and marker stored at Make, plus about 2.5 KB of answer |
| **Open ≤ 3 s** | **pass, ≈ 0.4 s as written over iPhone NFC (0.3 s over contact)** (two bytecode SHA3-256 permutations plus native AES). It drops under 0.1 s with native SHA-256 for the open-code hash and the open key, but that change isn't needed. |
| LMS key generation "up to about half an hour" | **fail at H10, about 50 min.** H9 takes about 25 min and H8 about 12.5 min. Alternatively, accept 50 minutes in parallel readers at the loading station. |

Does bytecode Keccak still fit the budgets? Yes, with the generated code, over
contact and over iPhone NFC: live Make takes about 4.2 s as written over NFC
and Open about 0.4 s. The plain-loop version did not fit.

## Not measured here

- A bytecode ML-DSA-44 signature. The spec already rules ML-DSA out on this
  card class, and with about 3.7 KB of RAM for an applet and no RAM int arrays
  this card is further from it than the spec assumed.

## Raw run

From 2026-11-17, with the generated code. The last line is the reader refusing
the 768-byte response (see "APDUs"); the 1,000-byte command itself went
through on 2026-11-16.

```
reader: Generic EMV Smartcard Reader
protocol: T=1
ATR: 3bf81300008131fe454a434f5076323431b7
select: 9000
  SHA-256 yes, SHA-512 yes, SHA3-256 no, SHA3-512 no, AES-CBC yes, AES-CTR
  yes, AES-GCM no, AES-CCM no, AES-256 key yes, AES-CMAC yes, HMAC-SHA256 no,
  SecureRandom yes, TRNG yes, KeyGen RNG yes, RAM int arrays no
  free persistent 143412 bytes, free RAM (reset) 2470 bytes, free RAM (deselect) 2464 bytes
APDU round trip (no-op): 7.90 ms
SHA-256 x1000 (55-byte input): 2413 ms total, 2.413 ms per call
SHA3-256 bytecode (16-bit limbs) matches host: true
SHA3-256 bytecode (int locals) matches host: true
Keccak-f[1600] bytecode, int locals: 139 ms per permutation (1 run 139 ms, 10 runs 1391 ms)
ChaCha20 alone, 7 blocks: 198 ms
ChaCha20-Poly1305 generated code matches host: ciphertext true, tag true
ChaCha20-Poly1305 seal, generated code: 346 ms
Keccak-f[1600] bytecode, 16-bit limbs: 1452 ms per permutation (1 run 1457 ms, 10 runs 14529 ms)
ChaCha20-Poly1305 (352-byte note body + 40-byte AAD = 380-byte sealed note) matches host: ciphertext true, tag true
ChaCha20-Poly1305 seal: 1601 ms (1 run 1610 ms)
after allocating the 2,047-node LMS tree (65,504 bytes):
  free persistent 77876 bytes, free RAM (reset) 2470 bytes, free RAM (deselect) 2464 bytes
LMS H10/W4 sign (10 signatures): avg 1565 ms, min 1375 ms, max 1774 ms, avg 573 SHA-256 calls
LMS leaf key generation: 2936 ms per leaf (1074 SHA-256 calls per leaf)
LMS H10 key generation estimate (1,024 leaves + 1,023 inner nodes): 50.2 minutes
extended APDU: failed: javax.smartcardio.CardException: sun.security.smartcardio.PCSCException: SCARD_E_NOT_TRANSACTED
```

## Reproducing

1. Get GlobalPlatformPro, ant-javacard, the Oracle Java Card SDKs
   (`jc310r20210706_kit` to build, `jc305u4_kit` as the target) and JDK 17.
2. Put them in `~/jc-probe/tools/`, then run `ant` in `tools/card-probe/`
   with `JAVA_HOME` set to JDK 17 (a newer default JDK makes the build stop),
   and `gp --install probe.cap`.
3. Run `java Host.java` (`java Host.java fast` runs only the generated
   Keccak and seal timings; on macOS, add
   `-Dsun.security.smartcardio.library=/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC`).
4. Remove it with `gp --delete A00000084750524F42 -f`.

Only use a sacrificial card with known card manager keys, and never run
`--lock`.

### Over iPhone NFC

The app has a test screen for the probe. To use it:

1. Install the probe on the card.
2. In the app, open Settings, tap the version seven times to open the bench,
   then tap **Card probe**.
3. Tap Run and hold the card flat on the top of the iPhone for about 20
   seconds.

The screen shows:

- each step's time over NFC;
- whether the SHA3-256 and seal answers are right;
- whether a 1,000-byte command and answers of 256, 257 and 1,000 bytes get
  through;
- Make, Check and Open worked out the same way as above, each marked pass or
  over budget.

The text can be selected and copied. The probe's AID is in the app's ISO 7816
select identifiers. The run is in `modules/ghost-nfc/card-probe.ts`.
