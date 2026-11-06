# Ghost Sealed cards

Status: design, with the Seal's card logic built and tested against a
simulated NTAG 424 DNA. The enclave that runs it, the phone relay, the chain
check, the card setup and the app screens are separate pieces of work that
build on this document.

## What a Ghost Sealed card is

A Ghost Sealed card is an NTAG 424 DNA card whose keys and whose Phantom Key
live only in **the Seal**: a small service running inside an attested
enclave. The phone never holds a card key or the Phantom Key. It only relays
raw commands between the card and the Seal, one APDU in and one answer out,
and shows the Seal's signed answers.

That changes what an NTAG 424 DNA card can be. On its own the chip cannot
make or use a secret, so whoever writes it knows what it holds, and the
bearer-card specification keeps it carry-to-Claim only. With the Seal, the
writer is the Seal itself: no phone, app or person ever sees the key, so a
receiver who runs a fresh Check can accept the card. Offline or trust-free
certainty still needs the Java Card plan; a Sealed card trusts the Seal.

The parts:

- **The card**: an NTAG 424 DNA. Its five AES-128 keys are the Seal's,
  derived from the Seal's master key M and the card's UID. Its record file
  (file 2, 256 bytes) is encrypted and MACed on the air (CommMode.Full) and
  holds the card record and the Phantom Key.
- **The Seal**: holds M and nothing else long-lived. It derives every card's
  keys when it needs them, runs EV2 secure messaging with the card through
  the phone, makes Phantom Keys, signs every answer with ML-DSA-65 and
  releases a key only at the end of an Open, encrypted with ML-KEM-768 to the
  phone key bound when the Open started.
- **The phone**: relays APDUs, sends a fresh random challenge with every
  request, and checks the Seal's signed answers against the Seal's pinned
  public key and code measurement.
- **The chain check**: tells the Seal whether a coin is paid exactly and
  final. The Seal only asks it; how it decides is its own design.

No elliptic-curve key exists anywhere: the card uses AES, the Seal signs with
ML-DSA-65 and encrypts with ML-KEM-768, and every derivation is HKDF with
HMAC-SHA3-256.

## Flows

Every flow is a state machine driven by the card's answers. A flow cut off at
any step (the card moved away, the relay dropped, the Seal restarted) is run
again from the start and carries on from what the card and the Seal's
journal say. Every flow begins by selecting the NDEF application, which drops
any session left on the chip.

### Fill

1. Read the version of keys 2 and 0 (GetKeyVersion, outside any session):
   they give the card's generation, and must agree.
2. AuthenticateEV2First with key 2 of that generation, then GetCardUID: the
   chip must report the UID asked about.
3. GetFileSettings of the record file: CommMode.Full, key 2 reads and
   writes, key 1 reads, key 0 changes the settings, 256 bytes. Anything else
   is a card that was not set up.
4. Read the header frame. It must be Empty with no key in the slot.
5. Make a Phantom Key inside the Seal with the wallet core's derivation (the
   same calls the app's card Vanish uses: a new card-only key and its coin
   commit number 0), from the Seal's random source.
6. Journal the coin (its public commit data) before the card changes.
7. Write the key slot frame, read it back and compare.
8. Write the header frame (still Empty, key present, the coin, the amount and
   the Open PIN hash if one was asked for), read it back and compare.
9. Wipe the key from memory. Return only the commit data, the amount and a
   signed answer (state Empty).

The card is **not** Sealed yet. The phone sends the Vanish with the commit
data. Then the Seal is asked to confirm:

10. Read the header (key 2) and the key slot; they must match.
11. Ask the chain check whether exactly this coin and exactly this amount are
    paid and final. If not: nothing changes.
12. Write the header Sealed, read it back, answer Sealed.

A Fill asked again while one is waiting for its payment hands back the same
commit data (from the journal), never a new key, so a Vanish sent for a lost
answer is never stranded. A Fill with another amount or PIN is refused until
the waiting one is paid.

### Check

1. Read the version of key 1: the generation of the check key.
2. AuthenticateEV2First with key 1, then GetCardUID.
3. Read the header frame only. The key slot is never read.
4. Answer the state, the coin, the amount and the Open PIN status (whether
   an Open needs a PIN, and the tries left), signed over the phone's
   challenge. While an Open is journaled the answer is **Opening** (or
   **Opened** once the key was released), whatever the card still says.
5. A Sealed card whose Open PIN has no tries left can never be opened, so it
   is never certified: with no Open journaled, Check refuses it (PIN locked)
   instead of answering Sealed. Confirming its Fill again is refused the same
   way. Otherwise a sender could burn the tries on purpose and still hand a
   receiver a fresh Sealed answer for a coin nobody can redeem.

### Open

1. Read the version of key 2, authenticate with it, GetCardUID, read the
   header. It must be Sealed (a card that says Opening with no journal is
   refused: the journal was lost).
2. If the card has an Open PIN: refuse without a PIN; refuse when no tries are
   left; otherwise write the header with one try fewer, read it back, and only
   then compare the PIN. A cut connection never buys a free guess.
3. Read the key slot; it must hold the key of this coin.
4. **Journal the Open first**: the phase, the generation, the coin, the
   amount, the phone key and the Phantom Key, sealed under keys derived from
   M. Nothing about the Open changes the card before this save succeeds.
5. Mark the card Opening, bound to the hash of the phone key, and read it
   back.
6. Wipe the key slot (an empty slot frame over it) and read it back.
7. Rotate all five card keys to the next generation: keys 1 to 4 first, the
   application master key last, each ChangeKey checked, then every key
   version read back.
8. Verify by fresh authentication with each of the five new keys, then write
   the header Opened at the new generation and read it back.
9. Only then release the key: encrypted with ML-KEM-768 to the phone key
   bound in step 4, with a signed answer (state Opened) that binds the
   release package's hash.

The journal records each phase after its card step was verified, and every
card step is idempotent: a header already Opening, a slot already empty or a
key already at the new version is left alone. An Open asked again after it
finished hands the same key to the same phone key only; any other phone key
is refused.

## Why a receiver can be certain

- **The key never left the Seal and the card.** It is made inside the Seal,
  crosses the relay only inside the chip's encrypted channel, and is never
  returned by Fill or Check. The phone that filled the card never saw it.
- **The answer is fresh.** Every answer is signed over the receiver's own
  random challenge and carries an expiry. An old "Sealed" answer replayed
  after an Open fails the receiver's check.
- **The answer is about this card.** The Seal authenticates the card with
  keys derived for its UID and checks the UID the chip itself reports.
- **The coin is paid.** The card is marked Sealed only after the chain check
  confirmed exactly this commit data and exactly this amount.
- **An Open is final and visible.** From the moment an Open is journaled,
  every Check answers Opening or Opened, never Sealed. The key slot is wiped
  and the card's keys rotated before the key is released.
- **The answer comes from the right code.** It carries the Seal's code
  measurement, which the phone compares with the one it pins.
- **Nothing stands between the receiver and the coin unseen.** Every answer
  says, under its signature, whether an Open needs a PIN and how many tries
  are left, so a sender cannot pass on a PIN-protected card while keeping the
  PIN; a card whose PIN tries are used up is never answered Sealed.

## What is still trusted

- **The Seal**: the enclave's isolation, its attestation, and the code at the
  pinned measurement. A Seal that misbehaved could release a key early.
- **M**: whoever holds M can derive every card's keys. M exists only inside
  the Seal; there is no function that exports it or backs it up.
- **The journal store**: it must keep entries durably. It sees only sealed
  bytes, but deleting an Open entry after the key slot was wiped would lose
  that key.
- **The chain check**: that it confirms only exact, final payments.
- **The card's hardware**: that the chip keeps its AES keys, and that one
  WriteData either lands or not.
- **The phone and the receiver's app**: to send a fresh challenge and check
  the answer against the pinned key and measurement.

## Hardening list

In place:

- Five keys per card, each from its own HKDF label, none ever stored: the
  Seal derives them on every tap.
- Least privilege on the card: Check reads with key 1, which cannot write;
  only key 2 writes the record; only key 0 changes keys and settings.
- GetCardUID inside the session, so a card answering for another UID is
  refused.
- Every state change rewrites exactly one frame of 128 bytes or less, each
  frame carries its own check, and every write is read back.
- The PIN try is counted on the card before the PIN is compared; the PIN
  hash is keyed with a key derived from M, so a copied record does not allow
  offline guessing.
- Journal before any Open step; release only after the wipe, the rotation and
  a fresh authentication with every new key.
- The release is bound to the phone key chosen when the Open started, and
  the Open answer binds the release package's hash.
- Secrets live in wrappers that wipe on drop and have no `Debug` or
  `Display`; nothing logs them.
- No elliptic-curve crate and no hand-written cipher, MAC, KDF or KEM: AES,
  CBC, CMAC, SHA3, HMAC, HKDF, ML-KEM and ML-DSA come from audited RustCrypto
  crates pinned to exact versions.

Next:

- Key 3 is kept for SUN messages, so a Check can also prove the tap is live.
- Rate-limit Opens and Checks per card in the Seal.
- Sealed journal entries replicated with the Seal across regions, with
  rollback protection.

## Card keys

HKDF (RFC 5869) with HMAC-SHA3-256:

- salt: `ghost-seal/v1/card-keys`;
- input key material: M (32 bytes);
- info: the key's label, one zero byte, the 7-byte UID, the 4-byte
  generation (big endian);
- output: 16 bytes (an AES-128 key).

| Key | Label | Use |
| --- | --- | --- |
| 0 | `ghost-seal/v1/card-key/0/application-master` | ChangeKey, ChangeFileSettings |
| 1 | `ghost-seal/v1/card-key/1/check-read` | reads the record (Check) |
| 2 | `ghost-seal/v1/card-key/2/record-read-write` | reads and writes the record (Fill, Open) |
| 3 | `ghost-seal/v1/card-key/3/sdm-mac` | kept for SUN messages; no right uses it |
| 4 | `ghost-seal/v1/card-key/4/reserve` | kept in reserve; no right uses it |

The card setup gives a card the keys of generation 0. Each Open moves it to
the next generation. A key of generation g carries key version g + 1, so
version 0 is always the factory key; the Seal reads a key's version
(GetKeyVersion, outside a session) to know which generation to authenticate
with. The record file's settings are FileOption 03 (CommMode.Full) and
access rights 20 12: read-and-write key 2, change key 0, read key 1, write
key 2.

## Card record layout

The record is two frames in file 2. Integers are big endian.

Header frame, offset 0, 116 bytes:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | magic `GSH1` |
| 4 | 1 | layout version, 1 |
| 5 | 1 | state: 0 Empty, 1 Sealed, 2 Opening, 3 Opened |
| 6 | 1 | flags: bit 0 a key is in the slot, bit 1 an Open PIN is set |
| 7 | 1 | Open PIN tries left (5 when set) |
| 8 | 4 | generation |
| 12 | 16 | amount in wei |
| 28 | 32 | the coin: SHA3-256 of its commit data |
| 60 | 16 | Open PIN hash, zeros without a PIN |
| 76 | 32 | hash of the phone key an Open is bound to, zeros before |
| 108 | 8 | check |

Key slot frame, offset 128, 113 bytes:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | magic `GSK1` |
| 4 | 4 | generation |
| 8 | 32 | the coin the key belongs to, zeros when empty |
| 40 | 1 | key length, 0 when empty |
| 41 | 64 | the Phantom Key, zero padded |
| 105 | 8 | check |

The check is the first 8 bytes of SHA3-256(`ghost-seal/v1/record-check` ||
the frame's magic || UID || the frame's bytes between the magic and the
check). A frame of all zeros is a blank file (a card set up and never
filled). Any other frame that fails its check is torn: the Seal refuses it
and never reads it as a state.

## Frames

- Every ReadData and WriteData of the record carries 128 bytes or less. With
  ISO/IEC 9797-1 padding, the 7-byte header and the 8-byte MAC, a WriteData
  in CommMode.Full is at most 159 bytes of data, inside a short APDU.
- Every change of state rewrites exactly one frame, so a card pulled away
  mid-write is left either before or after the change.
- Every frame written is read back over the encrypted channel and compared
  before the flow goes on.
- The secure messaging is EV2 as the NTAG 424 DNA datasheet and AN12196 give
  it: session keys CMAC(K, SV1) and CMAC(K, SV2), IVs E(SesAuthENCKey,
  A5 5A || TI || CmdCtr || 0^8) for commands and 5A A5 for answers, MACs over
  Cmd || CmdCtr || TI || header || data truncated to the CMAC's odd bytes,
  ChangeKey cryptograms (NewKey XOR OldKey) || KeyVer || CRC32(NewKey), or
  NewKey || KeyVer for the session's own key.

## Signed answers

Every Check, Fill and Open answer is these 203 bytes, signed with ML-DSA-65
(FIPS 204, deterministic signing, context string `ghost-seal answer`) under
a key whose seed is HKDF(M) with the label
`ghost-seal/v1/answer-signing-key`. Integers are big endian.

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 20 | domain `ghost-seal/v1/answer` |
| 20 | 1 | kind: 1 Check, 2 Fill, 3 Open |
| 21 | 32 | the phone's random challenge |
| 53 | 7 | card UID |
| 60 | 4 | generation |
| 64 | 32 | the coin: SHA3-256 of its commit data (zeros when Empty) |
| 96 | 48 | the Seal's code measurement |
| 144 | 1 | state: 0 Empty, 1 Sealed, 2 Opening, 3 Opened |
| 145 | 16 | amount in wei (0 when Empty) |
| 161 | 8 | expiry, seconds since the Unix epoch |
| 169 | 32 | binding: SHA3-256 of the commit data (Fill), of the release package (Open), zeros (Check) |
| 201 | 1 | Open PIN: 0 none, 1 an Open of this card needs its PIN |
| 202 | 1 | Open PIN tries left (0 without a PIN) |

A phone accepts an answer only when the signature verifies under the pinned
Seal key, the measurement is the pinned one, the challenge is the one it
just sent, the UID is the card it tapped and the expiry has not passed.
Answers live 120 seconds.

A receiver accepts a Sealed card as payment only if it can redeem it: when
the answer says an Open needs a PIN, the receiver must have been given that
PIN (and the answer shows how many tries are left); otherwise the card is not
safe to accept. The PIN status is inside the signature, so a relay cannot
hide it. An answer about a card with a journaled Open carries no PIN status:
that Open is bound to its phone key and no PIN stands before the key.

## Open release

The phone sends an ML-KEM-768 encapsulation key (1,184 bytes) when it starts
an Open; the card record and the journal bind its hash, SHA3-256
(`ghost-seal/v1/phone-key` || key). The release package is:

`GSR1` (4) || ML-KEM-768 ciphertext (1,088) || IV (16) || ciphertext ||
tag (32).

From the ML-KEM shared secret, HKDF with HMAC-SHA3-256 (salt
`ghost-seal/v1/open-release`, info UID || new generation) gives 64 bytes: an
AES-256 key, then an HMAC-SHA3-256 key. The ciphertext is the padded Phantom
Key under AES-256-CBC; the tag is HMAC-SHA3-256 over
`ghost-seal/v1/open-release` || UID || generation || everything before the
tag. The shared secret never leaves the Seal.

## Journal

The Seal journals a Fill's public commit data before writing the card, and an
Open (phase, generation, coin, amount, phone key, Phantom Key) before
changing the card. The store sees only sealed entries: AES-256-CBC under a
fresh IV, then HMAC-SHA3-256 over `ghost-seal/v1/journal` || entry kind ||
UID || IV || ciphertext, both keys from HKDF(M) with the label
`ghost-seal/v1/journal`.

## Every derivation label

| Label | Derives |
| --- | --- |
| `ghost-seal/v1/card-keys` (salt) and `ghost-seal/v1/card-key/N/...` | card key N |
| `ghost-seal/v1/answer-signing-key` | the ML-DSA-65 seed of the answer key |
| `ghost-seal/v1/open-pin` | the key of the Open PIN hash (info: label, UID, generation); the hash is HMAC-SHA3-256 over the label and the PIN, first 16 bytes |
| `ghost-seal/v1/journal` | the journal's AES-256 and HMAC keys |
| `ghost-seal/v1/open-release` | the release's AES-256 and HMAC keys, from the ML-KEM shared secret |
| `ghost-seal/v1/record-check` | the check of each record frame |
| `ghost-seal/v1/phone-key` | the hash of a bound phone key |

## Relation to the bearer-card specification

The bearer-card specification keeps NTAG 424 DNA carry-to-Claim only, and
keeps the Java Card plan for a card that is a bearer object on its own. A
Ghost Sealed card is the one exception: its keys and Phantom Key live only in
the Seal, so it can be accepted after a fresh Check. A receiver who wants
certainty offline, or without trusting the Seal, still needs the Java Card
plan.
