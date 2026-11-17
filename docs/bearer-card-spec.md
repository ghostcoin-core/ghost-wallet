# Bearer cards: a Phantom Key no phone ever sees

Status: specification. The card type is chosen and measured: the NXP J3R180
(a JCOP 4 P71 class Java Card), over a contact reader and over iPhone NFC, in
`docs/j3r180-measurements.md`. Every time below comes from that document.
Cards are reusable: after one fill is opened, the card can be filled again.
Java Cards need no Ghost server. The applet is built to this document in
`card-applet/`, whose README gives each command's bytes. The app's side, and
trying it on phones, is a separate step (see "Left for the hardware step" at
the end).

## Goal

Putting Ghost on a card must make it a true bearer object, like a banknote:

- nobody who loads the card, including with a modified app, middleware between
  the app and the card, or any NFC tool, can see or keep the Phantom Key;
- someone handed the card can tap it, see what it holds, and know there is
  virtually no chance the coins can be taken from them without the card itself;
- once its coins are taken off, the same card can be filled again, and nobody
  who held an earlier fill gains anything over the new one.

## Why NTAG 424 DNA cannot be a bearer object

The cards the app writes today are NTAG 424 DNA. That chip only stores files
and checks AES keys. It cannot draw a secret of its own and it cannot compute
anything on a secret it holds: every key and every file is written from
outside. So:

- whatever writes the card (our app, a modified copy of it, or any NFC tool)
  knows the Phantom Key, and nothing the card can show tells a receiver whether
  a copy was kept;
- spending needs the phone to compute a proof from the key's secrets, so the
  key must leave the card in the clear to be used.

Today the app makes the Phantom Key on the phone and seals it under keys saved
only in the writing phone's Keychain. A Vanish to a card shows no words: the
native core makes a card-only key, never hands its words to the screen or
checks any of them, writes it to the card and reads it back, and only then
signs and sends the Vanish. The card is the only copy. A Vanish written down
as 24 words can still be put on a card as well. The writing phone can read
the card again at any time, and any other phone is told the card was not
written on it.

### NTAG 424 DNA is carry-to-Claim only

**NTAG 424 DNA is carry-to-Claim only.** A Phantom Key on an NTAG 424 DNA card
is a way to carry a key to the person who will Claim it to their own account
straight away. It must never be shown, described or sold as a bearer object,
and the app must never call such a card "sealed" or "safe to accept". Whoever
wrote it may still hold the key. Card Vanish now ships with no words shown, so
whoever holds the card holds the coins and a lost card loses them, but it is
still not shipped as a bearer feature: the writing phone saw the key, and a
seal check a receiver can trust still needs the secure-element card type
below, built and checked on real hardware.

#### The one exception: a Ghost Sealed card

A Ghost Sealed card is the one exception to this rule. It is an NTAG 424 DNA
card too, but its keys and its Phantom Key live only in the Seal, an attested
enclave: no phone, app or person ever sees them, the Seal writes the key and
marks the card sealed only once the payment is confirmed, and every answer is
signed over the receiver's own fresh challenge. So a Ghost Sealed card can be
accepted after a fresh Check. Offline or trust-free certainty still needs the
Java Card: a Ghost Sealed card trusts the Seal. Its design is in
`docs/sealed-card.md`.

Once Java Cards ship, the Sealed card path is closed to new fills: the app
offers Fill only on a Java Card. Sealed cards that already hold GHOST keep
Check and Open through the Seal until they are cashed out (see "Java Cards
need no Seal" below).

## Card type

**Chosen:** a programmable secure-element card, a Java Card running one locked
Ghost applet. The product is the NXP J3R180 (JCOP 4 P71 class), measured in
`docs/j3r180-measurements.md`.

A product qualifies only if it has all of these:

- Java Card 3.0.5 or later on a GlobalPlatform card manager, contactless
  (ISO/IEC 14443 type A) so an iPhone can talk to it, with extended-length or
  chained APDUs;
- native SHA-256, native AES-256 with CTR and CMAC, and a hardware true random
  number generator;
- SHA3-256 and Ghost's Keccak-256, natively or as bytecode Keccak, fast enough
  that Make, Check and Open meet the time budgets below;
- persistent memory writes inside atomic transactions, so a card pulled away
  mid-command is left either before or after the command, never between;
- at least 100 KiB of free persistent memory for the applet and its
  attestation tree;
- a Common Criteria certification of the secure element at a high assurance
  level (EAL6+ class), covering side-channel and fault-injection resistance.

**The J3R180 qualifies.** It runs Java Card 3.0.5 code on a GlobalPlatform 2.3
card manager; it has native SHA-256, AES-256, AES-CTR, AES-CMAC and a TRNG;
its transactions work; it has about 143 KB of persistent memory free with a
61 KB test applet loaded; extended commands work, and over the iPhone answers
of 1,000 bytes come back whole; and its chip, JCOP 4 P71, is certified EAL6+.
Over iPhone NFC it is about 5% slower than over contact.

Its one gap is SHA3-256: the API does not offer it. That does not matter for
Ghost, because a card's SHA3-256 could not compute Ghost's own hashes anyway:
F, the commitment and the marker use Keccak-256 with the original 0x01
padding, which a SHA3-256 interface (0x06 padding) cannot express. So the
applet carries one bytecode Keccak-f\[1600\] permutation, generated code with
the whole state in local variables, and builds both SHA3-256 and Keccak-256 on
it. It takes **146 ms per permutation over iPhone NFC** (139 ms over contact),
and its answers match Ghost's client. It fits every budget:

| Work, card on an iPhone | Bytecode permutations | Estimate | Budget |
| --- | --- | --- | --- |
| Make (below) | 10 (11 with the note lookup tag) | ≈ 2.0 s | ≤ 10 s |
| Check | none (one more to confirm an open code) | ≈ 1.9 s (≈ 2.0 s) | ≤ 3 s |
| Open | 3 | ≈ 0.5 s | ≤ 3 s |
| Refill | 1 | ≈ 0.3 s | ≤ 3 s |

The estimates add up measured parts (permutations, the note seal, the LMS
signature, the answer's bytes at the measured rate, and 0.2 s for the atomic
write and I/O); a timed run of the real applet is part of the hardware step.

The J3R180's other limits shape the applet: about 3.7 KB of RAM for one
applet, no RAM `int` arrays (32-bit state lives in local variables or short
arrays), and no AES-GCM or AES-CCM.

Cards from a reseller arrive with the card manager in OP_READY and factory
default keys. The certificate covers the chip, not that card's history, which
is why loading (below) replaces those keys and the issuer samples each batch.

Prior art: Coinkite SATSCARD makes its key on the card and lets it be read only
after an irreversible unseal, which is the same shape as this design. SATSCARD
uses elliptic-curve keys and signatures. This design is the quantum-safe
version: every primitive on the card is a hash function or a symmetric cipher,
and the attestation is hash-based end to end.

## Terms

- **Phantom Key**: the secret whose coins can be Summoned or Claimed. Its 24
  words encode its seed bytes; Ghost derives the key's secrets from those bytes
  with SHA3-256 (Ghost spec 01, section 7).
- **F**: the fingerprint of the key's coin, computed with the in-proof hash
  from the key's secrets and the coin's salt. The commit data carries F, never
  the secrets.
- **Commitment**: the coin tree leaf, computed from F and the amount.
- **Commit data**: the 430 bytes a Vanish carries: version `0x0003`, F (32
  bytes), the salt (16 bytes) and the 380-byte version-3 note sealed under the
  key's note key.
- **Commit-data digest**: the SHA-256 of the 430 commit-data bytes, computed
  natively by the card and signed into the seal statement.
- **Marker**: the value a coin shows when it is spent. Only the key's secrets
  can compute it.
- **Fill**: one Phantom Key and its coin on a card, from Make to Refill.
  **Fill number**: a counter on the card that every Make advances by one, so
  the card's first fill is fill 1.
- **Open code**: a 160-bit secret, one per fill, that the holder needs to open
  that fill. The card keeps only its SHA3-256.
- **Writer**: whoever loads value onto a card (taps it to make the key, then
  sends the Vanish).
- **Holder**: whoever has the card now. **Receiver**: someone being offered
  the card. **Opener**: the holder who opens it to Summon or Claim.
- **Issuer**: whoever installs the applet and certifies each card. **Card
  maker**: whoever makes the chip and the card body.

## Design

### Card states

The applet has three states, and each fill moves through them in order:

1. **Blank**: applet installed, attestation key made, no Phantom Key. A new
   card is blank with fill number 0; a refilled card is blank and keeps the
   number of the fill it last held.
2. **Sealed (fill N)**: a Phantom Key and one coin's commit data made on the
   card. The key has never left it.
3. **Opened (fill N)**: the key was released. The card stays opened until
   **Refill**.

```
Blank (0) --Make--> Sealed (1) --Open--> Opened (1) --Refill--> Blank (1)
Blank (1) --Make--> Sealed (2) --Open--> Opened (2) --Refill--> Blank (2) ...
```

- Make works only on a blank card, Open only on a sealed or opened card, and
  Refill only on an opened card with that fill's open code. No command takes a
  sealed card back to blank, so a key that has never left the card is never
  thrown away with its coin still on it.
- No command writes a key or a coin into a card. Every fill's key is drawn on
  the card at its own Make.
- The fill number only goes up. It is advanced inside Make's atomic write and
  signed into every seal statement, so a receiver always sees the card's
  current fill and never an older fill's state.

**What carries over between fills, and what does not:**

| Carries over (the card's identity) | Wiped at Refill (the fill) |
| --- | --- |
| card id and the issuer's certificate | the card random and the writer nonce |
| the LMS attestation key, its stored tree and its next leaf index | the commit data, amount, chain id, commitment and marker |
| the fill number | the open code's hash |
| the applet | the opened flag |

The seed bytes and the key's secrets are never stored at all: Make derives
them, uses them and drops them, and the opener's phone derives them again from
what Open releases.

### Made on the card

The card makes the Phantom Key and computes everything a Vanish needs from it;
the phone only ever sees public values.

1. The writer's app makes a new open code (below) and sends **Make** with the
   amount, the chain id, a 32-byte writer nonce from the phone's random source
   and the SHA3-256 of the new open code.
2. The card refuses unless it is blank and has at least 16 seal checks left
   (see "A quantum-safe attestation signature"). It draws 32 bytes from its
   own random source and sets the Phantom Key's seed bytes to
   SHA3-256("ghost-card-key" || card random || writer nonce). Neither the card
   maker (who could weaken the card's random source) nor the writer (who chose
   the nonce) can know the key alone.
3. The card derives the key's secrets (SHA3-256, as Ghost spec 01, section 7),
   draws the salt, computes F with the in-proof hash, the commitment from F and
   the amount, the marker, and the version-3 note sealed under the key's note
   key (ChaCha20-Poly1305, as Ghost's client seals notes, with a nonce from the
   card's random source). It hashes the 430 commit-data bytes with native
   SHA-256 into the commit-data digest.
4. In one atomic write it advances the fill number to N, stores the card
   random, the writer nonce, the commit data, the digest, the amount, the chain
   id, the commitment, the marker and the open code's hash, and becomes
   **Sealed (fill N)**.
5. It answers with the fill number, the 430-byte commit data and the
   commitment, **unsigned**. It never answers with the key, the card random or
   any secret derived from them.

Make no longer signs: the LMS signature (1.62 s over NFC) was the largest part
of Make. The writer's app gets the signed statement the same way every
receiver does, with a **Check** in the same tap (about 1.9 s over NFC), and
checks that the statement says Sealed with this fill number, this commitment,
and a commit-data digest equal to the SHA-256 of the bytes Make returned. Only
then does it build and sign the Vanish, exactly as it does today. So bytes
altered between the card and the app are caught before any coins move. Make
plus that Check is about 4 s with the card held still; if the card is pulled
away in between, the app asks for one more tap and sends **Commit data** and
Check.

**Words are never shown**, because the phone never has them. A **Commit data**
command returns the same bytes again while the card is sealed, so a Vanish
that failed or expired can be signed and sent again.

Make is computed live, with the writer's nonce in the key. Precomputing the
key when the card is emptied would save only about 1.4 s and would mix in the
previous opener's nonce instead of the writer's, so it is not used.

The card is now the only copy of the key. A lost or destroyed sealed card is
lost value, as with cash; the app says so before Make.

### The open code

Each fill has its own open code, made by the writer's app at Make:

- 160 bits from the phone's random source, shown once as a QR code and as 32
  base32 characters, for the writer to keep with the card (a sticker on the
  card, or written down) and hand over with it. The app keeps no copy and
  never logs it; it warns that a lost code means the coins can only be taken
  off by whoever has both the card and the code, so nobody.
- The card keeps only the code's SHA3-256 and checks a code by hashing it.
- A code works for its own fill only. After Refill its hash is wiped, and the
  next Make stores the next writer's new code.

A receiver handed a card and a code can confirm the code without opening:
the receiver's app adds SHA3-256("ghost-card-code" || SHA3-256(code) ||
challenge) to its Check, the card compares it with its stored hash and signs
the result into the statement. The value sent is good for that one challenge
only and does not give the code away.

The trade-off: the writer knows the code, and so does anyone they showed it
to. That gives nothing without the card in hand, the same as anyone who saw
the code on its way to the receiver. Pocket skimming still fails, because a
skimmer has no code.

### Seal check on every tap

Any phone can check a card. The receiver's app sends **Check** with a fresh
32-byte random challenge (and, optionally, an open-code confirmation as above).
The card advances its LMS leaf index in an atomic write and answers with a
seal statement signed by its attestation key:

- the statement's domain ("ghost-card-seal-v1"), the card id, the state
  (blank, sealed or opened), the fill number, the chain id, the amount, the
  commitment, the commit-data digest (SHA-256), the coin's marker, how many
  seal checks remain, the attestation signature's leaf index, whether an open
  code was confirmed (not asked, right or wrong) and the receiver's challenge;
- the card's certificate from the issuer: card id, attestation public key,
  applet code hash and batch, signed by an issuer key the app pins.

A blank card's statement carries the fill number and the remaining checks and
no coin fields. Where Ghost's marker depends on the coin's position in the
coin tree, the receiver's app first finds the commitment in the tree itself
and sends that position with the challenge; the card signs the marker together
with it. The statement is about 2.5 KB and comes back in a few long answers.

The receiver's app then checks, on the receiver's own phone:

1. the issuer's signature on the certificate, against the pinned issuer keys
   and the app's revocation list;
2. the attestation signature on the statement, and that it covers this tap's
   challenge;
3. the card id against the number printed on the card's face;
4. from the chain: a Vanish whose commit data have exactly this digest
   (SHA-256) is in the coin tree on the app's network, buried under enough
   blocks, its path leading to a root in a header the app checked, and the
   marker is not among the spent markers.

It shows one of:

- **Sealed: holds X GHOST** (all checks pass), with the fill number, as
  "Sealed (fill N): holds X GHOST", and whether the open code was confirmed;
- **Opened: not safe to accept**;
- **Blank (fill N): holds nothing**;
- **Not on the chain yet: not safe to accept** (sealed but no matching Vanish,
  or a Vanish whose commit data differ);
- **Spent while sealed: not safe to accept** (the marker is spent; the card is
  broken and the app asks the holder to report it);
- **Open code wrong: not safe to accept** (the code handed over does not open
  this fill);
- **Not a genuine Ghost card: not safe to accept** (any signature fails, or
  the issuer is unknown or revoked);
- **Carry to Claim: not safe to accept** (an NTAG 424 DNA card).

The app asks the receiver to confirm the open code before accepting a card,
and shows how many seal checks remain.

The marker is public once the coin is spent, so showing it early costs only
privacy: whoever tapped the card can later recognise the spend.

An **Identify** command answers the card id, state, fill number, remaining
checks and certificate without a signature and without using a check. Apps use
it to label a card quickly; it is never shown as proof.

### Opening is one-way

Within a fill, opening is one-way. To Summon or Claim, the opener's app sends
**Open** with that fill's open code and a fresh 32-byte challenge.

- Without the code no tap can open the card, so a reader held near a pocket
  cannot open it.
- On a right code the card first writes "opened" (atomic, persistent), then
  releases the card random and the writer nonce (64 bytes), encrypted with
  **AES-256-CTR and authenticated with AES-CMAC** (the card has no GCM or CCM):
  - the encryption key is SHA3-256("ghost-card-open-enc" || card id || fill
    number || open code || challenge), and the MAC key is the same with
    "ghost-card-open-mac";
  - the CTR counter block starts from 16 fresh bytes from the card's random
    source, sent with the answer;
  - the tag is the full 16-byte AES-CMAC over the domain
    ("ghost-card-open-v1"), card id, fill number, challenge, counter block and
    ciphertext (encrypt, then MAC).

  The opener's app checks the tag before it decrypts anything and refuses on a
  mismatch. Because each key is bound to the card, the fill and the challenge,
  and each answer has a fresh counter block, no key stream is ever used twice.
  An eavesdropper on the NFC field sees only ciphertext and cannot guess a
  160-bit code.
- The opener's app recomputes the seed bytes, then F, the commitment and the
  commit-data digest, and checks they match the card's statement (or, if the
  card has no checks left, the Vanish on chain) before Summoning or Claiming at
  once. The key is held in native code, as a typed key is today, and kept there
  until the Summon or Claim is confirmed.
- An opened card answers **Open** again with the same code, so a card pulled
  away mid-release is not lost. Every later **Check** says opened, until
  Refill starts a new fill.

### Refill: filling the card again

After a fill is opened, its coins taken off and confirmed, the card can be
filled again:

1. The opener's app sends **Refill** with that fill's open code, and only once
   the app shows the released coin's marker spent on chain. The card cannot
   see the chain, so it gates on the code instead: only someone with the card
   and the code can refill it.
2. The card refuses unless it is opened and the code is right. In one atomic
   write it wipes the fill (the table above) and becomes **Blank (fill N)**.
3. The next writer, the same person or anyone they hand the card to, sends
   Make, which draws a fresh key on the card, advances to fill N + 1 and sets a
   new open code.

Refilling can't hurt anyone: the old key is already out, so wiping it takes
nothing from the card that the opener does not already have, and the new
fill's key is new card randomness plus the new writer's nonce. Refill is only
a convenience gate: if an opened card were refilled before its claim
confirmed, the opener's app still holds the released seed material.

### Java Cards need no Seal

Fill (Make), Check, Open and Refill on a Java Card run between the phone and
the card alone. No Ghost server takes part, so this removes, for Java Cards:

- the Seal enclave and its attestation, the relay between the phone and the
  Seal, and the app attestation the Seal asks for;
- the Seal's card keys and the Seal holding any Phantom Key: the key is drawn
  and kept on the card;
- the Seal's payment confirmation before a card is marked sealed: the card is
  sealed at Make, and the chain check below says whether it is funded;
- any dependence on a Ghost server being up, honest or reachable: a card can be
  filled, checked, opened and refilled while that service is down.

What the receiver still checks, all on their own phone: the issuer's
certificate against the pinned issuer keys and the revocation list that ships
with the app; the LMS signature over their own fresh challenge; the card id
against the printed number; the state, fill number and remaining checks; the
open code if they have it; and, from Ghost nodes, that a Vanish with this
commit-data digest is buried in the coin tree under a header the app checked
and that the marker is unspent. Talking to chain nodes is not a Ghost server:
the app checks their answers against headers itself and asks more than one.

What remains to trust is the card's hardware and the issuer (see the threat
model), not a service.

### Locked applet

- The issuer loads the applet, has it make its attestation key, certifies the
  card, and then replaces the card manager's keys with random keys that are
  discarded at once. After that nobody can load, delete or personalise any
  applet on the card, the issuer included.
- The applet has no command that reads out its key, the card random, the
  attestation key or its own code, and none that writes them.
- The applet's code is published and its hash is in every card's certificate.

### Commands

| Command     | Allowed in     | Does                                                                              |
| ----------- | -------------- | --------------------------------------------------------------------------------- |
| Identify    | any state      | card id, state, fill number, checks left, certificate; unsigned, uses no check    |
| Make        | blank          | with a new open code's hash: makes the key and the coin, advances the fill number; returns commit data and commitment, unsigned |
| Commit data | sealed         | returns the 430-byte commit data again                                            |
| Check       | any state      | signed seal statement over the receiver's challenge, optionally confirming an open code; uses one check |
| Open        | sealed, opened | with the fill's open code: marks opened, releases the seed material (AES-256-CTR plus AES-CMAC) |
| Refill      | opened         | with the fill's open code: wipes the fill and returns to blank                   |

## Open questions

### The in-proof hash for F and the note's sealing

**Answer:** yes, on the J3R180, in bytecode, within every time budget. Make is
about 2.0 s over iPhone NFC against a 10 s budget.

**Why:** the card computes only the key's secrets, F, the commitment, the
marker and one note. It never proves anything: the proof is made on the
opener's phone after opening. Ghost's secrets are SHA3-256 derivations and its
in-proof hash is built on the Keccak permutation. The J3R180 has no native
SHA3-256, and no card's SHA3-256 could compute Keccak-256 with Ghost's 0x01
padding anyway, so the applet runs every permutation in bytecode, at 146 ms
each over NFC. Make needs 10: the seed (1), the secrets s, r, b₀, the note key
and the note tag (5), F (2), the commitment (1) and the marker (1); 11 with
the note lookup tag.

The commit-data digest uses the card's native SHA-256 (about 2.5 ms), not
SHA3-256, which would add 4 bytecode permutations (0.6 s) over the 430 bytes.
The digest is the card's own construction, not Ghost's, so the chain does not
change; the receiver's app hashes the on-chain commit data with SHA-256 to
compare.

The note's sealing is ChaCha20-Poly1305 over 380 bytes, which no Java Card
API offers. The applet carries generated ChaCha20 (seven 64-byte blocks,
rotations inline) and Poly1305 (ten 13-bit limbs): 0.36 s over NFC, matching
Ghost's client.

| Make over iPhone NFC | Time |
| --- | --- |
| 10 permutations × 0.146 s | 1.46 s |
| Note seal | 0.36 s |
| Atomic write, SHA-256 digest, I/O | about 0.2 s |
| **Total** | **about 2.0 s** (2.2 s with the lookup tag) |

Budgets on the chosen product, card on the phone: Make within 10 seconds,
Check within 3 seconds, Open within 3 seconds. The estimates (Make 2.0 s,
Check 1.9 s, Open 0.5 s) meet them; the hardware step times the real applet.

Rejected alternative: the card hands the phone the note key and the phone
seals the note. The writer would keep a key that reads the coin's notes and
recognises the coins left after a Summon. That is not a theft risk, but it is
not a clean bearer object either.

### A quantum-safe attestation signature

**Answer:** a stateful hash-based signature, LMS (RFC 8554, NIST SP 800-208)
with SHA-256, made and kept on the card, at **height 10** with Winternitz
parameter 4 (LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W4): 1,024 seal checks for
the card's whole life. The issuer certifies it with SLH-DSA (FIPS 205).

**Why:**

- ML-DSA is **ruled out** on this card class: no Java Card API offers it, and
  a bytecode version needs polynomial arithmetic, a rejection-sampling loop
  and SHAKE on a card with about 3.7 KB of RAM for an applet and no RAM `int`
  arrays. It can be revisited for a card with native ML-DSA.
- SLH-DSA on the card is **ruled out**: stateless, but each signature needs
  hundreds of thousands of hash calls, which is minutes on a card.
- LMS needs only SHA-256, which the card has natively (2.5 ms per call). A
  signature takes 1.62 s over NFC (about 570 SHA-256 calls) and is about
  2.5 KB.
- LMS is stateful. The card keeps the next leaf index in persistent memory and
  advances it in the same atomic write that precedes every signature, so a leaf
  is never used twice, even on a torn tap. SP 800-208 asks for exactly this:
  key generation and signing inside a hardware module whose private key is
  never exported.

**Why height 10, and not 9 or 8:** key generation costs about 2.94 s per leaf
(1,074 SHA-256 calls), so H10 takes about 50 minutes per card, H9 about 25
and H8 about 12.5. That time is spent once, at the loading station, with many
cards in parallel readers; nobody waits for it at a tap. What a holder does
feel is the number of checks, because a reusable card spends them across all
its fills: each fill uses one for the writer's Check, one or more per
receiver, and one for the opener, about 5 to 10 in all. H10 gives a card
roughly 100 to 200 fills; H8 only 25 to 50. H10 is also the largest height
whose stored tree fits: 2,047 nodes (64 KiB, 65,504 bytes) left 77,876 bytes
free next to a 61 KB test applet, and H11's 128 KiB tree would not fit. HSS
(two LMS levels) was considered and not used: every leaf still costs the same
2.94 s to make, and the card cannot make the next lower tree during a 3 s tap,
so HSS adds signature size without adding checks.

**How the checks count down:** the count belongs to the card, not to a fill.
Every Check uses one leaf, whatever the state, and its statement says how many
remain (1,024 minus the next leaf index). Make no longer signs, Identify uses
none, and Open and Refill use none. Make refuses on a card with fewer than 16
checks left, so every new fill has checks for its writer, its receivers and
its opener; the writer's app warns before Make when fewer than 64 remain. A
sealed card with no checks left can still be opened and its coins taken off,
but it can no longer be checked, and the app shows it as not safe to accept.
After its last fill a card is retired.

The issuer's certificate is signed offline, once per card, so speed does not
matter there: SLH-DSA keeps the whole chain on hash functions only.

### Card supply and loading

**Answer:** the project acts as the first issuer and loads cards itself; more
issuers can be added later, each with its own pinned key.

**Why and how:**

- Blank J3R180 cards are bought from the chip maker's authorised distributors,
  with their card manager keys delivered separately from the cards. Cards that
  arrive with factory default keys are accepted only in sampled batches, and
  their keys are replaced at loading like any other.
- At a loading station the issuer installs the applet, whose code hash is
  published. The applet makes its card id and its H10 LMS key on the card from
  the card's own random source, about 50 minutes per card, many cards at once
  in parallel readers. The issuer reads the public key and signs the
  certificate offline with its SLH-DSA key (kept in a hardware security
  module), and writes the certificate to the card.
- No open code is printed or loaded: each fill's code is made by its writer's
  app at Make, so the issuer never knows one.
- The issuer replaces the card manager keys with discarded random keys,
  prints the card number (from the card id) on the face, and records the card
  in a published batch list.
- The app pins the issuers' public keys and ships a revocation list. A card
  reaches its first writer blank at fill 0; the writer's app refuses Make on
  any card that is not blank.
- Cards are sampled from each batch for destructive testing and for checking
  that the loaded code matches the published hash.

## Threat model

### Assets

- The coins behind a sealed card, and the receiver's ability to tell a sealed,
  funded card, at its current fill, from anything else.
- The card's remaining seal checks, which bound how many more fills it can
  hold.
- The privacy of who loaded and who spent a card, in second place.

### Attackers

- A **modified app** or any NFC tool on any phone that taps the card: the
  writer's, a previous holder's, or a stranger's.
- **Middleware**: software between the app and the card (a hooked NFC stack, a
  jailbreak tweak, a relay) or between the app and the Ghost node.
- The **card maker and the issuer**, and anyone in the supply chain between
  them and the writer.
- A **previous holder** or **thief** who had the card for a while, including
  the writer or opener of an earlier fill, who knows that fill's open code.
- A **network** attacker or dishonest node, and a future quantum computer.

### What remains to trust

- The card's hardware: that its secure element keeps its secrets against
  side-channel, fault-injection and invasive attacks, and that its random
  source is sound.
- Whoever makes and loads the cards: that the applet on the card is the
  published one, that the attestation key was made on the card, and that the
  issuer key certifies only real cards.
- The receiver's own phone and app (the receiver checks with software they
  trust, never with the giver's phone).

No Ghost server is trusted for a Java Card.

### Not protected

- **Possession**: a bearer card is cash. Whoever has the card and its open
  code can open it and take the coins; a sealed card that is lost or destroyed
  is lost value, and so is a sealed card whose open code is lost.
- **The writer's knowledge of the code**: the writer of a fill knows its open
  code. With the card in hand they could open it, like anyone holding the card
  and the code.
- **Relay**: see the middleware red-team below; a relay with a convincing
  counterfeit card body is a residual risk.
- **Laboratory attacks** on the chip: the app should advise against putting
  more on one card than such an attack would be worth.

## Red-team

Each item is an attack and how the design answers it.

### A modified app

- **Attack:** read the Phantom Key, the card random or any secret while the
  card is sealed. **Answer:** no command returns them; Make and Check answer
  with public values only, and Open needs the fill's open code.
- **Attack:** choose or bias the key through the writer nonce (for example
  all zeros, or a value it can replay). **Answer:** the seed bytes hash the
  card's own random bytes with the nonce, and those bytes never leave a sealed
  card, so a chosen nonce gives the writer nothing.
- **Attack:** make the card make a second key, or reset a sealed card to
  blank, keeping the first key's coin. **Answer:** Make works only on a blank
  card, and the only way back to blank is Refill, which works only on an
  opened card with that fill's code; the card manager is locked so the applet
  cannot be replaced.
- **Attack:** commit one amount on the card but send a Vanish of less, or send
  commit data with a corrupted note, or never send it. **Answer:** the card
  signs the amount and the SHA-256 of its own commit data; the receiver's app
  shows "not on the chain yet" unless those exact bytes are in the coin tree.
- **Attack:** open the card quietly and give it on as sealed. **Answer:**
  opening needs the fill's open code, and an opened card reports opened on
  every later tap, under a signature over the receiver's own challenge.
- **Attack:** hand the receiver a sealed, funded card with a wrong open code,
  so nobody but the writer can ever open it. **Answer:** the receiver's app
  confirms the code with the card before accepting, and the card signs the
  result into the statement; a wrong code shows "Open code wrong".
- **Attack:** use up the card's seal checks. **Answer:** this denies checks,
  not coins: a sealed card can still be opened, every statement shows how many
  checks remain, Identify reads the count without using one, and 1,024 checks
  at about two seconds each needs the card in reach for over half an hour.
  On a reusable card it shortens the card's life, which the remaining count
  shows to every receiver.
- **Attack:** pull the card away mid-Make, mid-Open or mid-Refill to leave it
  half-done. **Answer:** all three are atomic; Make leaves a blank or sealed
  card, Refill an opened or blank one, and an opened card releases its seed
  material again with the same code.
- **Attack:** refill a card whose fill was just opened, before the opener's
  Claim confirms, to destroy the coins. **Answer:** Refill needs that fill's
  open code, which only its writer and opener have, and the opener's app keeps
  the released seed material until the Claim confirms, so a wiped card takes
  nothing from it.
- **Attack:** keep an earlier fill's open code and use it on a later fill.
  **Answer:** each fill's code hash is wiped at Refill and replaced by the new
  writer's at Make, and the open keys mix in the fill number; an old code
  opens nothing.
- **Attack:** write an NTAG 424 DNA card and present it as sealed. **Answer:**
  the receiver's app shows "sealed" only for answers that chain to a pinned
  issuer key; an NTAG 424 DNA card is always shown as carry to Claim.

### Middleware

- **Attack:** record the NFC traffic to catch the key. **Answer:** a sealed
  card never sends it; Open sends it encrypted under keys from the 160-bit
  open code, the fill and the tap's challenge, which a recording does not
  hold.
- **Attack:** record an open-code confirmation and replay it, or learn the
  code from it. **Answer:** the confirmation hashes the tap's own challenge, so
  it is good for one Check, and it is built from the code's hash, so it does
  not reveal the code that Open needs.
- **Attack:** alter the ciphertext of an Open answer, or replay one from an
  earlier fill. **Answer:** the opener's app checks the AES-CMAC tag over the
  card id, fill number, its own challenge and the ciphertext before decrypting,
  and then checks the recomputed commitment against the statement.
- **Attack:** replace the commit data that Make returns unsigned, so the
  writer sends a Vanish for a coin no key can spend. **Answer:** before signing
  the Vanish, the writer's app runs a Check and requires the statement's
  commit-data digest and commitment to match the bytes it got.
- **Attack:** replay a recorded "sealed" answer after the card was opened, or
  one from an earlier fill. **Answer:** every statement signs the receiver's
  fresh challenge and the current fill number, so an old answer fails the
  check.
- **Attack:** alter the amount, the commitment, the fill number or the state
  in the answer. **Answer:** they are inside the attestation signature, which
  the receiver's app checks.
- **Attack:** relay the tap to a different, genuine sealed card held elsewhere
  while the receiver holds a worthless one. **Answer:** the statement's card id
  must match the number printed on the card in hand, so the relay also needs a
  counterfeit card body with that number. NFC cannot bound distance, so this is
  a residual risk the app names: accept cards in person and check the printed
  number and the card body.
- **Attack:** a dishonest node or a network attacker shows a Vanish that is
  not there, or hides a spent marker. **Answer:** the app checks the coin's
  path to a root in a header it checked itself, asks more than one node for
  spent markers, and waits for the Vanish to be buried under enough blocks.
- **Attack:** skim a card in a pocket and open or refill it. **Answer:** both
  need the fill's open code, which a skimmer does not have.

### The card maker and loader

- **Attack:** ship an applet with a hidden command that exports the key.
  **Answer:** the applet's code is published and its hash is in each card's
  certificate; batches are sampled and checked; this is the trust that remains
  in whoever loads the cards, stated as such.
- **Attack:** weaken the card's random source so keys can be predicted.
  **Answer:** every fill's key also hashes that fill's writer nonce, which the
  maker never sees, so a weak card random alone does not give the maker the
  key. This is why Make stays live instead of precomputing the key.
- **Attack:** keep a copy of a card's attestation key, or certify an emulator
  that says "sealed" for a coin whose key it shares. **Answer:** the
  attestation key is made on the card; the issuer key is kept offline in a
  hardware security module; the app pins issuer keys, checks the published
  batch list and revokes a misbehaving issuer. Certifying emulators is the
  issuer's remaining trust.
- **Attack:** sell a card that already holds a key the maker knows, or keep
  the open codes. **Answer:** a card must reach its writer blank, and the
  writer's app refuses Make on any other state; the state is signed. No open
  code exists until the writer's app makes one at Make.
- **Attack:** leave the card manager open, or keep its factory default keys,
  to replace the applet later. **Answer:** the card manager's keys are replaced
  by discarded random keys at loading, so no one, the issuer included, can
  load or delete an applet.
- **Attack:** swap a genuine chip for a counterfeit in the supply chain.
  **Answer:** a counterfeit cannot sign under a certified attestation key, so
  it fails the check.

### A previous holder or a thief

- **Attack:** note the open code while holding the card and pass it on.
  **Answer:** the code is useless without the card itself; the card's coins
  move only to whoever holds the card and the code, and the code dies with its
  fill.
- **Attack:** open the card, take the coins, then pass it on. **Answer:** the
  card says opened until refilled, a refilled card shows a higher fill number
  and holds nothing until its next Make, and the marker shows the old coin
  spent.
- **Attack:** extract the key by fault injection or a laser. **Answer:** this
  is the hardware trust; the secure element's certification and the advice to
  limit the value per card bound it.

### A quantum attacker

- **Attack:** forge a seal statement or a certificate, or break the open
  encryption, with a quantum computer. **Answer:** the seal statement is LMS
  over SHA-256, the certificate is SLH-DSA, the open encryption is AES-256-CTR
  with AES-CMAC under keys hashed with SHA3-256 from a 160-bit code, and the
  coin itself uses Ghost's hash-based commitments. None rests on elliptic
  curves or factoring.

## Left for the hardware step

The card type is measured. The applet, its loading and the checks on real
cards and phones are a later step. It must show, on the J3R180 and on an
iPhone:

- timed Make, Check (with and without an open-code confirmation), Open and
  Refill on the real applet within the budgets, and H10 key generation at
  loading;
- that the applet reproduces Ghost's F, commitment, commit data and marker
  bit for bit from fixed test inputs taken from Ghost's own client;
- that a card pulled away mid-Make, mid-Open and mid-Refill is left before or
  after the command (tearing was not tested);
- a seal check from a second phone that never touched the card, a one-way
  open whose later taps all show opened, and a Refill and second fill whose
  checks show the higher fill number while the first fill's code opens
  nothing.
