# Bearer cards: a Phantom Key no phone ever sees

Status: specification, red-teamed, card type chosen. This document changes no
applet, app, chain or node code. Building the applet and trying it on real
cards and phones is a separate, later step (see "Left for the hardware step"
at the end).

## Goal

Putting Ghost on a card must make it a true bearer object, like a banknote:

- nobody who loads the card, including with a modified app, middleware between
  the app and the card, or any NFC tool, can see or keep the Phantom Key;
- someone handed the card can tap it, see what it holds, and know there is
  virtually no chance the coins can be taken from them without the card itself.

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

## Card type

**Chosen:** a programmable secure-element card, a Java Card running one locked
Ghost applet, for example an NXP JCOP 4 class card.

A product qualifies only if it has all of these:

- Java Card 3.0.5 or later on a GlobalPlatform card manager, contactless
  (ISO/IEC 14443 type A) so an iPhone can talk to it, with extended-length or
  chained APDUs;
- native SHA-256 and SHA3-256 in its cryptographic API (Java Card 3.0.5 defines
  SHA3-256 in its message-digest algorithms; the product's data sheet must list
  it), native AES-256, and a hardware true random number generator;
- persistent memory writes inside atomic transactions, so a card pulled away
  mid-command is left either before or after the command, never between;
- at least 100 KiB of free persistent memory for the applet and its
  attestation tree;
- a Common Criteria certification of the secure element at a high assurance
  level (EAL6+ class), covering side-channel and fault-injection resistance.

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
- **Marker**: the value a coin shows when it is spent. Only the key's secrets
  can compute it.
- **Writer**: whoever first loads value onto a card (taps it to make the key,
  then sends the Vanish).
- **Holder**: whoever has the card now. **Receiver**: someone being offered
  the card. **Opener**: the holder who opens it to Summon or Claim.
- **Issuer**: whoever installs the applet and certifies each card. **Card
  maker**: whoever makes the chip and the card body.

## Design

### Card states

The applet has three states and moves only forward:

1. **Blank**: applet installed, attestation key made, no Phantom Key.
2. **Sealed**: a Phantom Key and one coin's commit data made on the card. The
   key has never left it.
3. **Opened**: the key was released. The card stays opened forever.

No command moves a card back to an earlier state, and no command writes a key
or a coin into a card.

### Made on the card

The card makes the Phantom Key and computes everything a Vanish needs from it;
the phone only ever sees public values.

1. The writer's app sends **Make** with the amount, the chain id and a 32-byte
   writer nonce from the phone's random source.
2. The card refuses unless it is blank. It draws 32 bytes from its own random
   source and sets the Phantom Key's seed bytes to
   SHA3-256("ghost-card-key" || card random || writer nonce). Neither the card
   maker (who could weaken the card's random source) nor the writer (who chose
   the nonce) can know the key alone.
3. The card derives the key's secrets (SHA3-256, as Ghost spec 01, section 7),
   draws the salt, computes F with the in-proof hash, the commitment from F and
   the amount, and the version-3 note sealed under the key's note key
   (ChaCha20-Poly1305, as Ghost's client seals notes, with a nonce from the
   card's random source).
4. In one atomic write it stores the key, the commit data, the amount, the
   chain id and the writer nonce, and becomes sealed.
5. It answers with the 430-byte commit data, the commitment and a signed seal
   statement (below). It never answers with the key, the card random or any
   secret derived from them.

The phone builds and signs the Vanish from those 430 bytes exactly as it does
today. **Words are never shown**, because the phone never has them. A
**Commit data** command returns the same bytes again while the card is sealed,
so a Vanish that failed or expired can be signed and sent again.

The card is now the only copy of the key. A lost or destroyed sealed card is
lost value, as with cash; the app says so before Make.

### Seal check on every tap

Any phone can check a card. The receiver's app sends **Check** with a fresh
32-byte random challenge. The card answers with a seal statement signed by its
attestation key:

- the statement's domain ("ghost-card-seal-v1"), the card id, the state
  (blank, sealed or opened), the chain id, the amount, the commitment, the
  SHA3-256 of the commit data, the coin's marker, how many seal checks remain,
  the attestation signature's leaf index and the receiver's challenge;
- the card's certificate from the issuer: card id, attestation public key,
  applet code hash and batch, signed by an issuer key the app pins.

Where Ghost's marker depends on the coin's position in the coin tree, the
receiver's app first finds the commitment in the tree itself and sends that
position with the challenge; the card signs the marker together with it.

The receiver's app then checks, on the receiver's own phone:

1. the issuer's signature on the certificate, against the pinned issuer keys
   and the app's revocation list;
2. the attestation signature on the statement, and that it covers this tap's
   challenge;
3. the card id against the number printed on the card's face;
4. from the chain: a Vanish with exactly these commit data (same SHA3-256) is
   in the coin tree on the app's network, buried under enough blocks, its
   path leading to a root in a header the app checked, and the marker is not
   among the spent markers.

It shows one of:

- **Sealed: holds X GHOST** (all checks pass);
- **Opened: not safe to accept**;
- **Not on the chain yet: not safe to accept** (sealed but no matching Vanish,
  or a Vanish whose commit data differ);
- **Spent while sealed: not safe to accept** (the marker is spent; the card is
  broken and the app asks the holder to report it);
- **Not a genuine Ghost card: not safe to accept** (any signature fails, or
  the issuer is unknown or revoked);
- **Carry to Claim: not safe to accept** (an NTAG 424 DNA card).

The marker is public once the coin is spent, so showing it early costs only
privacy: whoever tapped the card can later recognise the spend.

### Opening is one-way

To Summon or Claim, the opener's app sends **Open** with the card's open code
and a fresh 32-byte challenge.

- The **open code** is 160 random bits printed on the card under a scratch-off
  panel, as a QR code and as 32 base32 characters. The card keeps only its
  SHA3-256. Without the code no tap can open the card, so a reader held near a
  pocket cannot open it, and a scratched panel tells a receiver someone has
  read the code.
- On a right code the card first writes "opened" (atomic, persistent), then
  releases the card random and the writer nonce, encrypted under
  SHA3-256("ghost-card-open" || open code || that challenge) with AES-256 in an
  authenticated mode. An eavesdropper on the NFC field sees only ciphertext
  and cannot guess a 160-bit code.
- The opener's app recomputes the seed bytes, then F and the commitment, and
  checks they match the card's statement before Summoning or Claiming at once.
  The key is held in native code, as a typed key is today.
- An opened card answers **Open** again with the same code, so a card pulled
  away mid-release is not lost. Every later **Check** says opened.

### Locked applet

- The issuer loads the applet, has it make its attestation key, certifies the
  card, and then replaces the card manager's keys with random keys that are
  discarded at once. After that nobody can load, delete or personalise any
  applet on the card, the issuer included.
- The applet has no command that reads out its key, the card random, the
  attestation key or its own code, and none that writes them.
- The applet's code is published and its hash is in every card's certificate.

### Commands

| Command     | Allowed in     | Does                                                          |
| ----------- | -------------- | ------------------------------------------------------------- |
| Identify    | any state      | card id, state, certificate                                   |
| Make        | blank          | makes the key and the coin; returns commit data and statement |
| Commit data | sealed         | returns the 430-byte commit data again                        |
| Check       | any state      | signed seal statement over the receiver's challenge           |
| Open        | sealed, opened | with the open code: marks opened, releases the seed material  |

## Open questions

### The in-proof hash for F and the note's sealing

**Answer:** yes, on a card with native SHA3-256, within the time budget below;
a card type without native SHA3-256 is ruled out.

**Why:** the card computes only the key's secrets, F, the commitment, the
marker and one note. It never proves anything: the proof is made on the
opener's phone after opening. Ghost's secrets are SHA3-256 derivations and its
in-proof hash is built on the Keccak permutation, so on a card with native
SHA3-256 each step is a few native calls and the card's work is a few dozen
permutations at most. Where a step is a Keccak permutation the SHA3-256
interface cannot express, the applet runs that step in bytecode; a bytecode
Keccak permutation on a 16-bit card virtual machine is estimated at about a
second, which is why only a few such steps fit and why the hardware step
measures them.

The note's sealing is ChaCha20-Poly1305 over 380 bytes, which no Java Card
API offers. The applet carries its own ChaCha20 (about seven 64-byte blocks)
and Poly1305 (about 25 16-byte blocks, its 130-bit arithmetic done in 16-bit
limbs). That is estimated at one to three seconds, once per card, at Make.

Budgets the hardware step must meet on the chosen product, card on the phone:
Make within 10 seconds, Check within 3 seconds, Open within 3 seconds. A
product that misses them is not used.

Rejected alternative: the card hands the phone the note key and the phone
seals the note. The writer would keep a key that reads the coin's notes and
recognises the coins left after a Summon. That is not a theft risk, but it is
not a clean bearer object either.

### A quantum-safe attestation signature

**Answer:** a stateful hash-based signature, LMS (RFC 8554, NIST SP 800-208)
with SHA-256, made and kept on the card; the issuer certifies it with SLH-DSA
(FIPS 205).

**Why:**

- ML-DSA is **ruled out** on this card class: no Java Card API offers it, and
  a bytecode version needs 32-bit polynomial arithmetic, a rejection-sampling
  loop and SHAKE on a 16-bit virtual machine. It is estimated at tens of
  seconds per signature and needs more transient memory than these cards give
  an applet. It can be revisited for a card with native ML-DSA.
- SLH-DSA on the card is **ruled out**: stateless, but each signature needs
  hundreds of thousands of hash calls, which is minutes on a card.
- LMS needs only SHA-256, which every Java Card has natively. With
  LMS_SHA256_M32_H10 and LMOTS_SHA256_N32_W4 a signature costs about 500
  SHA-256 calls on average (at most about 1,000) plus reading stored tree nodes,
  estimated under two seconds. It is about 2.5 KB, a few NFC frames.
- LMS is stateful. The card keeps the next leaf index in persistent memory and
  advances it in the same atomic write that precedes every signature, so a leaf
  is never used twice, even on a torn tap. SP 800-208 asks for exactly this:
  key generation and signing inside a hardware module whose private key is
  never exported.
- A card can sign 1,024 seal statements. Each statement says how many remain;
  the app shows it. A card with none left can still be opened, but no longer
  checked, and the app shows it as not safe to accept.
- Key generation (about a million SHA-256 calls) runs once, on the card, at
  loading, and may take up to about half an hour per card in parallel readers.
  If the chosen product is too slow, the height drops to 8 (256 checks). The
  card stores its 2,047 tree nodes (64 KiB) so a check needs no tree rebuild.
- The issuer's certificate is signed offline, once per card, so speed does not
  matter there: SLH-DSA keeps the whole chain on hash functions only.

### Card supply and loading

**Answer:** the project acts as the first issuer and loads cards itself; more
issuers can be added later, each with its own pinned key.

**Why and how:**

- Blank Java Cards are bought from the chip maker's authorised distributors,
  with their card manager keys delivered separately from the cards.
- At a loading station the issuer installs the applet, whose code hash is
  published. The applet makes its card id and its LMS key on the card from the
  card's own random source; the issuer reads the public key, signs the
  certificate offline with its SLH-DSA key (kept in a hardware security module)
  and writes the certificate and the open code's hash to the card. The open code
  itself is printed under the scratch-off panel and then deleted from the
  station.
- The issuer replaces the card manager keys with discarded random keys,
  prints the card number (from the card id) on the face, and records the card
  in a published batch list.
- The app pins the issuers' public keys and ships a revocation list. A card
  reaches its writer blank; the writer's app refuses Make on any card that is
  not blank.
- Cards are sampled from each batch for destructive testing and for checking
  that the loaded code matches the published hash.

## Threat model

### Assets

- The coins behind a sealed card, and the receiver's ability to tell a sealed,
  funded card from anything else.
- The privacy of who loaded and who spent a card, in second place.

### Attackers

- A **modified app** or any NFC tool on any phone that taps the card: the
  writer's, a previous holder's, or a stranger's.
- **Middleware**: software between the app and the card (a hooked NFC stack, a
  jailbreak tweak, a relay) or between the app and the Ghost node.
- The **card maker and the issuer**, and anyone in the supply chain between
  them and the writer.
- A **previous holder** or **thief** who had the card for a while.
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

### Not protected

- **Possession**: a bearer card is cash. Whoever has the card and its open
  code can open it and take the coins; a sealed card that is lost or destroyed
  is lost value.
- **Relay**: see the middleware red-team below; a relay with a convincing
  counterfeit card body is a residual risk.
- **Laboratory attacks** on the chip: the app should advise against putting
  more on one card than such an attack would be worth.

## Red-team

Each item is an attack and how the design answers it.

### A modified app

- **Attack:** read the Phantom Key, the card random or any secret while the
  card is sealed. **Answer:** no command returns them; Make and Check answer
  with public values only, and Open needs the printed open code.
- **Attack:** choose or bias the key through the writer nonce (for example
  all zeros, or a value it can replay). **Answer:** the seed bytes hash the
  card's own random bytes with the nonce, and those bytes never leave a sealed
  card, so a chosen nonce gives the writer nothing.
- **Attack:** make the card make a second key, or reset it to blank, keeping
  the first key's coin. **Answer:** states only move forward and Make works only
  on a blank card; the card manager is locked so the applet cannot be replaced.
- **Attack:** commit one amount on the card but send a Vanish of less, or send
  commit data with a corrupted note, or never send it. **Answer:** the card
  signs the amount and the SHA3-256 of its own commit data; the receiver's app
  shows "not on the chain yet" unless those exact bytes are in the coin tree.
- **Attack:** open the card quietly and give it on as sealed. **Answer:**
  opening needs the code under the scratch-off panel, and an opened card
  reports opened on every later tap, under a signature over the receiver's own
  challenge.
- **Attack:** use up the card's seal checks. **Answer:** this denies checks,
  not coins: the card can still be opened, every statement shows how many
  checks remain, and 1,024 checks at about a second each needs the card in
  reach for a long time.
- **Attack:** pull the card away mid-Make or mid-Open to leave it half-done.
  **Answer:** both are atomic; Make leaves a blank or sealed card, and an
  opened card releases its seed material again with the same code.
- **Attack:** write an NTAG 424 DNA card and present it as sealed. **Answer:**
  the receiver's app shows "sealed" only for answers that chain to a pinned
  issuer key; an NTAG 424 DNA card is always shown as carry to Claim.

### Middleware

- **Attack:** record the NFC traffic to catch the key. **Answer:** a sealed
  card never sends it; Open sends it encrypted under a key from the 160-bit
  open code and the tap's challenge, which a recording does not hold.
- **Attack:** replay a recorded "sealed" answer after the card was opened.
  **Answer:** every statement signs the receiver's fresh challenge, so an old
  answer fails the check.
- **Attack:** alter the amount, the commitment or the state in the answer.
  **Answer:** they are inside the attestation signature, which the receiver's
  app checks.
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
- **Attack:** skim a card in a pocket and open it. **Answer:** opening needs the
  printed open code, which a skimmer does not have.

### The card maker and loader

- **Attack:** ship an applet with a hidden command that exports the key.
  **Answer:** the applet's code is published and its hash is in each card's
  certificate; batches are sampled and checked; this is the trust that remains
  in whoever loads the cards, stated as such.
- **Attack:** weaken the card's random source so keys can be predicted.
  **Answer:** the key also hashes the writer's nonce, which the maker never
  sees, so a weak card random alone does not give the maker the key.
- **Attack:** keep a copy of a card's attestation key, or certify an emulator
  that says "sealed" for a coin whose key it shares. **Answer:** the
  attestation key is made on the card; the issuer key is kept offline in a
  hardware security module; the app pins issuer keys, checks the published
  batch list and revokes a misbehaving issuer. Certifying emulators is the
  issuer's remaining trust.
- **Attack:** sell a card that already holds a key the maker knows.
  **Answer:** a card must reach its writer blank, and the writer's app refuses
  Make on any other state; the state is signed.
- **Attack:** leave the card manager open to replace the applet later.
  **Answer:** the card manager's keys are replaced by discarded random keys at
  loading, so no one, the issuer included, can load or delete an applet.
- **Attack:** swap a genuine chip for a counterfeit in the supply chain.
  **Answer:** a counterfeit cannot sign under a certified attestation key, so
  it fails the check.

### A previous holder or a thief

- **Attack:** scratch the panel, note the open code, cover it again and pass
  the card on. **Answer:** the code is useless without the card itself, and the
  receiver can see a disturbed panel; the card's coins move only to whoever
  holds the card and the code.
- **Attack:** open the card, take the coins, then pass it on. **Answer:** the
  card says opened forever, and the marker shows the coin spent.
- **Attack:** extract the key by fault injection or a laser. **Answer:** this
  is the hardware trust; the secure element's certification and the advice to
  limit the value per card bound it.

### A quantum attacker

- **Attack:** forge a seal statement or a certificate, or break the open
  encryption, with a quantum computer. **Answer:** the seal statement is LMS
  over SHA-256, the certificate is SLH-DSA, the open encryption is AES-256
  under a 160-bit code hashed with SHA3-256, and the coin itself uses Ghost's
  hash-based commitments. None rests on elliptic curves or factoring.

## Left for the hardware step

The applet, its loading and the checks on real cards and phones are a later
step. It must show, on the chosen product and on an iPhone:

- that the product exposes SHA3-256 natively and the timing budgets above are
  met (Make, Check, Open, and LMS key generation at loading);
- that the applet reproduces Ghost's F, commitment, commit data and marker
  bit for bit from fixed test inputs taken from Ghost's own client;
- a seal check from a second phone that never touched the card, and a one-way
  open whose later taps all show opened.
