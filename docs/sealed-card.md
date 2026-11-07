# Ghost Sealed cards

Status: design, with the Seal's card logic and its chain check built and
tested against a simulated NTAG 424 DNA and fake chain nodes, and the app's
screens (Check, Fill, Open into the wallet, the Open PIN; see
[The app](#the-app)) built and tested against a fake Seal. The enclave that
runs the Seal for phones, the proxy through which it reaches real nodes, and
the card setup are separate pieces of work that build on this document.

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
- **The chain check**: tells the Seal whether a coin is paid exactly,
  settled and still unspent, as two or more independent nodes agree (see
  [Chain check](#chain-check)).

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
   commit number 0), from the Seal's random source. The maker also returns
   the coin's spend marker.
6. Journal the coin (its public commit data and its spend marker) before the
   card changes.
7. Write the key slot frame, read it back and compare.
8. Write the header frame (still Empty, key present, the coin, the amount and
   the Open PIN hash if one was asked for), read it back and compare.
9. Wipe the key from memory. Return only the commit data, the amount and a
   signed answer (state Empty).

The card is **not** Sealed yet. The phone sends the Vanish with the commit
data. Then the Seal is asked to confirm:

10. Read the header (key 2) and the key slot; they must match.
11. Ask the chain check whether exactly this coin and exactly this amount are
    paid, settled and unspent. With the chain status check installed, the
    Seal also asks it itself, with the commit data and spend marker from its
    journal. If not: nothing changes (not paid, filling and waiting to
    settle, a wrong payment, spent, or can't check right now).
12. Write the header Sealed, read it back, answer Sealed.

A Fill asked again while one is waiting for its payment hands back the same
commit data (from the journal), never a new key, so a Vanish sent for a lost
answer is never stranded. A Fill with another amount or PIN is refused until
the waiting one is paid.

The key of step 5 is made inside the Seal, in the enclave, by
`CoreKeyMaker` (`seal/src/key_maker.rs`): 32 fresh bytes from the Seal's
random source (the enclave's `getrandom`) are the key's secret, its bytes
are the core's (`0x20`, then the 32 bytes, as the key slot and an Open
release hold them), and its coin is the core's coin commit number 0 for the
chain the chain check follows, its salt and note nonce from the same draw.
No elliptic-curve key is involved. The key exists in enclave memory only
from the maker's `make` until the key slot is written and read back (step
7): the Seal then wipes it, and keeps no copy. The Seal never makes its
24 words, and the key appears in no answer, no log line and no journal plaintext:
the journal holds only the coin's public commit data and spend marker. The
card is its only copy until an Open releases it, encrypted, to the phone.

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
6. With the chain status check installed, a card that says Sealed is
   answered Sealed only once the chain check finds its coin (the commit data
   and spend marker from the Fill journal entry) paid exactly, settled and
   unspent. Otherwise Check refuses: not settled, spent, can't check right
   now, or a payment that is not exactly this coin, and never a signed
   Sealed answer. A journaled Open still answers Opening or Opened first.

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
- **The coin is paid and still there.** The card is marked Sealed only after
  the chain check confirmed exactly this commit data and exactly this amount,
  settled; every Check asks again whether it is still unspent.
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
  bytes, and a store that changes, drops, repeats or reorders records, or
  rolls the log back while the Seal runs, is caught and refused. A log
  deleted, or cut while the Seal is stopped, is restored from the peer
  regions at the next start ("Journal"). What is still trusted: that the
  hosts of every region do not cut or delete the log at once, and that not
  every region is lost at once; that the peer regions are reachable, or no
  Fill or Open is served; and that no one launches new EC2 instances in the
  AWS account to answer for both peers.
- **The chain nodes**: that the nodes of the release node list do not all
  lie the same way at once. One node that is wrong, behind or unreachable
  only stops the answer.
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
- The app and DNS sending each card to its home region (today a Seal that is
  not the card's home refuses it `wrong-region`, naming the home).
- Fill and Open while one peer region is down: today every save waits for
  both peers (the conservative choice), so a region down stops Fills and
  Opens elsewhere until it is back or replaced; a restart waits for both
  peers too.
- Bind a peer answer to the deployed stack, not only to an instance: today
  whoever can launch new EC2 instances in the AWS account can answer for
  both peers from approved enclaves on instances of their own.

In place since the journal's head is anchored in the other regions: a host
that cuts the tail of the log while the enclave is stopped is caught at the
next start and the cut records restored from a peer; a journal that
survives the host instance being replaced (restored from a peer); and each
card served by one home region, so an Open begun in one region is never
finished, or certified Sealed, by another ("Journal", "Home region").

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

The Phantom Key's bytes, in the key slot and in a release, are the wallet
core's key bytes: the format code `0x20`, then the key's 32 secret bytes (33
bytes). The phone's core makes the same Phantom Key from them with Ghost's
client (a key of the words format is made from the first 32 bytes its source
gives) and refuses any other length, format code or secret.

## Chain check

The chain check (`seal/src/chain_check.rs`) answers one question about a
card's coin, given its commit data, the card's amount and the coin's spend
marker. It reuses the wallet core instead of copying it: the leaf a Vanish
adds (`commit_leaf`), the coin-tree page check (`check_coin_pages`) and the
settlement depth (`settle_confirmations`).

A node is a `ChainNode`: its network (chain id and genesis), its tip, the
receipts of the transactions to the coin commit entry that carry the coin's
fingerprint, the coin-tree page roots and one page as of a block, and
whether a spend marker is used. It is a trait, so the enclave reaches nodes
through its outside proxy; nothing in the Seal opens a socket.

From each node, at its tip:

1. The node must follow the Seal's network, or the answer is the wrong
   chain.
2. Find the successful Vanish to the coin commit entry signed for this chain
   id with exactly the card's commit data and exactly the card's amount.
   Without one, the nearest miss decides: the same commit data with another
   amount is the wrong amount; the coin's fingerprint with other commit data
   is wrong commit data; a payment signed for another chain id is the wrong
   chain; nothing (or only failed transactions) is filling.
3. The leaf that Vanish adds must be at the receipt's position in a page that
   `check_coin_pages` checked against the tip header's coin tree root.
   Anything else is a node whose answers do not fit together.
4. A used spend marker is spent.
5. A Vanish block fewer than the safe depth deep is filling, waiting to
   settle. The safe depth is the wallet's settlement policy, today a flat 3
   blocks for every amount.
6. Otherwise: exact, settled and unspent.

`NodeChainCheck` asks every node it holds (at least two, each named once)
and answers only when all of them give the same tip and the same result. An
unreachable node, a node whose data fails its check, or any disagreement is
"can't check right now". It also serves as a Fill confirmation's
`ChainCheck`: exact and settled and unspent is Paid; filling and can't check
now are NotYet; a wrong payment or a spent coin is Mismatch.

`Seal::new`, the only way to build a Seal, takes the chain status check and
the card registry: there is no Seal without them. The check gates every
Sealed answer of Check and of Fill's confirmation, with the commit data and
spend marker from the Fill journal entry (the card holds only the coin's
hash); the registry refuses an unregistered UID ("Not a Ghost card") before
any card traffic. The enclave builds its check over the compiled-in release
node list (`seal/src/node_list.rs`), each node an `RpcNode`
(`seal/src/node_rpc.rs`: JSON-RPC over TLS 1.3 ended inside the enclave,
`docs/seal-enclave.md`), and its registry from the file the host loads; the
development test server over the nodes it is given and its registry file
(`docs/seal-relay.md`).

## Journal

The Seal journals a Fill's public commit data and its coin's spend marker
before writing the card (a spend marker is public once the coin is spent
and tells nothing before), and an Open (phase, generation, coin, amount,
phone key, Phantom Key) before changing the card. The store sees only sealed entries: AES-256-CBC under a
fresh IV, then HMAC-SHA3-256 over `ghost-seal/v1/journal` || entry kind ||
UID || IV || ciphertext, both keys from HKDF(M) with the label
`ghost-seal/v1/journal`.

Under that, the journal is an append-only log (`seal/src/journal_log.rs`)
that the parent host keeps (`seal/src/host_journal.rs`,
`/var/lib/seal/journal.log`, served on vsock port 5005 by `seal_proxy
journal`). Each save of an entry appends one record:

```text
counter (u64, from 1, +1 each save)
record = IV (16) || AES-256-CBC(entry kind (1) || UID (7) || sealed entry, ISO 9797-1 padding 2) || tag (32)
tag    = HMAC-SHA3-256(ghost-seal/v1/host-journal || origin length (1) || origin || counter
                       || previous record's tag || IV || ciphertext)
```

The origin is the id of the region whose log it is (empty for a log
anchored nowhere, as in the dev test server), so a record of one region's
log never verifies as another region's: not on a host, not in a peer's log
of another origin, not in a restore. The previous tag of record 1 is 32 zero bytes. Both keys are HKDF(M) with
the label `ghost-seal/v1/host-journal` (salt and info), the first 32 bytes
for AES-256, the next 32 for HMAC. The host holds counters and ciphertext
only: no UID, entry kind, card data or key, and never M. A record is at most
4096 bytes.

- **Open.** The Seal reads every record in order and refuses the whole log
  (no flow is served) on a counter that is not the previous one plus 1 (a
  gap, a repeat or a reorder), a bad tag, a tag chained to another previous
  record, a record that does not decode, or another M. It keeps the latest
  entry per card and kind in enclave memory, and loads answer from that
  verified map, never from the host.
- **Save.** It appends the next record and waits for the host to confirm it
  is on disk (flushed with its directory); only then is the map changed and
  the save `Ok`, and the Seal changes a card only after that. Any store
  error is a journal error. An append whose answer was lost is taken as
  written if a later read of the host's log shows exactly it at the end.
- **Rollback.** While it runs, the Seal remembers the last counter and tag
  it wrote. A later read of the host's log (at each session) that has fewer
  records, more, or another tail is a rollback: refused, and no save is
  taken again until a restart.
- One log per Seal, behind one lock, shared by every session, so counters
  never collide.

The host's log alone cannot show a cut made while the Seal is stopped (the
shorter log is still valid) or a host replaced by one with an empty log. So
the log's head is anchored in the other regions (`seal/src/journal_anchor.rs`):

- **Peers.** Each other region's enclave is a peer. It keeps a copy of this
  region's log, ciphertext only, in a log per origin region on its own host
  (`/var/lib/seal/peer-<region>.log`, the same store and checks, the same
  vsock port 5005). It checks each record with M before it keeps it: the
  next counter, a good tag chained to the last record it holds and bound to
  the origin the request names, and that it decodes. A peer never holds a
  UID, an entry kind, card data, a key or M in the clear. Requests carry no
  caller authentication: anyone reaching the service port can fetch a log's
  ciphertext, but a record fetched from region A's log appended as region
  B's (as B's record 1 or any later one) fails its tag and is refused, the
  peer's log of B unchanged.
- **Save.** After the host's append is durable, the record goes to every
  peer (service request kind 3 over the service port, through the parent's
  vsock ports 5006 and 5007 and the host's proxy to the peer region's
  inbound proxy, 10 seconds each). The save is `Ok`, and a card changed,
  only once every peer answered a head that holds it. A peer that is
  unreachable or refuses fails the save: the card is unchanged, and the
  record is held back (not loaded) until a later save has every peer take
  it; a host that then drops it is a rollback. A peer that missed records
  while it was down is sent them first.
- **Start.** Once M is installed and before any flow, the enclave restores
  every log it keeps: first its copies of the other regions' logs (each
  from that region or the other peer that holds it), then its own. Each
  restore asks every peer for its head with a fresh 32-byte nonce, and
  unless **every** peer answers, it serves no flow (HTTP 503, the fixed
  event `the durable journal could not be anchored`, tried again every
  minute). A peer holding more than the host's copy (a cut tail, or an empty
  store on a replaced host) has the missing records fetched, each checked
  with M onto that log's chain and appended to the host's store, before
  anything is served. A peer head with the same counter and another tag (a
  fork), a restored record that fails its check, or a restore that does not
  end on the peer's head, is a refusal.
- **No copy.** A peer log not restored yet, or empty, answers *no copy*
  (`0 || reason`: 1 restored and empty, 2 not restored and nothing stored, 3
  not restored with records not confirmed yet), never a zero head; so does a
  region asked about its own log before that log is open. A *no copy* never
  counts as a head or as agreement: a region's own restore takes heads only
  when every peer holds one, and opens empty only when its store is empty
  and every peer answered 1 (a log never written); a store with records that
  no peer holds is refused. A peer log's restore with no head anywhere keeps
  the copy it holds (checked with M), but refuses it while a holder answers 1,
  and waits while it is empty and a holder answers 3. So a rolling
  replacement (one region after another, no write between) keeps every log:
  each replacement restores the others' logs before it serves.
- **Answers.** Every answer, a head, a no copy or a fetch, is responder
  length (1) || responder || document length (u16) || document || mac (32)
  || body, where body is `1 || counter (u64) || tag`, `0 || reason` or the
  fetched records, and mac is HMAC-SHA3-256 under the head key (HKDF(M),
  label `ghost-seal/v1/journal-head`, salt and info) over
  `ghost-seal/v1/journal-head` || op || origin length (1) || origin ||
  responder length (1) || responder || the asker's nonce || body. The
  responder is the region id compiled into the answering image; the
  document is a fresh Nitro attestation document from its NSM, with the
  asker's nonce as `nonce` and SHA3-256(`ghost-seal/v1/journal-head-answer`
  || mac) as `user_data`. The asker takes an answer only when the MAC
  verifies, the responder is the region of the port it asked and not its
  own, and the document verifies with the attestation verifier, names an
  approved build, and carries a PCR4 (the parent instance) that is not the
  asker's own (read from its own attestation, label
  `ghost-seal/v1/journal-head-own-instance`) and not another peer's in the
  same restore or save. The fresh nonce means an old answer is never taken
  again; the PCR4 means an approved enclave started on the asker's own
  host, or one instance answering for both peers, is never taken. No
  signature crate is needed.
- Because a save reaches every peer and a start needs every peer, a start
  always meets the peers that hold the last acknowledged record.

What it does not catch: an attacker who can launch new EC2 instances in the
AWS account itself (approved enclaves on two new instances, one per peer
port, each with a PCR4 of its own); every region lost at once, or the hosts
of every region cutting the log at once (no copy is left to restore from).
The cost is availability: Fill and Open wait while a peer region is down,
and a start waits for both peers. The log is not compacted; it survives the
enclave and the host restarting and the host instance being replaced, one
region at a time.

### Home region

Each card is served by one region only, its home: of the release's ordered
region list (compiled into the image, `RELEASE_REGIONS`: `us-east-1`,
`eu-central-1`, `ap-southeast-1`), the region id whose
SHA3-256(`ghost-seal/v1/home-region` || region id || UID) is the greatest,
compared as big-endian bytes (on a tie, the earlier region). Each enclave's
own region id is compiled into its image too (the `SEAL_REGION` build
argument of `enclave/Dockerfile`, one image and one set of PCRs per region,
each on the signed measurements list), never taken from the host. A Check, Fill, Fill confirmation or Open start of
a card whose home is another region is refused HTTP 422 with the reason
`wrong-region` and the home region in `homeRegion` (`docs/seal-relay.md`),
before any session: no card command, no journal read or write, no log line.
Check is pinned too: a region that never saw an Open would certify a card
Sealed. Fixed vectors are in `seal/tests/vectors/home-region.json`. The list
is fixed per release; changing it moves cards, so every Fill and Open is
finished first (`enclave/RUNBOOK.md`).

## Every derivation label

| Label | Derives |
| --- | --- |
| `ghost-seal/v1/card-keys` (salt) and `ghost-seal/v1/card-key/N/...` | card key N |
| `ghost-seal/v1/answer-signing-key` | the ML-DSA-65 seed of the answer key |
| `ghost-seal/v1/open-pin` | the key of the Open PIN hash (info: label, UID, generation); the hash is HMAC-SHA3-256 over the label and the PIN, first 16 bytes |
| `ghost-seal/v1/journal` | the journal's AES-256 and HMAC keys |
| `ghost-seal/v1/host-journal` | the journal log's AES-256 and HMAC keys (salt and info), and the first part of each record's tag |
| `ghost-seal/v1/journal-head` | the head key a peer region MACs its answers about a log's head with (salt and info), and the first part of each head MAC |
| `ghost-seal/v1/journal-head-answer` | not a key: the first part of the hash of a peer answer's MAC that its attestation document carries as `user_data` |
| `ghost-seal/v1/journal-head-own-instance` | not a key: the `user_data` and `nonce` of the document an enclave reads its own PCR4 from |
| `ghost-seal/v1/home-region` | not a key: the first part of the hash that picks a card's home region |
| `ghost-seal/v1/open-release` | the release's AES-256 and HMAC keys, from the ML-KEM shared secret |
| `ghost-seal/v1/record-check` | the check of each record frame |
| `ghost-seal/v1/phone-key` | the hash of a bound phone key |

## The app

Four screens, each laid out for the iPhone and for the iPhone Duo folded and
open: Check NFC Chip (`app/check-card.tsx`, a button on Home and in the
Cards section of Settings), Fill a card (`app/fill-card.tsx`) and Open a card
into my wallet (`app/open-card.tsx`), both in the Cards section. The flows are
`lib/seal/flows.ts`; the relay is `docs/seal-relay.md`.

### Checking an answer

Every answer is checked in the native core, never in JavaScript
(`core/src/seal_answer.rs`, the phone's side of `AnswerVerifier`, with the
`ml-dsa` version the Seal pins): the Seal's measurement is on the app's
pinned list (the PCR0 of each allowed build in
`lib/seal/pinned-measurements.ts`) and is the one the answer carries, the
ML-DSA-65 signature verifies under the Seal's key (context
`ghost-seal answer`), the answer is of the flow the phone ran, over the
32-byte challenge the native relay made and sent, about the card it tapped,
and not expired. The Seal's key and measurement come from one function,
`trustedSeal` in `lib/seal/trusted-seal.ts`. They will come from the Seal's
Nitro attestation (`GPA2`, `docs/seal-enclave.md`, which also binds the TLS
certificate the enclave serves), which the app does not fetch yet, so today
it returns nothing, and the pinned list is empty too:
every card shows "Can't verify this card".

### Check NFC Chip

A deliberate tap with a spinner while it runs; Home and Send never wait on
it. It shows one of:

- **Secured, 5 GHOST, never opened**: a fresh verified Sealed answer, with
  whether an Open needs a PIN and the tries left;
- **Filling, waiting to settle**: the Seal refused it as not settled, or this
  phone filled the card and the Seal still answers it Empty (it answers
  Empty until the Fill is confirmed); a button asks the Seal to confirm it;
- **Opened, empty**: Opening or Opened;
- **Empty, ready to fill**: set up and never filled (or filled by another
  phone and not yet confirmed);
- **Not a Ghost card**: the Seal does not know the card;
- **Can't check right now (no connection)**: the Seal or its chain check
  could not be reached;
- **Can't verify this card**, in red, never with an amount: any answer that
  failed a check (a bad signature, a replayed or expired answer, another
  card, Seal code not pinned), or no Seal to check with.

A card is shown Secured only after a fresh Check that verified.

### Fill a card

The person picks an amount (at least the smallest Vanish) and, if wanted, an
Open PIN, then taps a set-up empty card. The Seal writes a fresh key and
hands back the commit data; the app checks the Fill answer (it binds exactly
that commit data, for exactly that amount and PIN status) and Vanishes
exactly that amount to exactly that commit data through the existing Vanish
payment (`startSealedCardVanish` in `lib/vanish/actions.ts`): the Seal's
commit data replaces the key the core would have made. No words or key are
ever shown or held on the phone. A Fill asked again hands back the same
commit data, and the Vanish already saved for it is reused, never a second
one. The screen shows Filling until the Seal, asked with a tap once the
payment settled, answers Sealed. The phone remembers which cards it filled
(`lib/seal/fills.ts`: UID and amount only) so its own Check shows them as
Filling.

### Open into my wallet

The person Checks the card first: its amount, whether it needs a PIN and the
tries left come from that signed answer. On Open the native core makes an
ML-KEM-768 key pair (`core/src/seal_open.rs`, with the `ml-kem`, `hkdf`,
`hmac`, `aes` and `cbc` versions the Seal pins) and hands JavaScript only the
public encapsulation key. The relay hands the release to the core, which
checks the Open answer (it must bind exactly that package), opens the
package and puts the Phantom Key in its card-key slot. The app then at once
Claims the whole coin into the wallet's account with the existing Claim
(`startReveal` with the card key, as Summon from a card does) and shows its
status until it settles. The key never reaches JavaScript and is never
logged.

The private key's seed is kept in the Keychain, this device only, from just
before the Open is sent until that Claim settles, then wiped. An Open cut off
by a lost connection or a closed app is asked again with the same phone key,
and the Seal releases the key to it (and to no other).

### The Open PIN

Optional, 4 to 8 digits, set at Fill (typed twice). It goes to the Seal
through the relay only: it is never stored or logged, and the screens clear
it as soon as the call that needed it is made. An Open of a card with a PIN
asks for it; a wrong PIN costs a try, counted on the card, and the screen
shows the tries left again only from a new signed answer. A card with no
tries left is shown as locked and can never be opened. A filled card's PIN
stays as set at Fill: the Seal has no flow to set it again yet.

## Relation to the bearer-card specification

The bearer-card specification keeps NTAG 424 DNA carry-to-Claim only, and
keeps the Java Card plan for a card that is a bearer object on its own. A
Ghost Sealed card is the one exception: its keys and Phantom Key live only in
the Seal, so it can be accepted after a fresh Check. A receiver who wants
certainty offline, or without trusting the Seal, still needs the Java Card
plan.
