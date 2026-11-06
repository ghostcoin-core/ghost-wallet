# Ghost card setup

Status: the setup flow and the card registry are built in the Seal crate and
tested against a simulated NTAG 424 DNA. The test-card tool is
`tools/seal-setup`. The card design is in `docs/sealed-card.md`.

Every Ghost card is set up once, in a controlled step, before it is handed to
anyone. Setup gives the card the five keys the Seal derives for its UID
(generation 0), locks its record file to those keys, verifies all of it by
fresh authentication and records the UID in the card registry. A card the
registry does not hold is refused by Check, Fill and Open with "Not a Ghost
card", before the Seal sends it anything.

## Why a card is set up once

A blank NTAG 424 DNA leaves the factory with five all-zero keys. Changing a
key is sent encrypted under a session opened with the old key, so whoever
records the radio exchange of a setup from factory keys can decrypt it later
and learn every new key. A card set up from factory keys in the open can be
recorded, and that recording later gives away its keys.

So a card is set up once, in a controlled place, before anyone gets it, and
never again: a card is never set up in the field, and never from factory
keys in an open room. After setup no command ever runs under a factory key,
and every later change of keys (an Open moving the card to its next
generation) runs under the Seal's own keys inside the chip's encrypted
channel.

## Test cards on the Mac Studio

Test cards are set up on the Mac Studio with a USB NFC reader, in a room with
no other readers and no phone with NFC turned on near the reader. The tool
sets up test cards with the dev test Seal's master key only: it refuses to
run without `--dev-test-seal`, and the dev test master key is SHA3-256 of
the text `ghost-seal/dev-test-master/v1`, the value the test Seal server
uses. A test card is good for the test Seal only.

1. Build the tool with its reader feature (`pcsc-reader`) and attach exactly
   one reader. The tool refuses to pick a reader when more than one is
   attached.
2. Put one blank card on the reader and run the tool with `--dev-test-seal`,
   a batch name and the registry file, for example
   `seal-setup --dev-test-seal --batch test-2026-11 --registry cards.registry`.
3. The tool reads the UID the reader reports, runs the setup and prints one
   line: set up and registered, finished a setup that was cut off, already
   set up, or refused and why.
4. Take the card off the reader only after that line. If the card left the
   reader early, put it back and run the tool again: it finishes the setup.

The setup runs in this order:

1. Select the application and read the five key versions.
2. Prove each key is the one its version names (version 0 the factory key,
   version 1 the Seal's key of generation 0) by authenticating with it, then
   authenticate with key 0 and check the UID the chip itself reports.
   Nothing changes on the card before this.
3. Set the record file (file 2) to Full mode (encrypted and MACed),
   read and write with key 2, read with key 1, change with key 0, and SDM
   off.
4. Change keys 1 to 4, then key 0 last, to the Seal's keys of generation 0.
5. Zero the record file, both 128-byte frames, and read it back.
6. Verify (see below).
7. Only then record the UID in the registry.

## Production: the card maker's key-loading service

Production cards are not set up by the tool. The production master key
exists only inside the enclave, so production cards are loaded by the card
maker's secure key-loading service, in the maker's controlled personalisation
line:

1. The Seal derives the five keys of each card of the order from the card's
   UID (the maker sends the UID list of the batch first) and the production
   master key, inside the enclave.
2. The keys go to the maker wrapped for the maker's HSM, never in the clear:
   the enclave encrypts each card's keys to the HSM's key-transport key,
   which the maker's HSM attests and which is pinned for that maker. No
   person, script or file outside the enclave and the HSM ever holds an
   unwrapped card key.
3. Inside the HSM the keys are unwrapped and loaded onto each card: the HSM
   authenticates with the factory key in the maker's shielded line, sets the
   record file to Full mode with the Seal's rights and SDM off, and changes
   keys 1 to 4 then key 0, exactly as the setup above.
4. The maker returns, per card, the UID and the result of the setup step;
   the batch is then checked as below by the Seal over a reader of our own
   before any card of it is registered or shipped.
5. The wrapped key file is deleted at the maker once the batch is loaded.
   The master key never leaves the enclave and is never sent to the maker.

## What is checked after setup

- **Every key, by fresh authentication.** The Seal authenticates afresh with
  each of the five new keys and checks the UID the chip reports in each
  session. A factory key no longer opens a session.
- **The key versions.** Every key carries the generation 0 version (1).
- **The file mode, the permissions and SDM-off.** Read in a fresh session:
  Full mode, read and write key 2, read key 1, change key 0, 256 bytes, SDM
  off.
- **The record is blank.** Both frames were zeroed and read back over the
  encrypted channel.
- **The UID is recorded in the registry** (UID, set-up date and batch, all
  public values) only after every check above passed. A card the registry
  does not hold is refused by Check, Fill and Open.
- **A half-set-up card is finished or refused.** A setup cut off at any step
  is run again from the start and carries on from what the card says: all
  keys factory is a fresh setup; some keys already the Seal's, each
  authenticating as its version says, means finish the rest. A key version
  that is neither factory nor generation 0, or a key the chip refuses, means
  the card is refused, never guessed at.
- **A finished card is left alone.** Running the setup again on a registered
  card only verifies it; nothing on the card or in the registry changes. A
  card whose record file already holds a Ghost record is never zeroed.

## What is never done

- A card is never set up in the field, at a point of sale or by a phone in
  everyday use.
- A card is never set up from factory keys in an open room, or with more
  than one reader in the room.
- Card keys are never sent to a card maker in the clear, written to a file,
  printed or logged; the master key never leaves the enclave.
- The tool never sets up a card with the production master key, and never
  runs without `--dev-test-seal`.
- A card is never registered before every key, the file mode, the
  permissions and SDM-off were verified.
- A card is never set up twice: a registered card is only verified, and a
  card holding a Ghost record is never wiped.
