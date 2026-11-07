# Seal enclave runbook

Short operating notes for the Seal on AWS Nitro Enclaves. The design is in
`docs/seal-enclave.md`.

## Never

- Never start a Seal enclave with `--debug-mode`. Its PCRs are zeros and every
  check refuses it, and its console would be readable by the host.
- Never start genesis twice. Genesis makes a new M: a different Seal whose
  answers no phone accepts. Only the very first enclave is ever started in
  genesis mode; `deploy.sh` switches that region to join once its stack exists.
- Never sign a list that is not published in `enclave/measurements.json` at
  a commit on `main`. Any build on a list the release key signed can receive
  M; a list without that signature is refused by every enclave.
- Never let the release key's private half onto a networked machine, into the
  repository, an image or a fixture. The tests' keys are test-only.
- There is no KMS key, backup or export of M to restore from. If every
  enclave stops at once, M is gone and the cards it holds cannot be opened.
  Keep at least two regions running at all times.
- Never stop a region for long: every Fill and Open waits for both other
  regions to take its journal record. Keep every region running.

## Needs

An AWS account (Nathan's step), the aws CLI and jq for `deploy.sh`, and a
Nitro-capable arm64 builder (Amazon Linux 2023, docker, `aws-nitro-enclaves-cli`,
jq) for `compute-pcrs.sh`. Expect roughly $200 to $400 a month for 2 to 3 hosts.

## Release key (once, before the first image)

The release key is an ML-DSA-65 (FIPS 204) key pair. Its private half (a
32-byte seed) lives only on an offline machine: a computer with no network
(wifi and bluetooth off, no cable) that is used for nothing else. Its public
half (1952 bytes, 3904 lowercase hex digits) is compiled into every image as
`RELEASE_KEY_HEX` in `seal/src/measurements.rs`. A signature is over
`ghost-seal/v1/measurements/release` || the list's digest
(`MeasurementList::signing_message`), with context `ghost-seal measurements`,
written into the list as `"signature": "<6618 hex>"`. The tool
`tools/seal-release-key` makes the key and writes that signature; it never
opens a socket and never prints the private half.

### Make the key (once)

1. On the networked builder, at a commit on `main`:
   `cargo build --release --locked --manifest-path tools/seal-release-key/Cargo.toml`.
   The binary is `tools/seal-release-key/target/release/seal-release-key`.
   Note its SHA-256: `sha256sum tools/seal-release-key/target/release/seal-release-key`.
2. Copy only that binary to the offline machine (a freshly formatted USB
   stick that carries nothing else). The offline machine runs the same OS
   and CPU architecture as the builder. On the offline machine, check the
   SHA-256 matches the one from step 1; stop if it does not.
3. On the offline machine:
   `./seal-release-key keygen --out release.key`. It writes the private half
   to `release.key` (mode 0600; it refuses a file that already exists) and
   prints only the public half: 3904 lowercase hex digits.
4. Keep `release.key` on the offline machine. Never copy it anywhere else.
5. Carry back only the public hex: write it down, or copy only that text to
   the USB stick (`./seal-release-key keygen --out release.key > release.pub`
   does both at once), and check it reads back the same.
6. Back on a networked machine, a one-line change puts the public hex into
   `RELEASE_KEY_HEX` in `seal/src/measurements.rs`, reviewed like any other
   change. Every image built after that trusts the lists the key signs.

### Sign a list (each publish)

1. Bring the list to sign (`enclave/measurements.json` at a commit on
   `main`) and the public hex to the offline machine.
2. On the offline machine:
   `./seal-release-key sign measurements.json --key release.key --out measurements.signed.json`.
   It refuses a key file that group or others can read (`chmod 600 release.key`),
   reads the list strictly, drops any old signature and writes the list in
   one layout with its new `"signature"`. It never overwrites an existing
   output unless given `--force`.
3. Still offline:
   `./seal-release-key verify measurements.signed.json --public release.pub`
   (or the hex itself after `--public`). It exits 0 and prints `ok: ...`
   only when the list is signed and the signature verifies; anything else
   prints one line and exits non-zero.
4. Carry back only `measurements.signed.json`, commit it as
   `enclave/measurements.json`, and run `verify` once more on the builder
   with the public hex.

The private half is never on a networked machine, in the repository, in an
image or in a fixture; the tests' keys are test-only keys made in the tests.
If the offline machine or `release.key` is lost, no new list can be signed:
the images trust only the key compiled into them.

## Publish a build

1. On the builder, at the release commit: `bash enclave/scripts/check-reproducible.sh`.
2. `bash enclave/scripts/compute-pcrs.sh seal-YYYY-MM-DD`. It writes
   `enclave/out/seal.eif` and its SHA-256, and adds the build to
   `enclave/measurements.json`.
3. Export the host proxy:
   `docker build --platform linux/arm64 -f enclave/Dockerfile --target proxy -o enclave/out .`
4. Have a second person rebuild from the same commit and compare the three
   PCRs. The release owner signs the list offline (above). Commit the signed
   list; add the same entry to `lib/seal/pinned-measurements.ts` in the app
   release that should accept it.
5. Upload `seal.eif`, `seal_proxy` and the committed `measurements.json` to
   an HTTPS location, and note the SHA-256 of each.

## First deploy

`bash enclave/scripts/deploy.sh` prints the plan. Then run it again with
`--apply` and the URLs and hashes from above plus `--ghost-node HOST:PORT`
and `--ghost-node-2 HOST:PORT`: the two nodes of the release node list
compiled into the image (`seal/src/node_list.rs`), in its order, each at its
HTTPS port 443. The host carries the enclave's vsock port 5003 to the first
(unit `seal-node`) and 5004 to the second (unit `seal-node-2`); the bytes stay
TLS, which ends inside the enclave and trusts only ISRG Root X1 for the
node's own host name, so pointing a unit at any other server only stops the
chain check ("can't check right now"). The first region in
`enclave/deploy/regions.json` starts in genesis; each other region joins from
the peer listed for it. Check each host's `/ghost-seal/<stack>` log group for
`ok: made M (genesis)` and `ok: received M from a running enclave`.

Each image is built for one region: `SEAL_REGION` (one of the region list
compiled into it, `RELEASE_REGIONS` in `seal/src/journal_anchor.rs`) is set
when the enclave program is built, so each region has its own build and
PCRs on the signed list. An image built without it logs
`no region was compiled into this image; not answering cards`.
`enclave/Dockerfile` and `compute-pcrs.sh` do not pass `SEAL_REGION` yet:
until they do, an image they build answers no card.
`regions.json` must list exactly the compiled region list, in its order;
`deploy.sh` refuses otherwise. Each stack gets the two other regions as its
journal anchor peers (`AnchorPeerRegion`, `AnchorPeerRegion2`) and their
proxies' addresses (`AnchorPeerAddress` for vsock port 5006,
`AnchorPeerAddress2` for 5007, units `seal-anchor` and `seal-anchor-2`).
On the first deploy the earlier regions have no address for the later ones
yet, so `deploy.sh` deploys them again at the end with every address: their
hosts are replaced before any card is served, join M from a running region
and restore their (empty) journals from a peer.

## The journal store

The enclave keeps its journal (what it writes before it changes a card, so
a Fill or an Open cut off is finished, never lost or replayed) as a log of
records it encrypts and MACs under keys derived from M. The host keeps that
log and sees counters and ciphertext only: no UID, card data, key or M.

- The stack runs it as the unit `seal-journal`:
  `/opt/seal/seal_proxy journal 5005 /var/lib/seal/journal.log <region>=/var/lib/seal/peer-<region>.log <region 2>=/var/lib/seal/peer-<region 2>.log`,
  the same `seal_proxy` binary, serving the enclave on vsock port 5005: its
  own log, and the copy of each other region's log it keeps as that region's
  peer (the peer log files, one per other region). `StateDirectory=seal`
  gives it `/var/lib/seal`; every file is created mode 0600. It starts
  before the enclave, which reads the whole log as soon as it holds M.
- On a host by hand, before `seal_proxy start`:
  `systemctl enable --now seal-journal`, then check
  `/var/log/seal/seal-journal.log` for
  `serving the journal store /var/lib/seal/journal.log (N records) on vsock port 5005`
  and one `serving the peer log of <region>` line per other region.
- The log's head is anchored in the other regions. After each record the
  enclave sends it (ciphertext only) to both other regions' enclaves over
  its vsock ports 5006 and 5007 (units `seal-anchor` and `seal-anchor-2`,
  outbound to their proxies, 10 seconds each); each checks it with M and
  keeps it in its host's peer log. A Fill or an Open goes on only once both
  took it. When the enclave starts, after it holds M and before it serves,
  it asks both for its log's head with a fresh nonce and restores from a
  peer any records its host's log lacks.
- If the enclave logs `the durable journal was refused`, it answers every
  card `unavailable`. Either the store was not reachable (start
  `seal-journal`; the enclave tries again every minute and at each registry
  load) or the log failed the enclave's checks: a record changed, dropped,
  repeated or reordered, or a log of another M. Do not edit, cut or copy
  records into the file; the enclave refuses it.
- If the enclave logs `the durable journal could not be anchored in a peer
  region`, it answers every card `unavailable` and tries again every minute:
  no other region answered (start `seal-anchor` and `seal-anchor-2`, and the
  other regions), or a peer holds another log at the same counter (a fork),
  or a record restored from a peer failed its check. A fork or a bad restore
  is not fixed by retrying: stop and look at the peer regions' logs.
- Never delete or truncate `/var/lib/seal/journal.log` or a peer log while
  cards are being filled or opened. Never compact them by hand.

What it survives, what it costs and what it does not cover:

- It survives the enclave restarting and the host restarting: the files stay
  in `/var/lib/seal`.
- It survives the host instance being replaced (a redeploy of the stack, an
  upgrade, "Replace a lost region"): the new host starts with an empty
  journal, and the new enclave restores the whole log from a peer region
  before it serves, so a Fill or an Open begun before is finished, never
  lost or replayed.
- A host that cuts the end off the log while the enclave is stopped is
  caught when the enclave starts again, and the cut records are restored
  from a peer. A cut made while the enclave runs is caught and refused.
- The cost is availability: while a peer region is down or unreachable,
  every Fill and Open in the regions that need it waits (refused, nothing
  changed on the card); with no peer answering at its start an enclave
  serves no card. Keep every region running. A lost region is replaced by a
  redeploy, which restores from a peer.
- It does not cover every region lost at once, nor the hosts of every
  region cutting the log at once: there is then no copy left to restore
  from.

Each card is served by its home region only (`docs/sealed-card.md`, "Home
region"); every other region refuses it `wrong-region`, naming the home, and
touches no journal, card or log. The app must send each card to its home.

## Load the card registry

After each enclave has started (genesis or join), and again whenever cards
have been set up, send it the whole card registry file the card setup
writes:

`/opt/seal/seal_proxy registry <enclave CID> registry.txt`

It answers `ok: took the card registry (N cards, M new, K lines left out)`.
It refuses, and changes nothing, a file that leaves out a card it already
holds or changes one's entry: send the full, current file, never a part of
it. Until the first load the enclave serves no card. A restarted enclave
starts empty: load it again after its start.

## Upgrade to a new build

1. Build the new image with the running build in `COMPILED_BUILDS`
   (`seal/src/measurements.rs`), so it takes M from it. Publish it (above)
   with status `allowed`, keeping the running build allowed.
2. On every running host, give the enclave the signed list:
   `/opt/seal/seal_proxy list <enclave CID> measurements.json`. It answers
   `ok: took a signed list` only for a list the release key signed that keeps
   every build it already holds.
3. Redeploy one region at a time with the new EIF and the new list: each new
   host joins from a region still running. Wait for its `ok` before the next.
4. When every region runs the new build and the app pins it, mark the old
   build `revoked` in a later signed list and give it to every enclave.

## Revoke a build

Set its `status` to `revoked` in `enclave/measurements.json` and in
`lib/seal/pinned-measurements.ts`, have the release owner sign the list,
publish, and give it to every running enclave with `seal_proxy list`. A
revoked build is given M by no enclave, gives M to none, and is refused by the
app. Build later images with the revoked entry in `COMPILED_BUILDS`, so no
older signed list can bring it back.

## Replace a lost region

Redeploy its stack: the new host starts in join mode from its peer (or from
any running region: change its `peer` in `regions.json`). Then load the card
registry into it (above). Its host's journal starts empty and the enclave
restores it from a peer region before it serves (see "The journal store");
until one other region answers, it serves no card. Its peer logs of the
other regions start empty too and fill again with their next records.

## Change the region list

The region list is compiled into the image and fixed per release. Changing
it (adding, dropping or reordering a region) moves cards to other home
regions. Before a release with another list, finish every Fill and Open on
every region, then upgrade every region to the new list together.
