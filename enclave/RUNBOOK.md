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
- Never run one region's EIF in another region's stack, nor one EIF in two
  regions. Each region's image has its region id compiled in;
  `deploy.sh` takes one EIF per region and refuses one EIF for two regions.

## Needs

An AWS account (Nathan's step), the aws CLI and jq for `deploy.sh`, and a
Nitro-capable arm64 builder (Amazon Linux 2023, docker, `aws-nitro-enclaves-cli`,
jq) for `compute-pcrs.sh`.

Each region runs one host, a c7g.large by default (`InstanceType` in
`enclave/deploy/seal-stack.template.json`): 2 vCPU and 4 GiB, with Nitro
Enclaves support. The enclave takes 1 vCPU and 2048 MiB (`EnclaveCpuCount`,
`EnclaveMemoryMiB`); the host keeps the other vCPU and about 2 GiB for the
proxy units. Expect about $160 a month for three c7g.large hosts (about $53
each in us-east-1), against about $105 each for a c7g.xlarge. The template
also takes c6g.large and m7g.large, and the xlarge and 2xlarge sizes.

A larger size is a redeploy that replaces the host: redeploy one region's
stack with `InstanceType` set to the new size (for example
`InstanceType=c7g.xlarge`, and a larger `EnclaveCpuCount` if the enclave
should get more), the rest of its parameters unchanged. The new host joins M
from a running region and restores its journal from a peer, as in "Replace a
lost region". Replace one region at a time, and only once the one before
serves again. A stack keeps its size when `deploy.sh` redeploys it, since
`deploy.sh` does not set `InstanceType`.

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

Each region runs its own image: the enclave's region id is the
`SEAL_REGION` build argument of `enclave/Dockerfile`, compiled into
`seal_enclave`, so the host can never change it. A release is one image per
region of `enclave/deploy/regions.json`, each with its own PCRs and its own
entry on the signed list. The Dockerfile refuses to build an enclave image
without `SEAL_REGION` or with one that is not on the compiled region list
(`RELEASE_REGIONS` in `seal/src/journal_anchor.rs`).

1. On the builder, at the release commit: `bash enclave/scripts/check-reproducible.sh`.
   It builds each region's program twice and fails unless each region's
   two builds match and no two regions' builds are the same.
2. `bash enclave/scripts/compute-pcrs.sh seal-YYYY-MM-DD`. For each region
   it builds the image with `--build-arg SEAL_REGION=<region>`, writes
   `enclave/out/seal-<region>.eif` and its SHA-256, and adds one build per
   region, named `seal-YYYY-MM-DD-<region>`, to `enclave/measurements.json`
   (all at once, and only if no two regions share a PCR0).
3. Export the host proxy (the same for every region):
   `docker build --platform linux/arm64 -f enclave/Dockerfile --target proxy -o enclave/out .`
4. Have a second person rebuild from the same commit and compare the three
   PCRs of every region. The release owner signs the list offline (above).
   Commit the signed list; add every region's entry to
   `lib/seal/pinned-measurements.ts` in the app release that should accept
   it.
5. Upload each region's `seal-<region>.eif`, `seal_proxy` and the committed
   `measurements.json` to an HTTPS location, and note the SHA-256 of each.

## First deploy

`bash enclave/scripts/deploy.sh` prints the plan. Then run it again with
`--apply` and the URLs and hashes from above: each region's own EIF as
`--eif-url <region>=URL --eif-sha256 <region>=HEX`, one of each for every
region of `regions.json` (for example
`--eif-url us-east-1=https://.../seal-us-east-1.eif --eif-sha256 us-east-1=<hex>`),
plus `--ghost-node HOST:PORT` and `--ghost-node-2 HOST:PORT`. `deploy.sh`
refuses when any region's EIF URL or hash is missing, names a region not in
`regions.json`, or gives one EIF to two regions. The two nodes of the release node list
compiled into the image (`seal/src/node_list.rs`), in its order, each at its
HTTPS port 443. The host carries the enclave's vsock port 5003 to the first
(unit `seal-node`) and 5004 to the second (unit `seal-node-2`); the bytes stay
TLS, which ends inside the enclave and trusts only ISRG Root X1 for the
node's own host name, so pointing a unit at any other server only stops the
chain check ("can't check right now"). The first region in
`enclave/deploy/regions.json` starts in genesis; each other region joins from
the peer listed for it. Check each host's `/ghost-seal/<stack>` log group for
`ok: made M (genesis)` and `ok: received M from a running enclave`.

Each image is built for one region (see "Publish a build"), so each stack
runs its own region's EIF and PCRs, each on the signed list. Each enclave
logs `serves the cards whose home region is <region>` at its start; check it
names the stack's region. An image built some other way without a region
logs `no region was compiled into this image; not answering cards` and
serves no card. Because the regions run different images, a joining
enclave trusts its giver in another region only through the release's
signed list: `seal_proxy start` offers `measurements.json` before the start
frame (the enclave answers `ok: took a signed list before the start`). The
release key must exist and the list must be signed before the first deploy;
an unsigned list is refused and the join then fails
(`refused: join failed`).
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
  it restores every log it keeps: its copies of the other regions' logs
  (each from that region or the other peer that holds it) and its own log.
  Each restore asks both other regions with a fresh nonce (both must
  answer; one is not enough) and restores any records its host's file
  lacks. An empty or not yet restored copy answers "no copy", never an
  empty head, and a "no copy" is never taken as agreement.
- Every answer between regions carries a fresh attestation document from
  the answering enclave, with the asker's nonce. The enclave takes it only
  from a build on its trusted list, of the region of the port it came on
  (not its own region), on a parent instance (PCR4) that is not its own and
  not the other peer's: an approved enclave started on the same host, or one
  instance answering for both peers, is refused.
- If the enclave logs `the durable journal was refused`, it answers every
  card `unavailable`. Either the store was not reachable (start
  `seal-journal`; the enclave tries again every minute and at each registry
  load) or the log failed the enclave's checks: a record changed, dropped,
  repeated or reordered, or a log of another M. Do not edit, cut or copy
  records into the file; the enclave refuses it.
- If the enclave logs `the durable journal could not be anchored in a peer
  region`, it answers every card `unavailable` and tries again every minute:
  an other region did not answer (start `seal-anchor` and `seal-anchor-2`,
  and the other regions: both must run), an other region has not restored
  its copy yet (it is starting too; this clears once it has), an answer was
  not attested by that region's enclave on an instance of its own (look for
  an extra enclave on this host or a peer port led elsewhere), the host
  holds records no other region holds a copy of, or a peer holds another log
  at the same counter (a fork), or a record restored from a peer failed its
  check. A fork or a bad restore is not fixed by retrying: stop and look at
  the peer regions' logs.
- Never delete or truncate `/var/lib/seal/journal.log` or a peer log while
  cards are being filled or opened. Never compact them by hand.

What it survives, what it costs and what it does not cover:

- It survives the enclave restarting and the host restarting: the files stay
  in `/var/lib/seal`.
- It survives the host instance being replaced (a redeploy of the stack, an
  upgrade, "Replace a lost region"): the new host starts with an empty
  journal, and the new enclave restores the whole log from a peer region
  before it serves, so a Fill or an Open begun before is finished, never
  lost or replayed. It restores its copies of the other regions' logs
  before it serves too, so replacing the regions one after another keeps
  every log: replace one region at a time, and only once the one before
  serves again.
- A host that cuts the end off the log while the enclave is stopped is
  caught when the enclave starts again, and the cut records are restored
  from a peer. A cut made while the enclave runs is caught and refused.
- The cost is availability: while a peer region is down or unreachable,
  every Fill and Open in the regions that need it waits (refused, nothing
  changed on the card); unless both other regions answer at its start an
  enclave serves no card. Keep every region running.
  A lost region is replaced by a redeploy, which restores from a peer.
- It does not cover every region lost at once, nor the hosts of every
  region cutting the log at once: there is then no copy left to restore
  from.
- It does not cover an attacker who can launch new EC2 instances in the AWS
  account itself: approved enclaves on two new instances (each with a PCR4
  of its own), one led to each peer port, are taken as the two peers. Keep
  the right to launch instances, and to change the peer ports' routes, to
  the few who deploy. A membership list of the regions' instances signed
  with the release key is the later change that closes this.
- A journal written by the release before the anchor (its records carry no
  origin) is upgraded in place the first time the new enclave opens it on
  that host: each record is checked with the previous rule and rewritten for
  this region with the same counters and entries, both peers take the
  rewritten log, and the file is replaced at once (`journal.log.new` is
  written, flushed and renamed over `journal.log`). Until both other regions
  run the new release and have started, it waits, the file unchanged. A log
  mixing the two formats, or a record failing the previous check, is refused
  (`the durable journal was refused`): keep the file as it is and ask the
  release owner. A leftover `journal.log.new` is harmless and is overwritten.

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

1. Build the new images (one per region) with the running builds (every
   region's) in `COMPILED_BUILDS` (`seal/src/measurements.rs`), so they take
   M from them. Publish them (above) with status `allowed`, keeping the
   running builds allowed.
2. On every running host, give the enclave the signed list:
   `/opt/seal/seal_proxy list <enclave CID> measurements.json`. It answers
   `ok: took a signed list` only for a list the release key signed that keeps
   every build it already holds.
3. Redeploy one region at a time with that region's new EIF and the new list
   (`deploy.sh` with every region's `--eif-url` and `--eif-sha256`): each new
   host joins from a region still running. Wait for its `ok` before the next.
   A release that changes the answers between regions (as the attested
   answers did) is not taken by the release before it: until every region
   runs it, Fills and Opens wait and a restarted region serves no card, and
   each region serves again once all three run it.
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

Redeploy its stack with that region's own EIF (the same `--eif-url` and
`--eif-sha256` per region as before): the new host starts in join mode from
its peer (or from any running region: change its `peer` in `regions.json`). Then load the card
registry into it (above). Its host's journal starts empty and the enclave
restores it from a peer region before it serves (see "The journal store");
until both other regions answer, it serves no card. Its peer logs of the
other regions start empty too, and it restores them from those regions
before it serves. Replace one region at a time: wait until the replaced
region serves again before the next.

## Change the region list

The region list is compiled into the image and fixed per release. Changing
it (adding, dropping or reordering a region) moves cards to other home
regions. Before a release with another list, finish every Fill and Open on
every region, then upgrade every region to the new list together.
