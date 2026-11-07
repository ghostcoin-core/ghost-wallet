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
registry into it (above).
