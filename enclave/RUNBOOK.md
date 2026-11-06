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

The release owner makes an ML-DSA-65 (FIPS 204) key pair on an offline
machine and keeps the private half there. Its public half (1952 bytes, as
lowercase hex) goes into `RELEASE_KEY_HEX` in `seal/src/measurements.rs`;
every image built after that trusts lists it signs. A signature is over
`ghost-seal/v1/measurements/release` || the list's digest
(`MeasurementList::signing_message`), with context `ghost-seal measurements`,
written into the list as `"signature": "<6618 hex>"`.

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
`--apply` and the URLs and hashes from above plus `--ghost-node HOST:PORT`.
The first region in `enclave/deploy/regions.json` starts in genesis; each
other region joins from the peer listed for it. Check each host's
`/ghost-seal/<stack>` log group for `ok: made M (genesis)` and
`ok: received M from a running enclave`.

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
any running region: change its `peer` in `regions.json`).
