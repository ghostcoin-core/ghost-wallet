# Seal enclave runbook

Short operating notes for the Seal on AWS Nitro Enclaves. The design is in
`docs/seal-enclave.md`.

## Never

- Never start a Seal enclave with `--debug-mode`. Its PCRs are zeros and every
  check refuses it, and its console would be readable by the host.
- Never start genesis twice. Genesis makes a new M: a different Seal whose
  answers no phone accepts. Only the very first enclave is ever started in
  genesis mode; `deploy.sh` switches that region to join once its stack exists.
- Never put a build in a list that is not published in
  `enclave/measurements.json` at a commit on `main`. Any listed build can
  receive M.
- There is no KMS key, backup or export of M to restore from. If every
  enclave stops at once, M is gone and the cards it holds cannot be opened.
  Keep at least two regions running at all times.

## Needs

An AWS account (Nathan's step), the aws CLI and jq for `deploy.sh`, and a
Nitro-capable arm64 builder (Amazon Linux 2023, docker, `aws-nitro-enclaves-cli`,
jq) for `compute-pcrs.sh`. Expect roughly $200 to $400 a month for 2 to 3 hosts.

## Publish a build

1. On the builder, at the release commit: `bash enclave/scripts/check-reproducible.sh`.
2. `bash enclave/scripts/compute-pcrs.sh seal-YYYY-MM-DD`. It writes
   `enclave/out/seal.eif` and its SHA-256, and adds the build to
   `enclave/measurements.json`.
3. Export the host proxy:
   `docker build --platform linux/arm64 -f enclave/Dockerfile --target proxy -o enclave/out .`
4. Have a second person rebuild from the same commit and compare the three
   PCRs. Commit the list; add the same entry to
   `lib/seal/pinned-measurements.ts` in the app release that should accept it.
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

1. Publish the new build (above) with status `allowed`, keeping the running
   build allowed.
2. Redeploy one region at a time with the new EIF and the new list: each new
   host joins from a region still running. Wait for its `ok` before the next.
3. When every region runs the new build and the app pins it, mark the old
   build `revoked` in a later list and redeploy with that list.

## Revoke a build

Set its `status` to `revoked` in `enclave/measurements.json` and in
`lib/seal/pinned-measurements.ts`, publish, and redeploy every region with the
new list. A revoked build is given M by no enclave, gives M to none, and is
refused by the app.

## Replace a lost region

Redeploy its stack: the new host starts in join mode from its peer (or from
any running region: change its `peer` in `regions.json`).
