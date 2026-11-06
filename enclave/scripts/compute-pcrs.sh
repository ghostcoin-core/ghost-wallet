#!/usr/bin/env bash
# Run on a Nitro-capable builder (an arm64 instance with docker, nitro-cli and
# jq): builds the enclave image from enclave/Dockerfile, turns it into the EIF
# with `nitro-cli build-enclave`, reads PCR0, PCR1 and PCR2 back with
# `nitro-cli describe-eif`, checks both agree, and adds the build to
# enclave/measurements.json as allowed. Anyone can run it again from the same
# commit and must get the same three values.
#
#   bash enclave/scripts/compute-pcrs.sh <build name> [YYYY-MM-DD]
#
# It writes enclave/out/seal.eif and enclave/out/seal.eif.sha256 (not
# committed) and changes only enclave/measurements.json in the repository.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
list="$repo/enclave/measurements.json"
out="$repo/enclave/out"

name="${1:-}"
released="${2:-$(date -u +%Y-%m-%d)}"
if ! [[ "$name" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; then
  echo "usage: compute-pcrs.sh <build name> [YYYY-MM-DD]" >&2
  exit 2
fi
if ! [[ "$released" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  echo "compute-pcrs: released must be YYYY-MM-DD" >&2
  exit 2
fi
for tool in docker nitro-cli jq sha256sum; do
  command -v "$tool" > /dev/null || { echo "compute-pcrs: needs $tool" >&2; exit 2; }
done
if jq -e --arg name "$name" '.builds[] | select(.name == $name)' "$list" > /dev/null; then
  echo "compute-pcrs: a build named $name is already listed" >&2
  exit 1
fi

mkdir -p "$out"
image="ghost-seal-enclave:$name"
docker build --platform linux/arm64 --target enclave -f "$repo/enclave/Dockerfile" -t "$image" "$repo"
nitro-cli build-enclave --docker-uri "$image" --output-file "$out/seal.eif" > "$out/build-enclave.json"
nitro-cli describe-eif --eif-path "$out/seal.eif" > "$out/describe-eif.json"
sha256sum "$out/seal.eif" | cut -d' ' -f1 > "$out/seal.eif.sha256"

pcr() {
  local which="$1" built described
  built="$(jq -r ".Measurements.$which" "$out/build-enclave.json" | tr 'A-F' 'a-f')"
  described="$(jq -r ".Measurements.$which" "$out/describe-eif.json" | tr 'A-F' 'a-f')"
  if ! [[ "$built" =~ ^[0-9a-f]{96}$ ]] || [ "$built" != "$described" ]; then
    echo "compute-pcrs: $which is not one 96-digit value in both outputs" >&2
    exit 1
  fi
  if [[ "$built" =~ ^0+$ ]]; then
    echo "compute-pcrs: $which is all zeros" >&2
    exit 1
  fi
  printf '%s' "$built"
}
pcr0="$(pcr PCR0)"
pcr1="$(pcr PCR1)"
pcr2="$(pcr PCR2)"

if jq -e --arg pcr0 "$pcr0" '.builds[] | select(.pcr0 == $pcr0)' "$list" > /dev/null; then
  echo "compute-pcrs: this image (PCR0 $pcr0) is already listed" >&2
  exit 1
fi

updated="$(mktemp)"
trap 'rm -f "$updated"' EXIT
jq --arg name "$name" --arg released "$released" \
  --arg pcr0 "$pcr0" --arg pcr1 "$pcr1" --arg pcr2 "$pcr2" \
  '.builds += [{name: $name, released: $released, pcr0: $pcr0, pcr1: $pcr1, pcr2: $pcr2, status: "allowed"}]' \
  "$list" > "$updated"
mv "$updated" "$list"

echo "compute-pcrs: added $name"
echo "  PCR0 $pcr0"
echo "  PCR1 $pcr1"
echo "  PCR2 $pcr2"
echo "  EIF sha256 $(cat "$out/seal.eif.sha256")"
echo "Commit enclave/measurements.json, then copy the build into lib/seal/pinned-measurements.ts."
