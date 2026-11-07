#!/usr/bin/env bash
# Run on a Nitro-capable builder (an arm64 instance with docker, nitro-cli and
# jq): for each region of enclave/deploy/regions.json, builds that region's
# enclave image from enclave/Dockerfile (--build-arg SEAL_REGION=<region>,
# compiled into the enclave program), turns it into the region's EIF with
# `nitro-cli build-enclave`, reads PCR0, PCR1 and PCR2 back with
# `nitro-cli describe-eif` and checks both agree. Then it adds one build per
# region, named <build name>-<region>, to enclave/measurements.json as
# allowed, all at once and only when every region was built and no two
# regions share a PCR0. Anyone can run it again from the same commit and must
# get the same values.
#
#   bash enclave/scripts/compute-pcrs.sh <build name> [YYYY-MM-DD]
#
# It writes enclave/out/seal-<region>.eif and enclave/out/seal-<region>.eif.sha256
# for each region (not committed) and changes only enclave/measurements.json
# in the repository. deploy.sh takes each region's EIF URL and hash.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
list="$repo/enclave/measurements.json"
regions_file="$repo/enclave/deploy/regions.json"
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

# The regions: regions.json, which must be the region list compiled into the
# enclave program, in its order (the Dockerfile refuses any other region).
compiled="$(grep -o 'RELEASE_REGIONS: \[&str; [0-9]*] = \[[^]]*]' "$repo/seal/src/journal_anchor.rs" |
  grep -o '"[a-z0-9-]*"' | tr -d '"' | paste -sd, -)"
listed="$(jq -r '[.regions[].region] | join(",")' "$regions_file")"
if [ -z "$listed" ] || [ "$compiled" != "$listed" ]; then
  echo "compute-pcrs: regions.json lists $listed; the program has $compiled compiled in" >&2
  exit 1
fi
regions=()
while IFS= read -r region; do
  regions+=("$region")
done < <(jq -r '.regions[].region' "$regions_file")

# Each region's build name, checked before anything is built.
for region in "${regions[@]}"; do
  build_name="$name-$region"
  if [ "${#build_name}" -gt 64 ]; then
    echo "compute-pcrs: $build_name is longer than 64 characters; use a shorter build name" >&2
    exit 2
  fi
  if jq -e --arg name "$build_name" '.builds[] | select(.name == $name)' "$list" > /dev/null; then
    echo "compute-pcrs: a build named $build_name is already listed" >&2
    exit 1
  fi
done

mkdir -p "$out"

pcr() {
  local region="$1" which="$2" built described
  built="$(jq -r ".Measurements.$which" "$out/build-enclave-$region.json" | tr 'A-F' 'a-f')"
  described="$(jq -r ".Measurements.$which" "$out/describe-eif-$region.json" | tr 'A-F' 'a-f')"
  if ! [[ "$built" =~ ^[0-9a-f]{96}$ ]] || [ "$built" != "$described" ]; then
    echo "compute-pcrs: $region: $which is not one 96-digit value in both outputs" >&2
    exit 1
  fi
  if [[ "$built" =~ ^0+$ ]]; then
    echo "compute-pcrs: $region: $which is all zeros" >&2
    exit 1
  fi
  printf '%s' "$built"
}

# The new entries, one per region, added to the list together at the end.
entries="[]"
for region in "${regions[@]}"; do
  image="ghost-seal-enclave:$name-$region"
  eif="$out/seal-$region.eif"
  docker build --platform linux/arm64 --target enclave --build-arg "SEAL_REGION=$region" \
    -f "$repo/enclave/Dockerfile" -t "$image" "$repo"
  nitro-cli build-enclave --docker-uri "$image" --output-file "$eif" > "$out/build-enclave-$region.json"
  nitro-cli describe-eif --eif-path "$eif" > "$out/describe-eif-$region.json"
  sha256sum "$eif" | cut -d' ' -f1 > "$eif.sha256"

  pcr0="$(pcr "$region" PCR0)"
  pcr1="$(pcr "$region" PCR1)"
  pcr2="$(pcr "$region" PCR2)"
  if jq -e --arg pcr0 "$pcr0" '.builds[] | select(.pcr0 == $pcr0)' "$list" > /dev/null ||
    jq -e --arg pcr0 "$pcr0" '.[] | select(.pcr0 == $pcr0)' <<< "$entries" > /dev/null; then
    echo "compute-pcrs: $region's image (PCR0 $pcr0) is already listed: each region's image must be its own" >&2
    exit 1
  fi
  entries="$(jq --arg name "$name-$region" --arg released "$released" \
    --arg pcr0 "$pcr0" --arg pcr1 "$pcr1" --arg pcr2 "$pcr2" \
    '. + [{name: $name, released: $released, pcr0: $pcr0, pcr1: $pcr1, pcr2: $pcr2, status: "allowed"}]' <<< "$entries")"
done

updated="$(mktemp)"
trap 'rm -f "$updated"' EXIT
jq --argjson entries "$entries" '.builds += $entries' "$list" > "$updated"
mv "$updated" "$list"

for region in "${regions[@]}"; do
  echo "compute-pcrs: added $name-$region"
  jq -r --arg name "$name-$region" '.builds[] | select(.name == $name) | "  PCR0 \(.pcr0)\n  PCR1 \(.pcr1)\n  PCR2 \(.pcr2)"' "$list"
  echo "  EIF enclave/out/seal-$region.eif, sha256 $(cat "$out/seal-$region.eif.sha256")"
done
echo "Commit enclave/measurements.json, then copy every new build into lib/seal/pinned-measurements.ts."
echo "Deploy each region with its own EIF: deploy.sh --eif-url <region>=URL --eif-sha256 <region>=HEX for each region."
