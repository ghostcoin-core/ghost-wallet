#!/usr/bin/env bash
# Builds the enclave program (seal_enclave) of each region of
# enclave/deploy/regions.json twice, from two different directories, with the
# pinned settings of enclave/build.env, the release profile of
# seal/Cargo.toml and SEAL_REGION set to the region (as enclave/Dockerfile
# does), and fails unless each region's two binaries have the same SHA-256
# and no two regions' binaries are the same (each image has its own region
# compiled in). Needs cargo, the pinned toolchain and jq only: no Docker, no
# Nitro tool.
#
#   bash enclave/scripts/check-reproducible.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
regions_file="$repo/enclave/deploy/regions.json"

command -v jq > /dev/null || { echo "check-reproducible: needs jq" >&2; exit 2; }

# The pinned settings: KEY=value lines.
while IFS='=' read -r key value; do
  case "$key" in
    SEAL_*) printf -v "$key" '%s' "$value" ;;
  esac
done < "$repo/enclave/build.env"
: "${SEAL_TOOLCHAIN:?missing from build.env}" "${SEAL_TARGET:?}" "${SEAL_SOURCE_DATE_EPOCH:?}"
: "${SEAL_TARGET_FEATURES:?}" "${SEAL_BUILD_ROOT:?}" "${SEAL_CARGO_ROOT:?}"

# The regions to build: regions.json, which must be the region list compiled
# into the program, in its order.
compiled="$(grep -o 'RELEASE_REGIONS: \[&str; [0-9]*] = \[[^]]*]' "$repo/seal/src/journal_anchor.rs" |
  grep -o '"[a-z0-9-]*"' | tr -d '"' | paste -sd, -)"
listed="$(jq -r '[.regions[].region] | join(",")' "$regions_file")"
if [ -z "$listed" ] || [ "$compiled" != "$listed" ]; then
  echo "check-reproducible: regions.json lists $listed; the program has $compiled compiled in" >&2
  exit 1
fi
regions=()
while IFS= read -r region; do
  regions+=("$region")
done < <(jq -r '.regions[].region' "$regions_file")

cargo_home="${CARGO_HOME:-$HOME/.cargo}"
work="$(mktemp -d "${TMPDIR:-/tmp}/seal-repro.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# Each build has its own copy of the sources and its own target directory.
# Cargo is pointed at them through one fixed path (the `src` link), as the
# Dockerfile always builds at one fixed root: cargo mixes the absolute path of
# a path dependency outside the crate's workspace (the wallet core) into
# symbol hashes, which no path remapping undoes.
build() {
  local root="$1" region="$2" at="$work/src"
  # The seal crate and the wallet core it depends on (`../core`).
  mkdir -p "$root/seal" "$root/core"
  cp "$repo/seal/Cargo.toml" "$repo/seal/Cargo.lock" "$root/seal/"
  cp -R "$repo/seal/src" "$root/seal/src"
  cp "$repo/core/Cargo.toml" "$repo/core/Cargo.lock" "$root/core/"
  cp -R "$repo/core/src" "$root/core/src"
  ln -sfn "$root" "$at"
  SEAL_REGION="$region" \
    RUSTUP_TOOLCHAIN="$SEAL_TOOLCHAIN" \
    SOURCE_DATE_EPOCH="$SEAL_SOURCE_DATE_EPOCH" \
    CARGO_TARGET_DIR="$root/target" \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS="-C target-feature=$SEAL_TARGET_FEATURES -C link-arg=-Wl,--build-id=none --remap-path-prefix=$root=$SEAL_BUILD_ROOT --remap-path-prefix=$at=$SEAL_BUILD_ROOT --remap-path-prefix=$cargo_home=$SEAL_CARGO_ROOT" \
    cargo build --quiet --release --locked --features nitro --bin seal_enclave \
      --target "$SEAL_TARGET" --manifest-path "$at/seal/Cargo.toml"
  sha256sum "$root/target/$SEAL_TARGET/release/seal_enclave" | cut -d' ' -f1
}

hashes=()
for region in "${regions[@]}"; do
  echo "$region: building seal_enclave in $work/$region/first ..."
  first="$(build "$work/$region/first" "$region")"
  echo "$region: building seal_enclave in $work/$region/second-build ..."
  second="$(build "$work/$region/second-build" "$region")"

  echo "$region: first:  $first"
  echo "$region: second: $second"
  if [ "$first" != "$second" ]; then
    echo "check-reproducible: the two builds of $region differ" >&2
    exit 1
  fi
  for seen in ${hashes[@]+"${hashes[@]}"}; do
    if [ "$seen" = "$first" ]; then
      echo "check-reproducible: $region builds the same program as another region: SEAL_REGION was not compiled in" >&2
      exit 1
    fi
  done
  hashes+=("$first")
  # The next region's builds start from fresh copies.
  rm -rf "$work/$region"
done

echo "check-reproducible: each region's two builds are identical, and each region's differs ($SEAL_TARGET, toolchain $SEAL_TOOLCHAIN): ${regions[*]}"
