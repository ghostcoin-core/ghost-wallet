#!/usr/bin/env bash
# Builds the enclave program (seal_enclave) twice, from two different
# directories, with the pinned settings of enclave/build.env and the release
# profile of seal/Cargo.toml, and fails unless the two binaries have the same
# SHA-256. Needs cargo and the pinned toolchain only: no Docker, no Nitro tool.
#
#   bash enclave/scripts/check-reproducible.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

# The pinned settings: KEY=value lines.
while IFS='=' read -r key value; do
  case "$key" in
    SEAL_*) printf -v "$key" '%s' "$value" ;;
  esac
done < "$repo/enclave/build.env"
: "${SEAL_TOOLCHAIN:?missing from build.env}" "${SEAL_TARGET:?}" "${SEAL_SOURCE_DATE_EPOCH:?}"
: "${SEAL_TARGET_FEATURES:?}" "${SEAL_BUILD_ROOT:?}" "${SEAL_CARGO_ROOT:?}"

cargo_home="${CARGO_HOME:-$HOME/.cargo}"
work="$(mktemp -d "${TMPDIR:-/tmp}/seal-repro.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# Each build has its own copy of the sources and its own target directory.
# Cargo is pointed at them through one fixed path (the `src` link), as the
# Dockerfile always builds at one fixed root: cargo mixes the absolute path of
# a path dependency outside the crate's workspace (the wallet core) into
# symbol hashes, which no path remapping undoes.
build() {
  local root="$1" at="$work/src"
  # The seal crate and the wallet core it depends on (`../core`).
  mkdir -p "$root/seal" "$root/core"
  cp "$repo/seal/Cargo.toml" "$repo/seal/Cargo.lock" "$root/seal/"
  cp -R "$repo/seal/src" "$root/seal/src"
  cp "$repo/core/Cargo.toml" "$repo/core/Cargo.lock" "$root/core/"
  cp -R "$repo/core/src" "$root/core/src"
  ln -sfn "$root" "$at"
  RUSTUP_TOOLCHAIN="$SEAL_TOOLCHAIN" \
    SOURCE_DATE_EPOCH="$SEAL_SOURCE_DATE_EPOCH" \
    CARGO_TARGET_DIR="$root/target" \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS="-C target-feature=$SEAL_TARGET_FEATURES -C link-arg=-Wl,--build-id=none --remap-path-prefix=$root=$SEAL_BUILD_ROOT --remap-path-prefix=$at=$SEAL_BUILD_ROOT --remap-path-prefix=$cargo_home=$SEAL_CARGO_ROOT" \
    cargo build --quiet --release --locked --features nitro --bin seal_enclave \
      --target "$SEAL_TARGET" --manifest-path "$at/seal/Cargo.toml"
  sha256sum "$root/target/$SEAL_TARGET/release/seal_enclave" | cut -d' ' -f1
}

echo "building seal_enclave in $work/first ..."
first="$(build "$work/first")"
echo "building seal_enclave in $work/second-build ..."
second="$(build "$work/second-build")"

echo "first:  $first"
echo "second: $second"
if [ "$first" != "$second" ]; then
  echo "check-reproducible: the two builds differ" >&2
  exit 1
fi
echo "check-reproducible: both builds are identical ($SEAL_TARGET, toolchain $SEAL_TOOLCHAIN)"
