#!/usr/bin/env bash
# Runs one shard of the Rust core tests, so CI can split them across parallel
# jobs. Usage: scripts/rust-test-shard.sh <index> <count>, index from 0.
#
# Every test of every test target (the library's unit tests and each file in
# core/tests) is listed, the list is sorted, and test number i runs in shard
# i % count. All shards together run every test exactly once. Shard 0 also
# runs the doc tests.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <index> <count>" >&2
  exit 2
fi
index="$1"
count="$2"
if ! [[ "$index" =~ ^[0-9]+$ && "$count" =~ ^[0-9]+$ ]] || [ "$count" -lt 1 ] || [ "$index" -ge "$count" ]; then
  echo "need whole numbers with 0 <= index < count" >&2
  exit 2
fi

cd "$(dirname "$0")/.."
manifest=core/Cargo.toml

cargo test --manifest-path "$manifest" --locked --no-run

# Test targets as cargo selectors: "lib" or "test <name>".
mapfile -t targets < <(
  cargo metadata --manifest-path "$manifest" --locked --no-deps --format-version 1 |
    jq -r '.packages[0].targets[]
      | if any(.kind[]; . == "lib") then "lib"
        elif any(.kind[]; . == "test") then "test " + .name
        else empty end' |
    LC_ALL=C sort
)

if [ "${#targets[@]}" -eq 0 ]; then
  echo "no test targets found" >&2
  exit 1
fi

selector_for() {
  if [ "$1" = lib ]; then
    selector=(--lib)
  else
    selector=(--test "${1#test }")
  fi
}

# One line per test: "<target><TAB><test name>", in a fixed order.
all_tests=$(
  for target in "${targets[@]}"; do
    selector_for "$target"
    cargo test --manifest-path "$manifest" --locked "${selector[@]}" -- --list --format terse |
      sed -n 's/: test$//p' |
      while IFS= read -r name; do printf '%s\t%s\n' "$target" "$name"; done
  done | LC_ALL=C sort
)

if [ -z "$all_tests" ]; then
  echo "no tests found" >&2
  exit 1
fi

total=$(printf '%s\n' "$all_tests" | wc -l)
mine=$(printf '%s\n' "$all_tests" | awk -F '\t' -v i="$index" -v n="$count" '(NR - 1) % n == i')
echo "==> shard $index of $count: $(printf '%s' "$mine" | grep -c . || true) of $total tests"

for target in "${targets[@]}"; do
  mapfile -t names < <(printf '%s\n' "$mine" | awk -F '\t' -v t="$target" '$1 == t { print $2 }')
  if [ "${#names[@]}" -eq 0 ]; then
    continue
  fi
  selector_for "$target"
  cargo test --manifest-path "$manifest" --locked "${selector[@]}" -- --exact "${names[@]}"
done

if [ "$index" -eq 0 ]; then
  cargo test --manifest-path "$manifest" --locked --doc
fi
