#!/usr/bin/env bash
# Build a Release Ghost Wallet for an iOS simulator, install it, and run the
# native benchmarks on the bench screen with Maestro.
#
# Runs on the Mac Studio (macOS, Xcode with the simulator runtime, CocoaPods,
# Node 22, rustup, Maestro and openjdk@17).
#
#   bash scripts/sim-test.sh
#   GHOST_WALLET_SIM="iPhone Duo" BENCHES="dummy summon" bash scripts/sim-test.sh
#   BENCHES="dummy summon kill-recovery header-sync restore worst-case" bash scripts/sim-test.sh
#
# GHOST_WALLET_SIM names the simulator (default "iPhone Duo"); BENCHES lists
# the benchmarks to run (default "dummy summon kill-recovery"). Each one must
# finish with a result that starts with "<name>: ok". A screenshot of each
# result is saved under sim-results/.
#
# The node benchmarks (header-sync, restore, worst-case) run against the local
# test chain of scripts/test-chain.sh: when BENCHES names one, the chain is
# started, mined past the second RandomX key, and its node URL and test-only
# chain overrides are written into the simulator's UserDefaults.
#
# By default each node benchmark starts from a pinned checkpoint, as the app
# will, so a run takes minutes: header-sync from 1,000 blocks below the tip,
# worst-case from height 8000 (below the second key's first use at 8449, so
# its sync still crosses the key change), and restore from just below a
# wallet birthday, after the test accounts are funded again above it. Every
# header after a checkpoint is checked in full. The background wait is 10
# seconds.
#
#   FULL=1 BENCHES="header-sync restore worst-case" bash scripts/sim-test.sh
#
# FULL=1 runs the node benchmarks from genesis with no birthday and the
# compiled 180-second background wait, for a final confirmation.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
  echo "sim-test: $*" >&2
  exit 1
}

[ "$(uname -s)" = "Darwin" ] || fail "this script runs on macOS only"

SIM="${GHOST_WALLET_SIM:-iPhone Duo}"
BENCHES="${BENCHES:-dummy summon kill-recovery}"
FULL="${FULL:-0}"
APP_ID=com.ghostcoin.wallet

# The benchmarks that need a Ghost node, and what the local test chain needs
# for them: past height 8449 (the second RandomX key) for worst-case.
NODE_BENCHES="header-sync restore worst-case"
TEST_CHAIN_PORT=8547
TEST_CHAIN_HEIGHT=8600
# The Maestro wait for a result: 10 minutes, or 90 for a node benchmark.
BENCH_TIMEOUT_MS=600000
NODE_BENCH_TIMEOUT_MS=5400000
# The checkpoint starts (unless FULL=1): header-sync checks this many headers
# up to the tip; worst-case starts below 8449, the second key's first use;
# restore's birthday is this many blocks below the late funding, and its
# checkpoint the block below the birthday.
HEADER_SYNC_WINDOW=1000
WORST_CASE_CHECKPOINT=8000
RESTORE_BIRTHDAY_LEAD=100
BACKGROUND_WAIT_SECONDS=10

case "$FULL" in
  0 | 1) ;;
  *) fail "FULL must be 0 or 1" ;;
esac

is_node_bench() {
  case " $NODE_BENCHES " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

needs_chain=false
for bench in $BENCHES; do
  if is_node_bench "$bench"; then
    needs_chain=true
  fi
done

# Expo's downloaded precompiled module binaries do not match the core they pair
# with; build every Expo module from source.
export EXPO_USE_PRECOMPILED_MODULES=0

# Homebrew's node@22 and openjdk@17 (for Maestro) are keg-only.
if ! command -v node >/dev/null 2>&1 && [ -x /opt/homebrew/opt/node@22/bin/node ]; then
  export PATH="/opt/homebrew/opt/node@22/bin:$PATH"
fi
if ! java -version >/dev/null 2>&1 && [ -x /opt/homebrew/opt/openjdk@17/bin/java ]; then
  export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"
fi
if ! command -v maestro >/dev/null 2>&1 && [ -x "$HOME/.maestro/bin/maestro" ]; then
  export PATH="$HOME/.maestro/bin:$PATH"
fi

for tool in node corepack pod xcodebuild xcrun cargo rustup java maestro; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
done

node_major="$(node -p 'process.versions.node.split(".")[0]')"
[ "$node_major" = "22" ] || echo "sim-test: warning: expected Node 22, found $(node --version)" >&2

if [ "$needs_chain" = true ]; then
  # Started before the build so the chain mines while the app builds.
  echo "==> local test chain"
  bash scripts/test-chain.sh start
fi

echo "==> finding simulator \"$SIM\""
# shellcheck disable=SC2016
udid="$(xcrun simctl list devices available --json | SIM="$SIM" node -e '
  let text = "";
  process.stdin.on("data", (chunk) => (text += chunk));
  process.stdin.on("end", () => {
    const devices = Object.values(JSON.parse(text).devices).flat();
    const match = devices.find((device) => device.name === process.env.SIM);
    if (match) process.stdout.write(match.udid);
  });
')"
[ -n "$udid" ] || fail "no available simulator named \"$SIM\" (see xcrun simctl list devices)"

echo "==> booting $SIM ($udid)"
xcrun simctl boot "$udid" 2>/dev/null || true
xcrun simctl bootstatus "$udid" -b

echo "==> pnpm install"
corepack enable
pnpm install --frozen-lockfile

echo "==> rust core (XCFramework and bindings)"
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
(cd modules/ghost-core && ../../node_modules/.bin/ubrn build ios --config ubrn.config.yaml --and-generate --release)

echo "==> swift bindings of the rust core"
# uniffi-bindgen reads `cargo metadata`, so it runs from core/. The bindings
# are compiled into the GhostBench pod, which turns on GHOST_CORE_BINDINGS.
generated="$PWD/modules/ghost-bench/ios/Generated"
bindings_out="$(mktemp -d)"
(cd core && cargo run --release --manifest-path ../tools/uniffi-bindgen/Cargo.toml -- \
  generate --library target/aarch64-apple-ios-sim/release/libghost_wallet_core.a \
  --language swift --out-dir "$bindings_out")
rm -rf "$generated"
mkdir -p "$generated"
cp "$bindings_out/ghost_wallet_core.swift" "$bindings_out/ghost_wallet_coreFFI.h" "$generated/"
rm -rf "$bindings_out"

echo "==> expo prebuild (ios)"
pnpm exec expo prebuild --platform ios --clean --no-install

echo "==> pod install"
(cd ios && pod install)

echo "==> building Release for the simulator (arm64)"
# The core is built for aarch64-apple-ios-sim only, so build arm64 alone.
xcodebuild \
  -workspace ios/GhostWallet.xcworkspace \
  -scheme GhostWallet \
  -configuration Release \
  -destination "id=$udid" \
  -derivedDataPath ios/build \
  ARCHS=arm64 ONLY_ACTIVE_ARCH=YES \
  build

echo "==> installing on $SIM"
xcrun simctl install "$udid" ios/build/Build/Products/Release-iphonesimulator/GhostWallet.app

if [ "$needs_chain" = true ]; then
  echo "==> waiting for the test chain to reach height $TEST_CHAIN_HEIGHT"
  bash scripts/test-chain.sh wait "$TEST_CHAIN_HEIGHT"
  genesis_rlp="$(bash scripts/test-chain.sh genesis)"
  [ -n "$genesis_rlp" ] || fail "the test chain returned no block 0"

  echo "==> pointing the app on $SIM at the test chain"
  # Test-only overrides (TestChainConfig.swift): the chain's 1-second blocks,
  # the miner running up to an hour ahead of the clock, its block 0 as the
  # start, and the three test accounts funded by test-chain.sh.
  sim_defaults() {
    xcrun simctl spawn "$udid" defaults write "$APP_ID" "$@"
  }
  sim_defaults_delete() {
    xcrun simctl spawn "$udid" defaults delete "$APP_ID" "$1" >/dev/null 2>&1 || true
  }
  sim_defaults benchNodeUrl -string "http://127.0.0.1:$TEST_CHAIN_PORT"
  sim_defaults benchTestChain.blockTime -int 1
  sim_defaults benchTestChain.futureDrift -int 3600
  sim_defaults benchTestChain.genesisRlpHex -string "$genesis_rlp"
  sim_defaults benchTestChain.restoreAccountsExpected -int 3

  if [ "$FULL" = 1 ]; then
    echo "==> FULL=1: the node benchmarks start from genesis"
    sim_defaults_delete benchTestChain.backgroundWaitSeconds
  else
    sim_defaults benchTestChain.backgroundWaitSeconds -int "$BACKGROUND_WAIT_SECONDS"
    case " $BENCHES " in
      *" restore "*)
        echo "==> funding the test accounts again for the restore birthday"
        late_block="$(bash scripts/test-chain.sh fund-late "$TEST_CHAIN_HEIGHT")"
        [[ "$late_block" =~ ^[0-9]+$ ]] || fail "test-chain.sh fund-late printed no block"
        restore_birthday=$((late_block - RESTORE_BIRTHDAY_LEAD))
        ;;
    esac
  fi
fi

# The start of one node benchmark: a checkpoint (and, for restore, the
# wallet's birthday), or genesis with FULL=1. The checkpoint is made from the
# node's chain right before the benchmark runs.
set_bench_start() {
  local bench="$1" checkpoint_height="" checkpoint tip
  sim_defaults_delete benchTestChain.checkpoint
  sim_defaults_delete benchTestChain.restoreBirthday
  [ "$FULL" = 1 ] && return
  case "$bench" in
    header-sync)
      tip="$(bash scripts/test-chain.sh height)"
      checkpoint_height=$((tip - HEADER_SYNC_WINDOW))
      ;;
    worst-case) checkpoint_height="$WORST_CASE_CHECKPOINT" ;;
    restore)
      checkpoint_height=$((restore_birthday - 1))
      sim_defaults benchTestChain.restoreBirthday -int "$restore_birthday"
      ;;
  esac
  checkpoint="$(bash scripts/test-chain.sh checkpoint "$checkpoint_height")"
  [ -n "$checkpoint" ] || fail "test-chain.sh printed no checkpoint at $checkpoint_height"
  sim_defaults benchTestChain.checkpoint -string "$checkpoint"
  echo "    $bench starts from the checkpoint at height $checkpoint_height"
}

mkdir -p sim-results
failed=()
for bench in $BENCHES; do
  echo "==> benchmark $bench"
  timeout_ms="$BENCH_TIMEOUT_MS"
  if is_node_bench "$bench"; then
    timeout_ms="$NODE_BENCH_TIMEOUT_MS"
    set_bench_start "$bench"
  fi
  # The flow waits for a result that starts with "$bench: ok".
  if maestro --device "$udid" test -e BENCH="$bench" -e TIMEOUT="$timeout_ms" .maestro/bench.yaml; then
    status=ok
  else
    status=failed
    failed+=("$bench")
  fi
  xcrun simctl io "$udid" screenshot "sim-results/$bench.png" >/dev/null 2>&1 || true
  echo "    $bench: $status (screenshot: sim-results/$bench.png)"
done

echo
if [ "${#failed[@]}" -gt 0 ]; then
  fail "failed: ${failed[*]}"
fi
echo "All benchmarks passed on $SIM: $BENCHES"
