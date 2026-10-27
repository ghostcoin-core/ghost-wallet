#!/usr/bin/env bash
# Build a Release Ghost Wallet for an iOS simulator, install it, and run the
# native benchmarks on the bench screen with Maestro.
#
# Runs on the Mac Studio (macOS, Xcode with the simulator runtime, CocoaPods,
# Node 22, rustup, Maestro and openjdk@17).
#
#   bash scripts/sim-test.sh
#   GHOST_WALLET_SIM="iPhone Duo" BENCHES="dummy summon" bash scripts/sim-test.sh
#
# GHOST_WALLET_SIM names the simulator (default "iPhone Duo"); BENCHES lists
# the benchmarks to run (default "dummy summon kill-recovery"). Each one must
# finish with a result that starts with "<name>: ok". A screenshot of each
# result is saved under sim-results/.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
  echo "sim-test: $*" >&2
  exit 1
}

[ "$(uname -s)" = "Darwin" ] || fail "this script runs on macOS only"

SIM="${GHOST_WALLET_SIM:-iPhone Duo}"
BENCHES="${BENCHES:-dummy summon kill-recovery}"

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

mkdir -p sim-results
failed=()
for bench in $BENCHES; do
  echo "==> benchmark $bench"
  # The flow waits for a result that starts with "$bench: ok".
  if maestro --device "$udid" test -e BENCH="$bench" .maestro/bench.yaml; then
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
