#!/usr/bin/env bash
# Build a Release Ghost Wallet (JavaScript bundled, no Metro needed) and
# install and launch it on a connected iPhone.
#
# Runs on the Mac Studio (macOS, Xcode, CocoaPods, Node 22).
#
#   GHOST_WALLET_DEVICE=<iphone-udid> bash scripts/mac-install.sh
#
# Find the UDID with `xcrun devicectl list devices`.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
  echo "mac-install: $*" >&2
  exit 1
}

[ "$(uname -s)" = "Darwin" ] || fail "this script runs on macOS only"

DEVICE="${GHOST_WALLET_DEVICE:-}"
[ -n "$DEVICE" ] || fail "set GHOST_WALLET_DEVICE to the UDID of the connected iPhone"

# Expo's downloaded precompiled module binaries do not match the core they pair
# with; build every Expo module from source.
export EXPO_USE_PRECOMPILED_MODULES=0

# Homebrew's node@22 is keg-only, so it is not on PATH by default.
if ! command -v node >/dev/null 2>&1 && [ -x /opt/homebrew/opt/node@22/bin/node ]; then
  export PATH="/opt/homebrew/opt/node@22/bin:$PATH"
fi

for tool in git node corepack pod xcodebuild xcrun cargo rustup; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
done

node_major="$(node -p 'process.versions.node.split(".")[0]')"
[ "$node_major" = "22" ] || echo "mac-install: warning: expected Node 22, found $(node --version)" >&2

echo "==> pulling main"
git checkout main
git pull --ff-only origin main

echo "==> pnpm install"
corepack enable
pnpm install --frozen-lockfile

echo "==> rust core (XCFramework and bindings)"
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
cargo test --manifest-path core/Cargo.toml --locked
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

echo "==> building Release for device $DEVICE"
# Build with xcodebuild and install with devicectl: neither needs the Simulator app.
xcodebuild \
  -workspace ios/GhostWallet.xcworkspace \
  -scheme GhostWallet \
  -configuration Release \
  -destination "id=$DEVICE" \
  -derivedDataPath ios/build \
  -allowProvisioningUpdates \
  build

commit="$(git rev-parse --short HEAD)"
version="$(node -p 'require("./app.json").expo.version')"
bundle_id="$(node -p 'require("./app.json").expo.ios.bundleIdentifier')"

echo "==> installing on device $DEVICE"
xcrun devicectl device install app --device "$DEVICE" ios/build/Build/Products/Release-iphoneos/GhostWallet.app

echo "==> launching $bundle_id"
xcrun devicectl device process launch --device "$DEVICE" "$bundle_id"

echo
echo "Installed Ghost Wallet (Release)"
echo "  bundle id: $bundle_id"
echo "  version:   $version"
echo "  commit:    $commit"
echo "  device:    $DEVICE"
