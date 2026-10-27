#!/usr/bin/env bash
# Build a debug dev-client of Ghost Wallet and install it on a connected iPhone.
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

echo "==> expo prebuild (ios)"
pnpm exec expo prebuild --platform ios --clean

echo "==> building debug dev-client for device $DEVICE"
# Build with xcodebuild and install with devicectl: neither needs the Simulator app.
xcodebuild \
  -workspace ios/GhostWallet.xcworkspace \
  -scheme GhostWallet \
  -configuration Debug \
  -destination "id=$DEVICE" \
  -derivedDataPath ios/build \
  -allowProvisioningUpdates \
  build

echo "==> installing on device $DEVICE"
xcrun devicectl device install app --device "$DEVICE" ios/build/Build/Products/Debug-iphoneos/GhostWallet.app

commit="$(git rev-parse --short HEAD)"
version="$(node -p 'require("./app.json").expo.version')"
bundle_id="$(node -p 'require("./app.json").expo.ios.bundleIdentifier')"

echo
echo "Installed Ghost Wallet (debug dev-client)"
echo "  bundle id: $bundle_id"
echo "  version:   $version"
echo "  commit:    $commit"
echo "  device:    $DEVICE"
echo
echo "Start the JS server with: pnpm exec expo start --dev-client"
