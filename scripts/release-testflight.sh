#!/usr/bin/env bash
# Archive, sign and upload a store build of Ghost Wallet to TestFlight.
#
# Runs on the Mac Studio (macOS, Xcode signed in to the team, CocoaPods,
# Node 22, rustup), from a clean checkout of the commit to release.
#
#   bash scripts/release-testflight.sh --dry-run
#   GHOST_ASC_KEY_PATH=<path to the .p8 key> GHOST_ASC_KEY_ID=<key id> \
#     GHOST_ASC_ISSUER_ID=<issuer id> bash scripts/release-testflight.sh
#
# --dry-run archives and exports a signed .ipa into ios/build/release/export
# without uploading it, and needs no App Store Connect key. A real run uploads
# the build with the App Store Connect API key named by GHOST_ASC_KEY_PATH,
# GHOST_ASC_KEY_ID and GHOST_ASC_ISSUER_ID. Keep the key outside the
# repository; the script never prints those values.
#
# The build number is GHOST_BUILD_NUMBER when set (a positive whole number),
# otherwise the number of commits on the current branch. See docs/release.md.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
  echo "release-testflight: $*" >&2
  exit 1
}

warn() {
  echo "release-testflight: warning: $*" >&2
}

usage() {
  echo "usage: bash scripts/release-testflight.sh [--dry-run]" >&2
  exit 2
}

dry_run=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=true ;;
    -h | --help) usage ;;
    *)
      echo "release-testflight: unknown argument: $arg" >&2
      usage
      ;;
  esac
done

# Homebrew's node@22 is keg-only, so it is not on PATH by default.
if ! command -v node >/dev/null 2>&1 && [ -x /opt/homebrew/opt/node@22/bin/node ]; then
  export PATH="/opt/homebrew/opt/node@22/bin:$PATH"
fi

for tool in git node; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
done

# Everything is checked before anything is built, so a refusal changes nothing.

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "not inside a git checkout"
if [ -n "$(git status --porcelain)" ]; then
  git status --short >&2
  fail "the working tree has uncommitted changes; commit or stash them first, so the build matches a commit"
fi

build_number="${GHOST_BUILD_NUMBER:-}"
if [ -n "$build_number" ]; then
  [[ "$build_number" =~ ^[1-9][0-9]*$ ]] ||
    fail "GHOST_BUILD_NUMBER must be a positive whole number, got \"$build_number\""
else
  build_number="$(git rev-list --count HEAD)"
  branch="$(git rev-parse --abbrev-ref HEAD)"
  if [ "$branch" != "main" ]; then
    warn "on branch $branch, not main: the commit count only goes up on main"
  fi
fi

if [ "$dry_run" = false ]; then
  for name in GHOST_ASC_KEY_PATH GHOST_ASC_KEY_ID GHOST_ASC_ISSUER_ID; do
    [ -n "${!name:-}" ] || fail "$name is not set; it is needed to upload (use --dry-run to build without uploading)"
  done
  [ -f "$GHOST_ASC_KEY_PATH" ] || fail "the App Store Connect key file named by GHOST_ASC_KEY_PATH does not exist"
fi

for tool in corepack cargo rustup pod xcodebuild; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
done

node_major="$(node -p 'process.versions.node.split(".")[0]')"
[ "$node_major" = "22" ] || warn "expected Node 22, found $(node --version)"

version="$(node -p 'require("./package.json").version')"
team_id="$(node -p 'require("./app.json").expo.ios.appleTeamId')"
bundle_id="$(node -p 'require("./app.json").expo.ios.bundleIdentifier')"
commit="$(git rev-parse --short HEAD)"

# app.config.js configures the store build and reads the build number from
# here; the JavaScript bundle built during the archive reads the same build flag.
export EXPO_PUBLIC_GHOST_BUILD=release
export GHOST_BUILD_NUMBER="$build_number"
# Expo's downloaded precompiled module binaries do not match the core they pair
# with; build every Expo module from source.
export EXPO_USE_PRECOMPILED_MODULES=0

if [ "$dry_run" = true ]; then
  mode="dry run (archive and export, no upload)"
else
  mode="upload to App Store Connect"
fi
echo "==> Ghost Wallet version $version build $build_number (commit $commit): $mode"

echo "==> pnpm install"
corepack enable
command -v pnpm >/dev/null 2>&1 || fail "pnpm is not installed"
pnpm install --frozen-lockfile

echo "==> rust core (XCFramework and bindings)"
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
(cd modules/ghost-core && ../../node_modules/.bin/ubrn build ios --config ubrn.config.yaml --and-generate --release)

echo "==> swift bindings of the rust core"
# uniffi-bindgen reads `cargo metadata`, so it runs from core/. The bindings
# are compiled into the GhostBench pod, which turns on GHOST_CORE_BINDINGS.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
generated="$PWD/modules/ghost-bench/ios/Generated"
bindings_out="$work/bindings"
mkdir -p "$bindings_out"
(cd core && cargo run --release --manifest-path ../tools/uniffi-bindgen/Cargo.toml -- \
  generate --library target/aarch64-apple-ios-sim/release/libghost_wallet_core.a \
  --language swift --out-dir "$bindings_out")
rm -rf "$generated"
mkdir -p "$generated"
cp "$bindings_out/ghost_wallet_core.swift" "$bindings_out/ghost_wallet_coreFFI.h" "$generated/"

echo "==> expo prebuild (ios, release configuration)"
pnpm exec expo prebuild --platform ios --clean --no-install

echo "==> pod install"
(cd ios && pod install)

# Inside ios/build, which is git-ignored.
out="ios/build/release"
archive="$out/GhostWallet.xcarchive"
export_dir="$out/export"
rm -rf "$archive" "$export_dir"
mkdir -p "$out"

# The key flags are only passed on a real run. Their values go to xcodebuild's
# arguments and are never echoed.
auth=()
if [ "$dry_run" = false ]; then
  auth=(
    -authenticationKeyPath "$GHOST_ASC_KEY_PATH"
    -authenticationKeyID "$GHOST_ASC_KEY_ID"
    -authenticationKeyIssuerID "$GHOST_ASC_ISSUER_ID"
  )
fi

echo "==> archiving (Release)"
xcodebuild \
  -workspace ios/GhostWallet.xcworkspace \
  -scheme GhostWallet \
  -configuration Release \
  -destination "generic/platform=iOS" \
  -derivedDataPath ios/build \
  -archivePath "$archive" \
  -allowProvisioningUpdates \
  ${auth[@]+"${auth[@]}"} \
  archive

if [ "$dry_run" = true ]; then
  destination=export
else
  destination=upload
fi

export_options="$work/ExportOptions.plist"
cat >"$export_options" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>method</key>
  <string>app-store-connect</string>
  <key>destination</key>
  <string>$destination</string>
  <key>teamID</key>
  <string>$team_id</string>
  <key>distributionBundleIdentifier</key>
  <string>$bundle_id</string>
  <key>signingStyle</key>
  <string>automatic</string>
  <key>manageAppVersionAndBuildNumber</key>
  <false/>
  <key>uploadSymbols</key>
  <true/>
</dict>
</plist>
PLIST

if [ "$dry_run" = true ]; then
  echo "==> exporting a signed .ipa (no upload)"
else
  echo "==> exporting and uploading to App Store Connect"
fi
xcodebuild \
  -exportArchive \
  -archivePath "$archive" \
  -exportPath "$export_dir" \
  -exportOptionsPlist "$export_options" \
  -allowProvisioningUpdates \
  ${auth[@]+"${auth[@]}"}

echo
if [ "$dry_run" = true ]; then
  ipa="$(find "$export_dir" -maxdepth 1 -name '*.ipa' -print -quit 2>/dev/null || true)"
  [ -n "$ipa" ] || fail "the export left no .ipa in $export_dir"
  echo "Exported Ghost Wallet (dry run, not uploaded)"
  echo "  ipa:       $ipa"
else
  echo "Uploaded Ghost Wallet to App Store Connect"
fi
echo "  bundle id: $bundle_id"
echo "  version:   $version"
echo "  build:     $build_number"
echo "  commit:    $commit"
