#!/usr/bin/env bash
# Copy the bench screen's results off a connected iPhone and print them as a table.
#
# Runs on the Mac Studio (macOS, Xcode, Node 22), with the dev-client installed.
#
#   GHOST_WALLET_DEVICE=<iphone-udid> bash scripts/pull-results.sh [destination.json]
#
# Find the UDID with `xcrun devicectl list devices`. The copy is kept at the
# destination (default: a new file under $TMPDIR) and its path is printed.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
  echo "pull-results: $*" >&2
  exit 1
}

[ "$(uname -s)" = "Darwin" ] || fail "this script runs on macOS only"

DEVICE="${GHOST_WALLET_DEVICE:-}"
[ -n "$DEVICE" ] || fail "set GHOST_WALLET_DEVICE to the UDID of the connected iPhone"

for tool in node xcrun; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
done

bundle_id="$(node -p 'require("./app.json").expo.ios.bundleIdentifier')"
destination="${1:-${TMPDIR:-/tmp}/bench-results-$(date +%Y%m%d-%H%M%S).json}"

echo "==> copying Documents/bench-results.json of $bundle_id from $DEVICE" >&2
xcrun devicectl device copy from \
  --device "$DEVICE" \
  --domain-type appDataContainer \
  --domain-identifier "$bundle_id" \
  --source Documents/bench-results.json \
  --destination "$destination" >&2

echo "==> saved to $destination" >&2
echo >&2
node scripts/format-results.js < "$destination"
