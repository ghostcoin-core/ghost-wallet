#!/usr/bin/env bash
# Launch the Ghost Wallet installed on the connected iPhone at the bench
# screen, set up for one benchmark, and say which benchmark to tap.
#
#   GHOST_WALLET_DEVICE=<udid> bash scripts/phone-launch.sh <bench>
#
# Runs on the Mac Studio after scripts/mac-install.sh has installed the app.
# <bench> is one of dummy, summon, kill-recovery, header-sync, restore or
# worst-case. For the node benchmarks (header-sync, restore, worst-case,
# kill-recovery) the local test chain of scripts/test-chain.sh must be
# running: the phone reaches it on this Mac's LAN address (GHOST_WALLET_LAN_IP,
# else en0's or en1's) on port 8547. No header window or checkpoint is needed:
# header-sync and worst-case spot check the node's tip header once, restore
# looks up each account's current state at the node's tip, and kill-recovery
# sends test GHOST from account 0 of the test words to account 3.
#
# The test-only overrides of TestChainConfig.swift are passed as launch
# arguments ("-key value"), which iOS puts in UserDefaults' argument domain
# for that launch only: nothing is written to the phone. kill-recovery keeps
# the node URL of its last run in its own state file, so a payment killed
# mid-send is still recovered when the app is next opened from its icon.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
  echo "phone-launch: $*" >&2
  exit 1
}

usage() {
  echo "usage: GHOST_WALLET_DEVICE=<udid> bash scripts/phone-launch.sh" \
    "dummy | summon | kill-recovery | header-sync | restore | worst-case" >&2
  exit 2
}

[ "$#" -eq 1 ] || usage
BENCH="$1"
case "$BENCH" in
  dummy | summon | kill-recovery | header-sync | restore | worst-case) ;;
  *) usage ;;
esac

[ "$(uname -s)" = "Darwin" ] || fail "this script runs on macOS only"
DEVICE="${GHOST_WALLET_DEVICE:-}"
[ -n "$DEVICE" ] || fail "set GHOST_WALLET_DEVICE to the UDID of the connected iPhone"
command -v xcrun >/dev/null 2>&1 || fail "xcrun is not installed"

APP_ID=com.ghostcoin.wallet
TEST_CHAIN_PORT=8547
# As in scripts/sim-test.sh: past the test accounts' funding near block 5.
TEST_CHAIN_HEIGHT=100

args=()
case "$BENCH" in
  header-sync | restore | worst-case | kill-recovery)
    lan_ip="${GHOST_WALLET_LAN_IP:-}"
    if [ -z "$lan_ip" ]; then
      lan_ip="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)"
    fi
    [ -n "$lan_ip" ] || fail "no LAN address found on en0 or en1; set GHOST_WALLET_LAN_IP"

    echo "==> test chain"
    bash scripts/test-chain.sh wait "$TEST_CHAIN_HEIGHT"

    args+=(
      -benchNodeUrl "http://$lan_ip:$TEST_CHAIN_PORT"
      -benchTestChain.restoreAccountsExpected 3
    )
    echo "    node http://$lan_ip:$TEST_CHAIN_PORT"
    ;;
esac

echo "==> launching $APP_ID on $DEVICE at the bench screen"
launch=(xcrun devicectl device process launch --device "$DEVICE" --terminate-existing
  --payload-url ghostwallet://bench "$APP_ID")
if [ "${#args[@]}" -gt 0 ]; then
  launch+=(-- "${args[@]}")
fi
"${launch[@]}"

echo
echo "On the phone, tap \"$BENCH\" on the bench screen, then Run."
echo "Keep the app in front until the result shows; do not lock the phone."
