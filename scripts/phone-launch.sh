#!/usr/bin/env bash
# Launch the Ghost Wallet installed on the connected iPhone at the bench
# screen, set up for one benchmark, and say which benchmark to tap.
#
#   GHOST_WALLET_DEVICE=<udid> bash scripts/phone-launch.sh <bench>
#
# Runs on the Mac Studio after scripts/mac-install.sh has installed the app.
# <bench> is one of dummy, summon, kill-recovery, header-sync, restore or
# worst-case. For the node benchmarks (header-sync, restore, worst-case) the
# local test chain of scripts/test-chain.sh must be running: the phone reaches
# it on this Mac's LAN address (GHOST_WALLET_LAN_IP, else en0's or en1's) on
# port 8547, and each checks headers from a checkpoint as in
# scripts/sim-test.sh: header-sync and restore 1,000 blocks below the tip,
# worst-case at height 8000. Restore looks up each account's current state at
# the checked tip, so the checkpoint is not where it starts looking.
#
# The test-only overrides of TestChainConfig.swift are passed as launch
# arguments ("-key value"), which iOS puts in UserDefaults' argument domain
# for that launch only: nothing is written to the phone. The background wait
# keeps its compiled 180 seconds, so header-sync's resume stage can be tried
# by sending the app to the home screen and reopening it.
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
# As in scripts/sim-test.sh.
HEADER_SYNC_WINDOW=1000
WORST_CASE_CHECKPOINT=8000
# Past height 8449, the second RandomX key, for worst-case.
TEST_CHAIN_HEIGHT=8600

args=()
case "$BENCH" in
  header-sync | restore | worst-case)
    lan_ip="${GHOST_WALLET_LAN_IP:-}"
    if [ -z "$lan_ip" ]; then
      lan_ip="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)"
    fi
    [ -n "$lan_ip" ] || fail "no LAN address found on en0 or en1; set GHOST_WALLET_LAN_IP"

    echo "==> test chain"
    bash scripts/test-chain.sh wait "$TEST_CHAIN_HEIGHT"
    genesis_rlp="$(bash scripts/test-chain.sh genesis)"
    [ -n "$genesis_rlp" ] || fail "the test chain returned no block 0"

    case "$BENCH" in
      header-sync | restore)
        tip="$(bash scripts/test-chain.sh height)"
        checkpoint_height=$((tip - HEADER_SYNC_WINDOW))
        ;;
      worst-case) checkpoint_height="$WORST_CASE_CHECKPOINT" ;;
    esac
    checkpoint="$(bash scripts/test-chain.sh checkpoint "$checkpoint_height")"
    [ -n "$checkpoint" ] || fail "test-chain.sh printed no checkpoint at $checkpoint_height"

    args+=(
      -benchNodeUrl "http://$lan_ip:$TEST_CHAIN_PORT"
      -benchTestChain.blockTime 1
      -benchTestChain.futureDrift 3600
      -benchTestChain.genesisRlpHex "$genesis_rlp"
      -benchTestChain.restoreAccountsExpected 3
      -benchTestChain.checkpoint "$checkpoint"
    )
    echo "    node http://$lan_ip:$TEST_CHAIN_PORT, checkpoint at height $checkpoint_height"
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
