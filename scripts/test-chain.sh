#!/usr/bin/env bash
# A local Ghost test chain for the node benchmarks (header-sync, restore and
# worst-case): ghost-node's internal-net genesis (chain 6777971, difficulty 1,
# 1-second blocks), mined by one archive node on the Mac Studio.
#
#   bash scripts/test-chain.sh start           # build, init, mine, fund the test wallet
#   bash scripts/test-chain.sh wait <height>   # block until the chain reaches <height>
#   bash scripts/test-chain.sh stop            # stop the node
#   bash scripts/test-chain.sh genesis         # print the block 0 RLP as hex
#
# Runs on macOS only (Go 1.26+, git, make, curl and rustup installed; the Rust
# toolchain is the one pinned in ghost-node's rust-toolchain.toml). The node
# answers JSON-RPC on port 8547 on every interface, so a phone on the LAN can
# reach it; port 8545 is left to the node forwarded from the VM.
#
# Everything lives under GHOST_TESTCHAIN_HOME (default ~/.ghost-wallet-testchain):
# the ghost-node checkout, the chain data, the node's log and its pid. The
# miner key is the internal net's public test key, not a secret.
set -euo pipefail

HOME_DIR="${GHOST_TESTCHAIN_HOME:-$HOME/.ghost-wallet-testchain}"
NODE_REPO="${GHOST_NODE_REPO:-https://github.com/ghostcoin-core/ghost-node.git}"
NODE_COMMIT="${GHOST_NODE_COMMIT:-9d46dfcba9149260db8a40116d0309d647d90439}"
PORT=8547
CHAIN_ID=6777971

SRC="$HOME_DIR/ghost-node"
GETH="$SRC/build/bin/geth"
DATA="$HOME_DIR/node"
PID_FILE="$HOME_DIR/geth.pid"
LOG="$HOME_DIR/geth.log"
RPC="http://127.0.0.1:$PORT"

# Accounts 0, 3 and 7 of the app's counting-bytes test words. Each gets
# 1 GHOST once, so the restore benchmark has three accounts to find.
FUND_ACCOUNTS=(
  0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd
  0xacf1b03442244bc14982f1aae0a11d76e1850e09
  0xa8c6efceaca7b3265182bbd1d516aa0568e15314
)
ONE_GHOST=0xde0b6b3a7640000

fail() {
  echo "test-chain: $*" >&2
  exit 1
}

say() {
  echo "test-chain: $*" >&2
}

usage() {
  echo "usage: bash scripts/test-chain.sh start | wait <height> | stop | genesis" >&2
  exit 2
}

# rpc METHOD PARAMS: the JSON-RPC response from the local node.
rpc() {
  curl -sS --max-time 10 -H 'Content-Type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$RPC"
}

# result METHOD PARAMS: the string result, or nothing (and the error on stderr).
result() {
  local response pattern='"result":"([^"]*)"'
  response="$(rpc "$1" "$2" 2>/dev/null)" || return 1
  if [[ "$response" =~ $pattern ]]; then
    echo "${BASH_REMATCH[1]}"
  else
    say "$1 failed: $response"
    return 1
  fi
}

height() {
  local hex
  hex="$(result eth_blockNumber '[]')" || return 1
  echo $((hex))
}

running() {
  [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

wait_for_rpc() {
  local tries=0
  until height >/dev/null 2>&1; do
    running || fail "the node exited; see $LOG"
    tries=$((tries + 1))
    [ "$tries" -lt 120 ] || fail "the node did not answer on $RPC; see $LOG"
    sleep 1
  done
}

check_tools() {
  [ "$(uname -s)" = "Darwin" ] || fail "this script runs on macOS only"
  for tool in git go make curl rustup; do
    command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
  done
  local version major minor
  version="$(go env GOVERSION)"
  version="${version#go}"
  major="${version%%.*}"
  minor="${version#*.}"
  minor="${minor%%.*}"
  if [ "$major" -lt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -lt 26 ]; }; then
    fail "Go 1.26 or newer is needed, found go$version"
  fi
}

build_node() {
  mkdir -p "$HOME_DIR"
  if [ ! -d "$SRC/.git" ]; then
    say "cloning ghost-node"
    git clone --quiet "$NODE_REPO" "$SRC"
  fi
  if [ "$(git -C "$SRC" rev-parse HEAD)" != "$NODE_COMMIT" ]; then
    say "checking out ghost-node $NODE_COMMIT"
    git -C "$SRC" fetch --quiet origin
    git -C "$SRC" checkout --quiet --detach "$NODE_COMMIT"
  fi
  if [ -x "$GETH" ] && [ "$(cat "$SRC/build/.test-chain-commit" 2>/dev/null)" = "$NODE_COMMIT" ]; then
    return
  fi
  say "building geth (make geth)"
  make -C "$SRC" geth
  echo "$NODE_COMMIT" >"$SRC/build/.test-chain-commit"
}

# The genesis of ghost-node's scripts/internal-net.sh at the pinned commit.
# The EIP 2565 fork key is spelt out by arithmetic in the heredoc.
write_genesis() {
  cat >"$HOME_DIR/genesis.json" <<EOF
{
  "config": {
    "networkId": $CHAIN_ID,
    "chainId": $CHAIN_ID,
    "eip2FBlock": 0, "eip7FBlock": 0, "eip150Block": 0, "eip155Block": 0,
    "eip160Block": 0, "eip161FBlock": 0, "eip170FBlock": 0, "eip100FBlock": 0,
    "eip140FBlock": 0, "eip198FBlock": 0, "eip211FBlock": 0, "eip212FBlock": 0,
    "eip213FBlock": 0, "eip214FBlock": 0, "eip658FBlock": 0, "eip145FBlock": 0,
    "eip1014FBlock": 0, "eip1052FBlock": 0, "eip1283FBlock": 0, "petersburgBlock": 0,
    "eip152FBlock": 0, "eip1108FBlock": 0, "eip1344FBlock": 0, "eip1884FBlock": 0,
    "eip2028FBlock": 0, "eip2200FBlock": 0, "eip$((2500 + 65))FBlock": 0, "eip2718FBlock": 0,
    "eip2929FBlock": 0, "eip2930FBlock": 0, "eip1559FBlock": 0, "eip3198FBlock": 0,
    "eip3529FBlock": 0, "eip3541FBlock": 0, "eip3651FBlock": 0, "eip3855FBlock": 0,
    "eip3860FBlock": 0, "eip6049FBlock": 0, "eip1153FBlock": 0, "eip5656FBlock": 0,
    "eip6780FBlock": 0, "disposalBlock": 0,
    "ethash": {}
  },
  "timestamp": "0x6abda280",
  "gasLimit": "0x1c9c380",
  "difficulty": "0x1",
  "baseFeePerGas": "0x3b9aca00",
  "alloc": {}
}
EOF
}

init_chain() {
  # The internal net's public test miner key and keystore password.
  printf '%064x' "$CHAIN_ID" >"$HOME_DIR/miner.key"
  printf 'internal-net-test-only' >"$HOME_DIR/password"
  chmod 600 "$HOME_DIR/miner.key" "$HOME_DIR/password"
  if [ ! -d "$DATA/geth/chaindata" ]; then
    say "initialising the internal-net genesis in $DATA"
    write_genesis
    "$GETH" --datadir "$DATA" --state.scheme hash init "$HOME_DIR/genesis.json" >>"$LOG" 2>&1 ||
      fail "geth init failed; see $LOG"
  fi
  if [ -z "$(miner_address)" ]; then
    "$GETH" --datadir "$DATA" --lightkdf account import \
      --password "$HOME_DIR/password" "$HOME_DIR/miner.key" >>"$LOG" 2>&1 ||
      fail "importing the miner key failed; see $LOG"
  fi
  [ -n "$(miner_address)" ] || fail "no miner account in $DATA"
}

miner_address() {
  local line pattern='[{]([0-9a-fA-F]{40})[}]'
  line="$("$GETH" --datadir "$DATA" account list 2>/dev/null | head -n 1)"
  if [[ "$line" =~ $pattern ]]; then
    echo "0x${BASH_REMATCH[1]}"
  fi
}

start_node() {
  local miner="$1"
  say "starting the node on port $PORT (log: $LOG)"
  nohup "$GETH" \
    --datadir "$DATA" \
    --networkid "$CHAIN_ID" \
    --syncmode full \
    --gcmode archive \
    --state.scheme hash \
    --port 0 \
    --authrpc.port 0 \
    --nat none \
    --nodiscover \
    --mine \
    --miner.threads 1 \
    --miner.etherbase "$miner" \
    --unlock "$miner" \
    --password "$HOME_DIR/password" \
    --allow-insecure-unlock \
    --http \
    --http.addr 0.0.0.0 \
    --http.port "$PORT" \
    --http.vhosts '*' \
    --http.api eth,net,web3,debug \
    --verbosity 3 \
    >>"$LOG" 2>&1 &
  echo $! >"$PID_FILE"
}

# Sends 1 GHOST from the miner to each test account, once per chain.
fund_accounts() {
  local miner="$1" marker="$DATA/test-wallet-funded"
  [ -f "$marker" ] && return
  say "waiting for the miner's first rewards"
  wait_height 5
  local account tx hashes=()
  for account in "${FUND_ACCOUNTS[@]}"; do
    tx="$(result eth_sendTransaction \
      "[{\"from\":\"$miner\",\"to\":\"$account\",\"value\":\"$ONE_GHOST\"}]")" ||
      fail "funding $account failed"
    say "sent 1 GHOST to $account ($tx)"
    hashes+=("$tx")
  done
  for tx in "${hashes[@]}"; do
    until rpc eth_getTransactionReceipt "[\"$tx\"]" 2>/dev/null | grep -q '"blockNumber"'; do
      running || fail "the node exited; see $LOG"
      sleep 1
    done
  done
  touch "$marker"
  say "test wallet funded (accounts 0, 3 and 7)"
}

wait_height() {
  local target="$1" now last_report=0
  while true; do
    now="$(height 2>/dev/null)" || now=0
    [ "$now" -ge "$target" ] && return
    running || fail "the node is not running; run: bash scripts/test-chain.sh start"
    if [ $((SECONDS - last_report)) -ge 60 ]; then
      say "height $now of $target"
      last_report=$SECONDS
    fi
    sleep 5
  done
}

cmd_start() {
  check_tools
  build_node
  init_chain
  local miner
  miner="$(miner_address)"
  if running; then
    say "the node is already running (pid $(cat "$PID_FILE"))"
  else
    start_node "$miner"
  fi
  wait_for_rpc
  fund_accounts "$miner"
  say "running at height $(height) on $RPC"
}

cmd_wait() {
  [ "$#" -eq 1 ] && [[ "$1" =~ ^[0-9]+$ ]] || usage
  running || fail "the node is not running; run: bash scripts/test-chain.sh start"
  wait_height "$1"
  say "height $(height) reached"
}

cmd_stop() {
  if ! running; then
    say "the node is not running"
    rm -f "$PID_FILE"
    return
  fi
  local pid tries=0
  pid="$(cat "$PID_FILE")"
  kill "$pid"
  while kill -0 "$pid" 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -lt 60 ] || fail "the node (pid $pid) did not stop"
    sleep 1
  done
  rm -f "$PID_FILE"
  say "stopped"
}

cmd_genesis() {
  running || fail "the node is not running; run: bash scripts/test-chain.sh start"
  local rlp
  rlp="$(result debug_getRawHeader '["0x0"]')" || fail "the node did not return block 0"
  [ -n "$rlp" ] || fail "the node returned an empty block 0"
  echo "$rlp"
}

[ "$#" -ge 1 ] || usage
command="$1"
shift
case "$command" in
  start) cmd_start ;;
  wait) cmd_wait "$@" ;;
  stop) cmd_stop ;;
  genesis) cmd_genesis ;;
  *) usage ;;
esac
