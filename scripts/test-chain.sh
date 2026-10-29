#!/usr/bin/env bash
# A local Ghost test chain for the node benchmarks (header-sync, restore and
# worst-case): ghost-node's internal-net genesis (chain 6777971, difficulty 1,
# 1-second blocks), mined by one archive node on the Mac Studio.
#
#   bash scripts/test-chain.sh start           # build, init, mine, fund the test wallet
#   bash scripts/test-chain.sh wait <height>   # block until the chain reaches <height>
#   bash scripts/test-chain.sh stop            # stop the node
#   bash scripts/test-chain.sh genesis         # print the block 0 RLP as hex
#   bash scripts/test-chain.sh height          # print the node's tip height
#   bash scripts/test-chain.sh checkpoint <h>  # print the checkpoint JSON for block <h>
#   bash scripts/test-chain.sh fund-late <h>   # at height <h>, fund the test accounts again
#   bash scripts/test-chain.sh faucet          # serve test GHOST to the app on port 8548
#
# `checkpoint` prints the JSON the benchmarks take in the test-only override
# benchTestChain.checkpoint: the header RLP of block <h> (the 19 fields in the
# order of HeaderSyncBenchmark.swift), the total work up to and including it
# (every header's difficulty summed from block 0), the genesis timestamp, and
# the key blocks at or below <h> that the headers from <h>+1 to the tip use
# (Ghost's seed_height, EPOCH_BLOCKS 8192 and EPOCH_LAG 256). Key blocks above
# <h> are not pinned: the header sync checks them itself. It needs Node.
#
# `fund-late` sends 1 GHOST to accounts 0, 3 and 7 again, every time it runs,
# once the chain reaches <h>, and prints the lowest block holding them: recent
# activity on the test accounts, on top of the first funding near block 0.
#
# `faucet` serves the app's "Get test GHOST" on port 8548 on every interface,
# in the foreground: POST {"address": "0x…"} to /faucet and the miner sends
# 10 test GHOST there, at most once a minute per address. The miner key is
# the public test key below, so the faucet gives away nothing of value. It
# needs Node.
#
# Runs on macOS only (Go 1.26+, git, make, curl and rustup installed; the Rust
# toolchain is the one pinned in ghost-node's rust-toolchain.toml). The node
# answers JSON-RPC on port 8547 on every interface, so a phone on the LAN can
# reach it; port 8545 is left to the node forwarded from the VM. That HTTP
# endpoint serves only the eth, net and web3 namespaces: the debug namespace
# (which can write files on this Mac) is reached only through the node's local
# IPC socket.
#
# Everything lives under GHOST_TESTCHAIN_HOME (default ~/.ghost-wallet-testchain):
# the ghost-node checkout, the chain data, the node's log and its pid. The
# miner key is the internal net's public test key, not a secret.
set -euo pipefail

HOME_DIR="${GHOST_TESTCHAIN_HOME:-$HOME/.ghost-wallet-testchain}"
NODE_REPO="${GHOST_NODE_REPO:-https://github.com/ghostcoin-core/ghost-node.git}"
NODE_COMMIT="${GHOST_NODE_COMMIT:-9d46dfcba9149260db8a40116d0309d647d90439}"
PORT=8547
FAUCET_PORT=8548
CHAIN_ID=6777971

SRC="$HOME_DIR/ghost-node"
GETH="$SRC/build/bin/geth"
DATA="$HOME_DIR/node"
PID_FILE="$HOME_DIR/geth.pid"
LOG="$HOME_DIR/geth.log"
RPC="http://127.0.0.1:$PORT"
IPC="$DATA/geth.ipc"

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
  echo "usage: bash scripts/test-chain.sh start | wait <height> | stop | genesis | height" \
    "| checkpoint <height> | fund-late <height> | faucet" >&2
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
    --ipcpath "$IPC" \
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
    --http.api eth,net,web3 \
    --verbosity 3 \
    >>"$LOG" 2>&1 &
  echo $! >"$PID_FILE"
}

# Sends 1 GHOST from the miner to each test account and waits until every
# transfer is in a block. Prints the lowest of those blocks' heights.
send_to_test_accounts() {
  local miner="$1" account tx response hashes=() lowest="" block
  local pattern='"blockNumber":"(0x[0-9a-fA-F]+)"'
  for account in "${FUND_ACCOUNTS[@]}"; do
    tx="$(result eth_sendTransaction \
      "[{\"from\":\"$miner\",\"to\":\"$account\",\"value\":\"$ONE_GHOST\"}]")" ||
      fail "funding $account failed"
    say "sent 1 GHOST to $account ($tx)"
    hashes+=("$tx")
  done
  for tx in "${hashes[@]}"; do
    while true; do
      response="$(rpc eth_getTransactionReceipt "[\"$tx\"]" 2>/dev/null)" || response=""
      [[ "$response" =~ $pattern ]] && break
      running || fail "the node exited; see $LOG"
      sleep 1
    done
    block=$((${BASH_REMATCH[1]}))
    if [ -z "$lowest" ] || [ "$block" -lt "$lowest" ]; then
      lowest="$block"
    fi
  done
  echo "$lowest"
}

# Sends 1 GHOST from the miner to each test account, once per chain.
fund_accounts() {
  local miner="$1" marker="$DATA/test-wallet-funded"
  [ -f "$marker" ] && return
  say "waiting for the miner's first rewards"
  wait_height 5
  send_to_test_accounts "$miner" >/dev/null
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
  [ -S "$IPC" ] || fail "no IPC socket at $IPC"
  # Through the local IPC socket: the debug namespace is not served over HTTP.
  local output rlp pattern='"(0x[0-9a-fA-F]+)"'
  output="$("$GETH" attach --exec 'debug.getRawHeader("0x0")' "$IPC" 2>&1)" ||
    fail "the node did not return block 0: $output"
  [[ "$output" =~ $pattern ]] || fail "the node returned no block 0: $output"
  rlp="${BASH_REMATCH[1]}"
  echo "$rlp"
}

cmd_height() {
  running || fail "the node is not running; run: bash scripts/test-chain.sh start"
  height || fail "the node did not report its height"
}

cmd_checkpoint() {
  [ "$#" -eq 1 ] && [[ "$1" =~ ^[0-9]+$ ]] || usage
  running || fail "the node is not running; run: bash scripts/test-chain.sh start"
  command -v node >/dev/null 2>&1 || fail "node is not installed"
  local tip
  tip="$(height)" || fail "the node did not report its height"
  [ "$1" -ge 1 ] && [ "$1" -lt "$tip" ] || fail "the checkpoint must be between 1 and the tip ($tip), exclusive"
  node -e "$(checkpoint_js)" checkpoint-main "$RPC" "$1" "$tip"
}

cmd_fund_late() {
  [ "$#" -eq 1 ] && [[ "$1" =~ ^[0-9]+$ ]] || usage
  running || fail "the node is not running; run: bash scripts/test-chain.sh start"
  local miner lowest
  miner="$(miner_address)"
  [ -n "$miner" ] || fail "no miner account in $DATA"
  wait_height "$1"
  lowest="$(send_to_test_accounts "$miner")"
  say "test wallet funded again from block $lowest (accounts 0, 3 and 7)"
  echo "$lowest"
}

# The checkpoint builder of `checkpoint`, in Node. __tests__/checkpoint.test.ts
# loads this same text and tests its encoding and key-block selection.
checkpoint_js() {
  cat <<'JS'
'use strict';

// Ghost's key block schedule (client/src/seal.rs).
const EPOCH_BLOCKS = 8192;
const EPOCH_LAG = 256;

// The 19 header fields in the order of HeaderSyncBenchmark.swift (spec 05,
// section 10): the node's JSON name, its kind and its size (bytes for fixed
// and bytes, bits for int).
const HEADER_FIELDS = [
  ['parentHash', 'fixed', 32],
  ['sha3Uncles', 'fixed', 32],
  ['miner', 'fixed', 20],
  ['stateRoot', 'fixed', 32],
  ['transactionsRoot', 'fixed', 32],
  ['receiptsRoot', 'fixed', 32],
  ['logsBloom', 'fixed', 256],
  ['difficulty', 'int', 256],
  ['number', 'int', 64],
  ['gasLimit', 'int', 64],
  ['gasUsed', 'int', 64],
  ['timestamp', 'int', 64],
  ['extraData', 'bytes', 32],
  ['mixHash', 'fixed', 32],
  ['nonce', 'fixed', 8],
  ['baseFeePerGas', 'int', 256],
  ['coinTreeRoot', 'fixed', 32],
  ['dataTreeRoot', 'fixed', 32],
  ['dataMarkerRoot', 'fixed', 32],
];

// The height of the key block a header at `height` uses: Ghost's seed_height.
function seedHeight(height) {
  if (height <= EPOCH_BLOCKS + EPOCH_LAG) return 0;
  return Math.floor((height - EPOCH_LAG - 1) / EPOCH_BLOCKS) * EPOCH_BLOCKS;
}

// The key blocks the headers from height + 1 to tip use that are at or below
// the checkpoint, in height order. A higher one is checked by the sync itself
// and cannot be pinned.
function keyBlockHeights(height, tip) {
  const heights = new Set();
  for (let next = height + 1; next <= tip; next++) {
    const seed = seedHeight(next);
    if (seed <= height) heights.add(seed);
  }
  return [...heights].sort((a, b) => a - b);
}

// Bytes of hex, with or without 0x; a quantity may have an odd digit count.
function hexBytes(text, quantity, name) {
  if (typeof text !== 'string') throw new Error(`the header has no ${name}`);
  let digits = text.replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]*$/.test(digits)) throw new Error(`its ${name} is not hex`);
  if (digits.length % 2 === 1) {
    if (!quantity) throw new Error(`its ${name} is not whole bytes`);
    digits = '0' + digits;
  }
  const bytes = [];
  for (let i = 0; i < digits.length; i += 2) bytes.push(parseInt(digits.slice(i, i + 2), 16));
  return bytes;
}

function toHex(bytes) {
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}

function lengthPrefix(length, base) {
  if (length < 56) return [base + length];
  const digits = [];
  for (let rest = length; rest > 0; rest = Math.floor(rest / 256)) digits.unshift(rest % 256);
  return [base + 55 + digits.length, ...digits];
}

// The header's RLP as hex (no 0x): the 19 fields, as HeaderRlp.encode does.
function encodeHeader(block) {
  const payload = [];
  for (const [name, kind, size] of HEADER_FIELDS) {
    let value = hexBytes(block[name], kind === 'int', name);
    if (kind === 'fixed' && value.length !== size) throw new Error(`its ${name} is not ${size} bytes`);
    if (kind === 'bytes' && value.length > size) throw new Error(`its ${name} is longer than ${size} bytes`);
    if (kind === 'int') {
      const first = value.findIndex((b) => b !== 0);
      value = first < 0 ? [] : value.slice(first);
      if (value.length * 8 > size) throw new Error(`its ${name} is out of range`);
    }
    if (value.length === 1 && value[0] < 0x80) payload.push(value[0]);
    else payload.push(...lengthPrefix(value.length, 0x80), ...value);
  }
  return toHex([...lengthPrefix(payload.length, 0xc0), ...payload]);
}

function hash32(block, name) {
  const bytes = hexBytes(block[name], false, name);
  if (bytes.length !== 32) throw new Error(`its ${name} is not 32 bytes`);
  return toHex(bytes);
}

// The checkpoint at `height` for a chain whose tip is `tip`. `getBlocks(from,
// through)` returns the node's blocks (eth_getBlockByNumber JSON) in height
// order. Every block from 0 to `height` is read: each must carry its height
// and link to the one before it, and its difficulty is summed.
async function buildCheckpoint(height, tip, getBlocks) {
  if (!Number.isSafeInteger(height) || !Number.isSafeInteger(tip) || height < 1 || height >= tip) {
    throw new Error('the checkpoint must be between 1 and the tip, exclusive');
  }
  const blocks = await getBlocks(0, height);
  if (blocks.length !== height + 1) throw new Error('the node did not return every block');
  let totalWork = 0n;
  blocks.forEach((block, index) => {
    if (!block) throw new Error(`the node has no block ${index}`);
    if (BigInt(block.number) !== BigInt(index)) throw new Error(`block ${index} carries another height`);
    if (index > 0 && hash32(block, 'parentHash') !== hash32(blocks[index - 1], 'hash')) {
      throw new Error(`block ${index} does not link to block ${index - 1}`);
    }
    totalWork += BigInt(block.difficulty);
  });
  if (totalWork >= 1n << 256n) throw new Error('the total work does not fit in 256 bits');
  return {
    rlpHex: encodeHeader(blocks[height]),
    height,
    totalWorkHex: totalWork.toString(16).padStart(64, '0'),
    genesisTimestamp: Number(BigInt(blocks[0].timestamp)),
    keyBlocks: keyBlockHeights(height, tip).map((key) => ({ height: key, hashHex: hash32(blocks[key], 'hash') })),
  };
}

// Blocks `from` through `through` from a node, in JSON-RPC batches.
async function nodeBlocks(url, from, through) {
  const blocks = [];
  for (let start = from; start <= through; start += 500) {
    const last = Math.min(through, start + 499);
    const calls = [];
    for (let number = start; number <= last; number++) {
      calls.push({ jsonrpc: '2.0', id: number - start, method: 'eth_getBlockByNumber', params: ['0x' + number.toString(16), false] });
    }
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(calls),
    });
    if (!response.ok) throw new Error(`the node answered HTTP ${response.status}`);
    const answers = await response.json();
    if (!Array.isArray(answers)) throw new Error('the node did not answer a JSON-RPC batch');
    const byId = new Map(answers.map((answer) => [answer.id, answer]));
    for (let id = 0; id < calls.length; id++) {
      const answer = byId.get(id);
      if (!answer || answer.error || !answer.result) throw new Error(`the node has no block ${start + id}`);
      blocks.push(answer.result);
    }
  }
  return blocks;
}

if (typeof exports === 'object' && exports !== null) {
  Object.assign(exports, { EPOCH_BLOCKS, EPOCH_LAG, HEADER_FIELDS, seedHeight, keyBlockHeights, encodeHeader, buildCheckpoint });
}

const mainAt = process.argv.indexOf('checkpoint-main');
if (mainAt >= 0) {
  const [url, height, tip] = process.argv.slice(mainAt + 1);
  buildCheckpoint(Number(height), Number(tip), (from, through) => nodeBlocks(url, from, through)).then(
    (checkpoint) => process.stdout.write(JSON.stringify(checkpoint) + '\n'),
    (error) => {
      process.stderr.write(`test-chain: checkpoint failed: ${error.message}\n`);
      process.exit(1);
    },
  );
}
JS
}

cmd_faucet() {
  [ "$#" -eq 0 ] || usage
  running || fail "the node is not running; run: bash scripts/test-chain.sh start"
  command -v node >/dev/null 2>&1 || fail "node is not installed"
  local miner
  miner="$(miner_address)"
  [ -n "$miner" ] || fail "no miner account in $DATA"
  say "sending 10 test GHOST from $miner to each address POSTed to http://0.0.0.0:$FAUCET_PORT/faucet"
  node -e "$(faucet_js)" faucet-main "$RPC" "$miner" "$FAUCET_PORT"
}

# The faucet of `faucet`, in Node: POST {"address": "0x…"} to /faucet and the
# miner (the internal net's public test account, already unlocked in the
# node) sends 10 test GHOST there, at most once a minute per address. It
# answers once the transfer is in a block: {"transactionHash": "0x…"}, or
# {"error": "…"} with 400, 429 or 502. The app never holds the miner's key.
# __tests__/test-network/faucet-endpoint.test.ts loads this same text.
faucet_js() {
  cat <<'FAUCET'
'use strict';

const FAUCET_WEI = 10n * 10n ** 18n;
const ONCE_EVERY_MS = 60000;
const MAX_BODY_BYTES = 1024;

// One JSON-RPC call to the node; the node's error message on a refusal.
function nodeRpc(url) {
  let id = 0;
  return async (method, params) => {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }),
    });
    if (!response.ok) throw new Error(`the node answered HTTP ${response.status}`);
    const answer = await response.json();
    if (answer.error) throw new Error(String(answer.error.message || 'the node refused the call'));
    return answer.result;
  };
}

// The faucet's requests. `rpc(method, params)` asks the node, `now()` is the
// time in ms, `sleep(ms)` waits between receipt checks.
function createFaucet({ from, rpc, now = Date.now, sleep = (ms) => new Promise((done) => setTimeout(done, ms)), receiptTries = 120 }) {
  const lastSent = new Map();

  async function send(to) {
    const hash = await rpc('eth_sendTransaction', [{ from, to, value: '0x' + FAUCET_WEI.toString(16) }]);
    for (let tries = 0; tries < receiptTries; tries++) {
      const receipt = await rpc('eth_getTransactionReceipt', [hash]);
      if (receipt && receipt.blockNumber) {
        if (BigInt(receipt.status) !== 1n) throw new Error('the transfer failed in its block');
        return hash;
      }
      await sleep(1000);
    }
    throw new Error('the transfer is not in a block yet');
  }

  // A request: its method, path and body text; the answer's status and JSON.
  async function handle(method, path, text) {
    if (path !== '/faucet') return { status: 404, json: { error: 'not found' } };
    if (method !== 'POST') return { status: 405, json: { error: 'POST an address to /faucet' } };
    let address;
    try {
      address = JSON.parse(text).address;
    } catch {
      address = undefined;
    }
    if (typeof address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
      return { status: 400, json: { error: 'that is not a Ghost address' } };
    }
    const key = address.toLowerCase();
    const last = lastSent.get(key);
    if (last !== undefined && now() - last < ONCE_EVERY_MS) {
      return { status: 429, json: { error: 'test GHOST goes to each address at most once a minute' } };
    }
    lastSent.set(key, now());
    try {
      const transactionHash = await send(key);
      return { status: 200, json: { transactionHash } };
    } catch (error) {
      // Nothing was sent: the address may ask again at once.
      lastSent.delete(key);
      return { status: 502, json: { error: error.message } };
    }
  }

  return { handle };
}

if (typeof exports === 'object' && exports !== null) {
  Object.assign(exports, { FAUCET_WEI, ONCE_EVERY_MS, createFaucet });
}

const mainAt = process.argv.indexOf('faucet-main');
if (mainAt >= 0) {
  const http = require('http');
  const [url, from, port] = process.argv.slice(mainAt + 1);
  const faucet = createFaucet({ from, rpc: nodeRpc(url) });
  const server = http.createServer((request, response) => {
    let text = '';
    let tooBig = false;
    request.setEncoding('utf8');
    request.on('data', (chunk) => {
      text += chunk;
      if (text.length > MAX_BODY_BYTES) {
        tooBig = true;
        request.destroy();
      }
    });
    request.on('end', async () => {
      if (tooBig) return;
      const { status, json } = await faucet.handle(request.method, request.url, text);
      process.stderr.write(`test-chain: faucet ${status} ${json.transactionHash || json.error}\n`);
      response.writeHead(status, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify(json));
    });
  });
  server.listen(Number(port), '0.0.0.0');
}
FAUCET
}

[ "$#" -ge 1 ] || usage
command="$1"
shift
case "$command" in
  start) cmd_start ;;
  wait) cmd_wait "$@" ;;
  stop) cmd_stop ;;
  genesis) cmd_genesis ;;
  height) cmd_height ;;
  checkpoint) cmd_checkpoint "$@" ;;
  fund-late) cmd_fund_late "$@" ;;
  faucet) cmd_faucet "$@" ;;
  *) usage ;;
esac
