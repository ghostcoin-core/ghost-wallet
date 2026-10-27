import fs from 'fs';
import path from 'path';

// The node benchmarks' chain settings: the compiled values in
// TestChainConfig.swift stay as shipped, and a local test chain changes them
// only through test-only UserDefaults overrides that the simulator script sets.
const ROOT = path.join(__dirname, '..');
const CONFIG = 'modules/ghost-bench/ios/Benchmarks/TestChainConfig.swift';

function read(relative: string): string {
  return fs.readFileSync(path.join(ROOT, relative), 'utf8');
}

const OVERRIDES = {
  blockTime: 'benchTestChain.blockTime',
  futureDrift: 'benchTestChain.futureDrift',
  genesisRlpHex: 'benchTestChain.genesisRlpHex',
  restoreAccountsExpected: 'benchTestChain.restoreAccountsExpected',
  checkpoint: 'benchTestChain.checkpoint',
  backgroundWaitSeconds: 'benchTestChain.backgroundWaitSeconds',
};

// The body of `enum <name> { ... }` in the Swift source.
function enumBody(source: string, name: string): string {
  const start = source.indexOf(`enum ${name} {`);
  expect(start).toBeGreaterThanOrEqual(0);
  let depth = 0;
  for (let i = source.indexOf('{', start); i < source.length; i++) {
    if (source[i] === '{') depth++;
    if (source[i] === '}' && --depth === 0) {
      return source.slice(source.indexOf('{', start) + 1, i);
    }
  }
  throw new Error(`enum ${name} is not closed`);
}

// The body of the computed property `static var <name>: <type> { ... }`.
function getterBody(source: string, name: string): string {
  const match = new RegExp(`static var ${name}: \\w+\\?? \\{`).exec(source);
  expect(match).not.toBeNull();
  const open = match!.index + match![0].length - 1;
  let depth = 0;
  for (let i = open; i < source.length; i++) {
    if (source[i] === '{') depth++;
    if (source[i] === '}' && --depth === 0) return source.slice(open + 1, i);
  }
  throw new Error(`${name} is not closed`);
}

describe('TestChainConfig.swift', () => {
  const source = read(CONFIG);

  it('keeps the compiled defaults: block time 30, future drift 30, nothing pinned', () => {
    const compiled = enumBody(source, 'Compiled');
    expect(compiled).toMatch(/static let blockTime: UInt64 = 30\n/);
    expect(compiled).toMatch(/static let futureDrift: UInt64 = 30\n/);
    expect(compiled).toMatch(/static let restoreAccountsExpected = 0\n/);
    expect(compiled).toContain('static let start: Start = .genesis(rlpHex: "")');
    expect(compiled).toMatch(/static let backgroundWaitSeconds: Double = 180\n/);
    expect(compiled).not.toMatch(/checkpoint|[bB]irthday/);
    expect(source).toContain('static let halfLife: UInt64 = 3600');
  });

  it('declares exactly the six override keys, with no restore start among them', () => {
    expect(source).not.toMatch(/[bB]irthday/);
    const keys = enumBody(source, 'OverrideKey');
    const declared = [...keys.matchAll(/static let (\w+) = "([^"]+)"/g)].map(([, name, key]) => [
      name,
      key,
    ]);
    expect(Object.fromEntries(declared)).toEqual(OVERRIDES);
    for (const key of Object.values(OVERRIDES)) {
      expect(source.split(`"${key}"`)).toHaveLength(2);
    }
  });

  it('falls back to the compiled value for each overridable setting', () => {
    expect(getterBody(source, 'blockTime')).toMatch(
      /overrideCount\(OverrideKey\.blockTime\)[\s\S]*\?\? Compiled\.blockTime/,
    );
    expect(getterBody(source, 'futureDrift')).toMatch(
      /overrideCount\(OverrideKey\.futureDrift\)[\s\S]*\?\? Compiled\.futureDrift/,
    );
    expect(getterBody(source, 'restoreAccountsExpected')).toMatch(
      /overrideCount\(OverrideKey\.restoreAccountsExpected\)[\s\S]*\?\? Compiled\.restoreAccountsExpected/,
    );
    expect(getterBody(source, 'backgroundWaitSeconds')).toMatch(
      /overrideCount\(OverrideKey\.backgroundWaitSeconds\)[\s\S]*\?\? Compiled\.backgroundWaitSeconds/,
    );
    const start = getterBody(source, 'start');
    expect(start).toContain('overrideString(OverrideKey.genesisRlpHex)');
    expect(start).toContain('return Compiled.start');
  });

  it('takes a checkpoint override before the genesis one and refuses one that does not decode', () => {
    const start = getterBody(source, 'start');
    const checkpoint = start.indexOf('overrideString(OverrideKey.checkpoint)');
    expect(checkpoint).toBeGreaterThanOrEqual(0);
    expect(checkpoint).toBeLessThan(start.indexOf('OverrideKey.genesisRlpHex'));
    expect(start).toContain('return try checkpoint(fromJson: json)');
    expect(start).toMatch(/object\(forKey: OverrideKey\.checkpoint\) != nil \{\s*throw/);
    const json = source.slice(source.indexOf('struct CheckpointJson'), source.indexOf('enum Compiled'));
    for (const field of ['rlpHex: String', 'height: UInt64', 'totalWorkHex: String', 'genesisTimestamp: UInt64']) {
      expect(json).toContain(`let ${field}`);
    }
    expect(json).toContain('let keyBlocks: [KeyBlock]');
    expect(json).toContain('let hashHex: String');
    const parse = source.slice(source.indexOf('static func checkpoint(fromJson'));
    expect(parse).toMatch(/catch \{\s*throw OverrideError\.badCheckpoint/);
  });

  it('reads every override from UserDefaults only', () => {
    expect(getterBody(source, 'blockTime')).not.toMatch(/UserDefaults|ProcessInfo|Bundle/);
    for (const reader of ['overrideCount', 'overrideString']) {
      const body = source.slice(source.indexOf(`func ${reader}(`));
      const fn = body.slice(0, body.indexOf('\n  }\n'));
      expect(fn).toContain('UserDefaults.standard.');
      expect(fn).toMatch(/forKey: key\)/);
    }
    expect(source).not.toMatch(/ProcessInfo|environment|arguments|Bundle\.main|infoDictionary/);
    expect(source).not.toMatch(/\.set\(|setValue|register\(defaults/);
  });

  it('has no other settable state', () => {
    expect(source).not.toMatch(/static var \w+: [\w.]+ = /);
  });
});

describe('the node benchmarks', () => {
  const headerSync = read('modules/ghost-bench/ios/Benchmarks/HeaderSyncBenchmark.swift');
  const restore = read('modules/ghost-bench/ios/Benchmarks/RestoreBenchmark.swift');
  const worstCase = read('modules/ghost-bench/ios/Benchmarks/WorstCaseBenchmark.swift');

  it('fail when the header after a checkpoint does not link to it', () => {
    const fromCheckpoint = headerSync.slice(headerSync.indexOf('case .checkpoint(let rlpHex'));
    expect(fromCheckpoint).toMatch(
      /HeaderSync\.fromCheckpoint\([\s\S]*try checkLinksToCheckpoint\(sync: sync, height: height, node: node\)\s*return sync/,
    );
    const check = headerSync.slice(headerSync.indexOf('static func checkLinksToCheckpoint'));
    expect(check).toContain('node.headers(from: height + 1, through: height + 1)');
    expect(check).toMatch(/guard parent == sync\.bestHash\(\) else \{\s*throw HeaderSyncBenchmarkError\.notLinkedToCheckpoint/);
  });

  it('restore looks up each account at the checked tip, with no start height', () => {
    expect(restore).not.toMatch(/[bB]irthday|scannedFrom|firstHeight|feedBlock|eth_getBlockByNumber|eth_getTransactionReceipt/);
    expect(restore).toContain('let tipHeight = sync.bestHeight()');
    expect(restore).toContain('let tipHash = sync.bestHash()');
    expect(restore).toMatch(
      /RestoreLookup\(\s*words: testWords, lookup: NodeAccountLookup\(url: url\), tipHeight: tipHeight,\s*tipHash: tipHash\)/,
    );
    expect(restore).toContain('while let account = try restore.lookUpNext()');
    const lookup = restore.slice(restore.indexOf('final class NodeAccountLookup: AccountLookup'));
    expect(lookup).toContain('func accountState(address: Data, blockHash: Data) throws -> AccountState');
    expect(lookup).toContain('"blockHash": "0x" + Hex.encode(blockHash), "requireCanonical": true');
    expect(lookup).toContain('("eth_getBalance", [account, block])');
    expect(lookup).toContain('("eth_getTransactionCount", [account, block])');
  });

  it('restore records the time to the first balance and its usual notes', () => {
    const firstBalance = restore.indexOf('"timeToFirstBalanceSeconds"');
    expect(firstBalance).toBeGreaterThan(restore.indexOf('while let account = try restore.lookUpNext()'));
    expect(restore).toMatch(/if lookedUp == 0 \{\s*context\.note\(\s*"timeToFirstBalanceSeconds"/);
    for (const note of ['restoreSeconds', 'accountsFound', 'accountsExpected', 'scanComplete']) {
      expect(restore).toContain(`context.note("${note}"`);
    }
    expect(restore).toMatch(/guard used\.count == expected|if used\.count != expected \{\s*throw/);
  });

  it('worst-case still fails unless it holds 2 caches', () => {
    expect(worstCase).toContain('static let wantedCaches: UInt64 = 2');
    expect(worstCase).toMatch(/guard before == wantedCaches else \{\s*throw WorstCaseBenchmarkError\.cachesNotLoaded/);
  });

  it('header-sync waits for the background for the configured time', () => {
    expect(headerSync).toContain('entered.wait(timeout: .now() + TestChainConfig.backgroundWaitSeconds)');
  });
});

describe('scripts/sim-test.sh', () => {
  const script = read('scripts/sim-test.sh');

  it('writes the node URL and every override into the simulator for the node benchmarks', () => {
    expect(script).toContain('NODE_BENCHES="header-sync restore worst-case"');
    expect(script).toMatch(/xcrun simctl spawn "\$udid" defaults write "\$APP_ID"/);
    expect(script).toContain('APP_ID=com.ghostcoin.wallet');
    expect(script).toContain('sim_defaults benchNodeUrl -string "http://127.0.0.1:$TEST_CHAIN_PORT"');
    expect(script).toContain(`sim_defaults ${OVERRIDES.blockTime} -int 1\n`);
    expect(script).toContain(`sim_defaults ${OVERRIDES.futureDrift} -int 3600\n`);
    expect(script).toContain(`sim_defaults ${OVERRIDES.genesisRlpHex} -string "$genesis_rlp"`);
    expect(script).toContain(`sim_defaults ${OVERRIDES.restoreAccountsExpected} -int 3\n`);
  });

  it('starts the test chain and waits past the second RandomX key first', () => {
    expect(script).toContain('bash scripts/test-chain.sh start');
    expect(script).toContain('bash scripts/test-chain.sh wait "$TEST_CHAIN_HEIGHT"');
    const height = Number(/^TEST_CHAIN_HEIGHT=(\d+)$/m.exec(script)?.[1]);
    expect(height).toBeGreaterThan(8449);
    expect(script).toMatch(/^TEST_CHAIN_PORT=8547$/m);
    const start = script.indexOf('bash scripts/test-chain.sh start');
    const install = script.indexOf('xcrun simctl install');
    const write = script.indexOf('sim_defaults benchNodeUrl');
    const run = script.indexOf('maestro --device');
    expect(start).toBeLessThan(install);
    expect(install).toBeLessThan(write);
    expect(write).toBeLessThan(run);
  });

  it('gives node benchmarks 90 minutes and passes BENCH and TIMEOUT to the flow', () => {
    expect(script).toMatch(/^NODE_BENCH_TIMEOUT_MS=5400000$/m);
    expect(script).toContain('-e BENCH="$bench" -e TIMEOUT="$timeout_ms"');
    expect(script).toMatch(/^BENCHES="\$\{BENCHES:-[^}]*\}"$/m);
  });

  it('starts worst-case from a checkpoint below the second key, so its sync crosses the key change', () => {
    const checkpoint = Number(/^WORST_CASE_CHECKPOINT=(\d+)$/m.exec(script)?.[1]);
    expect(checkpoint).toBe(8000);
    expect(checkpoint).toBeLessThan(8449);
    expect(script).toMatch(/worst-case\) checkpoint_height="\$WORST_CASE_CHECKPOINT" ;;/);
  });

  it('checks header-sync and restore headers from 1,000 blocks below the tip', () => {
    expect(script).toMatch(/^HEADER_SYNC_WINDOW=1000$/m);
    expect(script).toMatch(
      /header-sync \| restore\)\s*tip="\$\(bash scripts\/test-chain\.sh height\)"\s*checkpoint_height=\$\(\(tip - HEADER_SYNC_WINDOW\)\)/,
    );
  });

  it('gives restore no start height and no late funding', () => {
    expect(script).not.toMatch(/[bB]irthday|BIRTHDAY|fund-late/);
  });

  it('writes each node benchmark its checkpoint right before it runs', () => {
    expect(script).toContain('checkpoint="$(bash scripts/test-chain.sh checkpoint "$checkpoint_height")"');
    expect(script).toContain(`sim_defaults ${OVERRIDES.checkpoint} -string "$checkpoint"`);
    const loop = script.slice(script.indexOf('for bench in $BENCHES; do\n  echo "==> benchmark'));
    expect(loop.indexOf('set_bench_start "$bench"')).toBeGreaterThan(0);
    expect(loop.indexOf('set_bench_start "$bench"')).toBeLessThan(loop.indexOf('maestro --device'));
    // A benchmark never inherits the previous one's start.
    const setStart = script.slice(script.indexOf('set_bench_start() {'));
    expect(setStart).toMatch(
      /sim_defaults_delete benchTestChain\.checkpoint\s*\[ "\$FULL" = 1 \] && return/,
    );
  });

  it('waits 10 seconds for the background, and keeps FULL=1 from genesis as before', () => {
    expect(script).toMatch(/^BACKGROUND_WAIT_SECONDS=10$/m);
    expect(script).toContain(`sim_defaults ${OVERRIDES.backgroundWaitSeconds} -int "$BACKGROUND_WAIT_SECONDS"`);
    expect(script).toMatch(/^FULL="\$\{FULL:-0\}"$/m);
    expect(script).toMatch(
      /if \[ "\$FULL" = 1 \]; then[^\n]*\n[^\n]*\n\s*sim_defaults_delete benchTestChain\.backgroundWaitSeconds\n\s*else/,
    );
  });
});

describe('scripts/phone-launch.sh', () => {
  const script = read('scripts/phone-launch.sh');

  it('launches the installed app on the connected iPhone at the bench screen', () => {
    expect(script).toContain('DEVICE="${GHOST_WALLET_DEVICE:-}"');
    expect(script).toMatch(
      /xcrun devicectl device process launch --device "\$DEVICE" --terminate-existing\s*--payload-url ghostwallet:\/\/bench "\$APP_ID"/,
    );
    expect(script).toContain('launch+=(-- "${args[@]}")');
    expect(script).toContain('On the phone, tap \\"$BENCH\\" on the bench screen, then Run.');
  });

  it('passes the node on the LAN and each override as a launch argument', () => {
    expect(script).toContain('-benchNodeUrl "http://$lan_ip:$TEST_CHAIN_PORT"');
    expect(script).toContain(`-${OVERRIDES.checkpoint} "$checkpoint"`);
    expect(script).toContain(`-${OVERRIDES.genesisRlpHex} "$genesis_rlp"`);
    expect(script).toContain(`-${OVERRIDES.blockTime} 1\n`);
    expect(script).toContain(`-${OVERRIDES.futureDrift} 3600\n`);
    expect(script).toContain(`-${OVERRIDES.restoreAccountsExpected} 3\n`);
    expect(script).not.toMatch(/[bB]irthday|BIRTHDAY|fund-late/);
    expect(script).toMatch(
      /header-sync \| restore\)\s*tip="\$\(bash scripts\/test-chain\.sh height\)"\s*checkpoint_height=\$\(\(tip - HEADER_SYNC_WINDOW\)\)/,
    );
    expect(script).toMatch(/^TEST_CHAIN_PORT=8547$/m);
    expect(script).toMatch(/^WORST_CASE_CHECKPOINT=8000$/m);
    expect(script).toMatch(/^HEADER_SYNC_WINDOW=1000$/m);
  });
});

describe('.maestro/bench.yaml', () => {
  const flow = read('.maestro/bench.yaml');

  it('takes the benchmark from BENCH without a default that would override it', () => {
    expect(flow).not.toMatch(/^env:/m);
    expect(flow).toContain('id: bench-name-${BENCH}');
  });

  it('waits for the result for TIMEOUT', () => {
    expect(flow).toMatch(/text: '\$\{BENCH\}: ok[^\n]*\n\s*timeout: \$\{TIMEOUT/);
  });
});

describe('scripts/test-chain.sh', () => {
  const script = read('scripts/test-chain.sh');

  it('has the start, wait, stop, genesis, height, checkpoint and fund-late subcommands', () => {
    for (const command of ['start', 'wait', 'stop', 'genesis', 'height', 'checkpoint', 'fund-late']) {
      expect(script).toMatch(new RegExp(`^  ${command}\\) cmd_${command.replace('-', '_')}`, 'm'));
    }
  });

  it('funds accounts 0, 3 and 7 again at a later height on every fund-late', () => {
    const fundLate = script.slice(script.indexOf('cmd_fund_late() {'), script.indexOf('checkpoint_js() {'));
    expect(fundLate).toMatch(/wait_height "\$1"\s*lowest="\$\(send_to_test_accounts "\$miner"\)"/);
    expect(fundLate).not.toContain('marker');
    expect(fundLate).toMatch(/echo "\$lowest"\n\}/);
    const send = script.slice(script.indexOf('send_to_test_accounts() {'), script.indexOf('fund_accounts() {'));
    expect(send).toContain('for account in "${FUND_ACCOUNTS[@]}"; do');
    expect(send).toContain('eth_getTransactionReceipt');
  });

  it('pins ghost-node to a commit and builds geth', () => {
    expect(script).toMatch(/^NODE_COMMIT="\$\{GHOST_NODE_COMMIT:-[0-9a-f]{40}\}"$/m);
    expect(script).toContain('make -C "$SRC" geth');
  });

  it('mines the internal-net chain as an archive node on port 8547 for the LAN', () => {
    expect(script).toMatch(/^PORT=8547$/m);
    expect(script).toMatch(/^CHAIN_ID=6777971$/m);
    expect(script).toContain('"difficulty": "0x1"');
    expect(script).toContain('printf \'%064x\' "$CHAIN_ID"');
    for (const flag of [
      '--gcmode archive',
      '--state.scheme hash',
      '--mine',
      '--http.addr 0.0.0.0',
      '--http.port "$PORT"',
      '--datadir "$DATA"',
    ]) {
      expect(script).toContain(flag);
    }
    expect(script).toContain('HOME_DIR="${GHOST_TESTCHAIN_HOME:-$HOME/.ghost-wallet-testchain}"');
  });

  it('funds accounts 0, 3 and 7 of the test words once, with 1 GHOST each', () => {
    for (const account of [
      '0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd',
      '0xacf1b03442244bc14982f1aae0a11d76e1850e09',
      '0xa8c6efceaca7b3265182bbd1d516aa0568e15314',
    ]) {
      expect(script).toContain(`  ${account}\n`);
    }
    const oneGhost = /^ONE_GHOST=(0x[0-9a-f]+)$/m.exec(script)![1];
    expect(BigInt(oneGhost).toString()).toBe('1000000000000000000');
    expect(script).toContain('eth_sendTransaction');
    expect(script).toMatch(/\[ -f "\$marker" \] && return/);
  });

  it('serves only eth, net and web3 over the LAN HTTP endpoint', () => {
    const apis = script.match(/--http\.api (\S+)/g) ?? [];
    expect(apis).toEqual(['--http.api eth,net,web3']);
    expect(script).not.toMatch(/--http\.api[^\n]*(debug|admin|personal|miner)/);
    expect(script).not.toMatch(/result debug_|rpc debug_/);
  });

  it('prints block 0 through the local IPC socket', () => {
    expect(script).toContain('IPC="$DATA/geth.ipc"');
    expect(script).toContain('--ipcpath "$IPC"');
    expect(script).toContain(`"$GETH" attach --exec 'debug.getRawHeader("0x0")' "$IPC"`);
  });
});
