import fs from 'fs';
import path from 'path';

// The node benchmarks' chain settings: the compiled values in
// TestChainConfig.swift stay as shipped, and a local test chain changes them
// only through test-only UserDefaults overrides that the scripts set.
const ROOT = path.join(__dirname, '..');
const CONFIG = 'modules/ghost-bench/ios/Benchmarks/TestChainConfig.swift';

function read(relative: string): string {
  return fs.readFileSync(path.join(ROOT, relative), 'utf8');
}

const OVERRIDES = {
  restoreAccountsExpected: 'benchTestChain.restoreAccountsExpected',
};

// Overrides earlier versions read, for the header sync the phone no longer runs.
const RETIRED = ['blockTime', 'futureDrift', 'genesisRlpHex', 'checkpoint', 'backgroundWaitSeconds'];

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

// The body of `static func <name>(...) ... { ... }` in the Swift source.
function funcBody(source: string, name: string): string {
  const start = source.indexOf(`static func ${name}(`);
  expect(start).toBeGreaterThanOrEqual(0);
  const open = source.indexOf('{', start);
  let depth = 0;
  for (let i = open; i < source.length; i++) {
    if (source[i] === '{') depth++;
    if (source[i] === '}' && --depth === 0) return source.slice(open + 1, i);
  }
  throw new Error(`${name} is not closed`);
}

describe('TestChainConfig.swift', () => {
  const source = read(CONFIG);

  it('keeps the compiled default: no restore accounts expected', () => {
    const compiled = enumBody(source, 'Compiled');
    expect(compiled).toMatch(/static let restoreAccountsExpected = 0\n/);
    expect(compiled).not.toMatch(/checkpoint|[bB]irthday|start/);
  });

  it('declares exactly the one override key, and none of the header sync ones', () => {
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
    for (const retired of RETIRED) {
      expect(source).not.toContain(`benchTestChain.${retired}`);
    }
  });

  it('pins the spot check minimum difficulty at the test chain floor', () => {
    expect(source).toContain('static let spotCheckMinDifficulty: UInt64 = 1\n');
  });

  it('falls back to the compiled value', () => {
    expect(getterBody(source, 'restoreAccountsExpected')).toMatch(
      /overrideCount\(OverrideKey\.restoreAccountsExpected\)[\s\S]*\?\? Compiled\.restoreAccountsExpected/,
    );
  });

  it('reads every override from UserDefaults only', () => {
    const body = source.slice(source.indexOf('func overrideCount('));
    const fn = body.slice(0, body.indexOf('\n  }\n'));
    expect(fn).toContain('UserDefaults.standard.');
    expect(fn).toMatch(/forKey: key\)/);
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
  const benchmarks = { headerSync, restore, worstCase };

  it('never run the header sync', () => {
    for (const [name, source] of Object.entries(benchmarks)) {
      for (const call of [
        'HeaderSync.',
        'HeaderSync(',
        'startRun(',
        'addHeaders(',
        'syncThrough(',
        'makeSync(',
        'releaseCaches(',
        'waitForBackgroundRoundTrip',
        'didEnterBackgroundNotification',
      ]) {
        expect([name, source.includes(call)]).toEqual([name, false]);
      }
    }
    expect(headerSync).not.toMatch(/context\.stage\("(sync|resume)"\)/);
  });

  // The restore's run function, without the account lookup class.
  const restoreRun = restore.slice(
    restore.indexOf('static func run(_ context: BenchContext)'),
    restore.indexOf('final class NodeAccountLookup'),
  );

  it("restore looks up each account at the node's tip at once, with no start height", () => {
    expect(restore).not.toMatch(/[bB]irthday|scannedFrom|firstHeight|feedBlock|eth_getBlockByNumber|eth_getTransactionReceipt/);
    expect(restoreRun).toContain('let tip = try node.latestBlock()');
    expect(restoreRun).not.toMatch(/bestHeight|bestHash|blockNumber|spotCheck|SpotCheck/);
    expect(restoreRun).toMatch(
      /RestoreLookup\(\s*words: testWords, lookup: NodeAccountLookup\(url: url\), tipHeight: tip\.height,\s*tipHash: tip\.hash\)/,
    );
    expect(restoreRun).toMatch(/while let account = next \{[\s\S]*next = try lookup\.lookUpNext\(\)/);
    const latest = headerSync.slice(headerSync.indexOf('func latestBlock()'));
    expect(latest).toMatch(/hash\.count == 32/);
    expect(headerSync).toContain('"method": "eth_getBlockByNumber", "params": [tag, false]');
    expect(headerSync).toContain('try blockObject("latest", name: "latest block")');
    const lookup = restore.slice(restore.indexOf('final class NodeAccountLookup: AccountLookup'));
    expect(lookup).toContain('func accountState(address: Data, blockHash: Data) throws -> AccountState');
    expect(lookup).toContain('"blockHash": "0x" + Hex.encode(blockHash), "requireCanonical": true');
    expect(lookup).toContain('("eth_getBalance", [account, block])');
    expect(lookup).toContain('("eth_getTransactionCount", [account, block])');
  });

  it('restore records the time to the first balance and its usual notes', () => {
    const firstBalance = restoreRun.indexOf('"timeToFirstBalanceSeconds"');
    expect(firstBalance).toBeGreaterThan(restoreRun.indexOf('while let account = next {'));
    expect(restoreRun).toMatch(
      /if lookedUp == 0 \{\s*let seconds = HeaderSyncBenchmark\.uptime\(\) - restoreStart\s*timeToFirstBalanceSeconds = seconds\s*context\.note\("timeToFirstBalanceSeconds"/,
    );
    for (const note of ['restoreSeconds', 'accountsFound', 'accountsExpected', 'scanComplete']) {
      expect(restoreRun).toContain(`context.note("${note}"`);
    }
    expect(restoreRun).toMatch(/if used\.count != expected \{\s*throw/);
  });

  it('restore fails when the first balance takes more than 10 s', () => {
    expect(restore).toContain('static let firstBalanceLimitSeconds: Double = 10\n');
    expect(restoreRun).toMatch(/guard let firstBalance = timeToFirstBalanceSeconds else \{\s*throw/);
    expect(restoreRun).toMatch(
      /if firstBalance > firstBalanceLimitSeconds \{\s*throw RestoreBenchmarkError\.firstBalanceSlow/,
    );
  });

  it('restore shows first balance and lookup as its only stages', () => {
    const lookupStage = restoreRun.indexOf('try context.stage("lookup")');
    const firstStage = restoreRun.indexOf('try context.stage("first balance")');
    expect(lookupStage).toBeGreaterThanOrEqual(0);
    expect(firstStage).toBeGreaterThan(lookupStage);
    expect(firstStage).toBeLessThan(restoreRun.indexOf('let tip = try node.latestBlock()'));
    expect(restoreRun.indexOf('let restoreStart')).toBeLessThan(lookupStage);
    expect([...restore.matchAll(/context\.stage\("([^"]+)"\)/g)].map((m) => m[1])).toEqual([
      'lookup',
      'first balance',
    ]);
  });

  it('restore shows its result once the balances are in, with no header check and no wait', () => {
    expect(restore).not.toMatch(/lookupBlockVerified|BackgroundHeaderCheck|headerCheck\./);
    expect(restoreRun).not.toMatch(/\.wait\(|DispatchQueue|DispatchGroup|DispatchSemaphore/);
    expect(restore).not.toMatch(/headerCheckFailed|lookupBlockNotOnCheckedChain/);
    expect(restoreRun).toContain('context.note("headerCheck", "none")');
  });

  it('header-sync spot checks the tip once and notes its timings, memory and heat', () => {
    expect(headerSync).toContain('static let name = "header-sync"');
    const run = funcBody(headerSync, 'run');
    expect(run).toContain('try context.stage("fetch") { try fetchTip(node: node, context: context) }');
    expect(run).toMatch(
      /try context\.stage\("spot check"\) \{\s*try spotCheckHeader\(\s*header: tip\.header, keyBlockHash: tip\.keyBlockHash,\s*minDifficulty: minDifficulty\(\)\)/,
    );
    expect(run.match(/spotCheckHeader\(/g)).toHaveLength(1);
    const notes = funcBody(headerSync, 'noteSpotCheck');
    expect(notes).toContain('context.note("spotCheckCacheSeconds", String(format: "%.3f", report.cacheSeconds))');
    expect(notes).toContain('context.note("spotCheckHashSeconds", String(format: "%.3f", report.hashSeconds))');
    const device = funcBody(headerSync, 'noteDevice');
    expect(device).toContain('context.note("peakResidentBytes", String(memory.residentPeakBytes))');
    expect(device).toContain('context.note("thermalState", Metrics.thermalName(Metrics.thermalState()))');
    // headerBudgetOk is written only once the check has passed, last.
    const budget = run.indexOf('context.note("headerBudgetOk", "true")');
    expect(budget).toBeGreaterThan(run.indexOf('try requirePassed(report, tip: tip)'));
    expect(run.slice(budget, run.indexOf('#else')).trim()).toBe('context.note("headerBudgetOk", "true")');
  });

  it("header-sync keys the check with the tip's key block and fails on a header it did not ask for", () => {
    const fetch = funcBody(headerSync, 'fetchTip');
    expect(fetch).toContain('let keyHeight = spotCheckSeedHeight(height: latest.height)');
    expect(fetch).toContain('let keyHash = try node.blockHash(at: keyHeight)');
    expect(fetch).toMatch(/guard latest\.height > 0 else \{\s*throw HeaderSyncBenchmarkError\.noSealedTip/);
    const passed = funcBody(headerSync, 'requirePassed');
    expect(passed).toMatch(/guard report\.height == tip\.height else \{\s*throw/);
    expect(passed).toMatch(/guard report\.hash == tip\.hash else \{\s*throw HeaderSyncBenchmarkError\.hashMismatch/);
    expect(passed).toMatch(/guard report\.passed else \{\s*throw HeaderSyncBenchmarkError\.spotCheckFailed/);
    expect(funcBody(headerSync, 'minDifficulty')).toContain('TestChainConfig.spotCheckMinDifficulty.bigEndian');
  });

  it('worst-case holds one spot-check cache through its proofs, with no header sync', () => {
    expect(worstCase).toContain('static let wantedCaches: UInt64 = 1');
    const run = funcBody(worstCase, 'run');
    expect(run).toContain('let key = try SpotCheckKey(keyBlockHash: tip.keyBlockHash)');
    expect(run).toMatch(/guard before == wantedCaches else \{\s*throw WorstCaseBenchmarkError\.cacheNotHeld/);
    const firstProof = run.indexOf('proveTestSummon()');
    const release = run.indexOf('key.release()');
    expect(run.indexOf('SpotCheckKey(')).toBeLessThan(firstProof);
    expect(release).toBeGreaterThan(run.indexOf('throw WorstCaseBenchmarkError.notVerified(index)'));
    expect(run).toMatch(/guard key\.isHeld\(\) else \{\s*throw WorstCaseBenchmarkError\.cacheNotHeld/);
    expect(run.match(/release\(\)/g)).toHaveLength(1);
    // Any tip above block 0 will do: no second RandomX key is needed.
    expect(worstCase).not.toMatch(/8449|8192|cachesNotLoaded/);
  });

  it('worst-case is noted as the stress case', () => {
    expect(worstCase).toContain('context.note("workerStress", "true")');
    expect(worstCase).toContain('static let kind = "stress benchmark only"');
    expect(worstCase).toContain('HeaderSyncBenchmark.noteSpotCheck(report, context: context)');
  });
});

describe('scripts/sim-test.sh', () => {
  const script = read('scripts/sim-test.sh');

  it('writes the node URL and the restore override into the simulator for the node benchmarks', () => {
    expect(script).toContain('NODE_BENCHES="header-sync restore worst-case"');
    expect(script).toMatch(/xcrun simctl spawn "\$udid" defaults write "\$APP_ID"/);
    expect(script).toContain('APP_ID=com.ghostcoin.wallet');
    expect(script).toContain('sim_defaults benchNodeUrl -string "http://127.0.0.1:$TEST_CHAIN_PORT"');
    expect(script).toContain(`sim_defaults ${OVERRIDES.restoreAccountsExpected} -int 3\n`);
  });

  it('passes only what the benchmarks still read, and clears the retired overrides', () => {
    expect([...script.matchAll(/^\s*sim_defaults (\S+)/gm)].map((m) => m[1])).toEqual([
      'benchNodeUrl',
      OVERRIDES.restoreAccountsExpected,
    ]);
    expect(script).toContain(`for unread in ${RETIRED.join(' ')}; do`);
    expect(script).toContain('sim_defaults_delete "benchTestChain.$unread"');
    expect(script).not.toMatch(/HEADER_SYNC_WINDOW|WORST_CASE_CHECKPOINT|BACKGROUND_WAIT|test-chain\.sh (checkpoint|genesis)|FULL/);
  });

  it('starts the test chain and waits past the test accounts funding first', () => {
    expect(script).toContain('bash scripts/test-chain.sh start');
    expect(script).toContain('bash scripts/test-chain.sh wait "$TEST_CHAIN_HEIGHT"');
    const height = Number(/^TEST_CHAIN_HEIGHT=(\d+)$/m.exec(script)?.[1]);
    expect(height).toBeGreaterThan(5);
    expect(height).toBeLessThan(8449);
    expect(script).toMatch(/^TEST_CHAIN_PORT=8547$/m);
    const start = script.indexOf('bash scripts/test-chain.sh start');
    const install = script.indexOf('xcrun simctl install');
    const write = script.indexOf('sim_defaults benchNodeUrl');
    const run = script.indexOf('maestro --device');
    expect(start).toBeLessThan(install);
    expect(install).toBeLessThan(write);
    expect(write).toBeLessThan(run);
  });

  it('gives node benchmarks 20 minutes and passes BENCH and TIMEOUT to the flow', () => {
    expect(script).toMatch(/^NODE_BENCH_TIMEOUT_MS=1200000$/m);
    expect(script).toContain('-e BENCH="$bench" -e TIMEOUT="$timeout_ms"');
    expect(script).toMatch(/^BENCHES="\$\{BENCHES:-[^}]*\}"$/m);
  });

  it('gives restore no start height and no late funding', () => {
    expect(script).not.toMatch(/[bB]irthday|BIRTHDAY|fund-late/);
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

  it('passes only the node on the LAN and the restore override as launch arguments', () => {
    const args = script.slice(script.indexOf('args+=('), script.indexOf(')', script.indexOf('args+=(') + 7));
    expect(args).toContain('-benchNodeUrl "http://$lan_ip:$TEST_CHAIN_PORT"');
    expect(args).toContain(`-${OVERRIDES.restoreAccountsExpected} 3\n`);
    expect([...args.matchAll(/^\s*-(\S+)/gm)].map((m) => m[1])).toEqual([
      'benchNodeUrl',
      OVERRIDES.restoreAccountsExpected,
    ]);
    for (const retired of RETIRED) {
      expect(script).not.toContain(`benchTestChain.${retired}`);
    }
    expect(script).not.toMatch(/[bB]irthday|BIRTHDAY|fund-late/);
    expect(script).not.toMatch(/HEADER_SYNC_WINDOW|WORST_CASE_CHECKPOINT|test-chain\.sh (checkpoint|genesis)/);
    expect(script).toMatch(/^TEST_CHAIN_PORT=8547$/m);
    expect(Number(/^TEST_CHAIN_HEIGHT=(\d+)$/m.exec(script)?.[1])).toBeLessThan(8449);
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
