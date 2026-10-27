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
  const match = new RegExp(`static var ${name}: \\w+ \\{`).exec(source);
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
    expect(source).toContain('static let halfLife: UInt64 = 3600');
  });

  it('declares exactly the four override keys', () => {
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
    const start = getterBody(source, 'start');
    expect(start).toContain('overrideString(OverrideKey.genesisRlpHex)');
    expect(start).toContain('return Compiled.start');
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

  it('has the start, wait, stop and genesis subcommands', () => {
    for (const command of ['start', 'wait', 'stop', 'genesis']) {
      expect(script).toMatch(new RegExp(`^  ${command}\\) cmd_${command}`, 'm'));
    }
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

  it('prints block 0 from the node', () => {
    expect(script).toContain('debug_getRawHeader \'["0x0"]\'');
  });
});
