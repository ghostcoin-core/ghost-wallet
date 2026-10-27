import fs from 'fs';
import path from 'path';

// The iOS build settings that keep the app from crashing at launch and let the
// benchmarks reach the native core. The build itself runs only on a Mac.
const ROOT = path.join(__dirname, '..');

function read(relative: string): string {
  return fs.readFileSync(path.join(ROOT, relative), 'utf8');
}

type PluginEntry = string | [string, Record<string, unknown>?];

function plugin(name: string): PluginEntry | undefined {
  const plugins: PluginEntry[] = JSON.parse(read('app.json')).expo.plugins ?? [];
  return plugins.find((entry) => (Array.isArray(entry) ? entry[0] : entry) === name);
}

describe('pnpm layout', () => {
  it('hoists node_modules so only one copy of each Expo module is installed', () => {
    const lines = read('.npmrc')
      .split('\n')
      .map((line) => line.trim());
    expect(lines).toContain('node-linker=hoisted');
  });
});

describe('expo-build-properties', () => {
  it('builds Expo modules from source instead of using precompiled binaries', () => {
    const entry = plugin('expo-build-properties');
    expect(Array.isArray(entry)).toBe(true);
    const options = (entry as [string, { ios?: Record<string, unknown> }])[1];
    expect(options?.ios?.usePrecompiledModules).toBe(false);
  });

  it('is a direct dependency on the same SDK line as expo', () => {
    const pkg = JSON.parse(read('package.json'));
    expect(pkg.dependencies.expo).toMatch(/^~58\./);
    expect(pkg.dependencies['expo-build-properties']).toMatch(/^~58\./);
  });
});

describe('simulator test', () => {
  it('has the simulator script', () => {
    expect(fs.existsSync(path.join(ROOT, 'scripts/sim-test.sh'))).toBe(true);
  });

  it('builds the simulator app for arm64 only', () => {
    const script = read('scripts/sim-test.sh');
    expect(script).toContain('ARCHS=arm64');
    expect(script).toContain('ONLY_ACTIVE_ARCH=YES');
  });

  it('turns off precompiled modules in both install scripts', () => {
    for (const file of ['scripts/sim-test.sh', 'scripts/mac-install.sh']) {
      expect(read(file)).toMatch(/^export EXPO_USE_PRECOMPILED_MODULES=0$/m);
    }
  });

  it('has a Maestro flow that opens the bench screen and waits for an ok result', () => {
    expect(fs.existsSync(path.join(ROOT, '.maestro/bench.yaml'))).toBe(true);
    const flow = read('.maestro/bench.yaml');
    expect(flow).toContain('openLink: ghostwallet://bench');
    expect(flow).toMatch(/extendedWaitUntil:[\s\S]*\$\{BENCH\}: ok/);
  });
});

describe('Swift bindings of the native core', () => {
  const benchIos = path.join(ROOT, 'modules/ghost-bench/ios');

  function swiftFiles(dir: string): string[] {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) return entry.name === 'Generated' ? [] : swiftFiles(full);
      return entry.name.endsWith('.swift') ? [full] : [];
    });
  }

  it('gates the core benchmarks on GHOST_CORE_BINDINGS, not on a module import', () => {
    const sources = swiftFiles(benchIos).map((file) => fs.readFileSync(file, 'utf8'));
    expect(sources.some((source) => source.includes('#if GHOST_CORE_BINDINGS'))).toBe(true);
    for (const source of sources) {
      expect(source).not.toContain('canImport(ghost_wallet_core)');
      expect(source).not.toMatch(/^\s*import ghost_wallet_core\b/m);
    }
  });

  it('sets GHOST_CORE_BINDINGS in the pod when the generated bindings exist', () => {
    const podspec = read('modules/ghost-bench/ios/GhostBench.podspec');
    expect(podspec).toContain("'Generated', 'ghost_wallet_core.swift'");
    expect(podspec).toMatch(/SWIFT_ACTIVE_COMPILATION_CONDITIONS'\]\s*=.*GHOST_CORE_BINDINGS/);
    expect(podspec).toContain("'DEFINES_MODULE' => 'YES'");
  });

  it('keeps the generated bindings out of git', () => {
    expect(read('modules/ghost-bench/.gitignore')).toMatch(/^ios\/Generated\/$/m);
  });
});
