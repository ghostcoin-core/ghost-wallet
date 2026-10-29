import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

// scripts/release-testflight.sh runs for real in a throwaway git repository,
// with stub executables first on PATH in place of the Mac-only tools. Each stub
// appends one JSON line (its name, arguments, working directory and the
// variables the build reads) to a log file.
const ROOT = path.join(__dirname, '..');
const SCRIPT = path.join(ROOT, 'scripts/release-testflight.sh');
const STUBBED = ['corepack', 'pnpm', 'cargo', 'rustup', 'pod', 'xcodebuild', 'xcrun'];

const FAKE_KEY_ID = 'FAKEKEY123';
const FAKE_ISSUER_ID = 'fake-issuer-for-tests';

type Call = {
  tool: string;
  args: string[];
  cwd: string;
  env: Record<string, string | null>;
  exportOptions?: string;
};

type Run = { status: number | null; output: string; calls: Call[] };

const STUB_JS = `
const fs = require('fs');
const path = require('path');
const [tool, ...args] = process.argv.slice(2);
const after = (flag) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : undefined; };
const env = {};
for (const name of ['EXPO_PUBLIC_GHOST_BUILD', 'GHOST_BUILD_NUMBER', 'EXPO_USE_PRECOMPILED_MODULES']) {
  env[name] = process.env[name] ?? null;
}
const call = { tool, args, cwd: process.cwd(), env };
if (tool === 'xcodebuild' && args.includes('-exportArchive')) {
  call.exportOptions = fs.readFileSync(after('-exportOptionsPlist'), 'utf8');
  fs.mkdirSync(after('-exportPath'), { recursive: true });
  fs.writeFileSync(path.join(after('-exportPath'), 'GhostWallet.ipa'), 'stub ipa');
}
if (tool === 'pnpm' && args.includes('prebuild')) {
  fs.mkdirSync('ios', { recursive: true });
}
if (tool === 'cargo' && after('--out-dir')) {
  fs.writeFileSync(path.join(after('--out-dir'), 'ghost_wallet_core.swift'), '// stub');
  fs.writeFileSync(path.join(after('--out-dir'), 'ghost_wallet_coreFFI.h'), '// stub');
}
fs.appendFileSync(process.env.STUB_LOG, JSON.stringify(call) + '\\n');
`;

let tmp: string;
let repo: string;
let stubs: string;
let log: string;
let keyFile: string;

function git(...args: string[]): string {
  const result = spawnSync('git', args, { cwd: repo, encoding: 'utf8', env: gitEnv() });
  if (result.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${result.stderr}`);
  return result.stdout.trim();
}

function gitEnv(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_AUTHOR_NAME: 'Test',
    GIT_AUTHOR_EMAIL: 'test@example.com',
    GIT_COMMITTER_NAME: 'Test',
    GIT_COMMITTER_EMAIL: 'test@example.com',
  };
}

function writeStub(dir: string, name: string) {
  const file = path.join(dir, name);
  fs.writeFileSync(file, `#!/usr/bin/env bash\nexec node "${path.join(tmp, 'stub.js')}" "${name}" "$@"\n`);
  fs.chmodSync(file, 0o755);
}

function commitFile(file: string, content: string, message: string) {
  fs.mkdirSync(path.dirname(path.join(repo, file)), { recursive: true });
  fs.writeFileSync(path.join(repo, file), content);
  git('add', file);
  git('commit', '-q', '-m', message);
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'release-testflight-'));
  repo = path.join(tmp, 'repo');
  stubs = path.join(tmp, 'bin');
  log = path.join(tmp, 'calls.jsonl');
  keyFile = path.join(tmp, 'outside', 'fake-key.p8');
  fs.mkdirSync(repo);
  fs.mkdirSync(stubs);
  fs.mkdirSync(path.dirname(keyFile));
  fs.writeFileSync(keyFile, 'fake key for tests only\n');
  fs.writeFileSync(path.join(tmp, 'stub.js'), STUB_JS);
  for (const tool of STUBBED) writeStub(stubs, tool);

  git('init', '-q');
  git('symbolic-ref', 'HEAD', 'refs/heads/main');
  commitFile('.gitignore', 'ios/\nnode_modules/\nmodules/ghost-bench/ios/Generated/\n', 'ignore');
  commitFile('package.json', JSON.stringify({ name: 'fixture', version: '3.4.5' }), 'package');
  commitFile(
    'app.json',
    JSON.stringify({ expo: { ios: { appleTeamId: 'TEAM123456', bundleIdentifier: 'com.example.wallet' } } }),
    'app',
  );
  commitFile('core/README', 'core\n', 'core');
  commitFile('modules/ghost-core/README', 'module\n', 'module');
  commitFile('scripts/release-testflight.sh', fs.readFileSync(SCRIPT, 'utf8'), 'script');
  // Six commits on main.

  // Git-ignored, like the real node_modules.
  fs.mkdirSync(path.join(repo, 'node_modules/.bin'), { recursive: true });
  writeStub(path.join(repo, 'node_modules/.bin'), 'ubrn');
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function run(args: string[] = [], extraEnv: Record<string, string> = {}): Run {
  const env: NodeJS.ProcessEnv = { ...gitEnv() };
  for (const name of Object.keys(env)) {
    if (name.startsWith('GHOST_') || name.startsWith('EXPO_')) delete env[name];
  }
  Object.assign(env, { PATH: `${stubs}:${process.env.PATH}`, STUB_LOG: log }, extraEnv);
  const result = spawnSync('bash', [path.join(repo, 'scripts/release-testflight.sh'), ...args], {
    cwd: tmp,
    env,
    encoding: 'utf8',
  });
  const calls = fs.existsSync(log)
    ? fs
        .readFileSync(log, 'utf8')
        .trim()
        .split('\n')
        .filter(Boolean)
        .map((line) => JSON.parse(line) as Call)
    : [];
  return { status: result.status, output: result.stdout + result.stderr, calls };
}

function expectOk(result: Run) {
  if (result.status !== 0) throw new Error(`the script exited ${result.status}:\n${result.output}`);
}

const keyEnv = () => ({
  GHOST_ASC_KEY_PATH: keyFile,
  GHOST_ASC_KEY_ID: FAKE_KEY_ID,
  GHOST_ASC_ISSUER_ID: FAKE_ISSUER_ID,
});

const prebuild = (calls: Call[]) => calls.find((c) => c.tool === 'pnpm' && c.args.includes('prebuild'));
const archive = (calls: Call[]) => calls.find((c) => c.tool === 'xcodebuild' && c.args.includes('archive'));
const exportCall = (calls: Call[]) =>
  calls.find((c) => c.tool === 'xcodebuild' && c.args.includes('-exportArchive'));

function destination(plist: string | undefined): string | undefined {
  return /<key>destination<\/key>\s*<string>([^<]*)<\/string>/.exec(plist ?? '')?.[1];
}

function after(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

jest.setTimeout(60000);

describe('refusals', () => {
  it('refuses a tree with an uncommitted change before calling any tool', () => {
    fs.appendFileSync(path.join(repo, 'core/README'), 'edited\n');
    const result = run(['--dry-run']);
    expect(result.status).not.toBe(0);
    expect(result.output).toMatch(/uncommitted changes/);
    expect(result.calls).toEqual([]);
  });

  it('refuses an untracked file too', () => {
    fs.writeFileSync(path.join(repo, 'stray.txt'), 'not committed\n');
    const result = run(['--dry-run']);
    expect(result.status).not.toBe(0);
    expect(result.output).toMatch(/uncommitted changes/);
    expect(result.calls).toEqual([]);
  });

  it('refuses a GHOST_BUILD_NUMBER that is not a positive whole number', () => {
    for (const bad of ['0', '-3', '1.2', 'abc', '07', '5 ']) {
      const result = run(['--dry-run'], { GHOST_BUILD_NUMBER: bad });
      expect(result.status).not.toBe(0);
      expect(result.output).toMatch(/GHOST_BUILD_NUMBER must be a positive whole number/);
      expect(result.calls).toEqual([]);
    }
  });

  it('refuses a real run when any key variable is unset, naming it', () => {
    for (const missing of ['GHOST_ASC_KEY_PATH', 'GHOST_ASC_KEY_ID', 'GHOST_ASC_ISSUER_ID']) {
      const env: Record<string, string> = keyEnv();
      delete env[missing];
      const result = run([], env);
      expect(result.status).not.toBe(0);
      expect(result.output).toContain(`${missing} is not set`);
      expect(result.calls).toEqual([]);
    }
  });

  it('refuses a real run with none of the key variables', () => {
    const result = run();
    expect(result.status).not.toBe(0);
    expect(result.output).toContain('GHOST_ASC_KEY_PATH is not set');
    expect(result.calls).toEqual([]);
  });

  it('refuses a real run when the key file is missing, without printing its path', () => {
    const missingKey = path.join(tmp, 'outside', 'no-such-key.p8');
    const result = run([], { ...keyEnv(), GHOST_ASC_KEY_PATH: missingKey });
    expect(result.status).not.toBe(0);
    expect(result.output).toMatch(/key file named by GHOST_ASC_KEY_PATH does not exist/);
    expect(result.output).not.toContain(missingKey);
    expect(result.calls).toEqual([]);
  });

  it('refuses an unknown argument', () => {
    const result = run(['--upload-now']);
    expect(result.status).not.toBe(0);
    expect(result.output).toContain('unknown argument');
    expect(result.calls).toEqual([]);
  });
});

describe('build number and version', () => {
  it('defaults the build number to the commit count of the current branch', () => {
    const result = run(['--dry-run']);
    expectOk(result);
    expect(git('rev-list', '--count', 'HEAD')).toBe('6');
    expect(prebuild(result.calls)?.env).toMatchObject({ GHOST_BUILD_NUMBER: '6', EXPO_PUBLIC_GHOST_BUILD: 'release' });
    expect(archive(result.calls)?.env.GHOST_BUILD_NUMBER).toBe('6');
  });

  it('goes up with each new commit', () => {
    commitFile('core/README', 'core v2\n', 'more');
    const result = run(['--dry-run']);
    expectOk(result);
    expect(prebuild(result.calls)?.env.GHOST_BUILD_NUMBER).toBe('7');
  });

  it('uses GHOST_BUILD_NUMBER when the caller sets it', () => {
    const result = run(['--dry-run'], { GHOST_BUILD_NUMBER: '42' });
    expectOk(result);
    expect(prebuild(result.calls)?.env.GHOST_BUILD_NUMBER).toBe('42');
    expect(result.output).toContain('build 42');
    expect(result.output).not.toMatch(/build\s+6\b/);
  });

  it('prints the version and build number before archiving and when it finishes', () => {
    const result = run(['--dry-run']);
    expectOk(result);
    const lines = result.output.split('\n');
    const header = lines.findIndex((l) => l.includes('version 3.4.5 build 6'));
    const archiving = lines.findIndex((l) => l.includes('archiving'));
    expect(header).toBeGreaterThanOrEqual(0);
    expect(header).toBeLessThan(archiving);
    expect(result.output).toMatch(/version:\s+3\.4\.5/);
    expect(result.output).toMatch(/build:\s+6/);
  });

  it('leaves the tree clean and writes no build number into a file', () => {
    const result = run(['--dry-run']);
    expectOk(result);
    expect(git('status', '--porcelain')).toBe('');
  });
});

describe('--dry-run', () => {
  it('prebuilds, installs pods, archives Release and exports without uploading', () => {
    const result = run(['--dry-run']);
    expectOk(result);

    const order = result.calls;
    const pre = order.indexOf(prebuild(result.calls)!);
    const pod = order.findIndex((c) => c.tool === 'pod' && c.args.includes('install'));
    const arc = order.indexOf(archive(result.calls)!);
    const exp = order.indexOf(exportCall(result.calls)!);
    expect(pre).toBeGreaterThanOrEqual(0);
    expect(pre).toBeLessThan(pod);
    expect(pod).toBeLessThan(arc);
    expect(arc).toBeLessThan(exp);

    expect(prebuild(result.calls)!.args).toEqual(
      expect.arrayContaining(['exec', 'expo', 'prebuild', '--platform', 'ios', '--clean']),
    );
    const archiveArgs = archive(result.calls)!.args;
    expect(after(archiveArgs, '-configuration')).toBe('Release');
    expect(archive(result.calls)!.env.EXPO_PUBLIC_GHOST_BUILD).toBe('release');

    const exp2 = exportCall(result.calls)!;
    expect(after(exp2.args, '-archivePath')).toBe(after(archiveArgs, '-archivePath'));
    expect(destination(exp2.exportOptions)).toBe('export');
    expect(exp2.exportOptions).not.toContain('<string>upload</string>');
    expect(exp2.exportOptions).toContain('<string>app-store-connect</string>');
    expect(exp2.exportOptions).toContain('<string>TEAM123456</string>');
    expect(exp2.exportOptions).toContain('<string>com.example.wallet</string>');
    expect(exp2.exportOptions).toContain('<string>automatic</string>');

    for (const call of result.calls) {
      expect(call.args.join(' ')).not.toMatch(/-authenticationKey/);
    }
  });

  it('leaves the .ipa in the git-ignored ios/build folder and prints its path', () => {
    const result = run(['--dry-run']);
    expectOk(result);
    const exportPath = after(exportCall(result.calls)!.args, '-exportPath')!;
    expect(exportPath.startsWith('ios/build/')).toBe(true);
    expect(fs.existsSync(path.join(repo, exportPath, 'GhostWallet.ipa'))).toBe(true);
    expect(result.output).toContain(`${exportPath}/GhostWallet.ipa`);
    expect(result.output).toContain('not uploaded');
  });

  it('ignores the key variables when they are set', () => {
    const result = run(['--dry-run'], keyEnv());
    expectOk(result);
    expect(destination(exportCall(result.calls)!.exportOptions)).toBe('export');
    for (const call of result.calls) {
      expect(call.args).not.toContain(FAKE_KEY_ID);
    }
  });
});

describe('real run', () => {
  it('uploads with the App Store Connect API key flags', () => {
    const result = run([], keyEnv());
    expectOk(result);
    const exp = exportCall(result.calls)!;
    expect(destination(exp.exportOptions)).toBe('upload');
    expect(after(exp.args, '-authenticationKeyPath')).toBe(keyFile);
    expect(after(exp.args, '-authenticationKeyID')).toBe(FAKE_KEY_ID);
    expect(after(exp.args, '-authenticationKeyIssuerID')).toBe(FAKE_ISSUER_ID);
    expect(after(archive(result.calls)!.args, '-configuration')).toBe('Release');
    expect(result.output).toContain('Uploaded');
    expect(result.output).toMatch(/version:\s+3\.4\.5/);
    expect(result.output).toMatch(/build:\s+6/);
  });

  it('never prints the key path, key id or issuer id', () => {
    const result = run([], keyEnv());
    expectOk(result);
    expect(result.output).not.toContain(keyFile);
    expect(result.output).not.toContain('fake-key.p8');
    expect(result.output).not.toContain(FAKE_KEY_ID);
    expect(result.output).not.toContain(FAKE_ISSUER_ID);
  });
});

describe('docs/release.md', () => {
  const doc = () => fs.readFileSync(path.join(ROOT, 'docs/release.md'), 'utf8');

  it('documents the release script, its dry run and its variables', () => {
    const text = doc();
    for (const word of [
      'scripts/release-testflight.sh',
      '--dry-run',
      'GHOST_ASC_KEY_PATH',
      'GHOST_ASC_KEY_ID',
      'GHOST_ASC_ISSUER_ID',
    ]) {
      expect(text).toContain(word);
    }
  });

  it('still records the export compliance decision and the release flag', () => {
    const text = doc();
    expect(text).toContain('ITSAppUsesNonExemptEncryption');
    expect(text).toContain('EXPO_PUBLIC_GHOST_BUILD=release');
  });
});
