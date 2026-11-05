import fs from 'fs';
import os from 'os';
import path from 'path';

// Xcode 27.2's Swift compiler crashes on one line of expo-modules-core 58.0.26
// (`case .failure(let error as any Error):` in AsyncFunctionDefinition.swift).
// patches/expo-modules-core+58.0.26.patch carries the fix and patch-package
// applies it after every install. These checks run patch-package's own parser
// and applier against the installed file, so a patch that no longer applies,
// or that touches more than that one line, fails here and not on the Mac Studio.
const ROOT = path.join(__dirname, '..');
const PATCH = path.join(ROOT, 'patches', 'expo-modules-core+58.0.26.patch');
const SWIFT = path.join('node_modules', 'expo-modules-core', 'ios', 'Core', 'Functions', 'AsyncFunctionDefinition.swift');
const OLD_LINE = '        case .failure(let error as any Error):';
const NEW_LINE = '        case .failure(let error):';

type Effect = { type: string; path?: string };
const { parsePatchFile } = require('patch-package/dist/patch/parse') as {
  parsePatchFile: (text: string) => Effect[];
};
const { executeEffects } = require('patch-package/dist/patch/apply') as {
  executeEffects: (effects: Effect[], opts: { dryRun: boolean; cwd: string; bestEffort: boolean }) => void;
};
const { reversePatch } = require('patch-package/dist/patch/reverse') as {
  reversePatch: (effects: Effect[]) => Effect[];
};

const patchText = () => fs.readFileSync(PATCH, 'utf8');

let tmp: string;
let copy: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'expo-modules-core-patch-'));
  copy = path.join(tmp, SWIFT);
  fs.mkdirSync(path.dirname(copy), { recursive: true });
  fs.copyFileSync(path.join(ROOT, SWIFT), copy);
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

// The installed file as published, whether or not postinstall has patched it.
function unpatchedCopy(): string {
  const installed = fs.readFileSync(copy, 'utf8');
  if (!installed.split('\n').includes(OLD_LINE)) {
    executeEffects(reversePatch(parsePatchFile(patchText())), { dryRun: false, cwd: tmp, bestEffort: false });
  }
  return fs.readFileSync(copy, 'utf8');
}

describe('patches/expo-modules-core+58.0.26.patch', () => {
  it('touches only the one failure case line in AsyncFunctionDefinition.swift', () => {
    const effects = parsePatchFile(patchText());
    expect(effects).toEqual([expect.objectContaining({ type: 'patch', path: SWIFT })]);

    const lines = patchText().split('\n');
    const removed = lines.filter((l) => l.startsWith('-') && !l.startsWith('---'));
    const added = lines.filter((l) => l.startsWith('+') && !l.startsWith('+++'));
    expect(removed).toEqual([`-${OLD_LINE}`]);
    expect(added).toEqual([`+${NEW_LINE}`]);
  });

  it('applies to the installed expo-modules-core and leaves every other line alone', () => {
    const before = unpatchedCopy().split('\n');
    expect(before).toContain(OLD_LINE);

    executeEffects(parsePatchFile(patchText()), { dryRun: false, cwd: tmp, bestEffort: false });
    const after = fs.readFileSync(copy, 'utf8').split('\n');

    expect(after).toContain(NEW_LINE);
    expect(after).not.toContain(OLD_LINE);
    expect(after).toHaveLength(before.length);
    const changed = before.flatMap((line, i) => (line === after[i] ? [] : [i]));
    expect(changed).toEqual([before.indexOf(OLD_LINE)]);
  });

  it('names the expo-modules-core release the lockfile resolves', () => {
    const lock = fs.readFileSync(path.join(ROOT, 'pnpm-lock.yaml'), 'utf8');
    expect(lock).toMatch(/^ {2}expo-modules-core@58\.0\.26:$/m);
    expect(lock).not.toMatch(/^ {2}expo-modules-core@(?!58\.0\.26:)[^(]*:$/m);
  });
});

describe('package.json', () => {
  it('runs patch-package after every install, failing the install off CI too, from a pinned devDependencies entry', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    // Without --error-on-fail patch-package exits 0 outside CI when a patch
    // does not apply, and the Mac Studio would build the crashing source.
    expect(pkg.scripts.postinstall).toBe('patch-package --error-on-fail');
    expect(pkg.devDependencies['patch-package']).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

describe('docs/release.md', () => {
  it('describes the patch', () => {
    const doc = fs.readFileSync(path.join(ROOT, 'docs', 'release.md'), 'utf8');
    expect(doc).toContain('patches/expo-modules-core+58.0.26.patch');
    expect(doc).toContain('patch-package');
    expect(doc).toContain('Xcode 27.2');
  });
});
