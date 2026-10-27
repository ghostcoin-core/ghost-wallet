import fs from 'fs';
import path from 'path';

// pnpm only links packages the app lists itself, so every Babel preset the
// bundler loads has to be a direct dependency or the iOS bundle step fails.
const ROOT = path.join(__dirname, '..');

type PresetEntry = string | [string, ...unknown[]];

function loadBabelConfig(): { presets?: PresetEntry[] } {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const config = require(path.join(ROOT, 'babel.config.js'));
  if (typeof config !== 'function') return config;
  const api = { cache: Object.assign(() => undefined, { forever: () => undefined }) };
  return config(api);
}

function presetNames(): string[] {
  return (loadBabelConfig().presets ?? []).map((entry) =>
    Array.isArray(entry) ? entry[0] : entry,
  );
}

function directDependencies(): Record<string, string> {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  return { ...pkg.dependencies, ...pkg.devDependencies };
}

describe('babel presets', () => {
  it('names at least one preset', () => {
    expect(presetNames()).toContain('babel-preset-expo');
  });

  it.each(presetNames())('lists %s as a direct dependency', (name) => {
    expect(Object.keys(directDependencies())).toContain(name);
  });

  it('pins babel-preset-expo to the Expo SDK 54 line', () => {
    expect(directDependencies()['babel-preset-expo']).toMatch(/^~54\./);
  });
});
