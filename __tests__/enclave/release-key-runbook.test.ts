import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const ROOT = path.join(__dirname, '..', '..');
const RUNBOOK = fs.readFileSync(path.join(ROOT, 'enclave', 'RUNBOOK.md'), 'utf8');
const MEASUREMENTS_RS = fs.readFileSync(path.join(ROOT, 'seal', 'src', 'measurements.rs'), 'utf8');

function section(title: string): string {
  const start = RUNBOOK.indexOf(`## ${title}`);
  expect(start).toBeGreaterThanOrEqual(0);
  const next = RUNBOOK.indexOf('\n## ', start + 3);
  return RUNBOOK.slice(start, next === -1 ? undefined : next);
}

describe('the release key runbook', () => {
  const releaseKey = section('Release key (once, before the first image)');

  it('names the tool and how to build it on the builder', () => {
    expect(releaseKey).toContain('tools/seal-release-key');
    expect(releaseKey).toContain(
      'cargo build --release --locked --manifest-path tools/seal-release-key/Cargo.toml',
    );
    expect(releaseKey).toMatch(/SHA-256/);
  });

  it('makes the key on the offline machine and brings back only the public hex', () => {
    expect(releaseKey).toMatch(/offline machine/);
    expect(releaseKey).toContain('seal-release-key keygen --out release.key');
    expect(releaseKey).toMatch(/Carry back only the public hex/);
    expect(releaseKey).toContain('RELEASE_KEY_HEX');
    expect(releaseKey).toMatch(/Keep `release\.key` on the offline machine/);
  });

  it('signs and verifies each list offline, with the release context', () => {
    expect(releaseKey).toContain(
      'seal-release-key sign measurements.json --key release.key --out measurements.signed.json',
    );
    expect(releaseKey).toContain('seal-release-key verify measurements.signed.json --public');
    expect(releaseKey).toContain('ghost-seal measurements');
    expect(releaseKey).toContain('ghost-seal/v1/measurements/release');
    expect(releaseKey).toMatch(/Carry back only `measurements\.signed\.json`/);
  });

  it('repeats that the private half never leaves the offline machine', () => {
    expect(releaseKey).toMatch(
      /private half is never on a networked machine, in the repository, in an\s+image or in a fixture/,
    );
    expect(section('Never')).toMatch(/Never let the release key's private half onto a networked machine/);
  });
});

// SHA-256 of the release key's public hex, as recorded when the key was made
// offline. The image must compile in exactly this key and no other.
const RELEASE_KEY_HEX_SHA256 = '57755184a6489543d30d5b2f88d9ec9b619bccf7b8a49d4ee59aa268efd16009';

describe('the compiled-in release key', () => {
  const declarations = MEASUREMENTS_RS.match(/^pub const RELEASE_KEY_HEX: &str = "([^"\n]*)";$/gm) ?? [];
  const compiledIn = /"([^"]*)"/.exec(declarations[0] ?? '')?.[1] ?? '';

  it('is declared once, on one line', () => {
    expect(declarations).toHaveLength(1);
  });

  it('is the ML-DSA-65 public half as 3904 lowercase hex digits', () => {
    expect(compiledIn).toHaveLength(3904);
    expect(compiledIn).toMatch(/^[0-9a-f]{3904}$/);
  });

  it('is the release key made offline, by its recorded SHA-256', () => {
    const digest = crypto.createHash('sha256').update(compiledIn, 'utf8').digest('hex');
    expect(digest).toBe(RELEASE_KEY_HEX_SHA256);
  });
});
