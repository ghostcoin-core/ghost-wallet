// The app points at the live Seal: its regions in the Seal's release order,
// each at an https address, and every build on the signed published list
// pinned in the app with the same PCRs.
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import { parseMeasurementList, PINNED_MEASUREMENTS } from '../../lib/seal/pinned-measurements';
import { SEAL_REGIONS } from '../../lib/seal/seal-config';

const ROOT = path.join(__dirname, '..', '..');
const read = (...parts: string[]) => fs.readFileSync(path.join(ROOT, ...parts));

/** SHA-256 of the signed list the live Seal's release published. */
const SIGNED_LIST_SHA256 = 'dfd0c5c1bea5b6dfced1df13a89965bc3604c6c568a38013ac58753a174f9a6e';

/** The Seal's compiled-in region order, read from its source. */
function releaseRegions(): string[] {
  const source = read('seal', 'src', 'journal_anchor.rs').toString('utf8');
  const match = /pub const RELEASE_REGIONS: \[&str; (\d+)\] = \[([^\]]*)\];/.exec(source);
  expect(match).not.toBeNull();
  const ids = [...match![2].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  expect(ids).toHaveLength(Number(match![1]));
  return ids;
}

describe('SEAL_REGIONS', () => {
  it("lists the Seal's release regions, in its order, with the same ids", () => {
    const release = releaseRegions();
    expect(release.length).toBeGreaterThan(0);
    expect(SEAL_REGIONS.map((r) => r.id)).toEqual(release);
    // The deploy's region list agrees.
    const deploy = JSON.parse(read('enclave', 'deploy', 'regions.json').toString('utf8'));
    expect(deploy.regions.map((r: { region: string }) => r.region)).toEqual(release);
  });

  it('gives each region its own https address, on the default port, and nothing else', () => {
    expect(SEAL_REGIONS).toEqual([
      { id: 'us-east-1', url: 'https://23.20.15.18' },
      { id: 'eu-central-1', url: 'https://63.185.166.165' },
      { id: 'ap-southeast-1', url: 'https://18.140.26.20' },
    ]);
    for (const region of SEAL_REGIONS) {
      const url = new URL(region.url);
      expect([region.id, url.protocol]).toEqual([region.id, 'https:']);
      expect([region.id, url.port, url.pathname, url.search, url.username]).toEqual([region.id, '', '/', '', '']);
    }
    expect(new Set(SEAL_REGIONS.map((r) => r.url)).size).toBe(SEAL_REGIONS.length);
  });
});

describe('the published list', () => {
  const bytes = read('enclave', 'measurements.json');
  const text = bytes.toString('utf8');

  it('is exactly the signed list of the live release, signature and all', () => {
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(SIGNED_LIST_SHA256);
    expect(bytes.length).toBe(7905);
    expect(text.endsWith('}\n')).toBe(true);
    expect(text.endsWith('\n\n')).toBe(false);
    const signature = JSON.parse(text).signature;
    expect(typeof signature).toBe('string');
    expect(signature).toMatch(/^[0-9a-f]{6618}$/);
  });

  it('reads with the app\'s strict reader, one allowed build per release region', () => {
    const published = parseMeasurementList(text);
    expect(published.builds.map((b) => b.name)).toEqual(releaseRegions().map((id) => `seal-2026-11-07c-${id}`));
    expect(published.builds.every((b) => b.status === 'allowed')).toBe(true);
  });

  it('has every build pinned in the app with equal PCRs, name, date and status', () => {
    const published = parseMeasurementList(text);
    expect(published.builds.length).toBeGreaterThan(0);
    for (const build of published.builds) {
      const pinned = PINNED_MEASUREMENTS.builds.find((b) => b.name === build.name);
      expect([build.name, pinned]).toEqual([build.name, build]);
    }
    expect(PINNED_MEASUREMENTS.builds).toHaveLength(published.builds.length);
  });
});
