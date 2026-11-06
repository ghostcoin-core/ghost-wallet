import fs from 'fs';
import path from 'path';

import {
  MeasurementListError,
  PINNED_MEASUREMENTS,
  checkMeasurements,
  parseMeasurementList,
} from '../../lib/seal/pinned-measurements';

const ROOT = path.join(__dirname, '..', '..');
const FIXTURE = fs.readFileSync(path.join(ROOT, 'seal', 'tests', 'fixtures', 'measurements.json'), 'utf8');
const PUBLISHED = fs.readFileSync(path.join(ROOT, 'enclave', 'measurements.json'), 'utf8');

const hex = (byte: string) => byte.repeat(48);

function entry(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    name: 'seal-a',
    released: '2026-10-01',
    pcr0: hex('a1'),
    pcr1: hex('b1'),
    pcr2: hex('c1'),
    status: 'allowed',
    ...overrides,
  };
}

function list(builds: object[], extra: object = {}): string {
  return JSON.stringify({ version: 1, builds, ...extra });
}

function refused(text: string): boolean {
  try {
    parseMeasurementList(text);
    return false;
  } catch (error) {
    expect(error).toBeInstanceOf(MeasurementListError);
    return true;
  }
}

describe('the pinned measurements', () => {
  it('reads the fixture the Seal reads, to the same three builds', () => {
    const parsed = parseMeasurementList(FIXTURE);
    expect(parsed.builds.map((b) => [b.name, b.released, b.status])).toEqual([
      ['seal-2026-09-01', '2026-09-01', 'revoked'],
      ['seal-2026-10-01', '2026-10-01', 'allowed'],
      ['seal-2026-11-01', '2026-11-01', 'allowed'],
    ]);
    expect(parsed.builds[2]).toEqual({
      name: 'seal-2026-11-01',
      released: '2026-11-01',
      pcr0: hex('a2'),
      pcr1: hex('b1'),
      pcr2: hex('c2'),
      status: 'allowed',
    });
  });

  it('accepts a Seal only when all three PCRs are one allowed build', () => {
    const parsed = parseMeasurementList(FIXTURE);
    const check = (a: string, b: string, c: string) => checkMeasurements(parsed, { pcr0: hex(a), pcr1: hex(b), pcr2: hex(c) });
    expect(check('a1', 'b1', 'c1')).toEqual({ ok: true, build: parsed.builds[1] });
    expect(check('a2', 'b1', 'c2')).toEqual({ ok: true, build: parsed.builds[2] });
    expect(check('a1', 'b1', 'c2')).toEqual({ ok: false, reason: 'not-listed' });
    expect(check('a1', 'b2', 'c1')).toEqual({ ok: false, reason: 'not-listed' });
    expect(check('a1', 'b1', 'c3')).toEqual({ ok: false, reason: 'not-listed' });
    expect(check('a0', 'b0', 'c0')).toEqual({ ok: false, reason: 'revoked' });
    expect(check('00', '00', '00')).toEqual({ ok: false, reason: 'debug-mode' });
    expect(checkMeasurements(parsed, { pcr0: 'a1', pcr1: hex('b1'), pcr2: hex('c1') })).toEqual({ ok: false, reason: 'malformed' });
  });

  it('pins no build until the first one is published, so every Seal is refused', () => {
    expect(PINNED_MEASUREMENTS.builds).toEqual([]);
    expect(checkMeasurements(PINNED_MEASUREMENTS, { pcr0: hex('a1'), pcr1: hex('b1'), pcr2: hex('c1') })).toEqual({
      ok: false,
      reason: 'not-listed',
    });
  });

  it('pins only builds that are on the published list, with the same PCRs, never one it revoked', () => {
    const published = parseMeasurementList(PUBLISHED);
    for (const pinned of PINNED_MEASUREMENTS.builds) {
      const match = published.builds.find((b) => b.name === pinned.name);
      expect(match).toBeDefined();
      expect([match?.pcr0, match?.pcr1, match?.pcr2]).toEqual([pinned.pcr0, pinned.pcr1, pinned.pcr2]);
      if (match?.status === 'revoked') {
        expect(pinned.status).toBe('revoked');
      }
    }
  });

  it('refuses the wrong version and unknown or missing fields', () => {
    expect(refused(JSON.stringify({ version: 2, builds: [] }))).toBe(true);
    expect(refused('{"version": "1", "builds": []}')).toBe(true);
    expect(refused('{"version": 1.0, "builds": []}')).toBe(true);
    expect(refused('{"builds": []}')).toBe(true);
    expect(refused(list([], { extra: true }))).toBe(true);
    expect(refused(list([{ ...entry(), note: 'x' }]))).toBe(true);
    for (const field of ['name', 'released', 'pcr0', 'pcr1', 'pcr2', 'status']) {
      const missing: Record<string, string> = entry();
      delete missing[field];
      expect(refused(list([missing]))).toBe(true);
    }
    expect(refused(list([entry()]))).toBe(false);
  });

  it('refuses bad PCRs, names, dates and statuses', () => {
    for (const pcr0 of [hex('AB'), hex('a1').slice(2), `${hex('a1')}aa`, `${hex('a1').slice(2)}zz`, hex('00')]) {
      expect(refused(list([entry({ pcr0 })]))).toBe(true);
    }
    for (const name of ['', 'seal a', 'x'.repeat(65)]) {
      expect(refused(list([entry({ name })]))).toBe(true);
    }
    for (const released of ['2026-02-30', '2026-13-01', '2026-1-01', '26-10-01', '1999-10-01']) {
      expect(refused(list([entry({ released })]))).toBe(true);
    }
    expect(refused(list([entry({ released: '2028-02-29' })]))).toBe(false);
    for (const status of ['Allowed', 'deprecated', '']) {
      expect(refused(list([entry({ status })]))).toBe(true);
    }
  });

  it('refuses a build listed twice, but lets builds share PCR1', () => {
    const other = entry({ name: 'seal-b', pcr0: hex('a2'), pcr2: hex('c2') });
    expect(refused(list([entry(), other]))).toBe(false);
    expect(refused(list([entry(), { ...other, name: 'seal-a' }]))).toBe(true);
    expect(refused(list([entry(), entry({ name: 'seal-b', status: 'revoked' })]))).toBe(true);
  });

  it('refuses JSON that is not strict, as the Seal does', () => {
    const good = list([entry()]);
    expect(refused(`${good} {}`)).toBe(true);
    expect(refused(good.replace(']}', '],}'))).toBe(true);
    expect(refused(good.replace('"version":1,', '"version":1,"version":1,'))).toBe(true);
    expect(refused('')).toBe(true);
    expect(refused('[]')).toBe(true);
    expect(refused(`${'['.repeat(40)}${']'.repeat(40)}`)).toBe(true);
    const spaced = good.replace(/,/g, ',\n\t ').replace('seal-a', 'seal\\u002da');
    expect(parseMeasurementList(spaced)).toEqual(parseMeasurementList(good));
  });
});
