import fs from 'fs';
import path from 'path';

import { buildDoc, OUTPUT, TEMPLATE } from '../scripts/feasibility-doc';
import {
  deviceOf,
  JETSAM_LIMIT_BYTES,
  LIMITS,
  MINIMUM_PHONE,
  verdictOf,
} from '../scripts/feasibility-report';
import fixture from './fixtures/feasibility-results.json';

const MIB = 1024 * 1024;

type Run = {
  benchmark: string;
  device: { model?: string; systemName?: string; systemVersion?: string; simulator?: boolean };
  memory: { killed: boolean; warning: boolean; peakFootprintBytes?: number; minAvailableBytes?: number };
  notes: { [key: string]: string };
  startedAt: string;
  status: string;
  thermal: { start?: string; end?: string; worst?: string };
};

/** Notes that meet every limit and check of each benchmark. */
const PASSING_NOTES: { [benchmark: string]: { [key: string]: string } } = {
  summon: { runs: '5', verifiedCount: '5', 'proveMillis-1': '4000', 'proveMillis-2': '4500' },
  'header-sync': { syncedHeaders: '1000', headerBudgetOk: 'true' },
  restore: {
    accountsFound: '3',
    accountsExpected: '3',
    scanComplete: 'true',
    balanceFromCacheSeconds: '0.5',
    timeToFirstBalanceSeconds: '4.0',
  },
  'kill-recovery': { 'killPoint.none': 'ok: paid once', killPointsPassed: '7 of 7 kill points recorded' },
  'worst-case': { cacheCountBeforeProve: '2', runs: '3', verifiedCount: '3', 'proveMillis-1': '6000' },
};

/** A real iPhone 12 run of `benchmark` that passes everything. */
function run(benchmark: string, overrides: Partial<Run> = {}, notes: { [key: string]: string | undefined } = {}): Run {
  const merged: { [key: string]: string } = { ...PASSING_NOTES[benchmark] };
  for (const [key, value] of Object.entries(notes)) {
    if (value === undefined) {
      delete merged[key];
    } else {
      merged[key] = value;
    }
  }
  return {
    benchmark,
    device: { model: 'iPhone13,2', systemName: 'iOS', systemVersion: '18.1.0' },
    memory: { killed: false, warning: false, peakFootprintBytes: 600 * MIB, minAvailableBytes: 900 * MIB },
    notes: merged,
    startedAt: '2026-10-27T09:00:00Z',
    status: 'ok',
    thermal: { start: 'nominal', end: 'fair', worst: 'fair' },
    ...overrides,
  };
}

function fails(record: Run, reason: string) {
  const { verdict, reasons } = verdictOf(record);
  expect(verdict).toBe("doesn't work");
  expect(reasons).toContain(reason);
}

function passes(record: Run) {
  expect(verdictOf(record)).toEqual({ verdict: 'works', reasons: [] });
}

const BENCHMARKS = Object.keys(PASSING_NOTES);

describe('feasibility limits', () => {
  it('passes a clean real-device run of every benchmark', () => {
    for (const benchmark of BENCHMARKS) {
      passes(run(benchmark));
    }
  });

  describe('balance on screen from cache', () => {
    it('passes at 2 s and fails just over it', () => {
      expect(LIMITS.cachedBalanceSeconds).toBe(2);
      passes(run('restore', {}, { balanceFromCacheSeconds: '2.000' }));
      fails(run('restore', {}, { balanceFromCacheSeconds: '2.001' }), 'balance from cache 2.001 s, over 2 s');
    });

    it('fails when it was not measured', () => {
      fails(
        run('restore', {}, { balanceFromCacheSeconds: undefined }),
        'balance from cache not measured (no balanceFromCacheSeconds note)',
      );
      fails(
        run('restore', {}, { balanceFromCacheSeconds: 'soon' }),
        'balance from cache not measured (no balanceFromCacheSeconds note)',
      );
    });
  });

  describe('restore time to first balance', () => {
    it('passes at 10 s and fails just over it, even when the restore found every account', () => {
      expect(LIMITS.timeToFirstBalanceSeconds).toBe(10);
      passes(run('restore', {}, { timeToFirstBalanceSeconds: '10.000' }));
      // A two-hour restore that found everything still fails.
      fails(run('restore', {}, { timeToFirstBalanceSeconds: '7200.000' }), 'time to first balance 7200 s, over 10 s');
      fails(run('restore', {}, { timeToFirstBalanceSeconds: '10.5' }), 'time to first balance 10.5 s, over 10 s');
    });

    it('fails when it was not measured', () => {
      fails(
        run('restore', {}, { timeToFirstBalanceSeconds: undefined }),
        'time to first balance not measured (no timeToFirstBalanceSeconds note)',
      );
    });
  });

  describe('Summon proof', () => {
    it('passes when the slowest proof takes 10 s and fails just over it', () => {
      expect(LIMITS.summonProofSeconds).toBe(10);
      passes(run('summon', {}, { 'proveMillis-2': '10000' }));
      fails(run('summon', {}, { 'proveMillis-2': '10001' }), 'Summon proof 10.001 s, over 10 s');
    });

    it('fails when no proof time was recorded', () => {
      fails(
        run('summon', {}, { 'proveMillis-1': undefined, 'proveMillis-2': undefined }),
        'Summon proof not measured (no proveMillis notes)',
      );
    });
  });

  describe('peak memory', () => {
    const limit = JETSAM_LIMIT_BYTES['iPhone13,2'];

    it("passes just under the device's jetsam limit and fails at it, on every benchmark", () => {
      expect(limit).toBeGreaterThan(0);
      for (const benchmark of BENCHMARKS) {
        passes(run(benchmark, { memory: { killed: false, warning: false, peakFootprintBytes: limit - 1 } }));
        fails(
          run(benchmark, { memory: { killed: false, warning: false, peakFootprintBytes: limit } }),
          `peak footprint ${(limit / MIB).toFixed(1)} MiB, not under the iPhone13,2 jetsam limit ${(limit / MIB).toFixed(1)} MiB`,
        );
      }
    });

    it("judges by each device's own limit", () => {
      const bigger = JETSAM_LIMIT_BYTES['iPhone17,1'];
      expect(bigger).toBeGreaterThan(limit);
      const device = { model: 'iPhone17,1', systemName: 'iOS', systemVersion: '18.1.0' };
      passes(run('summon', { device, memory: { killed: false, warning: false, peakFootprintBytes: limit } }));
    });

    it('fails for a model with no known limit, or no reading', () => {
      const device = { model: 'iPhone99,9', systemName: 'iOS', systemVersion: '18.1.0' };
      fails(run('summon', { device }), 'no jetsam limit known for iPhone99,9');
      fails(run('summon', { memory: { killed: false, warning: false } }), 'peak memory not measured');
    });
  });

  describe('thermal state', () => {
    it('fails at serious or above and passes at fair, on every benchmark', () => {
      for (const benchmark of BENCHMARKS) {
        passes(run(benchmark, { thermal: { worst: 'nominal' } }));
        passes(run(benchmark, { thermal: { worst: 'fair' } }));
        fails(run(benchmark, { thermal: { worst: 'serious' } }), 'thermal serious');
        fails(run(benchmark, { thermal: { worst: 'critical' } }), 'thermal critical');
      }
    });

    it('fails when the thermal state was not recorded', () => {
      fails(run('summon', { thermal: {} }), 'thermal state not measured');
      fails(run('summon', { thermal: { worst: 'unknown' } }), 'thermal state not measured');
    });
  });

  describe('header checks', () => {
    it('pass only within their budget', () => {
      passes(run('header-sync', {}, { headerBudgetOk: 'true' }));
      fails(run('header-sync', {}, { headerBudgetOk: 'false' }), 'header checks over budget');
      fails(
        run('header-sync', {}, { headerBudgetOk: undefined }),
        'header budget not measured (no headerBudgetOk note)',
      );
    });
  });

  describe('kill recovery', () => {
    it('passes only when every kill point is covered', () => {
      passes(run('kill-recovery', {}, { killPointsPassed: '7 of 7 kill points recorded' }));
      fails(run('kill-recovery', {}, { killPointsPassed: '6 of 7 kill points recorded' }), 'only 6 of 7 kill points passed');
      fails(run('kill-recovery', {}, { killPointsPassed: '0 of 0 kill points recorded' }), 'only 0 of 0 kill points passed');
    });

    it('fails when the kill points were not counted', () => {
      fails(
        run('kill-recovery', {}, { killPointsPassed: undefined }),
        'kill points not counted (no killPointsPassed note)',
      );
      fails(run('kill-recovery', {}, { killPointsPassed: 'all of them' }), 'kill points not counted (no killPointsPassed note)');
    });
  });

  describe('device', () => {
    it('tells a simulator from a real device', () => {
      expect(deviceOf(run('summon'))).toEqual({ model: 'iPhone13,2', systemVersion: '18.1.0', kind: 'real device' });
      expect(deviceOf(run('summon', { device: { model: 'arm64', systemVersion: '18.1.0' } })).kind).toBe('simulator');
      expect(deviceOf(run('summon', { device: { model: 'x86_64', systemVersion: '18.1.0' } })).kind).toBe('simulator');
      // An explicit flag wins over the model.
      expect(
        deviceOf(run('summon', { device: { model: 'iPhone13,2', systemVersion: '18.1.0', simulator: true } })).kind,
      ).toBe('simulator');
      expect(deviceOf(run('summon', { device: { model: 'iPad', systemVersion: '18.1.0' } })).kind).toBe(
        'unknown device kind',
      );
    });

    it("never passes a simulator run, even one that meets every number", () => {
      for (const benchmark of BENCHMARKS) {
        fails(
          run(benchmark, { device: { model: 'iPhone13,2', systemVersion: '18.1.0', simulator: true } }),
          "simulator run: can't pass a real-device limit",
        );
        fails(run(benchmark, { device: { model: 'arm64', systemVersion: '18.1.0' } }), "simulator run: can't pass a real-device limit");
      }
    });

    it('fails a run that does not record its model, iOS version or device kind', () => {
      fails(run('summon', { device: { model: 'iPhone13,2' } }), 'no iOS version recorded');
      fails(run('summon', { device: { systemVersion: '18.1.0' } }), 'no device model recorded');
      fails(run('summon', { device: { model: 'iPad', systemVersion: '18.1.0' } }), 'not recorded whether simulator or real device');
    });
  });

  it('takes the iPhone 12 as the minimum phone until it is decided', () => {
    expect(MINIMUM_PHONE).toEqual({ name: 'iPhone 12', models: ['iPhone13,2'] });
  });

  describe('docs/feasibility.md', () => {
    const template = fs.readFileSync(TEMPLATE, 'utf8');

    it('is the committed template, generated with no runs yet', () => {
      expect(path.relative(path.join(__dirname, '..'), OUTPUT)).toBe(path.join('docs', 'feasibility.md'));
      expect(fs.readFileSync(OUTPUT, 'utf8')).toBe(buildDoc(template, []));
    });

    it('fills in the limits, the minimum phone and the results', () => {
      const empty = buildDoc(template, []);
      expect(empty).not.toMatch(/\{\{\w+\}\}/);
      expect(empty).not.toContain('<!--');
      expect(empty).toContain('Minimum phone: iPhone 12 (iPhone13,2), until it is decided.');
      expect(empty).toContain('restore time to first balance ≤ 10 s');
      expect(empty).toContain('No Phase 0 benchmark runs recorded.');
      expect(empty).toContain('Minimum-phone (iPhone 12) real-device run still owed.');

      const withRuns = buildDoc(template, fixture);
      expect(withRuns).toContain('### iPhone13,2 (iOS 17.6.1, real device)');
      expect(withRuns).toContain('### arm64 (iOS 18.1.0, simulator)');
      expect(withRuns).not.toContain('No Phase 0 benchmark runs recorded.');
    });

    it('refuses a template that lost a placeholder or names an unknown one', () => {
      expect(() => buildDoc(template.replace('{{results}}', ''), [])).toThrow('{{results}}');
      expect(() => buildDoc(`${template}\n{{battery}}\n`, [])).toThrow('unknown placeholder {{battery}}');
    });
  });
});
