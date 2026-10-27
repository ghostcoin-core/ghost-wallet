import { buildReport, buildReportText, STRESS_LABEL, verdictOf } from '../scripts/feasibility-report';
import fixture from './fixtures/feasibility-results.json';

const MIB = 1024 * 1024;

/** One run record, as the phone writes it to bench-results.json. */
type RunRecord = {
  benchmark: string;
  device: { model: string; systemName: string; systemVersion: string; lowPowerMode: boolean; simulator?: boolean };
  memory: {
    killed: boolean;
    warning: boolean;
    peakFootprintBytes: number;
    peakResidentBytes: number;
    minAvailableBytes: number;
  };
  notes: { [key: string]: string };
  stages: { name: string; seconds: number }[];
  startedAt: string;
  status: string;
  error?: string;
  thermal: { start: string; end: string; worst: string };
  totalSeconds: number;
};

function cells(line: string): string[] {
  return line
    .replace(/^\|\s?/, '')
    .replace(/\s?\|$/, '')
    .split(' | ')
    .map((cell) => cell.trim());
}

/** The lines of one phone's section of the report. */
function sectionLines(report: string, model: string): string[] {
  const lines = report.split('\n');
  const start = lines.findIndex((line) => line.startsWith(`## ${model} `));
  expect(start).toBeGreaterThanOrEqual(0);
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((line) => line.startsWith('## '));
  return end === -1 ? rest : rest.slice(0, end);
}

/** The table lines of one phone's section of the report. */
function section(report: string, model: string): string[] {
  return sectionLines(report, model).filter((line) => line.startsWith('|'));
}

/** Benchmark name -> its row's cells, for one phone (the header row and divider skipped). */
function rows(report: string, model: string): Map<string, string[]> {
  const byName = new Map<string, string[]>();
  for (const line of section(report, model).slice(2)) {
    const row = cells(line);
    if (row[0] !== '') {
      byName.set(row[0], row);
    }
  }
  return byName;
}

const RUN = 1;
const DEVICE = 2;
const FOOTPRINT = 4;
const WARNING = 5;
const KEY_NUMBERS = 8;
const VERDICT = 9;
const WHY = 10;
const WORST_CASE = 'worst-case (stress benchmark only)';

function ok(overrides: Partial<RunRecord> = {}): RunRecord {
  return {
    benchmark: 'kill-recovery',
    device: { model: 'iPhone13,2', systemName: 'iOS', systemVersion: '18.1.0', lowPowerMode: false },
    memory: {
      killed: false,
      warning: false,
      peakFootprintBytes: 500 * MIB,
      peakResidentBytes: 500 * MIB,
      minAvailableBytes: 1000 * MIB,
    },
    notes: { killPointsPassed: '7 of 7 kill points recorded' },
    stages: [],
    startedAt: '2026-10-20T09:00:00Z',
    status: 'ok',
    thermal: { start: 'nominal', end: 'fair', worst: 'fair' },
    totalSeconds: 1,
    ...overrides,
  };
}

describe('feasibility-report', () => {
  const report = buildReport(fixture);

  it('gives every Phase 0 benchmark one row per phone, in order', () => {
    for (const model of ['iPhone17,1', 'iPhone13,2', 'arm64']) {
      expect([...rows(report, model).keys()]).toEqual([
        'summon',
        'header-sync',
        'restore',
        'kill-recovery',
        WORST_CASE,
      ]);
    }
    expect(report).not.toContain('dummy');
  });

  it('labels the worst case a stress benchmark only', () => {
    expect(STRESS_LABEL).toBe('stress benchmark only');
    expect(report).toContain('- worst-case is a stress benchmark only');
    expect(report).not.toMatch(/\| worst-case \|/);
    const notRun = buildReport(fixture.filter((record) => record.benchmark !== 'worst-case'));
    expect(rows(notRun, 'iPhone17,1').get(WORST_CASE)![VERDICT]).toBe('not run');
  });

  it('names each phone with its iOS version and whether it is a simulator', () => {
    expect(report).toContain('## iPhone17,1 (iOS 18.1.0, real device)');
    expect(report).toContain('## iPhone13,2 (iOS 17.6.1, real device)');
    expect(report).toContain('## arm64 (iOS 18.1.0, simulator)');
  });

  it('records the device of every run in its row', () => {
    expect(rows(report, 'iPhone13,2').get('summon')![DEVICE]).toBe('iPhone13,2, iOS 17.6.1, real device');
    expect(rows(report, 'arm64').get('summon')![DEVICE]).toBe('arm64, iOS 18.1.0, simulator');
  });

  it('judges the first phone from its latest run of each benchmark', () => {
    const phone = rows(report, 'iPhone17,1');

    expect(phone.get('summon')![VERDICT]).toBe('works');
    expect(phone.get('summon')![KEY_NUMBERS]).toBe('verified 5/5, prove 4100-4800 ms, proof bytes 1800');

    // Serious heat now fails the run.
    expect(phone.get('header-sync')![VERDICT]).toBe("doesn't work");
    expect(phone.get('header-sync')![WHY]).toBe('thermal serious');
    expect(phone.get('header-sync')![KEY_NUMBERS]).toBe(
      'headers 4000, headers/s 12.5, max caches 2, resume s 9.000, budget ok true',
    );

    expect(phone.get('restore')![VERDICT]).toBe("doesn't work");
    expect(phone.get('restore')![WHY]).toBe('found 2 of 3 accounts');
    expect(phone.get('restore')![KEY_NUMBERS]).toBe(
      'accounts 2/3, scan complete true, cached balance s 0.800, first balance s 4.200, restore s 61.000',
    );

    // The failed run is older and the deliberate kill is not judged.
    expect(phone.get('kill-recovery')![RUN]).toBe('2026-10-20T09:40:00Z');
    expect(phone.get('kill-recovery')![VERDICT]).toBe('works');

    // The later worst-case run, with its memory warning and 1.6 GiB, under the 4 GiB limit.
    const worst = phone.get(WORST_CASE)!;
    expect(worst[RUN]).toBe('2026-10-20T10:30:00Z');
    expect(worst[FOOTPRINT]).toBe('1640.0 MiB');
    expect(worst[WARNING]).toBe('yes');
    expect(worst[KEY_NUMBERS]).toBe('caches 2, verified 3/3, prove 5600-7000 ms');
    expect(worst[VERDICT]).toBe('works with limits');
    expect(worst[WHY]).toBe('memory warning');

    expect(sectionLines(report, 'iPhone17,1')).toContain(
      "Verdict: fails (header-sync doesn't work, restore doesn't work).",
    );
  });

  it('judges the second phone, with a benchmark not run', () => {
    const phone = rows(report, 'iPhone13,2');

    expect(phone.get('summon')![VERDICT]).toBe("doesn't work");
    expect(phone.get('summon')![WHY]).toBe('status killed; killed; only 1 of 5 proofs verified; thermal serious');
    expect(phone.get('header-sync')![VERDICT]).toBe("doesn't work");
    expect(phone.get('header-sync')![WHY]).toBe('header checks over budget');
    expect(phone.get('restore')![VERDICT]).toBe('not run');
    expect(phone.get('kill-recovery')![VERDICT]).toBe("doesn't work");
    expect(phone.get('kill-recovery')![WHY]).toBe(
      'only 6 of 7 kill points passed; killPoint.prepared: FAILED: the record is gone and the chain has 0 payments',
    );
    expect(phone.get(WORST_CASE)![VERDICT]).toBe("doesn't work");
    expect(phone.get(WORST_CASE)![WHY]).toContain('1 RandomX caches held, not 2');
  });

  it("never passes a simulator run, however good its numbers", () => {
    const summon = rows(report, 'arm64').get('summon')!;
    expect(summon[VERDICT]).toBe("doesn't work");
    expect(summon[WHY]).toContain("simulator run: can't pass a real-device limit");
  });

  it("puts a PLAN change line right under each doesn't-work row but the stress one, and nowhere else", () => {
    for (const model of ['iPhone17,1', 'iPhone13,2', 'arm64']) {
      const lines = section(report, model).slice(2);
      lines.forEach((line, index) => {
        const row = cells(line);
        const isPlanLine = line.includes('PLAN change needed: (fill in)');
        if (isPlanLine) {
          expect(row[0]).toBe('');
          expect(row[VERDICT]).toBe('PLAN change needed: (fill in)');
          expect(cells(lines[index - 1])[VERDICT]).toBe("doesn't work");
          expect(cells(lines[index - 1])[0]).not.toBe(WORST_CASE);
        } else if (row[VERDICT] === "doesn't work" && row[0] !== WORST_CASE) {
          expect(lines[index + 1]).toContain('PLAN change needed: (fill in)');
        } else if (row[0] === WORST_CASE) {
          expect(lines[index + 1] ?? '').not.toContain('PLAN change needed');
        }
      });
    }
    // Header-sync and restore on the first phone; summon, header-sync and
    // kill-recovery on the second (not its stress worst case); summon in the simulator.
    expect(report.match(/PLAN change needed: \(fill in\)/g)).toHaveLength(6);
  });

  it('does not say a minimum-phone run is owed when the iPhone 12 ran on a real device', () => {
    expect(report).not.toContain('real-device run still owed');
  });

  it('ends with the minimum-phone run owed when the iPhone 12 did not run', () => {
    const onePhone = fixture.filter((record) => record.device.model === 'iPhone17,1');
    const single = buildReport(onePhone);

    expect(single).not.toContain('iPhone13,2 (');
    expect(single.trimEnd().endsWith('Minimum-phone (iPhone 12) real-device run still owed.')).toBe(true);
  });

  it('owes the minimum-phone run when the iPhone 12 ran only in the simulator', () => {
    const simulated = fixture
      .filter((record) => record.device.model === 'iPhone13,2')
      .map((record) => ({ ...record, device: { ...record.device, simulator: true } }));
    const single = buildReport(simulated);

    expect(single).toContain('## iPhone13,2 (iOS 17.6.1, simulator)');
    expect(single).toContain('Minimum-phone (iPhone 12) real-device run still owed.');
  });

  it('shows the limits it judged by and the minimum phone', () => {
    expect(report).toContain('balance on screen ≤ 2 s from cache');
    expect(report).toContain('restore time to first balance ≤ 10 s');
    expect(report).toContain('every Summon proof ≤ 10 s');
    expect(report).toContain("peak memory under the device's jetsam limit");
    expect(report).toContain('no thermal state of serious or critical');
    expect(report).toContain('header checks within their budget');
    expect(report).toContain('"N of M" with N = M');
    expect(report).toContain('Minimum phone: iPhone 12 (iPhone13,2), until it is decided.');
  });

  describe('verdicts', () => {
    it('is works for a clean real-device run', () => {
      expect(verdictOf(ok())).toEqual({ verdict: 'works', reasons: [] });
    });

    it('is works with limits for a memory warning', () => {
      expect(verdictOf(ok({ memory: { ...ok().memory, warning: true } }))).toEqual({
        verdict: 'works with limits',
        reasons: ['memory warning'],
      });
    });

    it("is doesn't work for a failed or killed run", () => {
      expect(verdictOf(ok({ status: 'failed', error: 'no node' })).reasons).toEqual(['status failed: no node']);
      expect(verdictOf(ok({ memory: { ...ok().memory, killed: true } })).verdict).toBe("doesn't work");
    });

    it("is doesn't work for a restore whose scan did not complete", () => {
      const notes = { accountsFound: '3', accountsExpected: '3', balanceFromCacheSeconds: '1', timeToFirstBalanceSeconds: '5' };
      const run = ok({ benchmark: 'restore', notes: { ...notes, scanComplete: 'false' } });
      expect(verdictOf(run)).toEqual({ verdict: "doesn't work", reasons: ['scan not complete'] });
      const complete = ok({ benchmark: 'restore', notes: { ...notes, scanComplete: 'true' } });
      expect(verdictOf(complete).verdict).toBe('works');
    });

    it("is doesn't work for a kill point that paid twice", () => {
      const run = ok({
        notes: {
          'killPoint.sent': 'FAILED: broadcast 2 times',
          'killPoint.none': 'ok: paid once',
          killPointsPassed: '7 of 7 kill points recorded',
        },
      });
      expect(verdictOf(run)).toEqual({
        verdict: "doesn't work",
        reasons: ['killPoint.sent: FAILED: broadcast 2 times'],
      });
    });

    it("is doesn't work for a worst case that proved all three but without both caches", () => {
      const run = ok({
        benchmark: 'worst-case',
        notes: { workerStress: 'true', cacheCountBeforeProve: '1', runs: '3', verifiedCount: '3' },
      });
      expect(verdictOf(run).verdict).toBe("doesn't work");
      const both = ok({
        benchmark: 'worst-case',
        notes: { workerStress: 'true', cacheCountBeforeProve: '2', runs: '3', verifiedCount: '3' },
      });
      expect(verdictOf(both).verdict).toBe('works');
    });

    it("is doesn't work for a worst case not run as the stress case", () => {
      const notStress = ok({
        benchmark: 'worst-case',
        notes: { workerStress: 'false', cacheCountBeforeProve: '2', runs: '3', verifiedCount: '3' },
      });
      expect(verdictOf(notStress)).toEqual({
        verdict: "doesn't work",
        reasons: ['workerStress false: not run as the stress case'],
      });
      // A run from before the note existed is judged by its caches alone.
      const unnoted = ok({
        benchmark: 'worst-case',
        notes: { cacheCountBeforeProve: '2', runs: '3', verifiedCount: '3' },
      });
      expect(verdictOf(unnoted).verdict).toBe('works');
    });

    it("is doesn't work for a header sync over its run budget or without the note", () => {
      const header = (notes: { [key: string]: string }) => ok({ benchmark: 'header-sync', notes });
      expect(verdictOf(header({ headerBudgetOk: 'true' }))).toEqual({ verdict: 'works', reasons: [] });
      expect(verdictOf(header({ headerBudgetOk: 'false' }))).toEqual({
        verdict: "doesn't work",
        reasons: ['header checks over budget'],
      });
      expect(verdictOf(header({}))).toEqual({
        verdict: "doesn't work",
        reasons: ['header budget not measured (no headerBudgetOk note)'],
      });
      // Other benchmarks do not need the note.
      const summon = ok({ benchmark: 'summon', notes: { runs: '1', verifiedCount: '1', 'proveMillis-1': '4000' } });
      expect(verdictOf(summon).verdict).toBe('works');
    });
  });

  it('reads the results file text, and rejects what is not an array', () => {
    expect(buildReportText(JSON.stringify(fixture))).toBe(report);
    expect(buildReportText('[]')).toContain('No Phase 0 benchmark runs recorded.');
    expect(() => buildReportText('{}')).toThrow('JSON array');
    expect(() => buildReportText('not json')).toThrow('not valid JSON');
  });
});
