import { buildReport, buildReportText, THRESHOLDS, verdictOf } from '../scripts/feasibility-report';
import fixture from './fixtures/feasibility-results.json';

const MIB = 1024 * 1024;

/** One run record, as the phone writes it to bench-results.json. */
type RunRecord = {
  benchmark: string;
  device: { model: string; systemName: string; systemVersion: string; lowPowerMode: boolean };
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

/** The table lines of one phone's section of the report. */
function section(report: string, model: string): string[] {
  const lines = report.split('\n');
  const start = lines.findIndex((line) => line.startsWith(`## ${model}`));
  expect(start).toBeGreaterThanOrEqual(0);
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((line) => line.startsWith('## '));
  return (end === -1 ? rest : rest.slice(0, end)).filter((line) => line.startsWith('|'));
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

const VERDICT = 8;
const WHY = 9;

function ok(overrides: Partial<RunRecord> = {}): RunRecord {
  return {
    benchmark: 'header-sync',
    device: { model: 'iPhone17,1', systemName: 'iOS', systemVersion: '18.1.0', lowPowerMode: false },
    memory: {
      killed: false,
      warning: false,
      peakFootprintBytes: 500 * MIB,
      peakResidentBytes: 500 * MIB,
      minAvailableBytes: 2000 * MIB,
    },
    notes: {},
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
    for (const model of ['iPhone17,1', 'iPhone13,2']) {
      expect([...rows(report, model).keys()]).toEqual([
        'summon',
        'header-sync',
        'restore',
        'kill-recovery',
        'worst-case',
      ]);
    }
    expect(report).not.toContain('dummy');
  });

  it('names each phone with its iOS version', () => {
    expect(report).toContain('## iPhone17,1 (iOS 18.1.0)');
    expect(report).toContain('## iPhone13,2 (iOS 17.6.1)');
  });

  it('judges the first phone from its latest run of each benchmark', () => {
    const phone = rows(report, 'iPhone17,1');

    expect(phone.get('summon')![VERDICT]).toBe('works');
    expect(phone.get('summon')![7]).toBe('verified 5/5, prove 4100-4800 ms, proof bytes 1800');

    expect(phone.get('header-sync')![VERDICT]).toBe('works with limits');
    expect(phone.get('header-sync')![WHY]).toBe('thermal serious');

    expect(phone.get('restore')![VERDICT]).toBe("doesn't work");
    expect(phone.get('restore')![WHY]).toBe('found 2 of 3 accounts');

    // The failed run is older and the deliberate kill is not judged.
    expect(phone.get('kill-recovery')![1]).toBe('2026-10-20T09:40:00Z');
    expect(phone.get('kill-recovery')![VERDICT]).toBe('works');

    // The later worst-case run, with its memory warning and 1.6 GiB.
    const worst = phone.get('worst-case')!;
    expect(worst[1]).toBe('2026-10-20T10:30:00Z');
    expect(worst[3]).toBe('1640.0 MiB');
    expect(worst[4]).toBe('yes');
    expect(worst[7]).toBe('caches 2, verified 3/3, prove 5600-7000 ms');
    expect(worst[VERDICT]).toBe('works with limits');
    expect(worst[WHY]).toBe('memory warning; peak footprint 1640.0 MiB');
  });

  it('judges the second phone, with a benchmark not run', () => {
    const phone = rows(report, 'iPhone13,2');

    expect(phone.get('summon')![VERDICT]).toBe("doesn't work");
    expect(phone.get('summon')![WHY]).toBe('status killed; killed; only 1 of 5 proofs verified');
    expect(phone.get('header-sync')![VERDICT]).toBe('works');
    expect(phone.get('restore')![VERDICT]).toBe('not run');
    expect(phone.get('kill-recovery')![VERDICT]).toBe("doesn't work");
    expect(phone.get('kill-recovery')![WHY]).toBe(
      'killPoint.prepared: FAILED: the record is gone and the chain has 0 payments',
    );
    expect(phone.get('worst-case')![VERDICT]).toBe("doesn't work");
    expect(phone.get('worst-case')![WHY]).toContain('1 RandomX caches held, not 2');
  });

  it("puts a PLAN change line right under each doesn't-work row and nowhere else", () => {
    for (const model of ['iPhone17,1', 'iPhone13,2']) {
      const lines = section(report, model).slice(2);
      lines.forEach((line, index) => {
        const row = cells(line);
        const isPlanLine = line.includes('PLAN change needed: (fill in)');
        if (isPlanLine) {
          expect(row[0]).toBe('');
          expect(cells(lines[index - 1])[VERDICT]).toBe("doesn't work");
        } else if (row[VERDICT] === "doesn't work") {
          expect(lines[index + 1]).toContain('PLAN change needed: (fill in)');
        }
      });
    }
    expect(report.match(/PLAN change needed: \(fill in\)/g)).toHaveLength(4);
  });

  it('does not say an older-phone run is owed when two phones ran', () => {
    expect(report).not.toContain('Older-phone run still owed.');
  });

  it('ends with the older-phone run owed when only one phone ran', () => {
    const onePhone = fixture.filter((record) => record.device.model === 'iPhone17,1');
    const single = buildReport(onePhone);

    expect(single).not.toContain('iPhone13,2');
    expect(single.trimEnd().endsWith('Older-phone run still owed.')).toBe(true);
  });

  it('shows the thresholds it judged by', () => {
    expect(report).toContain('2048.0 MiB or more');
    expect(report).toContain('1536.0 MiB or more');
    expect(report).toContain('serious or critical');
  });

  describe('verdicts', () => {
    it('is works for a clean run', () => {
      expect(verdictOf(ok())).toEqual({ verdict: 'works', reasons: [] });
    });

    it("is doesn't work at the footprint limit, and with limits just below it", () => {
      const at = ok({ memory: { ...ok().memory, peakFootprintBytes: THRESHOLDS.doesntWorkFootprintBytes } });
      const below = ok({ memory: { ...ok().memory, peakFootprintBytes: THRESHOLDS.doesntWorkFootprintBytes - 1 } });
      expect(verdictOf(at).verdict).toBe("doesn't work");
      expect(verdictOf(below).verdict).toBe('works with limits');
    });

    it('is works with limits at the lower footprint limit, and works just below it', () => {
      const at = ok({ memory: { ...ok().memory, peakFootprintBytes: THRESHOLDS.limitsFootprintBytes } });
      const below = ok({ memory: { ...ok().memory, peakFootprintBytes: THRESHOLDS.limitsFootprintBytes - 1 } });
      expect(verdictOf(at).verdict).toBe('works with limits');
      expect(verdictOf(below).verdict).toBe('works');
    });

    it('is works with limits at critical heat', () => {
      const hot = ok({ thermal: { start: 'fair', end: 'critical', worst: 'critical' } });
      expect(verdictOf(hot)).toEqual({ verdict: 'works with limits', reasons: ['thermal critical'] });
    });

    it("is doesn't work for a failed or killed run", () => {
      expect(verdictOf(ok({ status: 'failed', error: 'no node' })).reasons).toEqual(['status failed: no node']);
      expect(verdictOf(ok({ memory: { ...ok().memory, killed: true } })).verdict).toBe("doesn't work");
    });

    it("is doesn't work for a restore whose scan did not complete", () => {
      const run = ok({
        benchmark: 'restore',
        notes: { accountsFound: '3', accountsExpected: '3', scanComplete: 'false' },
      });
      expect(verdictOf(run)).toEqual({ verdict: "doesn't work", reasons: ['scan not complete'] });
      const complete = ok({
        benchmark: 'restore',
        notes: { accountsFound: '3', accountsExpected: '3', scanComplete: 'true' },
      });
      expect(verdictOf(complete).verdict).toBe('works');
    });

    it("is doesn't work for a kill point that paid twice", () => {
      const run = ok({
        benchmark: 'kill-recovery',
        notes: { 'killPoint.sent': 'FAILED: broadcast 2 times', 'killPoint.none': 'ok: paid once' },
      });
      expect(verdictOf(run)).toEqual({
        verdict: "doesn't work",
        reasons: ['killPoint.sent: FAILED: broadcast 2 times'],
      });
    });

    it("is doesn't work for a worst case that proved all three but without both caches", () => {
      const run = ok({
        benchmark: 'worst-case',
        notes: { cacheCountBeforeProve: '1', runs: '3', verifiedCount: '3' },
      });
      expect(verdictOf(run).verdict).toBe("doesn't work");
      const both = ok({
        benchmark: 'worst-case',
        notes: { cacheCountBeforeProve: '2', runs: '3', verifiedCount: '3' },
      });
      expect(verdictOf(both).verdict).toBe('works');
    });
  });

  it('reads the results file text, and rejects what is not an array', () => {
    expect(buildReportText(JSON.stringify(fixture))).toBe(report);
    expect(buildReportText('[]')).toContain('No Phase 0 benchmark runs recorded.');
    expect(() => buildReportText('{}')).toThrow('JSON array');
    expect(() => buildReportText('not json')).toThrow('not valid JSON');
  });
});
