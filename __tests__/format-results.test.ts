import { formatResults, formatResultsText } from '../scripts/format-results';
import fixture from './fixtures/bench-results.json';

// The file as pulled off the phone.
const FIXTURE = JSON.stringify(fixture, null, 2);

function cells(line: string): string[] {
  return line.split(' | ').map((cell) => cell.trim());
}

describe('format-results', () => {
  it('prints a header, a separator and one row per run', () => {
    const lines = formatResultsText(FIXTURE).split('\n');

    expect(lines).toHaveLength(4);
    expect(cells(lines[0])).toEqual([
      'started',
      'device',
      'iOS',
      'benchmark',
      'status',
      'stages',
      'total',
      'peak RSS',
      'peak footprint',
      'least avail',
      'mem warn',
      'killed',
      'thermal (start>end, worst)',
      'battery drop',
    ]);
    expect(lines[1]).toMatch(/^-+(-\+-+)+$/);
  });

  it('shows the numbers of a finished run', () => {
    const row = cells(formatResultsText(FIXTURE).split('\n')[2]);

    expect(row).toEqual([
      '2026-10-20T09:15:00Z',
      'iPhone16,1',
      '18.1.0',
      'dummy',
      'ok',
      'allocate 0.84s, hash 30.00s',
      '30.85s',
      '670.0 MiB',
      '660.0 MiB',
      '1200.0 MiB',
      'no',
      'no',
      'nominal>fair, fair',
      '1.0%',
    ]);
  });

  it('shows a killed run with its memory warning and an unknown battery drop', () => {
    const row = cells(formatResultsText(FIXTURE).split('\n')[3]);

    expect(row[4]).toBe('killed');
    expect(row[5]).toBe('allocate 1.50s');
    expect(row[7]).toBe('2100.0 MiB');
    expect(row[9]).toBe('50.0 MiB');
    expect(row[10]).toBe('yes');
    expect(row[11]).toBe('yes');
    expect(row[12]).toBe('fair>serious, serious');
    expect(row[13]).toBe('-');
  });

  it('aligns every column', () => {
    const lines = formatResultsText(FIXTURE).split('\n');
    const header = lines[0];
    const firstRow = lines[2];

    const headerBars = [...header].flatMap((char, index) => (char === '|' ? [index] : []));
    const rowBars = [...firstRow].flatMap((char, index) => (char === '|' ? [index] : []));
    expect(rowBars).toEqual(headerBars);
  });

  it('shows a failed run with its error', () => {
    const table = formatResults([
      { benchmark: 'dummy', status: 'failed', error: 'out of memory', stages: [] },
    ]);

    expect(cells(table.split('\n')[2])[4]).toBe('failed (out of memory)');
  });

  it('says so when no run is recorded', () => {
    expect(formatResultsText('[]')).toBe('No benchmark runs recorded.');
  });

  it('rejects a file that is not a JSON array of records', () => {
    expect(() => formatResultsText('{"benchmark": "dummy"}')).toThrow('JSON array');
    expect(() => formatResultsText('not json')).toThrow('not valid JSON');
  });
});
