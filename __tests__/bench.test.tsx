import { act, fireEvent, render, screen, waitFor } from '@testing-library/react-native';

import BenchScreen from '../app/bench';
import type { BenchRecord } from '../modules/ghost-bench';

const RECORD: BenchRecord = {
  status: 'ok',
  benchmark: 'dummy',
  startedAt: '2026-10-20T09:15:00Z',
  device: { model: 'iPhone16,1', systemName: 'iOS', systemVersion: '18.1.0', lowPowerMode: false },
  stages: [
    { name: 'allocate', seconds: 0.8421 },
    { name: 'hash', seconds: 30.0012 },
  ],
  totalSeconds: 30.8501,
  memory: {
    peakResidentBytes: 702545920,
    peakFootprintBytes: 692060160,
    minAvailableBytes: 1258291200,
    warning: true,
    killed: false,
  },
  thermal: { start: 'nominal', end: 'fair', worst: 'serious' },
  battery: { startLevel: 0.81, endLevel: 0.8, drop: 0.01, state: 'unplugged' },
  notes: { hashedMiB: '61440' },
};

// The Swift module runs only on the phone. This stand-in answers like it: two
// registered benchmarks, and a run that resolves with the appended record.
const mockListBenchmarks = jest.fn((): string[] => ['dummy', 'second']);
const mockRunBenchmark = jest.fn(
  (name: string): Promise<BenchRecord> => Promise.resolve({ ...RECORD, benchmark: name }),
);
const mockRequireNativeModule = jest.fn((name: string) => {
  if (name !== 'GhostBench') {
    throw new Error(`no native module ${name}`);
  }
  return {
    listBenchmarks: () => mockListBenchmarks(),
    resultsPath: () => '/Documents/bench-results.json',
    runBenchmark: (benchmark: string) => mockRunBenchmark(benchmark),
  };
});

jest.mock('expo', () => ({
  requireNativeModule: (name: string) => mockRequireNativeModule(name),
}));

describe('Bench screen', () => {
  beforeEach(() => {
    mockListBenchmarks.mockClear();
    mockRunBenchmark.mockClear();
    mockRequireNativeModule.mockClear();
  });

  it('lists the registered native benchmarks and selects the first', () => {
    render(<BenchScreen />);

    expect(screen.getByRole('header', { name: 'Bench' })).toBeOnTheScreen();
    expect(screen.getByTestId('bench-name-dummy')).toBeSelected();
    expect(screen.getByTestId('bench-name-second')).not.toBeSelected();
    expect(screen.getByTestId('bench-result')).toHaveTextContent('No result yet');
    expect(mockRequireNativeModule).toHaveBeenCalledWith('GhostBench');
  });

  it('runs the selected benchmark and shows its numbers as plain text', async () => {
    render(<BenchScreen />);

    fireEvent.press(screen.getByTestId('bench-name-second'));
    fireEvent.press(screen.getByTestId('bench-run'));

    await waitFor(() =>
      expect(screen.getByTestId('bench-result')).toHaveTextContent('second: ok', { exact: false }),
    );
    expect(mockRunBenchmark).toHaveBeenCalledTimes(1);
    expect(mockRunBenchmark).toHaveBeenCalledWith('second');

    const text = screen.getByTestId('bench-result').props.children as string;
    expect(text.split('\n')).toEqual([
      'second: ok',
      'iPhone16,1, iOS 18.1.0',
      'allocate: 0.84 s',
      'hash: 30.00 s',
      'total: 30.85 s',
      'peak resident: 670.0 MiB',
      'peak footprint: 660.0 MiB',
      'least available: 1200.0 MiB',
      'memory warning: yes',
      'killed: no',
      'thermal: start nominal, end fair, worst serious',
      'battery drop: 1.0%',
    ]);
  });

  it('does not start a second run while one is going', async () => {
    let finish: (record: BenchRecord) => void = () => {};
    mockRunBenchmark.mockImplementationOnce(
      () =>
        new Promise<BenchRecord>((resolve) => {
          finish = resolve;
        }),
    );
    render(<BenchScreen />);

    fireEvent.press(screen.getByTestId('bench-run'));
    expect(screen.getByText('Running…')).toBeOnTheScreen();
    expect(screen.getByTestId('bench-run')).toBeDisabled();
    fireEvent.press(screen.getByTestId('bench-run'));
    expect(mockRunBenchmark).toHaveBeenCalledTimes(1);

    await act(async () => {
      finish(RECORD);
    });
    expect(screen.getByText('Run')).toBeOnTheScreen();
    expect(screen.getByTestId('bench-result')).toHaveTextContent('dummy: ok', { exact: false });
  });

  it('shows the error when a run fails', async () => {
    mockRunBenchmark.mockImplementationOnce(() =>
      Promise.reject(new Error('A benchmark is already running.')),
    );
    render(<BenchScreen />);

    fireEvent.press(screen.getByTestId('bench-run'));

    await waitFor(() =>
      expect(screen.getByTestId('bench-result')).toHaveTextContent(
        'dummy: error (A benchmark is already running.)',
      ),
    );
  });

  it('says the benchmarks are unavailable when the native module is missing', () => {
    mockRequireNativeModule.mockImplementationOnce(() => {
      throw new Error('native module missing');
    });

    render(<BenchScreen />);

    expect(screen.getByText('Benchmarks unavailable in this build')).toBeOnTheScreen();
    expect(screen.getByTestId('bench-run')).toBeDisabled();
  });
});
