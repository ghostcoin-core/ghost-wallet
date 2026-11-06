import { act, fireEvent, render, screen, waitFor } from '@testing-library/react-native';

import SealSpeedScreen, { describeCheck, KEPT_RUNS } from '../app/seal-speed';
import type { SealCheck } from '../modules/ghost-nfc/relay';

const CHECK: SealCheck = {
  uid: '04518DFAA96180',
  state: 'sealed',
  amountWei: 1_500_000_000_000_000_000n,
  answer: new Uint8Array(203),
  signature: new Uint8Array(3309),
  rounds: [
    { kind: 'seal', ms: 80.4 },
    { kind: 'card', ms: 12.2 },
    { kind: 'seal', ms: 85.6 },
  ],
  totalMs: 1234.4,
};

// The relay runs only on the phone; the screen gets this stand-in.
const mockCheckWithSeal = jest.fn((_url: string): Promise<SealCheck> => Promise.resolve(CHECK));
jest.mock('../modules/ghost-nfc/relay', () => ({
  checkWithSeal: (url: string) => mockCheckWithSeal(url),
}));

const SEAL = 'https://seal.example:8443';

function lines(testID: string): string[] {
  return (screen.getByTestId(testID).props.children as string).split('\n');
}

describe('Seal speed screen', () => {
  beforeEach(() => {
    mockCheckWithSeal.mockClear();
  });

  it('says it times Check only, and waits for a Seal address', () => {
    render(<SealSpeedScreen />);

    expect(screen.getByRole('header', { name: 'Seal speed' })).toBeOnTheScreen();
    expect(screen.getByTestId('seal-speed-note')).toHaveTextContent('this times Check only', { exact: false });
    expect(screen.getByTestId('seal-speed-result')).toHaveTextContent('No run yet');
    expect(screen.getByTestId('seal-speed-run')).toBeDisabled();
    fireEvent.press(screen.getByTestId('seal-speed-run'));
    expect(mockCheckWithSeal).not.toHaveBeenCalled();
  });

  it('runs a Check against the typed address and shows the total and each round trip', async () => {
    render(<SealSpeedScreen />);

    fireEvent.changeText(screen.getByTestId('seal-speed-url'), SEAL);
    fireEvent.press(screen.getByTestId('seal-speed-run'));

    await waitFor(() => expect(screen.getByTestId('seal-speed-result')).toHaveTextContent('total: 1234 ms', { exact: false }));
    expect(mockCheckWithSeal).toHaveBeenCalledTimes(1);
    expect(mockCheckWithSeal).toHaveBeenCalledWith(SEAL);
    expect(lines('seal-speed-result')).toEqual([
      'total: 1234 ms (within the 2 s target)',
      'card 04518DFAA96180: sealed, 1500000000000000000 wei',
      'card round trips: 1, 12 ms',
      'Seal round trips: 2, 166 ms',
      '1. Seal: 80 ms',
      '2. card: 12 ms',
      '3. Seal: 86 ms',
    ]);
    expect(lines('seal-speed-runs')).toEqual(['run 1: 1234 ms, sealed']);
  });

  it('says when a Check is over the 2 second target', () => {
    expect(describeCheck({ ...CHECK, totalMs: 2400 }).split('\n')[0]).toBe('total: 2400 ms (over the 2 s target)');
  });

  it(`keeps only the last ${KEPT_RUNS} runs, newest first`, async () => {
    render(<SealSpeedScreen />);
    fireEvent.changeText(screen.getByTestId('seal-speed-url'), SEAL);

    for (let i = 1; i <= KEPT_RUNS + 2; i += 1) {
      mockCheckWithSeal.mockImplementationOnce(() => Promise.resolve({ ...CHECK, totalMs: 1000 + i }));
      await act(async () => {
        fireEvent.press(screen.getByTestId('seal-speed-run'));
      });
    }

    const runs = lines('seal-speed-runs');
    expect(runs).toHaveLength(KEPT_RUNS);
    expect(runs[0]).toBe(`run ${KEPT_RUNS + 2}: ${1000 + KEPT_RUNS + 2} ms, sealed`);
    expect(runs[KEPT_RUNS - 1]).toBe('run 3: 1003 ms, sealed');
  });

  it('does not start a second Check while one is running', async () => {
    let finish: (check: SealCheck) => void = () => {};
    mockCheckWithSeal.mockImplementationOnce(
      () =>
        new Promise<SealCheck>((resolve) => {
          finish = resolve;
        }),
    );
    render(<SealSpeedScreen />);
    fireEvent.changeText(screen.getByTestId('seal-speed-url'), SEAL);

    fireEvent.press(screen.getByTestId('seal-speed-run'));
    expect(screen.getByText('Checking…')).toBeOnTheScreen();
    expect(screen.getByTestId('seal-speed-run')).toBeDisabled();
    fireEvent.press(screen.getByTestId('seal-speed-run'));
    expect(mockCheckWithSeal).toHaveBeenCalledTimes(1);

    await act(async () => {
      finish(CHECK);
    });
    expect(screen.getByText('Run a Check')).toBeOnTheScreen();
  });

  it('shows a failed Check as a plain error and keeps it in the runs', async () => {
    mockCheckWithSeal.mockImplementationOnce(() => Promise.reject(new Error('The Seal refused this card.')));
    render(<SealSpeedScreen />);
    fireEvent.changeText(screen.getByTestId('seal-speed-url'), SEAL);
    fireEvent.press(screen.getByTestId('seal-speed-run'));

    await waitFor(() =>
      expect(screen.getByTestId('seal-speed-result')).toHaveTextContent('error: The Seal refused this card.'),
    );
    expect(lines('seal-speed-runs')).toEqual(['run 1: error (The Seal refused this card.)']);
  });
});
