import { act, fireEvent, render, screen, within } from '@testing-library/react-native';
import type { ComponentType } from 'react';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import HomeScreen from '../../app/home';
import { encodeDetails, type Advance } from '../../lib/vanish/payments';
import { holdVanish, resetPending, takeReopened } from '../../lib/vanish/pending';

const GHOST = 10n ** 18n;
const NOW = Date.now();

// Saved payments: step numbers are the core's Step (0 Prepared, 3 Sent, 4 Included, 5 Settled).
type MockPayment = { id: string; step: number; details: object };
let mockPayments: MockPayment[] = [];
const mockOpened: Record<string, { step: () => number; record: () => object }> = {};
function mockOpen(id: string) {
  const payment = mockPayments.find((one) => one.id === id);
  if (!payment) throw new Error('no such payment');
  mockOpened[id] = mockOpened[id] ?? {
    step: () => payment.step,
    record: () => ({ id, intent: { details: encodeDetails(payment.details as never) } }),
  };
  return mockOpened[id];
}

const mockCore = {
  savedAccountZeroAddress: () => '0x00000000000000000000000000000000000000aa',
  PaymentSequence: { open: (_store: unknown, id: string) => mockOpen(id) },
};
jest.mock('../../modules/ghost-core/src/index', () => mockCore, { virtual: true });

const mockStore = { list: () => mockPayments.map((one) => one.id), remove: jest.fn() };
jest.mock('../../lib/vanish/use-payment', () => ({
  paymentKit: () => ({ core: mockCore, store: mockStore, node: {}, nodeUrl: 'http://127.0.0.1:8547' }),
  treeAtTip: async () => ({ tree: { height: 1, hash: '', leaves: [], spent: [], spentBy: {} }, tip: 1 }),
  usePayment: () => null,
}));

// Home moves what is still pending; the chain is not asked here.
const mockAdvance = jest.fn(async (_node: unknown, _sequence: unknown, _rebuild: unknown, _tree: unknown): Promise<Advance> => ({
  status: 'sent',
  step: 3,
  needsKey: false,
  needsBackup: false,
}));
jest.mock('../../lib/vanish/payments', () => ({
  ...jest.requireActual('../../lib/vanish/payments'),
  advance: (node: unknown, sequence: unknown, rebuild: unknown, tree: unknown) => mockAdvance(node, sequence, rebuild, tree),
}));

jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));
jest.mock('../../lib/home/read-account', () => ({ readAccountZero: () => new Promise(() => {}) }));
jest.mock('../../lib/node/test-network', () => ({ useTestNetwork: () => false }));
const mockPush = jest.fn();
jest.mock('expo-router', () => ({ useRouter: () => ({ push: mockPush, back: jest.fn() }) }));

const mockWindow = { width: 393, height: 852, scale: 3, fontScale: 1 };
jest.mock('react-native/Libraries/Utilities/useWindowDimensions', () => ({ __esModule: true, default: () => mockWindow }));

const DEVICES = {
  iPhone: { width: 393, height: 852 },
  'iPhone Duo folded': { width: 466, height: 678 },
  'iPhone Duo open': { width: 626, height: 890 },
} as const;
type Device = keyof typeof DEVICES;

async function renderOn(device: Device, Screen: ComponentType = HomeScreen) {
  const { width, height } = DEVICES[device];
  mockWindow.width = width;
  mockWindow.height = height;
  const view = render(
    <SafeAreaProvider initialMetrics={{ frame: { x: 0, y: 0, width, height }, insets: { top: 47, left: 0, right: 0, bottom: 34 } }}>
      <Screen />
    </SafeAreaProvider>,
  );
  await act(async () => {});
  return view;
}

function vanish(id: string, step: number, at: number): MockPayment {
  return { id, step, details: { kind: 'vanish', commitData: '0x00', amountWei: (2n * GHOST).toString(), nonce: '0', at } };
}
function reveal(id: string, kind: 'summon' | 'claim', step: number, at: number): MockPayment {
  return { id, step, details: { kind, amountWei: GHOST.toString(), feeWei: '1000', marker: '0x01', at } };
}

beforeEach(() => {
  jest.clearAllMocks();
  resetPending();
  for (const id of Object.keys(mockOpened)) delete mockOpened[id];
  mockPayments = [];
});

describe.each(Object.keys(DEVICES) as Device[])('Home on the %s', (device) => {
  it('lists a Vanish and a Summon left mid-way as pending, with the step each is at', async () => {
    mockPayments = [vanish('vanish-a', 3, NOW - 60_000), reveal('summon-b', 'summon', 4, NOW - 30_000)];
    await renderOn(device);

    const activity = screen.getByTestId('activity');
    const vanishRow = within(activity).getByTestId('pending-vanish-a');
    expect(vanishRow).toHaveTextContent(/Vanish/);
    expect(screen.getByTestId('pending-vanish-a-detail')).toHaveTextContent('Pending: Sent');
    expect(vanishRow).toHaveTextContent(/−2\.00/);
    expect(screen.getByTestId('pending-summon-b-detail')).toHaveTextContent('Pending: In a block');
    expect(within(activity).getByTestId('pending-summon-b')).toHaveTextContent(/\+1\.00/);
    expect(screen.queryByText(/No activity yet/)).toBeNull();
  });

  it('does not list a settled or failed payment, nor a Vanish whose key was never kept', async () => {
    mockPayments = [
      vanish('vanish-done', 5, NOW),
      reveal('claim-failed', 'claim', 6, NOW),
      // Prepared, and the app was closed: no key is held, nothing was signed.
      vanish('vanish-lost', 0, NOW),
    ];
    await renderOn(device);
    expect(screen.queryByTestId(/^pending-/)).toBeNull();
    expect(screen.getByText(/No activity yet/)).toBeOnTheScreen();
  });

  it('lists a Vanish left before its key was written down, at that step', async () => {
    mockPayments = [vanish('vanish-key', 0, NOW)];
    holdVanish({ id: 'vanish-key', step: 'check', words: ['able'], positions: [1, 2, 3] });
    await renderOn(device);
    expect(screen.getByTestId('pending-vanish-key-detail')).toHaveTextContent('Pending: Write down the Phantom Key');
    // Nothing is signed or sent for it from Home.
    expect(mockAdvance).not.toHaveBeenCalled();
  });

  it('opens the progress of the payment tapped', async () => {
    mockPayments = [vanish('vanish-a', 3, NOW - 60_000), reveal('claim-c', 'claim', 3, NOW)];
    await renderOn(device);

    fireEvent.press(screen.getByTestId('pending-claim-c'));
    expect(mockPush).toHaveBeenLastCalledWith('/summon');
    expect(takeReopened(['summon', 'claim'])).toBe('claim-c');

    fireEvent.press(screen.getByTestId('pending-vanish-a'));
    expect(mockPush).toHaveBeenLastCalledWith('/vanish');
    // Only the Vanish screen takes a Vanish.
    expect(takeReopened(['summon', 'claim'])).toBeNull();
    expect(takeReopened(['vanish'])).toBe('vanish-a');
  });

  it('keeps moving a payment left mid-way, and drops its row once it settles', async () => {
    const left = vanish('vanish-a', 3, NOW);
    mockPayments = [left];
    mockAdvance.mockImplementationOnce(async () => {
      left.step = 5;
      return { status: 'settled', step: 5, needsKey: false, needsBackup: false };
    });
    await renderOn(device);
    // A Vanish is signed again without its key; it reads no coin tree.
    expect(mockAdvance).toHaveBeenCalledWith(expect.anything(), mockOpened['vanish-a'], expect.any(Function), null);
    expect(screen.queryByTestId('pending-vanish-a')).toBeNull();
  });
});
