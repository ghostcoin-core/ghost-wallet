import { act, render, screen, within } from '@testing-library/react-native';

import HomeScreen from '../../app/home';
import type { ActivityItem } from '../../lib/home/activity';
import type { AccountReading } from '../../lib/home/cache-refresh';
import { HISTORY_DELAY_MS, REFRESH_EVERY_MS } from '../../lib/home/use-home';
import { buffer, encodeDetails } from '../../lib/vanish/payments';
import { resetPending } from '../../lib/vanish/pending';

const GHOST = 10n ** 18n;
const NOW = Date.now();
const ADDRESS = '0x00000000000000000000000000000000000000aa';
const TO = '0x81d0' + '0'.repeat(32) + 'c7a4';
const EMPTY_TEXT = 'No activity yet. Payments to and from this account show here.';

function txHash(n: number): string {
  return '0x' + n.toString(16).padStart(64, '0');
}

// Saved payments: step numbers are the core's Step (3 Sent, 5 Settled, 6 Failed).
type MockPayment = { id: string; step: number; details: object; hash: number };
let mockPayments: MockPayment[] = [];
const mockOpened: Record<string, { step: () => number; record: () => object }> = {};
function mockOpen(id: string) {
  const payment = mockPayments.find((one) => one.id === id);
  if (!payment) throw new Error('no such payment');
  mockOpened[id] = mockOpened[id] ?? {
    step: () => payment.step,
    record: () => ({
      id,
      intent: { details: encodeDetails(payment.details as never) },
      attempts: [{ transactionHash: buffer(txHash(payment.hash)) }],
    }),
  };
  return mockOpened[id];
}

const mockCore = {
  savedAccountZeroAddress: () => ADDRESS,
  PaymentSequence: { open: (_store: unknown, id: string) => mockOpen(id) },
};
jest.mock('../../modules/ghost-core/src/index', () => mockCore, { virtual: true });

const mockStore = { list: () => mockPayments.map((one) => one.id), remove: jest.fn() };
jest.mock('../../lib/vanish/use-payment', () => ({
  paymentKit: () => ({ core: mockCore, store: mockStore, node: {}, nodeUrl: 'http://127.0.0.1:8547' }),
  treeAtTip: async () => ({ tree: { height: 1, hash: '', leaves: [], spent: [], spentBy: {} }, tip: 1 }),
  usePayment: () => null,
}));

// Home moves what is still pending; here nothing moves.
jest.mock('../../lib/vanish/payments', () => ({
  ...jest.requireActual('../../lib/vanish/payments'),
  advance: () => new Promise(() => {}),
}));

jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));

let mockReading: () => Promise<AccountReading>;
jest.mock('../../lib/home/read-account', () => ({ readAccountZero: () => mockReading() }));

let mockHistory: () => Promise<ActivityItem[]>;
jest.mock('../../lib/home/history', () => ({ scanHistory: () => mockHistory() }));

jest.mock('../../lib/node/test-network', () => ({ useTestNetwork: () => false }));
jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: jest.fn() }) }));

function send(id: string, step: number, at: number, hash: number): MockPayment {
  return {
    id,
    step,
    hash,
    details: { kind: 'send', to: TO, amountWei: (5n * GHOST).toString(), nonce: '0', maxFeePerGas: null, fromHeight: 1, at },
  };
}
function vanish(id: string, step: number, at: number, hash: number): MockPayment {
  return { id, step, hash, details: { kind: 'vanish', commitData: '0x00', amountWei: (3n * GHOST).toString(), nonce: '1', at } };
}

/** Lets the history lookup start, as it does a moment after the first balance. */
async function afterHistoryDelay() {
  await act(async () => {
    jest.advanceTimersByTime(HISTORY_DELAY_MS);
  });
  await act(async () => {});
}

afterEach(() => {
  jest.useRealTimers();
});

beforeEach(() => {
  jest.useFakeTimers();
  resetPending();
  for (const id of Object.keys(mockOpened)) delete mockOpened[id];
  mockPayments = [];
  mockReading = () => new Promise(() => {});
  mockHistory = () => new Promise(() => {});
});

describe('Home activity', () => {
  it('shows a settled send and a settled Vanish with their final state', async () => {
    mockPayments = [send('send-a', 5, NOW - 120_000, 1), vanish('vanish-b', 5, NOW - 60_000, 2)];
    render(<HomeScreen />);
    await act(async () => {});

    const activity = screen.getByTestId('activity');
    expect(within(activity).getByTestId('activity-send-a')).toHaveTextContent(/Sent to 0x81d0…c7a4/);
    expect(within(activity).getByTestId('activity-send-a')).toHaveTextContent(/−5\.00/);
    expect(screen.getByTestId('activity-send-a-detail')).toHaveTextContent(/^Sent, /);
    expect(within(activity).getByTestId('activity-vanish-b')).toHaveTextContent(/Vanished/);
    expect(within(activity).getByTestId('activity-vanish-b')).toHaveTextContent(/−3\.00/);
    expect(screen.queryByTestId('pending-send-a')).toBeNull();
    expect(screen.queryByText(EMPTY_TEXT)).toBeNull();
  });

  it('shows a failed send struck, nothing spent', async () => {
    mockPayments = [send('send-f', 6, NOW, 1)];
    render(<HomeScreen />);
    await act(async () => {});

    expect(screen.getByTestId('activity-send-f')).toHaveTextContent(/Send to 0x81d0…c7a4/);
    expect(screen.getByTestId('activity-send-f-detail')).toHaveTextContent('Failed, nothing spent');
  });

  it('shows a payment still going once, as its pending row', async () => {
    mockPayments = [send('send-p', 3, NOW, 1)];
    mockReading = async () => ({ balanceWei: GHOST.toString(), nonce: 1, tipHeight: 9 });
    // The chain has the same transaction.
    mockHistory = async () => [
      { id: `tx-${txHash(1)}`, direction: 'sent', counterparty: TO, amountWei: '5', state: 'pending', at: NOW, hash: txHash(1) },
    ];
    render(<HomeScreen />);
    await act(async () => {});
    await afterHistoryDelay();

    expect(screen.getByTestId('pending-send-p')).toBeOnTheScreen();
    expect(screen.queryByTestId(/^activity-/)).toBeNull();
    expect(screen.queryByText(EMPTY_TEXT)).toBeNull();
  });

  it('after a restore, lists the payments found on chain once the balance is shown', async () => {
    mockReading = async () => ({ balanceWei: (42n * GHOST).toString(), nonce: 1, tipHeight: 9 });
    let answer!: (items: ActivityItem[]) => void;
    const asked = jest.fn();
    mockHistory = () => {
      asked();
      return new Promise((resolve) => (answer = resolve));
    };
    render(<HomeScreen />);
    await act(async () => {});

    // The balance first; the history waits its turn and then for the node.
    expect(screen.getByTestId('balance-amount')).toHaveTextContent('42.00 GHOST');
    expect(asked).not.toHaveBeenCalled();
    await afterHistoryDelay();
    expect(asked).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('balance-amount')).toHaveTextContent('42.00 GHOST');
    expect(screen.getByText(EMPTY_TEXT)).toBeOnTheScreen();

    await act(async () => {
      answer([
        { id: `tx-${txHash(7)}`, direction: 'received', counterparty: TO, amountWei: (50n * GHOST).toString(), state: 'done', at: NOW - 60_000, hash: txHash(7) },
        { id: `tx-${txHash(8)}`, direction: 'sent', counterparty: TO, amountWei: (5n * GHOST).toString(), state: 'pending', at: NOW, hash: txHash(8) },
      ]);
    });

    expect(screen.getByTestId(`activity-tx-${txHash(7)}`)).toHaveTextContent(/Received from 0x81d0…c7a4/);
    expect(screen.getByTestId(`activity-tx-${txHash(8)}-detail`)).toHaveTextContent(/^Pending, /);
    expect(screen.queryByText(EMPTY_TEXT)).toBeNull();
  });

  it('shows a settled Summon once when the balance refresh sees what it credited', async () => {
    mockPayments = [
      { id: 'summon-s', step: 5, hash: 3, details: { kind: 'summon', amountWei: GHOST.toString(), feeWei: '1000', marker: '0x01', at: NOW - 30_000 } },
    ];
    mockReading = async () => ({ balanceWei: GHOST.toString(), nonce: 1, tipHeight: 9 });
    render(<HomeScreen />);
    await act(async () => {});

    // The Summon's coins came in: the balance went up with the nonce unchanged.
    mockReading = async () => ({ balanceWei: (2n * GHOST - 1000n).toString(), nonce: 1, tipHeight: 10 });
    await act(async () => {
      jest.advanceTimersByTime(REFRESH_EVERY_MS);
    });
    await act(async () => {});

    expect(screen.getByTestId('balance-amount')).toHaveTextContent('1.999999 GHOST');
    expect(screen.getByTestId('activity-summon-s')).toHaveTextContent(/Summoned/);
    expect(screen.queryAllByTestId(/^activity-received-/)).toHaveLength(0);
  });

  it('shows two Claims of 1 and 2 GHOST once when one refresh sees both', async () => {
    const claim = (id: string, ghost: bigint, at: number, hash: number): MockPayment => ({
      id,
      step: 5,
      hash,
      details: { kind: 'claim', amountWei: (ghost * GHOST).toString(), feeWei: '1000', marker: '0x01', at },
    });
    mockPayments = [claim('claim-one', 1n, NOW - 30_000, 3), claim('claim-two', 2n, NOW - 25_000, 4)];
    mockReading = async () => ({ balanceWei: GHOST.toString(), nonce: 1, tipHeight: 9 });
    render(<HomeScreen />);
    await act(async () => {});

    mockReading = async () => ({ balanceWei: (4n * GHOST).toString(), nonce: 1, tipHeight: 12 });
    await act(async () => {
      jest.advanceTimersByTime(REFRESH_EVERY_MS);
    });
    await act(async () => {});

    expect(screen.getByTestId('balance-amount')).toHaveTextContent('4.00 GHOST');
    expect(screen.getByTestId('activity-claim-one')).toHaveTextContent(/Claimed/);
    expect(screen.getByTestId('activity-claim-two')).toHaveTextContent(/Claimed/);
    expect(screen.queryAllByTestId(/^activity-received-/)).toHaveLength(0);
  });

  it('says there is no activity only when there is truly nothing', async () => {
    render(<HomeScreen />);
    await act(async () => {});
    expect(screen.getByText(EMPTY_TEXT)).toBeOnTheScreen();
    expect(screen.queryByTestId(/^(activity|pending)-/)).toBeNull();
  });
});
