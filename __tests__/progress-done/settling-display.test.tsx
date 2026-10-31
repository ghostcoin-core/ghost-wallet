import { act, fireEvent, render, screen } from '@testing-library/react-native';
import { readFileSync } from 'fs';
import { join } from 'path';
import type { ComponentType } from 'react';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import SummonScreen from '../../app/summon';
import VanishScreen from '../../app/vanish';
import { LEAVE_NOTE } from '../../components/vanish-ui';
import { describeActivity } from '../../lib/home/activity';
import { savedActivityItem } from '../../lib/home/saved-activity';
import { encodeDetails } from '../../lib/vanish/payments';
import { reopenPayment, resetPending } from '../../lib/vanish/pending';
import {
  SETTLE_CONFIRMATIONS,
  isFinal,
  settlingLine,
  statusOfStep,
  type PaymentStatus,
} from '../../lib/vanish/status-mapping';

// A Vanish, a Summon and a Claim, saved mid-way; each screen opens on its progress.
function mockSaved(id: string, details: object) {
  return {
    step: () => 4,
    record: () => ({ id, intent: { details: encodeDetails(details as never) } }),
    markBackedUp: jest.fn(),
  };
}
const mockSequences: Record<string, ReturnType<typeof mockSaved>> = {
  'vanish-1': mockSaved('vanish-1', { kind: 'vanish', commitData: '0x00', amountWei: '1500000000000000000', nonce: '0', at: 1 }),
  'summon-1': mockSaved('summon-1', { kind: 'summon', amountWei: '900000000000000000', feeWei: '1000', marker: '0x01', at: 1 }),
  'claim-1': mockSaved('claim-1', { kind: 'claim', amountWei: '400000000000000000', feeWei: '1000', marker: '0x02', at: 1 }),
};

const mockCore = {
  checkKeyWords: jest.fn(() => ({ verdict: 'word-check', position: 0 })),
  checkPhantomKeyWord: jest.fn(() => true),
  confirmPhantomKeySaved: jest.fn(),
  forgetPhantomKey: jest.fn(),
  forgetCardKey: jest.fn(),
  savedAccountZeroAddress: () => '0x00000000000000000000000000000000000000aa',
  hasAccount: () => true,
  PaymentSequence: {
    open: (_store: unknown, id: string) => {
      const found = mockSequences[id];
      if (!found) throw new Error('no such payment');
      return found;
    },
  },
};
jest.mock('../../modules/ghost-core/src/index', () => mockCore, { virtual: true });

let mockStatus: PaymentStatus = 'sent';
let mockStep: number | string = 3;
const mockStore = { list: () => Object.keys(mockSequences), remove: jest.fn() };
jest.mock('../../lib/vanish/use-payment', () => ({
  paymentKit: () => ({ core: mockCore, store: mockStore, node: {}, nodeUrl: 'http://127.0.0.1:8547' }),
  usePayment: (_kit: unknown, sequence: unknown) =>
    sequence ? { status: mockStatus, step: mockStep, needsKey: false, error: null } : null,
}));

jest.mock('../../lib/vanish/actions', () => ({
  CARD_KEY: { card: true },
  minimumVanish: () => new Promise(() => {}),
  vanishFee: () => new Promise(() => {}),
  startVanish: jest.fn(),
  lookUpKey: jest.fn(),
  signVanishAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
  proveRevealAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
  startReveal: jest.fn(),
}));

jest.mock('../../modules/ghost-nfc', () => ({
  ...jest.requireActual('../../modules/ghost-nfc'),
  cardsSupported: () => false,
}));

jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));
jest.mock('../../lib/home/read-account', () => ({ readAccountZero: () => new Promise(() => {}) }));
const mockBack = jest.fn();
jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: mockBack }) }));

const METRICS = { frame: { x: 0, y: 0, width: 393, height: 852 }, insets: { top: 47, left: 0, right: 0, bottom: 34 } };

function screenOf(Screen: ComponentType) {
  return (
    <SafeAreaProvider initialMetrics={METRICS}>
      <Screen />
    </SafeAreaProvider>
  );
}

function open(id: string, Screen: ComponentType) {
  reopenPayment(id);
  return render(screenOf(Screen));
}

beforeEach(() => {
  jest.clearAllMocks();
  resetPending();
  mockStatus = 'sent';
  mockStep = 3;
});

const SETTLING = 'Settling: 1 of 3 confirmations';

describe('the settled threshold shown', () => {
  it('is the core settled rule: three confirmations', () => {
    const core = readFileSync(join(__dirname, '../../core/src/step_sequence.rs'), 'utf8');
    const found = /pub const SETTLE_CONFIRMATIONS: u64 = (\d+);/.exec(core);
    expect(found).not.toBeNull();
    expect(SETTLE_CONFIRMATIONS).toBe(Number(found![1]));
    expect(SETTLE_CONFIRMATIONS).toBe(3);
    expect(settlingLine(1)).toBe(SETTLING);
    expect(settlingLine(2)).toBe('Settling: 2 of 3 confirmations');
  });

  it('does not end the payment at a block: the screen keeps following it until settled or failed', () => {
    expect(statusOfStep('Included')).toBe('in-block');
    expect(isFinal('in-block')).toBe(false);
  });
});

const REVEALS = [
  ['Summon', 'summon-1', 'The coins are in your account.'],
  ['Claim', 'claim-1', 'The coins are in your account.'],
] as const;

describe.each(REVEALS)('a %s', (_name, id, inBlockText) => {
  it.each(['proving', 'sent'] as const)('shows no success and no Done while %s', (status) => {
    mockStatus = status;
    open(id, SummonScreen);
    expect(screen.queryByTestId('coins-back')).toBeNull();
    expect(screen.queryByText(/coins are/)).toBeNull();
    expect(screen.queryByText(/Settling/)).toBeNull();
    expect(screen.queryByTestId('summon-done')).toBeNull();
    expect(screen.getByTestId('summon-leave-note')).toHaveTextContent(LEAVE_NOTE, { exact: false });
    expect(screen.getByTestId('summon-leave')).toBeOnTheScreen();
  });

  it('shows the coins in the account, the settling line and Done once in a block', () => {
    mockStatus = 'in-block';
    mockStep = 'Included';
    open(id, SummonScreen);
    expect(screen.getByTestId('coins-back')).toHaveTextContent(inBlockText);
    expect(screen.getByTestId('payment-status')).toHaveTextContent(SETTLING);
    expect(screen.queryByTestId('summon-leave-note')).toBeNull();
    expect(screen.queryByTestId('summon-leave')).toBeNull();
    fireEvent.press(screen.getByTestId('summon-done'));
    expect(mockBack).toHaveBeenCalledTimes(1);
  });

  it('says the coins are back, without the settling line, once settled', () => {
    mockStatus = 'in-block';
    mockStep = 'Included';
    const view = open(id, SummonScreen);
    mockStatus = 'settled';
    mockStep = 'Settled';
    act(() => view.rerender(screenOf(SummonScreen)));
    expect(screen.getByTestId('coins-back')).toHaveTextContent('The coins are back in your account.');
    expect(screen.queryByText(/Settling/)).toBeNull();
    expect(screen.getByTestId('summon-done')).toBeOnTheScreen();
  });

  it.each(['Failed', 'Conflicted'] as const)('still shows Failed when the block is dropped (%s)', (step) => {
    mockStatus = 'in-block';
    mockStep = 'Included';
    const view = open(id, SummonScreen);
    mockStatus = 'failed';
    mockStep = step;
    act(() => view.rerender(screenOf(SummonScreen)));
    expect(screen.getByTestId('progress-failed')).toHaveTextContent('Failed');
    expect(screen.queryByTestId('coins-back')).toBeNull();
    expect(screen.queryByText(/coins are/)).toBeNull();
    expect(screen.queryByText(/Settling/)).toBeNull();
    expect(screen.getByTestId('summon-done')).toBeOnTheScreen();
  });
});

describe('a Vanish', () => {
  it.each(['proving', 'sent'] as const)('shows no success and no Done while %s', (status) => {
    mockStatus = status;
    open('vanish-1', VanishScreen);
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
    expect(screen.queryByText(/Phantom Key\./)).toBeNull();
    expect(screen.queryByText(/Settling/)).toBeNull();
    expect(screen.queryByTestId('vanish-done')).toBeNull();
    expect(screen.getByTestId('vanish-leave-note')).toHaveTextContent(LEAVE_NOTE, { exact: false });
  });

  it('shows the coins in the Phantom Key, the settling line and Done once the Commit is in a block', () => {
    mockStatus = 'in-block';
    mockStep = 'Included';
    open('vanish-1', VanishScreen);
    const status = screen.getByTestId('payment-status');
    expect(status).toHaveTextContent('The coins are in the Phantom Key.', { exact: false });
    expect(status).toHaveTextContent(SETTLING, { exact: false });
    expect(screen.queryByTestId('vanish-leave-note')).toBeNull();
    fireEvent.press(screen.getByTestId('vanish-done'));
    expect(mockBack).toHaveBeenCalledTimes(1);
  });

  it('drops the settling line once settled', () => {
    mockStatus = 'settled';
    mockStep = 'Settled';
    open('vanish-1', VanishScreen);
    expect(screen.getByTestId('payment-status')).toHaveTextContent('The coins are in the Phantom Key.');
    expect(screen.queryByText(/Settling/)).toBeNull();
    expect(screen.getByTestId('vanish-done')).toBeOnTheScreen();
  });

  it('still shows Failed when the Commit is dropped from its block', () => {
    mockStatus = 'in-block';
    mockStep = 'Included';
    const view = open('vanish-1', VanishScreen);
    mockStatus = 'failed';
    mockStep = 'Conflicted';
    act(() => view.rerender(screenOf(VanishScreen)));
    expect(screen.getByTestId('progress-failed')).toHaveTextContent('Failed');
    expect(screen.getByTestId('payment-status')).toHaveTextContent('Another payment used these coins first.', {
      exact: false,
    });
    expect(screen.queryByText(/Settling/)).toBeNull();
    expect(screen.getByTestId('vanish-done')).toBeOnTheScreen();
  });
});

describe('Activity', () => {
  const NOW = 10_000;
  function row(id: string, step: string) {
    const item = savedActivityItem(id, mockSequences[id].record() as never, step);
    return item ? describeActivity(item, NOW) : null;
  }

  it.each(['vanish-1', 'summon-1', 'claim-1'])('lists %s as done only once it settled', (id) => {
    // In a block it is still Home's pending row, not a done Activity row.
    expect(row(id, 'Included')).toBeNull();
    expect(row(id, 'Settled')).toMatchObject({ icon: 'check', struck: false });
  });

  it.each(['Failed', 'Conflicted'])('lists one dropped after its block as %s, struck', (step) => {
    expect(row('summon-1', step)).toMatchObject({ struck: true, icon: step === 'Failed' ? 'cross' : 'warning' });
  });
});
