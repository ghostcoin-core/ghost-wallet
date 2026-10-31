import { act, fireEvent, render, renderHook, screen } from '@testing-library/react-native';
import { createElement } from 'react';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import VanishScreen from '../../app/vanish';
import { formatGhost } from '../../lib/home/balance-format';
import { MOVE_PENDING_EVERY_MS, usePendingPayments } from '../../lib/home/use-pending';
import { buildNetwork } from '../../lib/network/build-network';
import { signVanishAgain, startVanish } from '../../lib/vanish/actions';
import { encodeDetails, type PaymentDetails } from '../../lib/vanish/payments';
import { STOPPED_TEXT, pendingPayments, reopenPayment, resetPending, stoppedVanish } from '../../lib/vanish/pending';
import { MOVE_EVERY_MS, usePayment, type PaymentKit } from '../../lib/vanish/use-payment';
import type { CorePaymentIntent, CorePaymentRecord, CorePaymentSequence } from '../../modules/ghost-core';

const ACCOUNT = `0x${'aa'.repeat(20)}`;
const GHOST = 10n ** 18n;
// The account of the report: about 8 GHOST left.
const BALANCE = 79_998n * 10n ** 14n;
// The tip's base fee 7 and priority fee 1: a max fee of 15 per gas, at the Vanish gas limit.
const GAS_LIMIT = 100_000n;
const FEE = (2n * 7n + 1n) * GAS_LIMIT;
const NODE_URL = 'http://127.0.0.1:8547';
const REFUSED = 'the node refused a call: insufficient funds for gas * price + value';

// Steps are the core's Step: 0 Prepared, 1 BackedUp, 3 Sent.
type FakeSequence = CorePaymentSequence & { recover: jest.Mock; addAttempt: jest.Mock; markSent: jest.Mock };

function fakeSequence(id: string, intent: CorePaymentIntent, step: number, recovery: string): FakeSequence {
  const record: CorePaymentRecord = { id, intent, step, attempts: [], version: 1, checksum: new ArrayBuffer(0) };
  return {
    record: () => record,
    step: () => record.step,
    recover: jest.fn(() => ({ tag: recovery })),
    markBackedUp: jest.fn(),
    addAttempt: jest.fn(() => new ArrayBuffer(32)),
    markSent: jest.fn(() => new Uint8Array([0x02, 0x01]).buffer),
  } as unknown as FakeSequence;
}

const mockCore = {
  savedAccountZeroAddress: () => ACCOUNT,
  hasAccount: () => true,
  checkPhantomKeyWord: jest.fn(() => true),
  confirmPhantomKeySaved: jest.fn(),
  confirmPhantomKeySavedUnchecked: jest.fn(),
  forgetPhantomKey: jest.fn(),
  prepareVanish: jest.fn((_chainId: bigint, amountWei: string) => ({
    commitData: new Uint8Array([1, 2]).buffer,
    amountWei,
    commitment: new ArrayBuffer(32),
  })),
  takePhantomKeyWords: jest.fn(() => Array.from({ length: 24 }, () => 'able')),
  feeWindow: jest.fn(() => ({ referenceHeight: 99n, validUntil: 120n })),
  minVanishWei: jest.fn(() => '1000'),
  vanishGasLimit: () => GAS_LIMIT,
  signVanish: jest.fn(() => ({ transactionHash: new ArrayBuffer(32), sender: new ArrayBuffer(20), envelope: new Uint8Array([4]).buffer })),
  PaymentSequence: {
    start: jest.fn((_store: unknown, id: string, intent: CorePaymentIntent) => {
      const sequence = fakeSequence(id, intent, 0, 'BackUp');
      mockSaved.set(id, sequence);
      return sequence;
    }),
    open: jest.fn((_store: unknown, id: string) => {
      const found = mockSaved.get(id);
      if (!found) throw new Error('no such payment');
      return found;
    }),
  },
};
jest.mock('../../modules/ghost-core/src/index', () => mockCore, { virtual: true });

const mockSaved = new Map<string, FakeSequence>();
const mockStore = {
  list: () => [...mockSaved.keys()],
  remove: jest.fn((id: string) => {
    mockSaved.delete(id);
  }),
};
const mockNode = {
  chainId: jest.fn(async () => buildNetwork.chainId),
  tipHeight: jest.fn(async () => 100),
  block: jest.fn(async (height: number) => ({ height, hash: `0x${'47'.repeat(32)}`, baseFeePerGas: 7n, transactions: [] })),
  receipts: jest.fn(async (hashes: string[]) => hashes.map(() => null)),
  known: jest.fn(async (hashes: string[]) => hashes.map(() => false)),
  nonce: jest.fn(async () => 2n),
  maxPriorityFeePerGas: jest.fn(async () => 1n),
  sendRaw: jest.fn(async (_bytes: string) => `0x${'cc'.repeat(32)}`),
};
// What the node says the account holds when a Vanish is signed.
let mockChainBalance = BALANCE;
const mockBalance = jest.fn(async () => mockChainBalance);
const mockKit = { core: mockCore, store: mockStore, node: mockNode, nodeUrl: NODE_URL, balance: mockBalance };

jest.mock('../../lib/vanish/use-payment', () => ({
  ...jest.requireActual('../../lib/vanish/use-payment'),
  paymentKit: () => mockKit,
}));
jest.mock('../../lib/vanish/actions', () => {
  const actual = jest.requireActual('../../lib/vanish/actions');
  return { ...actual, startVanish: jest.fn(actual.startVanish) };
});

// Home's snapshot, as Send reads it: unknown until a reading arrives.
let mockReading: Promise<{ balanceWei: string; nonce: number; tipHeight: number }> = new Promise(() => {});
jest.mock('../../lib/home/read-account', () => ({ readAccountZero: () => mockReading }));
jest.mock('../../lib/home/history', () => ({ scanHistory: async () => [] }));
jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));
const mockBack = jest.fn();
jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: mockBack, replace: jest.fn() }) }));

const kit = mockKit as unknown as PaymentKit;

function vanishIntent(amountWei: bigint): CorePaymentIntent {
  const details: PaymentDetails = {
    kind: 'vanish',
    commitData: '0x0102',
    amountWei: amountWei.toString(),
    nonce: '2',
    at: 1,
    chainId: buildNetwork.chainId.toString(),
  };
  return {
    kind: 1,
    identity: { tag: 'AccountNonce', inner: { account: new Uint8Array(20).fill(0xaa).buffer, nonce: 2n } },
    details: encodeDetails(details),
  };
}

/** A Vanish saved with `step`, as the core would open it. */
function savedVanish(id: string, amountWei: bigint, step: number, recovery: string): FakeSequence {
  const sequence = fakeSequence(id, vanishIntent(amountWei), step, recovery);
  mockSaved.set(id, sequence);
  return sequence;
}

/** The Vanish screen with Home's mover running next to it, as in the app. */
function WithHome() {
  usePendingPayments(NODE_URL);
  return createElement(VanishScreen);
}

async function renderVanish(withHome = false) {
  const view = render(
    createElement(
      SafeAreaProvider,
      {
        initialMetrics: { frame: { x: 0, y: 0, width: 393, height: 852 }, insets: { top: 47, left: 0, right: 0, bottom: 34 } },
      },
      createElement(withHome ? WithHome : VanishScreen),
    ),
  );
  await act(async () => {});
  return view;
}

/** Lets the screen's and Home's timers run for `ms`. */
async function wait(ms: number) {
  await act(async () => {
    await jest.advanceTimersByTimeAsync(ms);
  });
}

function knownBalance(wei: bigint) {
  mockReading = Promise.resolve({ balanceWei: wei.toString(), nonce: 2, tipHeight: 100 });
}

beforeEach(() => {
  jest.clearAllMocks();
  jest.useFakeTimers();
  resetPending();
  mockSaved.clear();
  mockChainBalance = BALANCE;
  mockReading = new Promise(() => {});
  mockNode.sendRaw.mockImplementation(async () => `0x${'cc'.repeat(32)}`);
});

afterEach(() => {
  jest.useRealTimers();
});

describe('the Vanish screen', () => {
  const NOT_ENOUGH = `Not enough GHOST for the amount and its fee. You have ${formatGhost(BALANCE)} GHOST.`;

  it.each([
    ['more than the balance', '9'],
    ['one wei more than the balance less the Vanish fee', formatWei(BALANCE - FEE + 1n)],
  ])('refuses %s with the Send wording, before anything is saved or a key is made', async (_what, typed) => {
    knownBalance(BALANCE);
    await renderVanish();

    fireEvent.changeText(screen.getByTestId('vanish-amount'), typed);
    expect(screen.getByTestId('vanish-not-enough')).toHaveTextContent(NOT_ENOUGH, { exact: true });
    expect(screen.getByTestId('vanish-make-key')).toBeDisabled();
    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-make-key'));
    });

    expect(startVanish).not.toHaveBeenCalled();
    expect(mockCore.prepareVanish).not.toHaveBeenCalled();
    expect(mockCore.takePhantomKeyWords).not.toHaveBeenCalled();
    expect(mockCore.PaymentSequence.start).not.toHaveBeenCalled();
    expect(mockSaved.size).toBe(0);
    expect(screen.queryByTestId('phantom-key')).toBeNull();
  });

  it('accepts an amount equal to the balance less the Vanish fee', async () => {
    knownBalance(BALANCE);
    await renderVanish();

    fireEvent.changeText(screen.getByTestId('vanish-amount'), formatWei(BALANCE - FEE));
    expect(screen.queryByTestId('vanish-not-enough')).toBeNull();
    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-make-key'));
    });

    expect(startVanish).toHaveBeenCalledWith(expect.anything(), ACCOUNT, BALANCE - FEE);
    expect(mockCore.prepareVanish).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('phantom-key')).toBeOnTheScreen();
  });

  it('does not block while the balance is not known yet', async () => {
    await renderVanish();

    fireEvent.changeText(screen.getByTestId('vanish-amount'), '9');
    expect(screen.queryByTestId('vanish-not-enough')).toBeNull();
    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-make-key'));
    });

    expect(startVanish).toHaveBeenCalledWith(expect.anything(), ACCOUNT, 9n * GHOST);
    expect(screen.getByTestId('phantom-key')).toBeOnTheScreen();
  });
});

describe('a Vanish the node refuses for insufficient funds', () => {
  it('stops on its screen: no further move, a state the person can cancel, and no resend after a top-up', async () => {
    const sequence = savedVanish('vanish-1', 2n * GHOST, 3, 'Send');
    mockNode.sendRaw.mockRejectedValue(new Error(REFUSED));
    reopenPayment('vanish-1');
    await renderVanish(true);

    // Whichever moved it first, the screen or Home, it was sent once.
    expect(mockNode.sendRaw).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('vanish-stopped')).toHaveTextContent(/Not enough test GHOST in this account/);
    expect(screen.getByTestId('vanish-stopped')).toHaveTextContent(/will not be sent/);
    expect(screen.queryByText(/Trying again/)).toBeNull();
    expect(screen.queryByTestId('vanish-leave-note')).toBeNull();
    expect(stoppedVanish('vanish-1')).not.toBeNull();

    // The account is topped up: the screen and Home leave the Vanish alone.
    mockNode.sendRaw.mockImplementation(async () => `0x${'cc'.repeat(32)}`);
    mockChainBalance = 20n * GHOST;
    await wait(MOVE_EVERY_MS * 5 + MOVE_PENDING_EVERY_MS * 3);
    expect(mockNode.sendRaw).toHaveBeenCalledTimes(1);
    expect(sequence.recover).toHaveBeenCalledTimes(1);
    expect(mockCore.signVanish).not.toHaveBeenCalled();
    expect(pendingPayments(kit).find((payment) => payment.id === 'vanish-1')?.stepText).toBe(STOPPED_TEXT);
    expect(screen.getByTestId('vanish-stopped')).toHaveTextContent(/will not be sent/);

    fireEvent.press(screen.getByTestId('vanish-stopped-cancel'));
    expect(mockStore.remove).toHaveBeenCalledWith('vanish-1');
    expect(mockBack).toHaveBeenCalled();
    expect(stoppedVanish('vanish-1')).toBeNull();
    expect(pendingPayments(kit)).toEqual([]);
  });

  it('stops in the Home mover too, and its screen then does not move it either', async () => {
    const sequence = savedVanish('vanish-2', 2n * GHOST, 3, 'Send');
    mockNode.sendRaw.mockRejectedValue(new Error(REFUSED));

    const home = renderHook(() => usePendingPayments(NODE_URL));
    await wait(0);
    expect(mockNode.sendRaw).toHaveBeenCalledTimes(1);
    expect(stoppedVanish('vanish-2')).toMatch(/Not enough test GHOST/);

    mockNode.sendRaw.mockImplementation(async () => `0x${'cc'.repeat(32)}`);
    mockChainBalance = 20n * GHOST;
    const shown = renderHook(() => usePayment(kit, sequence, signVanishAgain(kit, sequence), false));
    await wait(MOVE_EVERY_MS * 5 + MOVE_PENDING_EVERY_MS * 3);

    expect(mockNode.sendRaw).toHaveBeenCalledTimes(1);
    expect(sequence.recover).toHaveBeenCalledTimes(1);
    expect(shown.result.current).toMatchObject({ stopped: true, error: expect.stringMatching(/Not enough test GHOST/) });
    shown.unmount();
    home.unmount();
  });

  it('is not signed while the balance is short of its amount and fee, so a restart does not send it', async () => {
    mockChainBalance = 2n * GHOST + FEE - 1n;
    const sequence = savedVanish('vanish-3', 2n * GHOST, 1, 'Sign');

    const home = renderHook(() => usePendingPayments(NODE_URL));
    await wait(MOVE_PENDING_EVERY_MS * 3);
    expect(mockCore.signVanish).not.toHaveBeenCalled();
    expect(sequence.addAttempt).not.toHaveBeenCalled();
    expect(mockNode.sendRaw).not.toHaveBeenCalled();
    expect(sequence.recover).toHaveBeenCalledTimes(1);
    expect(stoppedVanish('vanish-3')).not.toBeNull();
    home.unmount();

    // After a restart nothing is kept in memory; the check before signing still refuses.
    resetPending();
    await expect(signVanishAgain(kit, sequence)(100)).rejects.toThrow(/not enough/i);
    expect(mockCore.signVanish).not.toHaveBeenCalled();

    // Enough for the amount and the fee: signed as before.
    mockChainBalance = 2n * GHOST + FEE;
    await expect(signVanishAgain(kit, sequence)(100)).resolves.toHaveProperty('signed');
    expect(mockCore.signVanish).toHaveBeenCalledTimes(1);
    expect(mockBalance).toHaveBeenLastCalledWith(ACCOUNT, `0x${'47'.repeat(32)}`);
  });

  it('keeps retrying any other failure, as before', async () => {
    const sequence = savedVanish('vanish-4', 2n * GHOST, 3, 'Send');
    mockNode.sendRaw.mockRejectedValue(new Error('the node refused a call: nonce too high'));
    const shown = renderHook(() => usePayment(kit, sequence, signVanishAgain(kit, sequence), false));
    await wait(MOVE_EVERY_MS * 2);
    expect(mockNode.sendRaw.mock.calls.length).toBeGreaterThan(1);
    expect(stoppedVanish('vanish-4')).toBeNull();
    expect(shown.result.current?.stopped).toBeFalsy();
    shown.unmount();
  });
});

/** `wei` as a GHOST amount typed in full, all 18 decimals. */
function formatWei(wei: bigint): string {
  return `${wei / GHOST}.${(wei % GHOST).toString().padStart(18, '0')}`;
}
