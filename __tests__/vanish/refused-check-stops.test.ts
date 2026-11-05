// A Vanish the node's check before sending refuses (for instance one saved
// with commit data of an older version) is held stopped, beside its payment,
// and never tried again; one that never reached the node can be discarded on
// a tap, which sends nothing. A check that could not reach the node is still
// tried again.
import { act, fireEvent, render, renderHook, screen } from '@testing-library/react-native';
import { createElement } from 'react';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import VanishScreen from '../../app/vanish';
import { MOVE_PENDING_EVERY_MS, usePendingPayments } from '../../lib/home/use-pending';
import { buildNetwork } from '../../lib/network/build-network';
import { signVanishAgain } from '../../lib/vanish/actions';
import { sendCheckError } from '../../lib/vanish/node';
import { paymentStore, type PaymentFiles } from '../../lib/vanish/payment-store';
import { encodeDetails, type PaymentDetails } from '../../lib/vanish/payments';
import {
  REFUSED_STOPPED_TEXT,
  STOPPED_TEXT,
  discardVanish,
  discardableVanish,
  newestShared,
  pendingPayments,
  resetPending,
  stopVanish,
  stoppedVanish,
} from '../../lib/vanish/pending';
import { MOVE_EVERY_MS, usePayment, type PaymentKit } from '../../lib/vanish/use-payment';
import type { CoreAttempt, CorePaymentIntent, CorePaymentRecord, CorePaymentSequence } from '../../modules/ghost-core';

const ACCOUNT = `0x${'aa'.repeat(20)}`;
const GHOST = 10n ** 18n;
const NODE_URL = 'http://127.0.0.1:8547';
const COMMIT_REFUSAL = 'commit data is not 430 bytes of version 3: 206 bytes';
const ATTEMPT_HASH = `0x${'5e'.repeat(32)}`;

/** The node's check refusing the Vanish, with its own reason. */
function checkRefusal() {
  return sendCheckError(`the node refused a call: ${COMMIT_REFUSAL}`, true);
}

/** The check could not reach the node at all. */
function checkUnreachable() {
  return sendCheckError('the node could not check it: Network request failed', false);
}

// Steps are the core's Step: 0 Prepared, 1 BackedUp, 3 Sent.
type FakeSequence = CorePaymentSequence & { recover: jest.Mock; addAttempt: jest.Mock; markSent: jest.Mock };

function fakeSequence(id: string, intent: CorePaymentIntent, step: number, recovery: string, attempts: CoreAttempt[] = []): FakeSequence {
  const record: CorePaymentRecord = { id, intent, step, attempts, version: 1, checksum: new ArrayBuffer(0) };
  return {
    record: () => record,
    step: () => record.step,
    recover: jest.fn(() => ({ tag: recovery })),
    markBackedUp: jest.fn(() => {
      record.step = 1;
    }),
    addAttempt: jest.fn(() => new ArrayBuffer(32)),
    markSent: jest.fn(() => {
      record.step = 3;
      return new Uint8Array([0x52, 0x01]).buffer;
    }),
  } as unknown as FakeSequence;
}

// The core's view of each saved payment, kept across a restart like its files.
const mockSaved = new Map<string, FakeSequence>();

const mockCore = {
  savedAccountZeroAddress: () => ACCOUNT,
  hasAccount: () => true,
  encodePaymentRecord: (record: CorePaymentRecord) => new TextEncoder().encode(record.id).buffer,
  decodePaymentRecord: (bytes: ArrayBuffer) => mockSaved.get(new TextDecoder().decode(new Uint8Array(bytes)))!.record(),
  checkPhantomKeyWord: jest.fn(() => true),
  confirmPhantomKeySaved: jest.fn(),
  confirmPhantomKeySavedUnchecked: jest.fn(),
  forgetPhantomKey: jest.fn(),
  prepareVanish: jest.fn((_chainId: bigint, amountWei: string) => ({
    commitData: new Uint8Array(430).fill(3).buffer,
    amountWei,
    commitment: new ArrayBuffer(32),
  })),
  takePhantomKeyWords: jest.fn(() => Array.from({ length: 24 }, () => 'able')),
  feeWindow: jest.fn(() => ({ referenceHeight: 99n, validUntil: 120n })),
  minVanishWei: jest.fn(() => '1000'),
  vanishGasLimit: () => 100_000n,
  signVanish: jest.fn(() => ({ transactionHash: new ArrayBuffer(32), sender: new ArrayBuffer(20), envelope: new Uint8Array([0x52]).buffer })),
  PaymentSequence: {
    start: jest.fn((store: { save(record: CorePaymentRecord): void }, id: string, intent: CorePaymentIntent) => {
      const sequence = fakeSequence(id, intent, 0, 'BackUp');
      mockSaved.set(id, sequence);
      store.save(sequence.record());
      return sequence;
    }),
    open: jest.fn((store: { load(id: string): unknown }, id: string) => {
      const found = mockSaved.get(id);
      if (!found || !store.load(id)) throw new Error('no such payment');
      return found;
    }),
  },
};
jest.mock('../../modules/ghost-core/src/index', () => mockCore, { virtual: true });

/** The payments folder, in memory; it outlives a restart. */
const mockFiles = new Map<string, Uint8Array>();
const files: PaymentFiles = {
  read: (name) => mockFiles.get(name) ?? null,
  write: (name, bytes) => {
    mockFiles.set(name, new Uint8Array(bytes));
  },
  remove: (name) => {
    mockFiles.delete(name);
  },
  list: () => [...mockFiles.keys()],
};

const mockNode = {
  chainId: jest.fn(async () => buildNetwork.chainId),
  tipHeight: jest.fn(async () => 100),
  block: jest.fn(async (height: number) => ({ height, hash: `0x${'47'.repeat(32)}`, baseFeePerGas: 7n, transactions: [] })),
  receipts: jest.fn(async (hashes: string[]) => hashes.map(() => null)),
  known: jest.fn(async (hashes: string[]) => hashes.map(() => false)),
  nonce: jest.fn(async () => 2n),
  maxPriorityFeePerGas: jest.fn(async () => 1n),
  checkSend: jest.fn(async (_bytes: string, _from: string | null) => {}),
  sendRaw: jest.fn(async (_bytes: string) => `0x${'cc'.repeat(32)}`),
};
const mockBalance = jest.fn(async () => 20n * GHOST);
let mockKit: PaymentKit;

jest.mock('../../lib/vanish/use-payment', () => ({
  ...jest.requireActual('../../lib/vanish/use-payment'),
  paymentKit: () => mockKit,
}));
// Home's balance is never known here: the amount is checked against nothing.
jest.mock('../../lib/home/read-account', () => ({ readAccountZero: () => new Promise(() => {}) }));
jest.mock('../../lib/home/history', () => ({ scanHistory: async () => [] }));
jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));
const mockBack = jest.fn();
jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: mockBack, replace: jest.fn() }) }));

function vanishIntent(): CorePaymentIntent {
  const details: PaymentDetails = {
    kind: 'vanish',
    // Version-2 commit data, as saved before the fix: 206 bytes.
    commitData: `0x${'02'.repeat(206)}`,
    amountWei: (2n * GHOST).toString(),
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

/** A Vanish saved with `step`, its record written to the payments folder. */
function savedVanish(id: string, step: number, recovery: string, attempts: CoreAttempt[] = []): FakeSequence {
  const sequence = fakeSequence(id, vanishIntent(), step, recovery, attempts);
  mockSaved.set(id, sequence);
  mockKit.store.save(sequence.record());
  return sequence;
}

/** The app closed and opened again: nothing in memory is kept, the folder is. */
function restart() {
  resetPending();
  mockKit = {
    core: mockCore,
    store: paymentStore(mockCore as never, files),
    node: mockNode,
    nodeUrl: NODE_URL,
    balance: mockBalance,
  } as unknown as PaymentKit;
}

async function wait(ms: number) {
  await act(async () => {
    await jest.advanceTimersByTimeAsync(ms);
  });
}

/** Saves Vanish `id` signed-for but not sent, and lets Home's mover meet the check's refusal. */
async function refusedVanish(id: string): Promise<FakeSequence> {
  const sequence = savedVanish(id, 1, 'Sign');
  mockNode.checkSend.mockRejectedValue(checkRefusal());
  const home = renderHook(() => usePendingPayments(NODE_URL));
  await wait(0);
  expect(mockNode.checkSend).toHaveBeenCalledTimes(1);
  home.unmount();
  return sequence;
}

async function renderVanish() {
  const view = render(
    createElement(
      SafeAreaProvider,
      {
        initialMetrics: { frame: { x: 0, y: 0, width: 393, height: 852 }, insets: { top: 47, left: 0, right: 0, bottom: 34 } },
      },
      createElement(VanishScreen),
    ),
  );
  await act(async () => {});
  return view;
}

beforeEach(() => {
  jest.clearAllMocks();
  jest.useFakeTimers();
  mockSaved.clear();
  mockFiles.clear();
  mockNode.checkSend.mockImplementation(async () => {});
  mockNode.known.mockImplementation(async (hashes: string[]) => hashes.map(() => false));
  restart();
});

afterEach(() => {
  jest.useRealTimers();
});

describe('a Vanish the node’s check refuses', () => {
  it('is held stopped with the node’s reason and never tried again, by Home or its screen', async () => {
    const sequence = await refusedVanish('vanish-1');

    expect(stoppedVanish('vanish-1', mockKit.store)).toMatch(/would not take it/);
    expect(stoppedVanish('vanish-1', mockKit.store)).toContain(COMMIT_REFUSAL);
    expect(stoppedVanish('vanish-1', mockKit.store)).not.toMatch(/Trying again/);
    expect(discardableVanish('vanish-1', mockKit.store)).toBe(true);
    // Saved beside the payment, so a restart keeps it stopped.
    expect(mockFiles.has('vanish-1.refused')).toBe(true);
    expect(mockFiles.has('vanish-1.unsent')).toBe(true);
    expect(pendingPayments(mockKit).find((payment) => payment.id === 'vanish-1')?.stepText).toBe(REFUSED_STOPPED_TEXT);

    // The node would take it now: still nothing moves it.
    mockNode.checkSend.mockImplementation(async () => {});
    const home = renderHook(() => usePendingPayments(NODE_URL));
    const shown = renderHook(() => usePayment(mockKit, sequence, signVanishAgain(mockKit, sequence), false));
    await wait(MOVE_EVERY_MS * 5 + MOVE_PENDING_EVERY_MS * 3);

    expect(shown.result.current).toMatchObject({ stopped: true, discardable: true, error: expect.stringContaining(COMMIT_REFUSAL) });
    expect(mockNode.checkSend).toHaveBeenCalledTimes(1);
    expect(sequence.recover).toHaveBeenCalledTimes(1);
    expect(mockCore.signVanish).toHaveBeenCalledTimes(1);
    expect(sequence.addAttempt).not.toHaveBeenCalled();
    expect(mockNode.sendRaw).not.toHaveBeenCalled();
    shown.unmount();
    home.unmount();
  });

  it('stays stopped after a restart, and is never signed again', async () => {
    const sequence = await refusedVanish('vanish-2');

    restart();
    mockNode.checkSend.mockImplementation(async () => {});
    expect(stoppedVanish('vanish-2', mockKit.store)).toContain(COMMIT_REFUSAL);
    expect(discardableVanish('vanish-2', mockKit.store)).toBe(true);
    expect(pendingPayments(mockKit).find((payment) => payment.id === 'vanish-2')?.stepText).toBe(REFUSED_STOPPED_TEXT);

    const home = renderHook(() => usePendingPayments(NODE_URL));
    const shown = renderHook(() => usePayment(mockKit, sequence, signVanishAgain(mockKit, sequence), false));
    await wait(MOVE_EVERY_MS * 5 + MOVE_PENDING_EVERY_MS * 3);
    expect(shown.result.current).toMatchObject({ stopped: true, discardable: true });
    expect(mockNode.checkSend).toHaveBeenCalledTimes(1);
    expect(sequence.recover).toHaveBeenCalledTimes(1);
    shown.unmount();
    home.unmount();

    await expect(signVanishAgain(mockKit, sequence)(100)).rejects.toThrow(/will not be sent/);
    expect(mockCore.signVanish).toHaveBeenCalledTimes(1);
  });

  it('is discarded after a restart: its saved payment goes, nothing is sent, and a new Vanish can start', async () => {
    await refusedVanish('vanish-3');

    restart();
    mockNode.checkSend.mockImplementation(async () => {});
    expect(discardVanish(mockKit, 'vanish-3')).toBe(true);

    expect([...mockFiles.keys()]).toEqual([]);
    expect(stoppedVanish('vanish-3', mockKit.store)).toBeNull();
    expect(pendingPayments(mockKit)).toEqual([]);
    expect(newestShared(mockKit, ['vanish'])).toBeNull();
    // No chain action: nothing was signed, checked or sent for the discard.
    expect(mockNode.sendRaw).not.toHaveBeenCalled();
    expect(mockNode.checkSend).toHaveBeenCalledTimes(1);
    expect(mockCore.signVanish).toHaveBeenCalledTimes(1);

    restart();
    expect(stoppedVanish('vanish-3', mockKit.store)).toBeNull();
    expect(pendingPayments(mockKit)).toEqual([]);
  });

  it('stops one saved sent by an earlier build when the node holds none of its attempts', async () => {
    const sequence = savedVanish('vanish-4', 3, 'Send', [{ transactionHash: new Uint8Array(32).fill(0x5e).buffer }]);
    mockNode.checkSend.mockRejectedValue(checkRefusal());

    const shown = renderHook(() => usePayment(mockKit, sequence, signVanishAgain(mockKit, sequence), false));
    await wait(MOVE_EVERY_MS * 5);

    expect(mockNode.known).toHaveBeenCalledWith([ATTEMPT_HASH]);
    expect(shown.result.current).toMatchObject({ stopped: true, discardable: true });
    expect(mockNode.checkSend).toHaveBeenCalledTimes(1);
    expect(mockNode.sendRaw).not.toHaveBeenCalled();
    shown.unmount();

    restart();
    expect(discardableVanish('vanish-4', mockKit.store)).toBe(true);
  });

  it('is tried again, not discarded, while the node holds an earlier attempt of it', async () => {
    const sequence = savedVanish('vanish-5', 3, 'Send', [{ transactionHash: new Uint8Array(32).fill(0x5e).buffer }]);
    mockNode.checkSend.mockRejectedValue(checkRefusal());
    mockNode.known.mockImplementation(async (hashes: string[]) => hashes.map(() => true));

    const shown = renderHook(() => usePayment(mockKit, sequence, signVanishAgain(mockKit, sequence), false));
    await wait(MOVE_EVERY_MS * 3);
    expect(mockNode.checkSend.mock.calls.length).toBeGreaterThan(1);
    expect(shown.result.current?.stopped).toBeFalsy();
    expect(stoppedVanish('vanish-5', mockKit.store)).toBeNull();
    expect(discardVanish(mockKit, 'vanish-5')).toBe(false);
    expect(mockFiles.has('vanish-5.record')).toBe(true);
    shown.unmount();
  });

  it('cannot be discarded when it was stopped for lack of funds: that one is only cancelled', () => {
    savedVanish('vanish-6', 3, 'Send');
    stopVanish('vanish-6', 'Not enough test GHOST in this account.', mockKit.store);
    expect(discardableVanish('vanish-6', mockKit.store)).toBe(false);
    expect(discardVanish(mockKit, 'vanish-6')).toBe(false);
    expect(mockFiles.has('vanish-6.record')).toBe(true);
    expect(pendingPayments(mockKit).find((payment) => payment.id === 'vanish-6')?.stepText).toBe(STOPPED_TEXT);
  });
});

describe('a Vanish whose check cannot reach the node', () => {
  it('is still tried again, is not stopped, and goes out once the node answers', async () => {
    const sequence = savedVanish('vanish-7', 1, 'Sign');
    mockNode.checkSend.mockRejectedValue(checkUnreachable());

    const shown = renderHook(() => usePayment(mockKit, sequence, signVanishAgain(mockKit, sequence), false));
    await wait(MOVE_EVERY_MS * 3);
    expect(mockNode.checkSend.mock.calls.length).toBeGreaterThan(1);
    expect(shown.result.current?.stopped).toBeFalsy();
    expect(shown.result.current?.discardable).toBeFalsy();
    expect(shown.result.current?.error).toMatch(/could not check it first/);
    expect(stoppedVanish('vanish-7', mockKit.store)).toBeNull();
    expect(mockNode.sendRaw).not.toHaveBeenCalled();

    mockNode.checkSend.mockImplementation(async () => {});
    await wait(MOVE_EVERY_MS * 2);
    expect(mockNode.sendRaw).toHaveBeenCalled();
    shown.unmount();
  });

  it('is not stopped by Home either, and nothing is saved that holds it after a restart', async () => {
    savedVanish('vanish-8', 1, 'Sign');
    mockNode.checkSend.mockRejectedValue(checkUnreachable());
    const home = renderHook(() => usePendingPayments(NODE_URL));
    await wait(MOVE_PENDING_EVERY_MS * 2);
    expect(mockNode.checkSend.mock.calls.length).toBeGreaterThan(1);
    home.unmount();

    restart();
    expect(stoppedVanish('vanish-8', mockKit.store)).toBeNull();
    expect(mockFiles.has('vanish-8.refused')).toBe(false);
    expect(mockFiles.has('vanish-8.unsent')).toBe(false);
  });
});

describe('the Vanish screen of a Vanish the check refused', () => {
  it('shows it stopped with "Discard this Vanish", which removes it and lets a new Vanish start', async () => {
    await refusedVanish('vanish-9');
    restart();
    mockNode.checkSend.mockImplementation(async () => {});

    const first = await renderVanish();
    await wait(MOVE_EVERY_MS * 3);
    expect(screen.getByTestId('vanish-stopped')).toHaveTextContent(new RegExp(COMMIT_REFUSAL));
    expect(screen.getByTestId('vanish-stopped')).toHaveTextContent(/will not be sent/);
    expect(screen.queryByText(/Trying again/)).toBeNull();
    expect(screen.queryByTestId('vanish-stopped-cancel')).toBeNull();
    expect(screen.getByText('Discard this Vanish')).toBeOnTheScreen();
    expect(mockNode.checkSend).toHaveBeenCalledTimes(1);

    fireEvent.press(screen.getByTestId('vanish-discard'));
    expect(mockBack).toHaveBeenCalled();
    expect([...mockFiles.keys()]).toEqual([]);
    expect(mockNode.sendRaw).not.toHaveBeenCalled();
    expect(mockNode.checkSend).toHaveBeenCalledTimes(1);
    first.unmount();

    // Opened again, even after a restart: a new Vanish starts.
    restart();
    await renderVanish();
    expect(screen.queryByTestId('vanish-stopped')).toBeNull();
    fireEvent.changeText(screen.getByTestId('vanish-amount'), '1');
    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-make-key'));
    });
    expect(mockCore.prepareVanish).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('phantom-key')).toBeOnTheScreen();
  });
});
