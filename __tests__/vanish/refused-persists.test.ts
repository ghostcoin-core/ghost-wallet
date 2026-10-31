import { act, renderHook } from '@testing-library/react-native';

import { MOVE_PENDING_EVERY_MS, usePendingPayments } from '../../lib/home/use-pending';
import { buildNetwork } from '../../lib/network/build-network';
import { signVanishAgain } from '../../lib/vanish/actions';
import { paymentStore, refusedMarks, type PaymentFiles } from '../../lib/vanish/payment-store';
import { encodeDetails, type PaymentDetails } from '../../lib/vanish/payments';
import { STOPPED_TEXT, forgetShared, pendingPayments, resetPending, stoppedVanish } from '../../lib/vanish/pending';
import { MOVE_EVERY_MS, usePayment, type PaymentKit } from '../../lib/vanish/use-payment';
import type { CorePaymentIntent, CorePaymentRecord, CorePaymentSequence } from '../../modules/ghost-core';

const GHOST = 10n ** 18n;
const NODE_URL = 'http://127.0.0.1:8547';
const REFUSED = 'the node refused a call: insufficient funds for gas * price + value';

// Steps are the core's Step: 1 BackedUp, 3 Sent.
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

// The core's view of each saved payment, kept across a restart like its files.
const mockSaved = new Map<string, FakeSequence>();

const mockCore = {
  // A record file holds its id here; the core decodes it to the saved payment.
  encodePaymentRecord: (record: CorePaymentRecord) => new TextEncoder().encode(record.id).buffer,
  decodePaymentRecord: (bytes: ArrayBuffer) => mockSaved.get(new TextDecoder().decode(new Uint8Array(bytes)))!.record(),
  forgetPhantomKey: jest.fn(),
  vanishGasLimit: () => 100_000n,
  signVanish: jest.fn(() => ({ transactionHash: new ArrayBuffer(32), sender: new ArrayBuffer(20), envelope: new Uint8Array([4]).buffer })),
  PaymentSequence: {
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
  sendRaw: jest.fn(async (_bytes: string) => `0x${'cc'.repeat(32)}`),
};
let mockChainBalance = 1n * GHOST;
const mockBalance = jest.fn(async () => mockChainBalance);
let mockKit: PaymentKit;

jest.mock('../../lib/vanish/use-payment', () => ({
  ...jest.requireActual('../../lib/vanish/use-payment'),
  paymentKit: () => mockKit,
}));

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

/** A Vanish saved with `step`, its record written to the payments folder. */
function savedVanish(id: string, step: number, recovery: string): FakeSequence {
  const sequence = fakeSequence(id, vanishIntent(2n * GHOST), step, recovery);
  mockSaved.set(id, sequence);
  mockKit.store.save(sequence.record());
  return sequence;
}

/** The app closed and opened again: nothing in memory is kept, the folder is. */
function restart() {
  resetPending();
  mockKit = { core: mockCore, store: paymentStore(mockCore as never, files), node: mockNode, nodeUrl: NODE_URL, balance: mockBalance } as unknown as PaymentKit;
}

async function wait(ms: number) {
  await act(async () => {
    await jest.advanceTimersByTimeAsync(ms);
  });
}

/** Saves Vanish `id` sent, and lets Home's mover meet the node's refusal. */
async function refusedVanish(id: string): Promise<FakeSequence> {
  const sequence = savedVanish(id, 3, 'Send');
  mockNode.sendRaw.mockRejectedValue(new Error(REFUSED));
  const home = renderHook(() => usePendingPayments(NODE_URL));
  await wait(0);
  expect(mockNode.sendRaw).toHaveBeenCalledTimes(1);
  expect(stoppedVanish(id)).toMatch(/Not enough test GHOST/);
  home.unmount();
  return sequence;
}

beforeEach(() => {
  jest.clearAllMocks();
  jest.useFakeTimers();
  mockSaved.clear();
  mockFiles.clear();
  mockChainBalance = 1n * GHOST;
  mockNode.sendRaw.mockImplementation(async () => `0x${'cc'.repeat(32)}`);
  restart();
});

afterEach(() => {
  jest.useRealTimers();
});

describe('the refused marker beside a saved payment', () => {
  it('is saved beside the record, not listed as a payment, read back, and removed with the record', () => {
    const store = paymentStore(mockCore as never, files);
    const marks = refusedMarks(store)!;
    savedVanish('vanish-a', 3, 'Send');

    expect(marks.refusedReason('vanish-a')).toBeNull();
    marks.markRefused('vanish-a', 'Not enough test GHOST');
    expect(marks.refusedReason('vanish-a')).toBe('Not enough test GHOST');
    expect(store.list()).toEqual(['vanish-a']);
    // The record itself is not rewritten.
    expect(new TextDecoder().decode(mockFiles.get('vanish-a.record'))).toBe('vanish-a');

    store.remove('vanish-a');
    expect(marks.refusedReason('vanish-a')).toBeNull();
    expect(mockFiles.size).toBe(0);
  });

  it('is not offered by a store that keeps no markers', () => {
    expect(refusedMarks({ list: () => [] } as never)).toBeNull();
  });
});

describe('a Vanish the node refused for insufficient funds, after a restart and a top-up', () => {
  it('stays stopped: Home lists it stopped and never sends or signs it', async () => {
    const sequence = await refusedVanish('vanish-1');

    restart();
    mockNode.sendRaw.mockImplementation(async () => `0x${'cc'.repeat(32)}`);
    mockChainBalance = 20n * GHOST;

    expect(stoppedVanish('vanish-1', mockKit.store)).toMatch(/Not enough test GHOST/);
    expect(pendingPayments(mockKit).find((payment) => payment.id === 'vanish-1')?.stepText).toBe(STOPPED_TEXT);

    const home = renderHook(() => usePendingPayments(NODE_URL));
    await wait(MOVE_PENDING_EVERY_MS * 3);
    home.unmount();

    expect(mockNode.sendRaw).toHaveBeenCalledTimes(1);
    expect(sequence.recover).toHaveBeenCalledTimes(1);
    expect(mockCore.signVanish).not.toHaveBeenCalled();
  });

  it('is shown stopped on its screen, which does not move it', async () => {
    const sequence = await refusedVanish('vanish-2');

    restart();
    mockNode.sendRaw.mockImplementation(async () => `0x${'cc'.repeat(32)}`);
    mockChainBalance = 20n * GHOST;

    const shown = renderHook(() => usePayment(mockKit, sequence, signVanishAgain(mockKit, sequence), false));
    await wait(MOVE_EVERY_MS * 5);

    expect(shown.result.current).toMatchObject({ stopped: true, error: expect.stringMatching(/Not enough test GHOST/) });
    expect(mockNode.sendRaw).toHaveBeenCalledTimes(1);
    expect(sequence.recover).toHaveBeenCalledTimes(1);
    shown.unmount();
  });

  it('is never signed again, whatever the balance', async () => {
    const sequence = await refusedVanish('vanish-3');

    restart();
    mockChainBalance = 1_000n * GHOST;

    await expect(signVanishAgain(mockKit, sequence)(100)).rejects.toThrow(/will not be sent/);
    expect(mockCore.signVanish).not.toHaveBeenCalled();
  });

  it('is gone once cancelled, and a new Vanish is not held stopped by it', async () => {
    await refusedVanish('vanish-4');

    restart();
    expect(stoppedVanish('vanish-4', mockKit.store)).not.toBeNull();
    // Cancelling, as the Vanish screen does it.
    mockKit.store.remove('vanish-4');
    forgetShared('vanish-4');

    expect(stoppedVanish('vanish-4', mockKit.store)).toBeNull();
    expect(pendingPayments(mockKit)).toEqual([]);
    expect([...mockFiles.keys()]).toEqual([]);

    restart();
    expect(stoppedVanish('vanish-4', mockKit.store)).toBeNull();
  });

  it('is kept stopped when the refusal came while its screen was being left', async () => {
    const sequence = savedVanish('vanish-5', 3, 'Send');
    let refuse: (error: Error) => void = () => {};
    mockNode.sendRaw.mockImplementation(
      () =>
        new Promise<string>((_resolve, reject) => {
          refuse = reject;
        }),
    );
    const shown = renderHook(() => usePayment(mockKit, sequence, signVanishAgain(mockKit, sequence), false));
    await wait(0);
    expect(mockNode.sendRaw).toHaveBeenCalledTimes(1);
    shown.unmount();
    await act(async () => {
      refuse(new Error(REFUSED));
    });

    restart();
    expect(stoppedVanish('vanish-5', mockKit.store)).toMatch(/Not enough test GHOST/);
  });

  it('leaves a Vanish that failed for another reason to be tried again after a restart', async () => {
    savedVanish('vanish-6', 3, 'Send');
    mockNode.sendRaw.mockRejectedValue(new Error('the node refused a call: nonce too high'));
    const home = renderHook(() => usePendingPayments(NODE_URL));
    await wait(0);
    home.unmount();

    restart();
    expect(stoppedVanish('vanish-6', mockKit.store)).toBeNull();
    expect(mockFiles.has('vanish-6.refused')).toBe(false);
  });
});
