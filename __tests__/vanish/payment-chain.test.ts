import { act, renderHook } from '@testing-library/react-native';

import { usePendingPayments } from '../../lib/home/use-pending';
import { savedActivity, savedCredits } from '../../lib/home/saved-activity';
import { GHOST_DEV_CHAIN_ID, GHOST_PUBLIC_TEST_CHAIN_ID, buildNetwork } from '../../lib/network/build-network';
import { advanceSend, reservedNonce, signSend, startSend, type SendKit } from '../../lib/send/send-payment';
import { ALREADY_SUMMONED_TEXT, signVanishAgain, startReveal, startVanish } from '../../lib/vanish/actions';
import {
  OTHER_NETWORK_TEXT,
  advance,
  decodeDetails,
  encodeDetails,
  onOtherChain,
  savedChainId,
  type PaymentDetails,
  type SendDetails,
} from '../../lib/vanish/payments';
import { pendingPayments, resetPending } from '../../lib/vanish/pending';
import type { CorePaymentIntent, CorePaymentRecord, CorePaymentSequence } from '../../modules/ghost-core';

jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));

let mockKit: unknown = null;
jest.mock('../../lib/vanish/use-payment', () => ({
  paymentKit: () => mockKit,
  treeAtTip: async () => ({ tree: { height: 1, hash: '', leaves: [], spent: [], spentBy: {} }, tip: 1 }),
}));

const ACCOUNT = `0x${'aa'.repeat(20)}`;
const MARKER = `0x${'0b'.repeat(32)}`;
const OWN = buildNetwork.chainId.toString();
const OTHER = (buildNetwork.chainId === GHOST_DEV_CHAIN_ID ? GHOST_PUBLIC_TEST_CHAIN_ID : GHOST_DEV_CHAIN_ID).toString();

// Steps are the core's Step: 1 BackedUp, 3 Sent, 5 Settled.
type FakeSequence = CorePaymentSequence & {
  recover: jest.Mock;
  addAttempt: jest.Mock;
  markSent: jest.Mock;
  markBackedUp: jest.Mock;
};

function fakeSequence(id: string, intent: CorePaymentIntent, step: number, recovery = 'Sign'): FakeSequence {
  const record: CorePaymentRecord = {
    id,
    intent,
    step,
    attempts: [],
    version: 1,
    checksum: new ArrayBuffer(0),
  };
  return {
    record: () => record,
    step: () => record.step,
    recover: jest.fn(() => ({ tag: recovery })),
    markBackedUp: jest.fn(),
    addAttempt: jest.fn(() => new ArrayBuffer(32)),
    markSent: jest.fn(() => {
      record.step = 3;
      return new Uint8Array([0x02, 0x01]).buffer;
    }),
  };
}

function fakeKit() {
  const saved = new Map<string, FakeSequence>();
  const node = {
    chainId: jest.fn(async () => buildNetwork.chainId),
    tipHeight: jest.fn(async () => 100),
    block: jest.fn(async (height: number) => ({ height, hash: `0x${'47'.repeat(32)}`, baseFeePerGas: 7n, transactions: [] })),
    receipts: jest.fn(async (hashes: string[]) => hashes.map(() => null)),
    known: jest.fn(async (hashes: string[]) => hashes.map(() => false)),
    nonce: jest.fn(async () => 4n),
    maxPriorityFeePerGas: jest.fn(async () => 1n),
    sendRaw: jest.fn(async () => `0x${'cc'.repeat(32)}`),
  };
  const core = {
    prepareVanish: jest.fn(() => ({ commitData: new Uint8Array([1, 2]).buffer, amountWei: '500', commitment: new ArrayBuffer(32) })),
    takePhantomKeyWords: jest.fn(() => ['able']),
    forgetPhantomKey: jest.fn(),
    feeWindow: jest.fn(() => ({ referenceHeight: 99n, validUntil: 120n })),
    proveKeyReveal: jest.fn((_key: string, request: { outWei?: string }) => ({
      transactionHash: new ArrayBuffer(32),
      marker: new Uint8Array(32).fill(0x0b).buffer,
      envelope: new Uint8Array([0x03]).buffer,
      feeWei: '10',
      outWei: request.outWei ?? '700',
      remainderWei: '0',
      proveMillis: 1n,
    })),
    signVanish: jest.fn(() => ({ transactionHash: new ArrayBuffer(32), sender: new ArrayBuffer(20), envelope: new Uint8Array([0x04]).buffer })),
    signSend: jest.fn(() => ({ transactionHash: new ArrayBuffer(32), sender: new ArrayBuffer(20), envelope: new Uint8Array([0x05]).buffer })),
    vanishGasLimit: () => 100_000n,
    testSendGasLimit: () => 84_256n,
    PaymentSequence: {
      start: jest.fn((_store: unknown, id: string, intent: CorePaymentIntent) => {
        const sequence = fakeSequence(id, intent, 0);
        saved.set(id, sequence);
        return sequence;
      }),
      open: jest.fn((_store: unknown, id: string) => {
        const found = saved.get(id);
        if (!found) throw new Error('no such payment');
        return found;
      }),
    },
  };
  const store = { list: () => [...saved.keys()], remove: jest.fn() };
  // A Vanish is signed only when the account pays its amount and fee.
  const balance = jest.fn(async () => 10n ** 18n);
  const kit = { core, store, node, nodeUrl: 'http://127.0.0.1:8547', balance } as unknown as SendKit;
  return { kit, core, node, saved };
}

const NODE_ASKED = ['chainId', 'tipHeight', 'block', 'receipts', 'known', 'nonce', 'maxPriorityFeePerGas', 'sendRaw'] as const;

function expectNodeUntouched(node: ReturnType<typeof fakeKit>['node']) {
  for (const method of NODE_ASKED) {
    expect(node[method]).not.toHaveBeenCalled();
  }
}

function vanishDetails(chainId?: string): PaymentDetails {
  return { kind: 'vanish', commitData: '0x0102', amountWei: '500', nonce: '4', at: 1, ...(chainId ? { chainId } : {}) };
}
function sendDetails(chainId?: string): SendDetails {
  return {
    kind: 'send',
    to: `0x${'bb'.repeat(20)}`,
    amountWei: '900',
    nonce: '7',
    maxFeePerGas: null,
    fromHeight: 90,
    at: 2,
    ...(chainId ? { chainId } : {}),
  };
}
function revealDetails(kind: 'summon' | 'claim', chainId?: string): PaymentDetails {
  return { kind, amountWei: '700', feeWei: '10', marker: MARKER, at: 3, ...(chainId ? { chainId } : {}) };
}
function accountIntent(kind: number, details: PaymentDetails): CorePaymentIntent {
  return {
    kind,
    identity: { tag: 'AccountNonce', inner: { account: new Uint8Array(20).fill(0xaa).buffer, nonce: 7n } },
    details: encodeDetails(details),
  };
}
function markerIntent(details: PaymentDetails): CorePaymentIntent {
  return { kind: 2, identity: { tag: 'RevealMarker', inner: { marker: new Uint8Array(32).fill(0x0b).buffer } }, details: encodeDetails(details) };
}

function savedDetails(sequence: CorePaymentSequence): PaymentDetails | null {
  return decodeDetails(sequence.record().intent.details);
}

beforeEach(() => {
  resetPending();
  mockKit = null;
});

describe('a new payment', () => {
  it('saves a Vanish with the chain of this build', async () => {
    const { kit } = fakeKit();
    const { sequence } = await startVanish(kit, ACCOUNT, 500n);
    expect(savedDetails(sequence)).toMatchObject({ kind: 'vanish', chainId: OWN });
  });

  it.each([
    ['summon', null],
    ['claim', 300n],
  ] as const)('saves a %s with the chain of this build', async (kind, outWei) => {
    const { kit } = fakeKit();
    const sequence = await startReveal(kit, 'typed key words', ACCOUNT, outWei);
    expect(savedDetails(sequence)).toMatchObject({ kind, chainId: OWN });
  });

  it('saves a send with the chain of this build, even with the node out of reach', async () => {
    const { kit, node } = fakeKit();
    node.nonce.mockRejectedValue(new Error('offline'));
    node.tipHeight.mockRejectedValue(new Error('offline'));
    const sequence = await startSend(kit, {
      account: ACCOUNT,
      to: `0x${'bb'.repeat(20)}`,
      amountWei: 900n,
      maxFeePerGas: null,
      cached: { nonce: 2, tipHeight: 50 },
    });
    expect(savedDetails(sequence)).toMatchObject({ kind: 'send', chainId: OWN });
  });
});

describe('a Summon or Claim whose send may have reached the node', () => {
  it.each([
    ['the send timed out', new Error('the node did not answer in time')],
    ['the connection dropped', new TypeError('Network request failed')],
  ])('stays saved and sending when %s', async (_why, failure) => {
    const { kit, node, saved } = fakeKit();
    node.sendRaw.mockRejectedValueOnce(failure);
    const sequence = await startReveal(kit, 'typed key words', ACCOUNT, null);
    expect(saved.get(sequence.record().id)).toBe(sequence);
    expect(sequence.addAttempt).toHaveBeenCalledTimes(1);
    expect(sequence.markSent).toHaveBeenCalledTimes(1);
    expect(savedDetails(sequence)).toMatchObject({ kind: 'summon', marker: MARKER });

    // The payment mover takes it on: it sends the saved attempt again.
    (sequence.recover as jest.Mock).mockReturnValue({ tag: 'Send' });
    const moved = await advance(kit.node, sequence, null, null);
    expect(moved.otherNetwork).toBeUndefined();
    expect(moved.needsKey).toBe(false);
    expect(node.sendRaw).toHaveBeenCalledTimes(2);
    expect(node.sendRaw).toHaveBeenLastCalledWith('0x0201');
  });

  it('is listed as pending on Home after a timed-out send', async () => {
    const { kit, node } = fakeKit();
    node.sendRaw.mockRejectedValueOnce(new Error('the node did not answer in time'));
    const sequence = await startReveal(kit, 'typed key words', ACCOUNT, 300n);
    expect(pendingPayments(kit).map((payment) => payment.id)).toEqual([sequence.record().id]);
  });

  it('fails only when the node refuses it', async () => {
    const { kit, node } = fakeKit();
    node.sendRaw.mockRejectedValueOnce(new Error('the node refused a call: invalid sender'));
    await expect(startReveal(kit, 'typed key words', ACCOUNT, null)).rejects.toThrow(/refused a call: invalid sender/);
    node.sendRaw.mockRejectedValueOnce(new Error('the node refused a call: marker already spent'));
    await expect(startReveal(kit, 'typed key words', ACCOUNT, null)).rejects.toThrow(ALREADY_SUMMONED_TEXT);
  });
});

describe('a record saved before the chain was written down', () => {
  it('reads as a dev-chain payment', () => {
    expect(savedChainId(vanishDetails())).toBe(6777971n);
    expect(savedChainId(sendDetails())).toBe(6777971n);
    const record = { intent: accountIntent(1, vanishDetails()) };
    expect(onOtherChain(record, GHOST_DEV_CHAIN_ID)).toBe(false);
    expect(onOtherChain(record, GHOST_PUBLIC_TEST_CHAIN_ID)).toBe(true);
  });

  it('reads as another chain when what it says is not a chain id', () => {
    expect(savedChainId({ chainId: 'release' })).toBeNull();
    expect(onOtherChain({ intent: accountIntent(1, vanishDetails('release')) }, GHOST_DEV_CHAIN_ID)).toBe(true);
  });
});

describe('a payment saved on another chain', () => {
  it('is never signed or sent by advance', async () => {
    const { kit, core, node } = fakeKit();
    const sequence = fakeSequence('vanish-1', accountIntent(1, vanishDetails(OTHER)), 3, 'Rebuild');
    const result = await advance(kit.node, sequence, signVanishAgain(kit, sequence), null);
    expect(result).toMatchObject({ step: 3, needsKey: false, needsBackup: false, otherNetwork: true });
    expect(sequence.recover).not.toHaveBeenCalled();
    expect(sequence.addAttempt).not.toHaveBeenCalled();
    expect(sequence.markSent).not.toHaveBeenCalled();
    expect(core.signVanish).not.toHaveBeenCalled();
    expectNodeUntouched(node);
  });

  it('is never signed again by signVanishAgain', async () => {
    const { kit, core, node } = fakeKit();
    const sequence = fakeSequence('vanish-1', accountIntent(1, vanishDetails(OTHER)), 3);
    await expect(signVanishAgain(kit, sequence)(100)).rejects.toThrow(/another network/);
    expect(core.signVanish).not.toHaveBeenCalled();
    expectNodeUntouched(node);
  });

  it('is never signed or sent by advanceSend, and holds no nonce of this chain', async () => {
    const { kit, core, node, saved } = fakeKit();
    const sequence = fakeSequence('send-1', accountIntent(0, sendDetails(OTHER)), 1, 'Sign');
    saved.set('send-1', sequence);
    const result = await advanceSend(kit, sequence);
    expect(result.step).toBe(1);
    expect(sequence.recover).not.toHaveBeenCalled();
    expect(sequence.addAttempt).not.toHaveBeenCalled();
    expect(sequence.markSent).not.toHaveBeenCalled();
    expect(core.signSend).not.toHaveBeenCalled();
    expectNodeUntouched(node);
    await expect(signSend(kit, sendDetails(OTHER))).rejects.toThrow(/another network/);
    expect(reservedNonce(kit, ACCOUNT)).toBe(0n);
  });

  it('is listed as pending on another network, and the Home mover leaves it alone', async () => {
    const { kit, core, node, saved } = fakeKit();
    const vanish = fakeSequence('vanish-1', accountIntent(1, vanishDetails(OTHER)), 3, 'Rebuild');
    const send = fakeSequence('send-2', accountIntent(0, sendDetails(OTHER)), 1, 'Sign');
    const summon = fakeSequence('summon-3', markerIntent(revealDetails('summon', OTHER)), 3, 'Send');
    saved.set('vanish-1', vanish);
    saved.set('send-2', send);
    saved.set('summon-3', summon);
    mockKit = kit;

    const listed = pendingPayments(kit);
    expect(listed.map((payment) => payment.id).sort()).toEqual(['send-2', 'summon-3', 'vanish-1']);
    for (const payment of listed) {
      expect(payment.otherNetwork).toBe(true);
      expect(payment.stepText).toBe(OTHER_NETWORK_TEXT);
    }
    expect(OTHER_NETWORK_TEXT).toBe('Saved on another network. Not sent.');

    const { result, unmount } = renderHook(() => usePendingPayments('http://127.0.0.1:8547'));
    await act(async () => {});
    expect(result.current.map((payment) => payment.stepText)).toEqual([
      OTHER_NETWORK_TEXT,
      OTHER_NETWORK_TEXT,
      OTHER_NETWORK_TEXT,
    ]);
    for (const sequence of [vanish, send, summon]) {
      expect(sequence.recover).not.toHaveBeenCalled();
      expect(sequence.addAttempt).not.toHaveBeenCalled();
      expect(sequence.markSent).not.toHaveBeenCalled();
    }
    expect(core.signVanish).not.toHaveBeenCalled();
    expect(core.signSend).not.toHaveBeenCalled();
    expectNodeUntouched(node);
    unmount();
  });

  it('is kept out of this chain’s Activity and balance increases', () => {
    const { kit, saved } = fakeKit();
    saved.set('summon-1', fakeSequence('summon-1', markerIntent(revealDetails('summon', OTHER)), 5));
    saved.set('claim-2', fakeSequence('claim-2', markerIntent(revealDetails('claim', OWN)), 5));
    expect(savedActivity(kit).map((item) => item.id)).toEqual(['claim-2']);
    expect([...savedCredits(kit).keys()]).toEqual(['claim-2']);
  });
});

describe('a payment saved on this build’s chain', () => {
  it('is signed again and sent by advance as before', async () => {
    const { kit, core, node } = fakeKit();
    const sequence = fakeSequence('vanish-1', accountIntent(1, vanishDetails(OWN)), 3, 'Rebuild');
    const result = await advance(kit.node, sequence, signVanishAgain(kit, sequence), null);
    expect(result.otherNetwork).toBeUndefined();
    expect(sequence.recover).toHaveBeenCalledTimes(1);
    expect(core.signVanish).toHaveBeenCalledWith(expect.objectContaining({ chainId: buildNetwork.chainId, nonce: 4n }));
    expect(sequence.addAttempt).toHaveBeenCalledTimes(1);
    expect(node.sendRaw).toHaveBeenCalledWith('0x0201');
  });

  it('is signed and sent by advanceSend as before', async () => {
    const { kit, core, node } = fakeKit();
    const sequence = fakeSequence('send-1', accountIntent(0, sendDetails(OWN)), 1, 'Sign');
    await advanceSend(kit, sequence);
    expect(core.signSend).toHaveBeenCalledWith(expect.objectContaining({ chainId: buildNetwork.chainId, nonce: 7n }));
    expect(node.sendRaw).toHaveBeenCalledWith('0x0201');
  });

  it('is moved by the Home mover as before', async () => {
    const { kit, saved } = fakeKit();
    // Saved before the chain was written down: a dev-chain payment, this build's chain in tests.
    const vanish = fakeSequence('vanish-1', accountIntent(1, vanishDetails()), 3, 'Wait');
    const send = fakeSequence('send-2', accountIntent(0, sendDetails(OWN)), 1, 'Sign');
    saved.set('vanish-1', vanish);
    saved.set('send-2', send);
    mockKit = kit;

    const listed = pendingPayments(kit);
    expect(listed.every((payment) => !payment.otherNetwork && payment.stepText !== OTHER_NETWORK_TEXT)).toBe(true);
    const { unmount } = renderHook(() => usePendingPayments('http://127.0.0.1:8547'));
    await act(async () => {});
    expect(vanish.recover).toHaveBeenCalled();
    expect(send.recover).toHaveBeenCalled();
    expect(send.markSent).toHaveBeenCalled();
    unmount();
  });
});
