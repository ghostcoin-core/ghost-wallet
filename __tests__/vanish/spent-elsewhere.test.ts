// A Summon or Claim that needs a new proof, whose coin another transaction
// already took (an earlier try of it on this phone, whose upload failed), is
// stopped for the person to discard instead of waiting on a proof forever.
import { advance, encodeDetails } from '../../lib/vanish/payments';
import {
  discardSpentElsewhere,
  isSpentElsewhere,
  pendingPayments,
  resetPending,
  SPENT_ELSEWHERE_STEP_TEXT,
  stoppedVanish,
} from '../../lib/vanish/pending';
import { buildNetwork } from '../../lib/network/build-network';
import type { CorePaymentIntent, CorePaymentRecord, CorePaymentSequence } from '../../modules/ghost-core';

jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));

const MARKER = `0x${'0b'.repeat(32)}`;
const ATTEMPT = new Uint8Array(32).fill(0x06).buffer;

function revealSequence(id: string, attempts: ArrayBuffer[] = [ATTEMPT], recovery = 'Rebuild') {
  const intent: CorePaymentIntent = {
    kind: 2,
    identity: { tag: 'RevealMarker', inner: { marker: new Uint8Array(32).fill(0x0b).buffer } },
    details: encodeDetails({
      kind: 'summon',
      amountWei: '700',
      feeWei: '10',
      marker: MARKER,
      at: 3,
      chainId: buildNetwork.chainId.toString(),
    }),
  };
  const record: CorePaymentRecord = {
    id,
    intent,
    step: 3,
    attempts: attempts.map((transactionHash) => ({ transactionHash, validUntil: 90n })),
    version: 1,
    checksum: new ArrayBuffer(0),
  };
  return {
    record: () => record,
    step: () => record.step,
    recover: jest.fn(() => ({ tag: recovery })),
    addAttempt: jest.fn(),
    markSent: jest.fn(),
  } as unknown as CorePaymentSequence & { recover: jest.Mock };
}

function fakeNode(spent: string[] | Error, known = false) {
  return {
    tipHeight: jest.fn(async () => 100),
    block: jest.fn(async (height: number) => ({ height, hash: `0x${'47'.repeat(32)}`, baseFeePerGas: 7n, transactions: [] })),
    receipts: jest.fn(async (hashes: string[]) => hashes.map(() => null)),
    known: jest.fn(async (hashes: string[]) => hashes.map(() => known)),
    markerPages: jest.fn(async () => {
      if (spent instanceof Error) throw spent;
      return spent;
    }),
    checkSend: jest.fn(async () => {}),
    sendRaw: jest.fn(async () => `0x${'cc'.repeat(32)}`),
  };
}

beforeEach(() => resetPending());

describe('a Summon that needs a new proof', () => {
  it('with no key, is found already summoned when its marker is spent, settled, and the node knows none of its attempts', async () => {
    const node = fakeNode([`0x${'aa'.repeat(32)}`, MARKER.toUpperCase().replace('0X', '0x')]);
    const moved = await advance(node as never, revealSequence('summon-a'), null, null);
    expect(moved.spentElsewhere).toBe(true);
    expect(moved.needsKey).toBe(false);
    expect(isSpentElsewhere('summon-a')).toBe(true);
    // The markers are read as of a settled block, not the tip.
    expect(node.block).toHaveBeenCalledWith(98);
    // Nothing is sent.
    expect(node.sendRaw).not.toHaveBeenCalled();
    // Never saved as stopped: the next move asks again.
    expect(stoppedVanish('summon-a')).toBeNull();
  });

  it('with its key held, is proved again and left to the node, whatever the markers say', async () => {
    const node = fakeNode([MARKER]);
    const rebuild = jest.fn(async () => ({ signed: new Uint8Array([0x03]).buffer, validUntil: 130n }));
    const moved = await advance(node as never, revealSequence('summon-b'), rebuild, null);
    expect(moved.spentElsewhere).toBeUndefined();
    expect(rebuild).toHaveBeenCalledTimes(1);
    expect(node.markerPages).not.toHaveBeenCalled();
    expect(isSpentElsewhere('summon-b')).toBe(false);
  });

  it('is waiting again when a later move finds the marker not spent (a reorg)', async () => {
    const sequence = revealSequence('summon-c');
    await advance(fakeNode([MARKER]) as never, sequence, null, null);
    expect(isSpentElsewhere('summon-c')).toBe(true);
    const moved = await advance(fakeNode([]) as never, sequence, null, null);
    expect(moved.spentElsewhere).toBeUndefined();
    expect(moved.needsKey).toBe(true);
    expect(isSpentElsewhere('summon-c')).toBe(false);
  });

  it('is never found spent while the node still holds one of its attempts', async () => {
    const node = fakeNode([MARKER], true);
    const moved = await advance(node as never, revealSequence('summon-d'), null, null);
    expect(moved.needsKey).toBe(true);
    expect(node.markerPages).not.toHaveBeenCalled();
  });

  it('is never found spent when the marker pages cannot be read', async () => {
    const moved = await advance(fakeNode(new Error('the node did not answer in time')) as never, revealSequence('summon-e'), null, null);
    expect(moved.needsKey).toBe(true);
    expect(moved.spentElsewhere).toBeUndefined();
  });

  it('is not asked about when the payment only needs sending again, and the note clears', async () => {
    const node = fakeNode([MARKER]);
    await advance(node as never, revealSequence('summon-f'), null, null);
    expect(isSpentElsewhere('summon-f')).toBe(true);
    node.markerPages.mockClear();
    await advance(node as never, revealSequence('summon-f', [ATTEMPT], 'Send'), null, null);
    expect(node.markerPages).not.toHaveBeenCalled();
    expect(isSpentElsewhere('summon-f')).toBe(false);
  });
});

describe('a Summon found already summoned', () => {
  it('Home says so, and the tap discards it', async () => {
    const sequence = revealSequence('summon-g');
    const store = { list: () => ['summon-g'], remove: jest.fn() };
    const kit = { core: { PaymentSequence: { open: () => sequence } }, store } as never;
    await advance(fakeNode([MARKER]) as never, sequence, null, null);
    expect(pendingPayments(kit).map((payment) => payment.stepText)).toEqual([SPENT_ELSEWHERE_STEP_TEXT]);
    expect(discardSpentElsewhere(kit, 'summon-g')).toBe(true);
    expect(store.remove).toHaveBeenCalledWith('summon-g');
  });

  it('is never discarded unless its last move found the coin taken', () => {
    const store = { list: () => [], remove: jest.fn() };
    expect(discardSpentElsewhere({ store } as never, 'summon-h')).toBe(false);
    expect(store.remove).not.toHaveBeenCalled();
  });
});
