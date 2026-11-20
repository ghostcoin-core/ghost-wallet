// A Summon of a coin already saved and not yet in a block (its upload failed,
// or its window passed) is joined by a new try as its next attempt: one coin
// is never two payments.
import { buildNetwork } from '../../lib/network/build-network';
import { ALREADY_SUMMONED_TEXT, MAX_REVEAL_ATTEMPTS, startReveal } from '../../lib/vanish/actions';
import { pendingPayments, resetPending } from '../../lib/vanish/pending';
import type { CorePaymentIntent, CorePaymentRecord, CorePaymentSequence } from '../../modules/ghost-core';

jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));
jest.mock('../../lib/vanish/use-payment', () => ({
  treeAtTip: async () => ({ tree: { height: 1, hash: '', leaves: [], spent: [], spentBy: {} }, tip: 1 }),
}));

const ACCOUNT = `0x${'aa'.repeat(20)}`;

type Saved = CorePaymentSequence & { addAttempt: jest.Mock; record: () => CorePaymentRecord };

function fakeKit() {
  const saved = new Map<string, Saved>();
  let proofs = 0;
  const node = {
    chainId: jest.fn(async () => buildNetwork.chainId),
    block: jest.fn(async (height: number) => ({ height, hash: `0x${'47'.repeat(32)}`, baseFeePerGas: 7n, transactions: [] })),
    known: jest.fn(async (hashes: string[]) => hashes.map(() => false)),
    checkSend: jest.fn(async () => {}),
    sendRaw: jest.fn(async () => `0x${'cc'.repeat(32)}`),
  };
  const core = {
    feeWindow: jest.fn(() => ({ referenceHeight: 0n, validUntil: 7n })),
    proveCardKeyReveal: jest.fn((request: { outWei?: string }) => {
      proofs += 1;
      return {
        transactionHash: new ArrayBuffer(32),
        marker: new Uint8Array(32).fill(0x0b).buffer,
        envelope: new Uint8Array([0x50, proofs]).buffer,
        feeWei: '10',
        outWei: request.outWei ?? '700',
        remainderWei: '0',
        proveMillis: 1n,
      };
    }),
    PaymentSequence: {
      start: jest.fn((_store: unknown, id: string, intent: CorePaymentIntent) => {
        const record: CorePaymentRecord = { id, intent, step: 0, attempts: [], version: 1, checksum: new ArrayBuffer(0) };
        const sequence = {
          record: () => record,
          step: () => record.step,
          markBackedUp: jest.fn(() => {
            record.step = 1;
          }),
          addAttempt: jest.fn((envelope: ArrayBuffer, validUntil?: bigint) => {
            record.attempts = [...record.attempts, { transactionHash: envelope, validUntil }];
            record.step = 2;
            return envelope;
          }),
          markSent: jest.fn(() => {
            record.step = 3;
            return record.attempts[record.attempts.length - 1].transactionHash;
          }),
        } as unknown as Saved;
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
  const kit = { core, store, node, nodeUrl: 'http://node.example.com' } as never;
  return { kit, core, node, saved };
}

const CARD = { card: true } as never;

beforeEach(() => resetPending());

let clock = 1_000;
beforeEach(() => {
  clock += 1_000;
  jest.spyOn(Date, 'now').mockImplementation(() => (clock += 1));
});
afterEach(() => jest.restoreAllMocks());

describe('a card Summon tried again', () => {
  it('after its upload failed, joins the saved Summon as its next attempt', async () => {
    const { kit, core, node, saved } = fakeKit();
    node.sendRaw.mockRejectedValueOnce(new TypeError('Network request failed'));
    const first = await startReveal(kit, CARD, ACCOUNT, null);
    const again = await startReveal(kit, CARD, ACCOUNT, null);
    expect(again).toBe(first);
    expect(core.PaymentSequence.start).toHaveBeenCalledTimes(1);
    expect(saved.size).toBe(1);
    expect(first.record().attempts).toHaveLength(2);
    expect(node.sendRaw).toHaveBeenCalledTimes(2);
    expect(node.sendRaw).toHaveBeenLastCalledWith('0x5002');
    expect(pendingPayments(kit)).toHaveLength(1);
  });

  it('while its last attempt is still at the node, shows that one and sends nothing new', async () => {
    const { kit, core, node } = fakeKit();
    const first = await startReveal(kit, CARD, ACCOUNT, null);
    node.known.mockResolvedValueOnce([true]);
    const again = await startReveal(kit, CARD, ACCOUNT, null);
    expect(again).toBe(first);
    expect(core.PaymentSequence.start).toHaveBeenCalledTimes(1);
    expect(first.record().attempts).toHaveLength(1);
    expect(node.sendRaw).toHaveBeenCalledTimes(1);
  });

  it('fails as already summoned when the node refuses the joined attempt', async () => {
    const { kit, node } = fakeKit();
    node.sendRaw.mockRejectedValueOnce(new TypeError('Network request failed'));
    await startReveal(kit, CARD, ACCOUNT, null);
    node.sendRaw.mockRejectedValueOnce(new Error('the node refused a call: marker already spent'));
    await expect(startReveal(kit, CARD, ACCOUNT, null)).rejects.toThrow(ALREADY_SUMMONED_TEXT);
  });

  it('starts its own payment for a Claim of another amount', async () => {
    const { kit, core, node } = fakeKit();
    node.sendRaw.mockRejectedValueOnce(new TypeError('Network request failed'));
    await startReveal(kit, CARD, ACCOUNT, 300n);
    await startReveal(kit, CARD, ACCOUNT, 400n);
    expect(core.PaymentSequence.start).toHaveBeenCalledTimes(2);
  });

  it('joins a Claim of the same amount', async () => {
    const { kit, core, node } = fakeKit();
    node.sendRaw.mockRejectedValueOnce(new TypeError('Network request failed'));
    await startReveal(kit, CARD, ACCOUNT, 300n);
    await startReveal(kit, CARD, ACCOUNT, 300n);
    expect(core.PaymentSequence.start).toHaveBeenCalledTimes(1);
  });

  it('starts its own payment when the fee moved and the Summon brings back another amount', async () => {
    const { kit, core, node } = fakeKit();
    node.sendRaw.mockRejectedValueOnce(new TypeError('Network request failed'));
    await startReveal(kit, CARD, ACCOUNT, null);
    core.proveCardKeyReveal.mockImplementationOnce(() => ({
      transactionHash: new ArrayBuffer(32),
      marker: new Uint8Array(32).fill(0x0b).buffer,
      envelope: new Uint8Array([0x50, 0x77]).buffer,
      feeWei: '50',
      outWei: '660',
      remainderWei: '0',
      proveMillis: 1n,
    }));
    await startReveal(kit, CARD, ACCOUNT, null);
    expect(core.PaymentSequence.start).toHaveBeenCalledTimes(2);
  });

  it('starts its own payment when the saved one has no room for another attempt', async () => {
    const { kit, core, node } = fakeKit();
    node.sendRaw.mockRejectedValueOnce(new TypeError('Network request failed'));
    const first = await startReveal(kit, CARD, ACCOUNT, null);
    const record = first.record() as { attempts: unknown[] };
    record.attempts = Array.from({ length: MAX_REVEAL_ATTEMPTS }, (_, i) => ({ transactionHash: new Uint8Array([i]).buffer }));
    await startReveal(kit, CARD, ACCOUNT, null);
    expect(core.PaymentSequence.start).toHaveBeenCalledTimes(2);
  });

  it('starts its own payment once the saved one is in a block', async () => {
    const { kit, core, saved } = fakeKit();
    const first = await startReveal(kit, CARD, ACCOUNT, null);
    (first.record() as { step: number }).step = 4;
    await startReveal(kit, CARD, ACCOUNT, null);
    expect(core.PaymentSequence.start).toHaveBeenCalledTimes(2);
    expect(saved.size).toBe(2);
  });
});
