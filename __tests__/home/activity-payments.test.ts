import { describeActivity, type ActivityItem } from '../../lib/home/activity';
import { activityWithSaved, savedActivity, savedCredits, savedHashes } from '../../lib/home/saved-activity';
import { buffer, encodeDetails, type PaymentDetails } from '../../lib/vanish/payments';
import { pendingPayments, resetPending } from '../../lib/vanish/pending';

const GHOST = 10n ** 18n;
const NOW = new Date(2026, 9, 28, 14, 30).getTime();
const TO = '0x81d0' + '0'.repeat(32) + 'c7a4';

function txHash(n: number): string {
  return '0x' + n.toString(16).padStart(64, '0');
}

// Saved payments: step numbers are the core's Step (0 Prepared … 5 Settled, 6 Failed, 7 Conflicted).
type Saved = { id: string; step: number | string; details: PaymentDetails; attempts: string[]; included: string | null };
let saved: Saved[] = [];

const core = {
  PaymentSequence: {
    open: (_store: unknown, id: string) => {
      const payment = saved.find((one) => one.id === id);
      if (!payment) throw new Error('no such payment');
      return {
        step: () => payment.step,
        record: () => ({
          id,
          step: payment.step,
          intent: { kind: 0, identity: { tag: 'AccountNonce', inner: {} }, details: encodeDetails(payment.details) },
          attempts: payment.attempts.map((hash) => ({ transactionHash: buffer(hash) })),
          inclusion: payment.included
            ? { transactionHash: buffer(payment.included), blockHash: buffer(txHash(999)), blockHeight: 10n }
            : undefined,
          version: 1,
          checksum: new ArrayBuffer(0),
        }),
      };
    },
  },
};
const store = { list: () => saved.map((one) => one.id) };
const kit = { core, store } as unknown as Parameters<typeof savedActivity>[0];

function send(id: string, step: number | string, at: number, hash: number): Saved {
  return {
    id,
    step,
    details: { kind: 'send', to: TO, amountWei: (5n * GHOST).toString(), nonce: '1', maxFeePerGas: null, fromHeight: 1, at },
    attempts: [txHash(hash)],
    included: step === 5 ? txHash(hash) : null,
  };
}
function vanish(id: string, step: number | string, at: number, hash: number): Saved {
  return {
    id,
    step,
    details: { kind: 'vanish', commitData: '0x00', amountWei: (3n * GHOST).toString(), nonce: '2', at },
    attempts: [txHash(hash)],
    included: step === 5 ? txHash(hash) : null,
  };
}
function reveal(id: string, kind: 'summon' | 'claim', step: number | string, at: number, hash: number): Saved {
  return {
    id,
    step,
    details: { kind, amountWei: GHOST.toString(), feeWei: '1000', marker: '0x01', at },
    attempts: [txHash(hash)],
    included: step === 5 ? txHash(hash) : null,
  };
}

function byId(items: ActivityItem[]): Record<string, ActivityItem> {
  return Object.fromEntries(items.map((item) => [item.id, item]));
}

beforeEach(() => {
  resetPending();
  saved = [];
});

describe('saved payments in Activity', () => {
  it('lists a settled send, Vanish, Summon and Claim as done, with what each moved', () => {
    saved = [
      send('send-a', 5, NOW - 4_000, 1),
      vanish('vanish-b', 5, NOW - 3_000, 2),
      reveal('summon-c', 'summon', 5, NOW - 2_000, 3),
      reveal('claim-d', 'claim', 5, NOW - 1_000, 4),
    ];
    const items = byId(savedActivity(kit));

    expect(items['send-a']).toEqual({
      id: 'send-a',
      direction: 'sent',
      counterparty: TO,
      amountWei: (5n * GHOST).toString(),
      state: 'done',
      at: NOW - 4_000,
      kind: 'send',
      hash: txHash(1),
    });
    expect(items['vanish-b']).toMatchObject({ direction: 'sent', counterparty: null, state: 'done', kind: 'vanish', hash: txHash(2) });
    expect(items['summon-c']).toMatchObject({ direction: 'received', state: 'done', kind: 'summon', amountWei: GHOST.toString() });
    expect(items['claim-d']).toMatchObject({ direction: 'received', state: 'done', kind: 'claim' });
  });

  it('lists failed and conflicted payments with that state, never as done', () => {
    saved = [send('send-f', 6, NOW, 1), vanish('vanish-c', 7, NOW, 2), reveal('claim-f', 'claim', 'Failed', NOW, 3)];
    const items = byId(savedActivity(kit));
    expect(items['send-f'].state).toBe('failed');
    expect(items['vanish-c'].state).toBe('conflicted');
    expect(items['claim-f'].state).toBe('failed');
  });

  it('leaves a payment still going to its pending row, so it shows once', () => {
    saved = [send('send-p', 3, NOW, 1), vanish('vanish-p', 4, NOW, 2), reveal('summon-p', 'summon', 2, NOW, 3)];
    expect(savedActivity(kit)).toEqual([]);
    expect(pendingPayments(kit).map((one) => one.id).sort()).toEqual(['send-p', 'summon-p', 'vanish-p']);
  });

  it('shows a step it does not know as pending, not done', () => {
    saved = [send('send-x', 42, NOW, 1), vanish('vanish-y', 'Reorged', NOW, 2)];
    const items = byId(savedActivity(kit));
    expect(items['send-x'].state).toBe('pending');
    expect(items['vanish-y'].state).toBe('pending');
    // Nor is it a pending row too.
    expect(pendingPayments(kit)).toEqual([]);
  });

  it('skips a record whose details do not read and a Vanish never signed', () => {
    saved = [
      { ...send('send-bad', 5, NOW, 1), details: { kind: 'vanish' } as unknown as PaymentDetails },
      { ...vanish('vanish-never', 0, NOW, 2), attempts: [] },
    ];
    expect(savedActivity(kit)).toEqual([]);
  });

  it('names a Vanish, Summon and Claim by what they did', () => {
    saved = [vanish('vanish-b', 5, NOW, 2), reveal('summon-c', 'summon', 6, NOW, 3), reveal('claim-d', 'claim', 5, NOW, 4)];
    const rows = byId(savedActivity(kit));
    expect(describeActivity(rows['vanish-b'], NOW)).toMatchObject({ title: 'Vanished', icon: 'check', amount: '−3.00' });
    expect(describeActivity(rows['summon-c'], NOW)).toMatchObject({ title: 'Summon', icon: 'cross', struck: true });
    expect(describeActivity(rows['claim-d'], NOW)).toMatchObject({ title: 'Claimed', amount: '+1.00' });
  });
});

describe('activityWithSaved', () => {
  it('drops what Home found on chain when a saved payment, pending or not, made that transaction', () => {
    saved = [send('send-a', 5, NOW - 1_000, 1), vanish('vanish-p', 3, NOW, 2)];
    const found = (hash: number): ActivityItem => ({
      id: `tx-${txHash(hash)}`,
      direction: 'sent',
      counterparty: TO,
      amountWei: '1',
      state: 'done',
      at: NOW - 5_000,
      hash: txHash(hash),
    });
    const other = found(9);
    const list = activityWithSaved([found(1), found(2), other], savedActivity(kit), savedHashes(kit), 50);
    expect(list.map((item) => item.id)).toEqual(['send-a', other.id]);
  });

  it('shows a settled Summon or Claim once, not again as the balance going up', () => {
    // Summon of 1 GHOST paying a fee of 1000 wei; Claim of 1 GHOST.
    saved = [reveal('summon-c', 'summon', 5, NOW - 10_000, 3), reveal('claim-d', 'claim', 5, NOW - 5_000, 4)];
    const grew = (id: string, amountWei: string, at: number): ActivityItem => ({
      id,
      direction: 'received',
      counterparty: null,
      amountWei,
      state: 'done',
      at,
    });
    const kept = [
      grew('received-summon', (GHOST - 1000n).toString(), NOW - 9_000),
      grew('received-claim', GHOST.toString(), NOW - 4_000),
      // Came in before either payment: another payment, kept.
      grew('received-before', GHOST.toString(), NOW - 60_000),
      // A second credit of the same amount: only one is the Claim's.
      grew('received-again', GHOST.toString(), NOW - 1_000),
    ];
    const list = activityWithSaved(kept, savedActivity(kit), savedHashes(kit), 50, savedCredits(kit));
    expect(list.map((item) => item.id)).toEqual(['received-again', 'claim-d', 'summon-c', 'received-before']);
  });

  it('keeps the balance credit when the Summon has not settled', () => {
    saved = [reveal('summon-f', 'summon', 6, NOW - 10_000, 3)];
    const credit: ActivityItem = { id: 'received-x', direction: 'received', counterparty: null, amountWei: GHOST.toString(), state: 'done', at: NOW };
    const list = activityWithSaved([credit], savedActivity(kit), savedHashes(kit), 50, savedCredits(kit));
    expect(list.map((item) => item.id)).toEqual(['received-x', 'summon-f']);
  });

  it('keeps pending first, then the newest, and at most the limit', () => {
    const kept: ActivityItem[] = Array.from({ length: 5 }, (_, i): ActivityItem => ({
      id: `r-${i}`,
      direction: 'received',
      counterparty: null,
      amountWei: '1',
      state: i === 0 ? 'pending' : 'done',
      at: NOW - i * 1_000,
    }));
    saved = [send('send-new', 5, NOW + 1_000, 1)];
    const list = activityWithSaved(kept, savedActivity(kit), savedHashes(kit), 3);
    expect(list.map((item) => item.id)).toEqual(['r-0', 'send-new', 'r-1']);
  });
});
