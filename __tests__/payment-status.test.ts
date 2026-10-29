import { STEP_NAMES } from '../lib/vanish/status-mapping';
import {
  isFinalSend,
  SAFE_TO_CLOSE,
  sendHeadline,
  sendProgressRows,
  sendStatusDetail,
  sendStatusLabel,
  sendStatusOf,
  type SendStatus,
} from '../lib/send/payment-status';
import { hasReached, resetReached } from '../lib/send/reached';
import { advanceSend, savedSendStatus, startSend, type SendKit } from '../lib/send/send-payment';
import { encodeDetails, type SendDetails } from '../lib/vanish/payments';
import { resetPending } from '../lib/vanish/pending';
import { bytesToHex, hexToBytes } from '../modules/ghost-core/account-lookup';
import type { CoreChainView, CorePaymentIntent, CorePaymentSequence } from '../modules/ghost-core';

// The conflict lookup asks the node block by block; here it answers from a list.
const mockUsedBy = jest.fn(async (..._args: unknown[]): Promise<string | null> => null);
jest.mock('../lib/send/node', () => ({ nonceUsedBy: (...args: unknown[]) => mockUsedBy(...args) }));

describe('status mapping', () => {
  const step = (name: (typeof STEP_NAMES)[number]) => STEP_NAMES.indexOf(name);

  it('maps every saved step, by index or by name', () => {
    const expected: Record<(typeof STEP_NAMES)[number], SendStatus> = {
      Prepared: 'queued',
      BackedUp: 'queued',
      Signed: 'queued',
      Sent: 'sent',
      Included: 'in-block',
      Settled: 'settled',
      Failed: 'failed',
      Conflicted: 'conflicted',
    };
    for (const [name, status] of Object.entries(expected) as [(typeof STEP_NAMES)[number], SendStatus][]) {
      expect(sendStatusOf(step(name), true)).toBe(status);
      expect(sendStatusOf(name, true)).toBe(status);
      expect(sendStatusOf(name.toLowerCase(), true)).toBe(status);
    }
  });

  it('shows a send the node has not taken as queued, never as sent', () => {
    expect(sendStatusOf('Sent', false)).toBe('queued');
    expect(sendStatusOf(step('Sent'), false)).toBe('queued');
    expect(sendStatusOf('Signed', true)).toBe('queued');
    expect(sendStatusOf('BackedUp', true)).toBe('queued');
  });

  it('shows what the chain says once it is in a block, whatever the broadcast said', () => {
    expect(sendStatusOf('Included', false)).toBe('in-block');
    expect(sendStatusOf('Settled', false)).toBe('settled');
    expect(sendStatusOf('Failed', false)).toBe('failed');
    expect(sendStatusOf('Conflicted', false)).toBe('conflicted');
  });

  it('keeps failed and conflicted apart', () => {
    expect(sendStatusOf('Failed', true)).not.toBe(sendStatusOf('Conflicted', true));
  });

  it('never shows a step it does not know as done', () => {
    expect(sendStatusOf('Vanished', true)).toBe('failed');
    expect(sendStatusOf(8, true)).toBe('failed');
    expect(sendStatusOf(1.5, true)).toBe('failed');
  });

  it('stops only once settled, failed or conflicted', () => {
    expect(isFinalSend('settled')).toBe(true);
    expect(isFinalSend('failed')).toBe(true);
    expect(isFinalSend('conflicted')).toBe(true);
    for (const status of ['queued', 'sent', 'in-block'] as const) {
      expect(isFinalSend(status)).toBe(false);
    }
  });

  it('labels every status as the mockup does', () => {
    expect(sendStatusLabel('queued')).toBe('Queued');
    expect(sendStatusLabel('sent')).toBe('Sent');
    expect(sendStatusLabel('in-block')).toBe('In a block');
    expect(sendStatusLabel('settled')).toBe('Settled');
    expect(sendStatusLabel('failed')).toBe('Failed');
    expect(sendStatusLabel('conflicted')).toBe('Conflicted');
  });
});

describe('the progress on the payment screen', () => {
  const states = (status: SendStatus) => sendProgressRows(status).map((row) => [row.status, row.state]);

  it('shows sent, in a block and settled, with the current one marked', () => {
    expect(states('sent')).toEqual([
      ['sent', 'current'],
      ['in-block', 'waiting'],
      ['settled', 'waiting'],
    ]);
    expect(states('in-block')).toEqual([
      ['sent', 'done'],
      ['in-block', 'current'],
      ['settled', 'waiting'],
    ]);
    expect(states('settled')).toEqual([
      ['sent', 'done'],
      ['in-block', 'done'],
      ['settled', 'done'],
    ]);
  });

  it('puts a queued send before Sent, with nothing done', () => {
    expect(states('queued')).toEqual([
      ['queued', 'current'],
      ['sent', 'waiting'],
      ['in-block', 'waiting'],
      ['settled', 'waiting'],
    ]);
  });

  it('shows where a failed send stopped, and a conflicted one on its own', () => {
    expect(states('failed')).toEqual([
      ['sent', 'done'],
      ['in-block', 'done'],
      ['failed', 'current'],
    ]);
    expect(states('conflicted')).toEqual([['conflicted', 'current']]);
  });

  it('says it is safe to close while it is going, and what happened once it stopped', () => {
    expect(sendStatusDetail('sent')).toBe(SAFE_TO_CLOSE);
    expect(sendStatusDetail('in-block')).toBe(SAFE_TO_CLOSE);
    expect(sendStatusDetail('queued')).toContain('Queued, not sent yet.');
    expect(sendStatusDetail('queued')).toContain(SAFE_TO_CLOSE);
    expect(SAFE_TO_CLOSE).toBe('Safe to close the app. It never pays twice.');
    expect(sendStatusDetail('settled')).not.toContain(SAFE_TO_CLOSE);
    expect(sendStatusDetail('failed')).toContain('Nothing more is sent');
    expect(sendStatusDetail('conflicted')).toContain('Another payment from this account');
  });

  it('never says sent over a send that has not gone out or did not land', () => {
    expect(sendHeadline('queued')).toBe('You are sending');
    expect(sendHeadline('sent')).toBe('You sent');
    expect(sendHeadline('failed')).toBe('You tried to send');
    expect(sendHeadline('conflicted')).toBe('You tried to send');
    expect(sendProgressRows('queued').some((row) => row.status === 'sent' && row.state !== 'waiting')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// A send moved through the step sequence, with the core and the node faked.

const ACCOUNT = '0x00000000000000000000000000000000000000aa';
const RECIPIENT = '0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd';
const OTHER_TX = `0x${'cd'.repeat(32)}`;
const GENESIS = `0x${'47'.repeat(32)}`;
const OFFLINE = new Error('Network request failed');

function buffer(hex: string): ArrayBuffer {
  const bytes = hexToBytes(hex);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function details(nonce: number, maxFeePerGas: string | null = '5000000000'): SendDetails {
  return { kind: 'send', to: RECIPIENT, amountWei: '25000000000000000000', nonce: String(nonce), maxFeePerGas, fromHeight: 90, at: 1 };
}

/**
 * A stand-in for the core's PaymentSequence that follows the same rules as
 * core/src/step_sequence.rs for a send: sign once backed up, send the saved
 * bytes, wait while the node holds them, conflicted when another transaction
 * took the nonce.
 */
function fakeSequence(id: string, intent: CorePaymentIntent, start = 'Prepared') {
  let step = start;
  const attempts: string[] = [];
  const payloads = new Map<string, ArrayBuffer>();
  let inclusion: string | null = null;
  return {
    record: () => ({
      id,
      intent,
      step,
      attempts: attempts.map((hash) => ({ transactionHash: buffer(hash) })),
      inclusion: inclusion ? { transactionHash: buffer(inclusion), blockHash: buffer(GENESIS), blockHeight: 99n } : undefined,
      version: 2,
      checksum: new ArrayBuffer(32),
    }),
    step: () => step,
    recover(view: CoreChainView) {
      if (step === 'Prepared') return { tag: 'BackUp' };
      if (step === 'BackedUp') return { tag: 'Sign' };
      if (step === 'Signed' || step === 'Sent') {
        const used = view.identityUsedBy(intent.identity);
        if (used && view.receipt(used)) {
          step = 'Conflicted';
          inclusion = bytesToHex(used);
          return { tag: 'Done' };
        }
        const newest = attempts[attempts.length - 1];
        return step === 'Sent' && view.pending(buffer(newest)) ? { tag: 'Wait' } : { tag: 'Send' };
      }
      return { tag: 'Done' };
    },
    markBackedUp() {
      step = 'BackedUp';
    },
    addAttempt(signed: ArrayBuffer) {
      const hash = `0x${bytesToHex(signed).slice(2).padStart(64, '0')}`;
      attempts.push(hash);
      payloads.set(hash, signed);
      step = 'Signed';
      return buffer(hash);
    },
    markSent() {
      // Saved as sent first, then the saved bytes are handed out to broadcast.
      step = 'Sent';
      return payloads.get(attempts[attempts.length - 1]) as ArrayBuffer;
    },
  };
}

type Fake = ReturnType<typeof fakeSequence>;

/** Whether the fake node lists the newest attempt as waiting for a block. */
let pendingOnNode = false;

function fakeKit(online: { value: boolean }, saved: Record<string, Fake> = {}) {
  const reachable = <T>(value: T) => (online.value ? Promise.resolve(value) : Promise.reject(OFFLINE));
  const node = {
    chainId: jest.fn(() => reachable(6777971n)),
    tipHeight: jest.fn(() => reachable(100)),
    block: jest.fn((height: number) => reachable({ height, hash: GENESIS, baseFeePerGas: 7_000_000_000n, transactions: [] })),
    receipts: jest.fn((hashes: string[]) =>
      reachable(
        hashes.map((hash) =>
          hash === OTHER_TX ? { transactionHash: OTHER_TX, success: true, blockHash: GENESIS, blockHeight: 99 } : null,
        ),
      ),
    ),
    known: jest.fn((hashes: string[]) => reachable(hashes.map(() => pendingOnNode))),
    nonce: jest.fn(() => reachable(5n)),
    maxPriorityFeePerGas: jest.fn(() => reachable(1_000_000_000n)),
    sendRaw: jest.fn(() => reachable(OTHER_TX)),
    blocks: jest.fn(),
    rawTransaction: jest.fn(),
  };
  const core = {
    testChainId: () => 6777971n,
    testSendGasLimit: () => 84_256n,
    signSend: jest.fn(() => ({ transactionHash: buffer(`0x${'ab'.repeat(32)}`), sender: buffer(ACCOUNT), envelope: buffer('0x52ab') })),
    PaymentSequence: {
      start: jest.fn((_store: unknown, id: string, intent: CorePaymentIntent) => fakeSequence(id, intent)),
      open: (_store: unknown, id: string) => saved[id],
    },
  };
  const store = { list: () => Object.keys(saved) };
  return { kit: { core, store, node, nodeUrl: 'http://127.0.0.1:8547' } as unknown as SendKit, core, node };
}

function sendIntent(nonce: number, maxFeePerGas: string | null = '5000000000'): CorePaymentIntent {
  return {
    kind: 0,
    identity: { tag: 'AccountNonce', inner: { account: buffer(ACCOUNT), nonce: BigInt(nonce) } },
    details: encodeDetails(details(nonce, maxFeePerGas)),
  };
}

beforeEach(() => {
  resetReached({ read: () => null, write: async () => {} });
  resetPending();
  pendingOnNode = false;
  mockUsedBy.mockReset();
  mockUsedBy.mockResolvedValue(null);
});

describe('a send through the step sequence', () => {
  it('stays queued, unsigned, while the node is out of reach', async () => {
    const online = { value: false };
    const { kit, core, node } = fakeKit(online);
    const sequence = fakeSequence('send-a', sendIntent(5), 'BackedUp');
    await expect(advanceSend(kit, sequence as unknown as CorePaymentSequence)).rejects.toThrow('Network request failed');
    expect(core.signSend).not.toHaveBeenCalled();
    expect(node.sendRaw).not.toHaveBeenCalled();
    expect(sequence.step()).toBe('BackedUp');
    expect(savedSendStatus(sequence as unknown as CorePaymentSequence)).toBe('queued');
  });

  it('is signed in the core and sent once the node answers, then shows as sent', async () => {
    const online = { value: true };
    const { kit, core, node } = fakeKit(online);
    const sequence = fakeSequence('send-b', sendIntent(5), 'BackedUp');
    const moved = await advanceSend(kit, sequence as unknown as CorePaymentSequence);
    expect(moved.status).toBe('sent');
    expect(core.signSend).toHaveBeenCalledTimes(1);
    const signed = core.signSend.mock.calls[0] as unknown as [Record<string, unknown>];
    expect(signed[0]).toMatchObject({
      chainId: 6777971n,
      nonce: 5n,
      amountWei: '25000000000000000000',
      maxPriorityFeePerGas: 1_000_000_000n,
      // Twice the base fee and the priority fee would be 15 gwei: the reviewed 5 gwei is never exceeded.
      maxFeePerGas: 5_000_000_000n,
      gasLimit: 84_256n,
    });
    expect(bytesToHex(signed[0].recipient as ArrayBuffer)).toBe(RECIPIENT);
    expect(node.sendRaw).toHaveBeenCalledWith('0x52ab');
    expect(hasReached('send-b')).toBe(true);
  });

  it('signs a send saved offline with the fees of when it goes out', async () => {
    const { kit, core } = fakeKit({ value: true });
    const sequence = fakeSequence('send-c', sendIntent(5, null), 'BackedUp');
    await advanceSend(kit, sequence as unknown as CorePaymentSequence);
    expect((core.signSend.mock.calls[0] as unknown as [Record<string, unknown>])[0].maxFeePerGas).toBe(15_000_000_000n);
  });

  it('shows queued, not sent, when the broadcast does not get through', async () => {
    const online = { value: true };
    const { kit, node } = fakeKit(online);
    node.sendRaw.mockImplementationOnce(() => Promise.reject(OFFLINE));
    const sequence = fakeSequence('send-d', sendIntent(5), 'BackedUp');
    await expect(advanceSend(kit, sequence as unknown as CorePaymentSequence)).rejects.toThrow();
    expect(sequence.step()).toBe('Sent');
    expect(savedSendStatus(sequence as unknown as CorePaymentSequence)).toBe('queued');

    // The next move sends the same saved bytes, not a new signature.
    const moved = await advanceSend(kit, sequence as unknown as CorePaymentSequence);
    expect(moved.status).toBe('sent');
    expect(node.sendRaw).toHaveBeenCalledTimes(2);
    expect(node.sendRaw.mock.calls[1]).toEqual(['0x52ab']);
  });

  it('shows sent when the node lists the send, without sending it again', async () => {
    const { kit, node, core } = fakeKit({ value: true });
    const sequence = fakeSequence('send-e', sendIntent(5), 'BackedUp');
    sequence.addAttempt(buffer('0x52ab'));
    sequence.markSent();
    pendingOnNode = true;
    const moved = await advanceSend(kit, sequence as unknown as CorePaymentSequence);
    expect(moved.status).toBe('sent');
    expect(node.sendRaw).not.toHaveBeenCalled();
    expect(core.signSend).not.toHaveBeenCalled();
  });

  it('is conflicted, and never sent again, when another payment took its nonce', async () => {
    const { kit, node } = fakeKit({ value: true });
    const sequence = fakeSequence('send-f', sendIntent(5), 'BackedUp');
    sequence.addAttempt(buffer('0x52ab'));
    sequence.markSent();
    mockUsedBy.mockResolvedValue(OTHER_TX);
    const moved = await advanceSend(kit, sequence as unknown as CorePaymentSequence);
    expect(moved.status).toBe('conflicted');
    expect(node.sendRaw).not.toHaveBeenCalled();
    const [url, account, nonce, fromHeight, tip] = mockUsedBy.mock.calls[0];
    expect([url, account, nonce, fromHeight, tip]).toEqual(['http://127.0.0.1:8547', ACCOUNT, 5n, 90, 100]);
  });
});

describe('a new send', () => {
  it('is saved as queued with the node out of reach, from the nonce Home last saw', async () => {
    const { kit, node } = fakeKit({ value: false });
    const sequence = await startSend(kit, {
      account: ACCOUNT,
      to: RECIPIENT,
      amountWei: 25n * 10n ** 18n,
      maxFeePerGas: null,
      cached: { nonce: 3, tipHeight: 80 },
    });
    expect(node.sendRaw).not.toHaveBeenCalled();
    expect(savedSendStatus(sequence)).toBe('queued');
    const record = sequence.record();
    expect(record.intent.identity).toMatchObject({ tag: 'AccountNonce', inner: { nonce: 3n } });
    expect(record.id).toMatch(/^send-[a-z0-9]+$/);
  });

  it('never takes a nonce a saved payment holds', async () => {
    const saved = { 'send-old': fakeSequence('send-old', sendIntent(7), 'BackedUp') };
    const { kit } = fakeKit({ value: true }, saved);
    const sequence = await startSend(kit, {
      account: ACCOUNT,
      to: RECIPIENT,
      amountWei: 10n ** 18n,
      maxFeePerGas: 5_000_000_000n,
      cached: null,
    });
    expect(sequence.record().intent.identity).toMatchObject({ inner: { nonce: 8n } });
  });

  it('cannot be queued when the account was never seen and the node is out of reach', async () => {
    const { kit, core } = fakeKit({ value: false });
    await expect(
      startSend(kit, { account: ACCOUNT, to: RECIPIENT, amountWei: 1n, maxFeePerGas: null, cached: null }),
    ).rejects.toThrow('cannot be queued');
    expect(core.PaymentSequence.start).not.toHaveBeenCalled();
  });
});
