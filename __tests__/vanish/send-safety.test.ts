// A send the node can never mine must not sit on "Sent": the node checks
// every signed transaction (eth_estimateGas) before it is sent, a payment the
// node took but has not mined in 10 blocks shows as "Not mined yet" with a
// Cancel offer, and a Phantom Key whose commit never landed shows as empty.
import { act, renderHook } from '@testing-library/react-native';

import { buildNetwork } from '../../lib/network/build-network';
import { isRefusal, type FetchLike } from '../../lib/node/rpc';
import { sendProgressRows, sendStatusDetail, sendStatusLabel } from '../../lib/send/payment-status';
import { resetReached } from '../../lib/send/reached';
import { CANCEL_WEI, advanceSend, cancelStuck, type SendKit } from '../../lib/send/send-payment';
import { startReveal } from '../../lib/vanish/actions';
import { stoppedBeforeSend, vanishNode, type NodeReceipt, type VanishNode } from '../../lib/vanish/node';
import { advance, chainSnapshot, encodeDetails, type PaymentDetails, type SendDetails } from '../../lib/vanish/payments';
import { isCancel, pendingPayments, resetCancels, resetPending } from '../../lib/vanish/pending';
import {
  NOT_MINED_LABEL,
  STUCK_BLOCKS,
  notSentReason,
  progressRows,
  statusDetail,
  statusOfStep,
} from '../../lib/vanish/status-mapping';
import { MOVE_EVERY_MS, usePayment, type PaymentKit } from '../../lib/vanish/use-payment';
import { bytesToHex, hexToBytes } from '../../modules/ghost-core/account-lookup';
import type { CoreChainView, CorePaymentIntent, CorePaymentRecord, CorePaymentSequence } from '../../modules/ghost-core';
jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));
// Which transaction took a send's nonce is not asked here.
jest.mock('../../lib/send/node', () => ({ nonceUsedBy: async () => null }));

const NODE_URL = 'http://127.0.0.1:8547';
const ACCOUNT = `0x${'aa'.repeat(20)}`;
const RECIPIENT = `0x${'bb'.repeat(20)}`;
const COMMIT_ENTRY = '0x67686f7374000000000000000000000000000005';
const GENESIS = `0x${'47'.repeat(32)}`;
const CHAIN = buildNetwork.chainId;
/** What the node says of commit data it does not take. */
const COMMIT_REFUSAL = 'invalid commit data: version 2 is not accepted';

// --- A signed account transaction, laid out as the core lays it out ----------

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

function lengthPrefix(length: number, short: number, long: number): Uint8Array {
  if (length < 56) {
    return new Uint8Array([short + length]);
  }
  const digits: number[] = [];
  for (let rest = length; rest > 0; rest = Math.floor(rest / 256)) {
    digits.unshift(rest % 256);
  }
  return new Uint8Array([long + digits.length, ...digits]);
}

type Rlp = Uint8Array | Rlp[];

function rlp(item: Rlp): Uint8Array {
  if (item instanceof Uint8Array) {
    if (item.length === 1 && item[0] < 0x80) {
      return item;
    }
    return concat([lengthPrefix(item.length, 0x80, 0xb7), item]);
  }
  const body = concat(item.map(rlp));
  return concat([lengthPrefix(body.length, 0xc0, 0xf7), body]);
}

function quantity(value: bigint): Uint8Array {
  return value === 0n ? new Uint8Array(0) : hexToBytes(value.toString(16).padStart(Math.ceil(value.toString(16).length / 2) * 2, '0'));
}

type AccountTx = {
  nonce: bigint;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  gas: bigint;
  to: string;
  value: bigint;
  data: string;
};

/** `0x52 || rlp([...])`, the type-2 fields first, then a scheme, a key and a signature. */
function accountTx(tx: AccountTx, chainId: bigint = CHAIN): string {
  const fields: Rlp[] = [
    quantity(chainId),
    quantity(tx.nonce),
    quantity(tx.maxPriorityFeePerGas),
    quantity(tx.maxFeePerGas),
    quantity(tx.gas),
    hexToBytes(tx.to),
    quantity(tx.value),
    hexToBytes(tx.data),
    [],
    new Uint8Array([0x00, 0x03]),
    new Uint8Array(1344).fill(0x11),
    new Uint8Array(2420).fill(0x22),
  ];
  return bytesToHex(concat([new Uint8Array([0x52]), rlp(fields)]));
}

const COMMIT_DATA = `0x0002${'ab'.repeat(40)}`;
const VANISH_TX: AccountTx = {
  nonce: 4n,
  maxPriorityFeePerGas: 2n,
  maxFeePerGas: 20n,
  gas: 500_000n,
  to: COMMIT_ENTRY,
  value: 5n * 10n ** 17n,
  data: COMMIT_DATA,
};
const VANISH_SIGNED = accountTx(VANISH_TX);

function arrayBuffer(hex: string): ArrayBuffer {
  const bytes = hexToBytes(hex);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

// --- A node on the other end of JSON-RPC --------------------------------------

type Call = { id: number; method: string; params: unknown[] };

/**
 * A node answering JSON-RPC: `answer` gives each call's result, or throws an
 * Error to refuse it with that message. Every call is kept.
 */
function rpcNode(answer: (call: Call) => unknown) {
  const calls: Call[] = [];
  const fetchImpl = jest.fn(async (_url: string, init: RequestInit) => {
    const batch = JSON.parse(String(init.body)) as Call[];
    calls.push(...batch);
    return {
      ok: true,
      status: 200,
      json: async () =>
        batch.map((call) => {
          try {
            return { jsonrpc: '2.0', id: call.id, result: answer(call) };
          } catch (error) {
            return { jsonrpc: '2.0', id: call.id, error: { code: -32000, message: (error as Error).message } };
          }
        }),
    } as unknown as Response;
  });
  return { fetchImpl: fetchImpl as unknown as FetchLike, calls, methods: () => calls.map((call) => call.method) };
}

/** The test chain as the payments see it; `refuse` is what its estimate says of a transaction, if anything. */
function chainAnswers(refuse: (call: Record<string, string>) => string | null, tip = { height: 100 }) {
  return (call: Call): unknown => {
    switch (call.method) {
      case 'eth_chainId':
        return `0x${CHAIN.toString(16)}`;
      case 'eth_blockNumber':
        return `0x${tip.height.toString(16)}`;
      case 'eth_getBlockByNumber':
        return { number: '0x1', hash: GENESIS, baseFeePerGas: '0x3', transactions: [] };
      case 'eth_getTransactionReceipt':
        return null;
      case 'eth_getTransactionByHash':
        return null;
      case 'eth_maxPriorityFeePerGas':
        return '0x1';
      case 'eth_estimateGas': {
        const reason = refuse(call.params[0] as Record<string, string>);
        if (reason) {
          throw new Error(reason);
        }
        return '0x5208';
      }
      case 'eth_sendRawTransaction':
        return `0x${'cc'.repeat(32)}`;
      default:
        throw new Error(`the test node does not serve ${call.method}`);
    }
  };
}

// --- Saved payments -----------------------------------------------------------

type FakeSequence = CorePaymentSequence & {
  recover: jest.Mock;
  addAttempt: jest.Mock;
  markSent: jest.Mock;
  attemptHashes: string[];
};

/**
 * A stand-in for the core's PaymentSequence: steps by name, attempts with the
 * hash `hashOf` gives each signed transaction, bytes kept as the store keeps
 * them. `recover` says what to do, or lands an attempt with the view's say.
 */
function fakeSequence(
  id: string,
  intent: CorePaymentIntent,
  start: string,
  recover: (sequence: FakeSequence, view: CoreChainView) => { tag: string },
  hashOf: (signed: string) => string = (signed) => `0x${signed.slice(2).slice(-64).padStart(64, '0')}`,
): FakeSequence {
  let step = start;
  const payloads = new Map<string, string>();
  const attemptHashes: string[] = [];
  // Set below: `recover` hands the finished stand-in to the caller's rule.
  let self: FakeSequence | null = null;
  const sequence = {
    attemptHashes,
    record: (): CorePaymentRecord => ({
      id,
      intent,
      step,
      attempts: attemptHashes.map((hash) => ({ transactionHash: arrayBuffer(hash) })),
      version: 2,
      checksum: new ArrayBuffer(32),
    }),
    step: () => step,
    recover: jest.fn((view: CoreChainView): { tag: string } => recover(self!, view)),
    markBackedUp: jest.fn(() => {
      step = 'BackedUp';
    }),
    addAttempt: jest.fn((signed: ArrayBuffer) => {
      const hex = bytesToHex(signed);
      const hash = hashOf(hex);
      attemptHashes.push(hash);
      payloads.set(hash, hex);
      step = 'Signed';
      return arrayBuffer(hash);
    }),
    markSent: jest.fn(() => {
      step = 'Sent';
      return arrayBuffer(payloads.get(attemptHashes[attemptHashes.length - 1])!);
    }),
    /** For a store: the saved bytes of an attempt. */
    payload: (hash: string) => payloads.get(hash),
    setStep: (next: string) => {
      step = next;
    },
  };
  self = sequence as unknown as FakeSequence;
  return self;
}

function asStep(sequence: FakeSequence) {
  return sequence as unknown as { setStep(step: string): void; payload(hash: string): string | undefined };
}

function vanishIntent(): CorePaymentIntent {
  const details: PaymentDetails = {
    kind: 'vanish',
    commitData: COMMIT_DATA,
    amountWei: VANISH_TX.value.toString(),
    nonce: '4',
    at: 1,
    chainId: CHAIN.toString(),
  };
  return {
    kind: 1,
    identity: { tag: 'AccountNonce', inner: { account: arrayBuffer(ACCOUNT), nonce: 4n } },
    details: encodeDetails(details),
  };
}

function sendIntent(): CorePaymentIntent {
  const details: SendDetails = {
    kind: 'send',
    to: RECIPIENT,
    amountWei: '900',
    nonce: '7',
    maxFeePerGas: null,
    fromHeight: 90,
    at: 2,
    chainId: CHAIN.toString(),
  };
  return {
    kind: 0,
    identity: { tag: 'AccountNonce', inner: { account: arrayBuffer(ACCOUNT), nonce: 7n } },
    details: encodeDetails(details),
  };
}

function summonIntent(): CorePaymentIntent {
  const details: PaymentDetails = {
    kind: 'summon',
    amountWei: '700',
    feeWei: '10',
    marker: `0x${'0b'.repeat(32)}`,
    at: 3,
    chainId: CHAIN.toString(),
  };
  return { kind: 2, identity: { tag: 'RevealMarker', inner: { marker: new Uint8Array(32).fill(0x0b).buffer } }, details: encodeDetails(details) };
}

/** What `recover` says of a payment still in flight: sign it, then wait while the node holds it. */
function inFlight(sequence: FakeSequence): { tag: string } {
  const step = sequence.step();
  if (step === 'BackedUp') return { tag: 'Sign' };
  if (step === 'Signed') return { tag: 'Send' };
  return { tag: 'Wait' };
}

beforeEach(() => {
  resetPending();
  resetCancels({ read: () => null, write: async () => {} });
  resetReached({ read: () => null, write: async () => {} });
});

describe('the check before sending, in the node layer', () => {
  it('asks eth_estimateGas for the signed account transaction, as the call it makes from its sender', async () => {
    const node = rpcNode(chainAnswers(() => null));
    await vanishNode(NODE_URL, node.fetchImpl).checkSend(VANISH_SIGNED, ACCOUNT);

    expect(node.methods()).toEqual(['eth_estimateGas']);
    const [call, block] = node.calls[0].params as [Record<string, string>, string];
    expect(block).toBe('latest');
    expect(call).toEqual({
      from: ACCOUNT,
      to: COMMIT_ENTRY,
      value: `0x${VANISH_TX.value.toString(16)}`,
      gas: '0x7a120',
      maxFeePerGas: '0x14',
      maxPriorityFeePerGas: '0x2',
      input: COMMIT_DATA,
    });
  });

  it('stops with the node’s own reason when it refuses', async () => {
    const node = rpcNode(chainAnswers(() => COMMIT_REFUSAL));
    const outcome = await vanishNode(NODE_URL, node.fetchImpl)
      .checkSend(VANISH_SIGNED, ACCOUNT)
      .then(() => null, (error: unknown) => error);

    expect(stoppedBeforeSend(outcome)).toBe(true);
    expect(outcome).toMatchObject({ refused: true, nodeUrl: NODE_URL });
    expect(isRefusal(outcome)).toBe(true);
    expect(notSentReason(outcome, NODE_URL)).toBe(
      `Not sent: the test node checked it first and would not take it. The test node at ${NODE_URL} refused it: ${COMMIT_REFUSAL}.`,
    );
  });

  it('never passes for a node it cannot reach: it says the node could not be checked', async () => {
    const offline = jest.fn(async () => {
      throw new TypeError('Network request failed');
    }) as unknown as FetchLike;
    const outcome = await vanishNode(NODE_URL, offline)
      .checkSend(VANISH_SIGNED, ACCOUNT)
      .then(() => null, (error: unknown) => error);

    expect(stoppedBeforeSend(outcome)).toBe(true);
    expect(outcome).toMatchObject({ refused: false });
    expect(isRefusal(outcome)).toBe(false);
    expect(notSentReason(outcome, NODE_URL)).toMatch(/^Not sent: the test node could not check it first, so nothing was sent\. Can't reach/);
  });

  it('never passes for an answer that is not a gas amount', async () => {
    const node = rpcNode((call) => (call.method === 'eth_estimateGas' ? null : '0x1'));
    await expect(vanishNode(NODE_URL, node.fetchImpl).checkSend(VANISH_SIGNED, ACCOUNT)).rejects.toMatchObject({
      notSent: true,
      refused: false,
    });
  });

  it('asks the node nothing for a Summon or Claim (no sender): it checks a reveal when it is sent', async () => {
    const node = rpcNode(chainAnswers(() => null));
    await vanishNode(NODE_URL, node.fetchImpl).checkSend('0x50000102', null);
    expect(node.calls).toEqual([]);
  });

  it('asks nothing, and passes nothing, for bytes it cannot read or an account transaction with no sender', async () => {
    const node = rpcNode(chainAnswers(() => null));
    const checked = vanishNode(NODE_URL, node.fetchImpl);
    await expect(checked.checkSend('0x52c3', ACCOUNT)).rejects.toMatchObject({ notSent: true, refused: false });
    await expect(checked.checkSend('0x07', ACCOUNT)).rejects.toMatchObject({ notSent: true, refused: false });
    await expect(checked.checkSend(VANISH_SIGNED, null)).rejects.toMatchObject({ notSent: true, refused: false });
    expect(node.calls).toEqual([]);
  });
});

describe('a Vanish whose commit data the node rejects', () => {
  function vanishKit(node: VanishNode): PaymentKit {
    return { core: {}, store: { list: () => [] }, node, nodeUrl: NODE_URL } as unknown as PaymentKit;
  }

  it('is refused with the node’s reason, never sent and never marked Sent', async () => {
    const node = rpcNode(chainAnswers((call) => (call.input === COMMIT_DATA ? COMMIT_REFUSAL : null)));
    const sequence = fakeSequence('vanish-1', vanishIntent(), 'BackedUp', inFlight);
    const rebuild = jest.fn(async () => ({ signed: arrayBuffer(VANISH_SIGNED) }));

    const outcome = await advance(vanishNode(NODE_URL, node.fetchImpl), sequence, rebuild, null).then(
      () => null,
      (error: unknown) => error,
    );

    expect(rebuild).toHaveBeenCalledTimes(1);
    expect(node.methods()).toContain('eth_estimateGas');
    expect(node.methods()).not.toContain('eth_sendRawTransaction');
    expect(sequence.addAttempt).not.toHaveBeenCalled();
    expect(sequence.markSent).not.toHaveBeenCalled();
    expect(sequence.step()).toBe('BackedUp');
    expect(statusOfStep(sequence.step())).not.toBe('sent');
    expect(notSentReason(outcome, NODE_URL)).toContain(COMMIT_REFUSAL);
  });

  it('shows on its screen as not sent, with the node’s reason, instead of Sent', async () => {
    jest.useFakeTimers();
    try {
      const node = rpcNode(chainAnswers(() => COMMIT_REFUSAL));
      const sequence = fakeSequence('vanish-2', vanishIntent(), 'BackedUp', inFlight);
      const kit = vanishKit(vanishNode(NODE_URL, node.fetchImpl));
      const rebuild = async () => ({ signed: arrayBuffer(VANISH_SIGNED) });

      const shown = renderHook(() => usePayment(kit, sequence, rebuild, false));
      await act(async () => {
        await jest.advanceTimersByTimeAsync(MOVE_EVERY_MS * 3);
      });

      const view = shown.result.current!;
      expect(view.status).toBe('proving');
      expect(view.error).toBe(
        `Not sent: the test node checked it first and would not take it. The test node at ${NODE_URL} refused it: ${COMMIT_REFUSAL}.`,
      );
      expect(node.methods()).not.toContain('eth_sendRawTransaction');
      expect(sequence.markSent).not.toHaveBeenCalled();
      shown.unmount();
    } finally {
      jest.useRealTimers();
    }
  });

  it('is sent once the node would take it, checked first', async () => {
    const node = rpcNode(chainAnswers(() => null));
    const sequence = fakeSequence('vanish-3', vanishIntent(), 'BackedUp', inFlight);
    const moved = await advance(vanishNode(NODE_URL, node.fetchImpl), sequence, async () => ({ signed: arrayBuffer(VANISH_SIGNED) }), null);

    expect(moved.status).toBe('sent');
    const methods = node.methods();
    expect(methods.indexOf('eth_estimateGas')).toBeGreaterThanOrEqual(0);
    expect(methods.indexOf('eth_estimateGas')).toBeLessThan(methods.indexOf('eth_sendRawTransaction'));
  });

  it('is not sent again when the check cannot reach the node', async () => {
    let online = true;
    const answers = chainAnswers(() => null);
    const node = rpcNode((call) => {
      if (!online && call.method === 'eth_estimateGas') {
        throw new Error('the node did not answer in time');
      }
      return answers(call);
    });
    const sequence = fakeSequence('vanish-4', vanishIntent(), 'BackedUp', inFlight);
    sequence.addAttempt(arrayBuffer(VANISH_SIGNED));
    online = false;
    // Saved signed, not sent (the app was closed between): the mover sends its saved bytes.
    await expect(advance(vanishNode(NODE_URL, node.fetchImpl), sequence, null, null)).rejects.toMatchObject({ notSent: true });
    expect(node.methods()).not.toContain('eth_sendRawTransaction');
  });
});

describe('a Summon, Claim or plain send the node rejects', () => {
  it('saves and sends no Summon the node refuses', async () => {
    const start = jest.fn();
    const node = {
      chainId: jest.fn(async () => CHAIN),
      block: jest.fn(async (height: number) => ({ height, hash: GENESIS, baseFeePerGas: 7n, transactions: [] })),
      checkSend: jest.fn(async () => {
        throw Object.assign(new Error('the node refused a call: proof does not verify'), { notSent: true, refused: true });
      }),
      sendRaw: jest.fn(),
    };
    const core = {
      feeWindow: () => ({ referenceHeight: 99n, validUntil: 120n }),
      proveKeyReveal: () => ({
        transactionHash: new ArrayBuffer(32),
        marker: new Uint8Array(32).fill(0x0b).buffer,
        envelope: new Uint8Array([0x50, 0x00, 0x01]).buffer,
        feeWei: '10',
        outWei: '700',
        remainderWei: '0',
        proveMillis: 1n,
      }),
      PaymentSequence: { start },
    };
    const kit = { core, store: { list: () => [] }, node, nodeUrl: NODE_URL } as unknown as PaymentKit;
    const tree = { tree: { height: 100, hash: GENESIS, leaves: [], spent: [], spentBy: {} }, tip: 100, node };
    const useTree = jest.spyOn(jest.requireActual('../../lib/vanish/use-payment'), 'treeAtTip');
    useTree.mockResolvedValue(tree as never);

    await expect(startReveal(kit, 'typed key words', ACCOUNT, null)).rejects.toThrow(/proof does not verify/);
    expect(node.checkSend).toHaveBeenCalledWith('0x500001', null);
    expect(start).not.toHaveBeenCalled();
    expect(node.sendRaw).not.toHaveBeenCalled();
    useTree.mockRestore();
  });

  it('keeps a plain send the node refuses queued, unsent, with its reason', async () => {
    const node = rpcNode(chainAnswers((call) => (call.to === RECIPIENT ? 'insufficient funds for gas * price + value' : null)));
    const signed = accountTx({ nonce: 7n, maxPriorityFeePerGas: 1n, maxFeePerGas: 7n, gas: 84_256n, to: RECIPIENT, value: 900n, data: '0x' });
    const kit = {
      core: {
        testSendGasLimit: () => 84_256n,
        signSend: jest.fn(() => ({ transactionHash: arrayBuffer(`0x${'ab'.repeat(32)}`), sender: arrayBuffer(ACCOUNT), envelope: arrayBuffer(signed) })),
      },
      store: { list: () => [] },
      node: vanishNode(NODE_URL, node.fetchImpl),
      nodeUrl: NODE_URL,
    } as unknown as SendKit;
    const sequence = fakeSequence('send-1', sendIntent(), 'BackedUp', inFlight);

    const outcome = await advanceSend(kit, sequence).then(
      () => null,
      (error: unknown) => error,
    );
    expect(notSentReason(outcome, NODE_URL)).toMatch(/Not sent: the test node checked it first and would not take it\. Not enough test GHOST/);
    expect(sequence.step()).toBe('BackedUp');
    expect(node.methods()).not.toContain('eth_sendRawTransaction');
  });
});

describe(`a payment the node took but has not mined in ${STUCK_BLOCKS} blocks`, () => {
  /** A node holding the payment and mining nothing of it; its tip is `tip.height`. */
  function holdingNode(tip: { height: number }) {
    return {
      chainId: jest.fn(async () => CHAIN),
      tipHeight: jest.fn(async () => tip.height),
      block: jest.fn(async (height: number) => ({ height, hash: GENESIS, baseFeePerGas: 3n, transactions: [] })),
      receipts: jest.fn(async (hashes: string[]) => hashes.map(() => null)),
      known: jest.fn(async (hashes: string[]) => hashes.map(() => true)),
      nonce: jest.fn(async () => 4n),
      maxPriorityFeePerGas: jest.fn(async () => 1n),
      checkSend: jest.fn(async (_bytes: string, _from: string | null) => {}),
      sendRaw: jest.fn(async () => `0x${'cc'.repeat(32)}`),
    };
  }

  function sentVanish(id = 'vanish-9') {
    const sequence = fakeSequence(id, vanishIntent(), 'BackedUp', inFlight);
    sequence.addAttempt(arrayBuffer(VANISH_SIGNED));
    sequence.markSent();
    return sequence;
  }

  it('is flagged "Not mined yet" with a Cancel offer from the 10th block, never as plain Sent', async () => {
    const tip = { height: 100 };
    const node = holdingNode(tip);
    const sequence = sentVanish();

    const first = await advance(node as unknown as VanishNode, sequence, null, null);
    expect(first).toMatchObject({ status: 'sent', stuck: false, cancellable: false });

    tip.height = 100 + STUCK_BLOCKS - 1;
    expect(await advance(node as unknown as VanishNode, sequence, null, null)).toMatchObject({ status: 'sent', cancellable: false });

    tip.height = 100 + STUCK_BLOCKS;
    const late = await advance(node as unknown as VanishNode, sequence, null, null);
    expect(late).toMatchObject({ status: 'stuck', stuck: true, cancellable: true });

    // What the screen shows: no stage says Sent, the Phantom Key is shown empty.
    const rows = progressRows(late.status, 'vanish');
    expect(rows.map((row) => row.label)).not.toContain('Sent');
    expect(rows.find((row) => row.state === 'current')?.label).toBe(NOT_MINED_LABEL);
    expect(statusDetail(late.status, 'vanish')).toMatch(/^Not mined yet: 10 blocks went by/);
    expect(statusDetail(late.status, 'vanish')).toContain('The Phantom Key holds nothing until it is.');
    expect(statusDetail(late.status, 'vanish')).toContain('Cancel');

    // Home lists it the same way.
    const kit = { core: { PaymentSequence: { open: () => sequence } }, store: { list: () => ['vanish-9'] } };
    expect(pendingPayments(kit as never)[0].stepText).toBe('Not mined yet. The Phantom Key holds nothing yet.');

    // Nothing is cancelled or sent again by itself.
    expect(node.sendRaw).not.toHaveBeenCalled();
    expect(sequence.addAttempt).toHaveBeenCalledTimes(1);
  });

  it('flags a Summon too, without a Cancel: it has no nonce to replace', async () => {
    const tip = { height: 50 };
    const node = holdingNode(tip);
    const sequence = fakeSequence('summon-1', summonIntent(), 'BackedUp', inFlight);
    sequence.addAttempt(arrayBuffer('0x5000ff'));
    sequence.markSent();
    await advance(node as unknown as VanishNode, sequence, null, null);
    tip.height = 50 + STUCK_BLOCKS;
    expect(await advance(node as unknown as VanishNode, sequence, null, null)).toMatchObject({
      status: 'stuck',
      cancellable: false,
    });
  });

  it('flags a plain send the node took as "Not mined yet" with a Cancel offer', async () => {
    const tip = { height: 200 };
    const node = holdingNode(tip);
    const signed = accountTx({ nonce: 7n, maxPriorityFeePerGas: 1n, maxFeePerGas: 7n, gas: 84_256n, to: RECIPIENT, value: 900n, data: '0x' });
    const kit = { core: {}, store: { list: () => [] }, node, nodeUrl: NODE_URL } as unknown as SendKit;
    const sequence = fakeSequence('send-2', sendIntent(), 'BackedUp', inFlight);
    sequence.addAttempt(arrayBuffer(signed));
    asStep(sequence).setStep('Signed');

    expect(await advanceSend(kit, sequence)).toMatchObject({ status: 'sent', cancellable: false });
    tip.height = 200 + STUCK_BLOCKS;
    const late = await advanceSend(kit, sequence);
    expect(late).toMatchObject({ status: 'stuck', cancellable: true });
    expect(sendStatusLabel(late.status)).toBe(NOT_MINED_LABEL);
    expect(sendProgressRows(late.status).map((row) => row.label)).not.toContain('Sent');
    expect(sendStatusDetail(late.status)).toMatch(/^Not mined yet: 10 blocks went by/);
  });

  it('counts again from a new attempt, and not at all once in a block', async () => {
    const tip = { height: 100 };
    const node = holdingNode(tip);
    const sequence = sentVanish('vanish-10');
    await advance(node as unknown as VanishNode, sequence, null, null);
    tip.height = 100 + STUCK_BLOCKS;
    expect((await advance(node as unknown as VanishNode, sequence, null, null)).stuck).toBe(true);

    asStep(sequence).setStep('Included');
    expect(await advance(node as unknown as VanishNode, sequence, null, null)).toMatchObject({ status: 'in-block', stuck: false });
  });
});

describe('cancelling a payment not mined yet', () => {
  const CANCEL_HASH = `0x${'ce'.repeat(32)}`;

  /** A payment stuck on the node: a Vanish, or with `stuck` any account transaction of `intent`. */
  function stuckVanish(tip: { height: number }, stuck: { tx: AccountTx; intent: CorePaymentIntent } = { tx: VANISH_TX, intent: vanishIntent() }) {
    const node = {
      chainId: jest.fn(async () => CHAIN),
      tipHeight: jest.fn(async () => tip.height),
      block: jest.fn(async (height: number) => ({ height, hash: GENESIS, baseFeePerGas: 3n, transactions: [] })),
      receipts: jest.fn(async (hashes: string[]): Promise<(NodeReceipt | null)[]> => hashes.map(() => null)),
      known: jest.fn(async (hashes: string[]) => hashes.map(() => true)),
      maxPriorityFeePerGas: jest.fn(async () => 1n),
      checkSend: jest.fn(async (_bytes: string, _from: string | null) => {}),
      sendRaw: jest.fn(async () => `0x${'cc'.repeat(32)}`),
    };
    const cancelBytes = accountTx({ nonce: 4n, maxPriorityFeePerGas: 3n, maxFeePerGas: 23n, gas: 84_256n, to: ACCOUNT, value: 1n, data: '0x' });
    const sequence = fakeSequence('vanish-20', stuck.intent, 'BackedUp', inFlight, (signed) =>
      signed === cancelBytes ? CANCEL_HASH : `0x${'0a'.repeat(32)}`,
    );
    sequence.addAttempt(arrayBuffer(accountTx(stuck.tx)));
    sequence.markSent();
    const core = {
      testSendGasLimit: () => 84_256n,
      signSend: jest.fn(() => ({ transactionHash: arrayBuffer(CANCEL_HASH), sender: arrayBuffer(ACCOUNT), envelope: arrayBuffer(cancelBytes) })),
    };
    const store = {
      list: () => ['vanish-20'],
      loadPayload: (_id: string, hash: ArrayBuffer) => {
        const saved = asStep(sequence).payload(bytesToHex(hash));
        return saved ? arrayBuffer(saved) : undefined;
      },
    };
    const kit = { core, store, node, nodeUrl: NODE_URL } as unknown as SendKit;
    return { node, sequence, core, kit, cancelBytes };
  }

  async function makeStuck(kit: SendKit, sequence: FakeSequence, tip: { height: number }) {
    await advance(kit.node, sequence, null, null);
    tip.height += STUCK_BLOCKS;
    expect((await advance(kit.node, sequence, null, null)).cancellable).toBe(true);
  }

  it('is offered only once it is stuck', async () => {
    const tip = { height: 300 };
    const { kit, sequence, core } = stuckVanish(tip);
    await advance(kit.node, sequence, null, null);
    await expect(cancelStuck(kit, sequence)).rejects.toThrow(/not mined yet/);
    expect(core.signSend).not.toHaveBeenCalled();
  });

  it('replaces it with 1 wei to its own account, same nonce, at least 15% more fee, checked before it is sent', async () => {
    const tip = { height: 300 };
    const { kit, sequence, core, node, cancelBytes } = stuckVanish(tip);
    await makeStuck(kit, sequence, tip);

    await cancelStuck(kit, sequence);

    const [send] = core.signSend.mock.calls[0] as unknown as [Record<string, unknown>];
    expect(send).toMatchObject({ chainId: CHAIN, nonce: 4n, amountWei: CANCEL_WEI.toString(), gasLimit: 84_256n });
    expect(bytesToHex(send.recipient as ArrayBuffer)).toBe(ACCOUNT);
    // The stuck one paid 2 and 20 per gas: 15% more, rounded up, is 3 and 23.
    expect(send.maxPriorityFeePerGas).toBe(3n);
    expect(send.maxFeePerGas).toBe(23n);
    expect((send.maxFeePerGas as bigint) * 100n).toBeGreaterThanOrEqual(VANISH_TX.maxFeePerGas * 115n);

    expect(node.checkSend).toHaveBeenLastCalledWith(cancelBytes, ACCOUNT);
    const checked = node.checkSend.mock.invocationCallOrder[node.checkSend.mock.invocationCallOrder.length - 1];
    expect(checked).toBeLessThan(sequence.addAttempt.mock.invocationCallOrder[1]);
    expect(node.sendRaw).toHaveBeenLastCalledWith(cancelBytes);
    expect(isCancel(CANCEL_HASH)).toBe(true);
    // The count starts again for the cancel.
    expect((await advance(kit.node, sequence, null, null)).stuck).toBe(false);
  });

  it.each([
    ['an inflated priority fee', { priority: 1_000_000_000_000n, baseFee: 3n }],
    ['an inflated base fee', { priority: 1n, baseFee: 1_000_000_000_000n }],
    ['a priority fee just above the cap', { priority: 4n, baseFee: 3n }],
  ])('signs and sends nothing when the node quotes %s, however affordable', async (_what, quote) => {
    const tip = { height: 300 };
    const { kit, sequence, core, node } = stuckVanish(tip);
    await makeStuck(kit, sequence, tip);
    node.maxPriorityFeePerGas.mockResolvedValue(quote.priority);
    node.block.mockImplementation(async (height: number) => ({ height, hash: GENESIS, baseFeePerGas: quote.baseFee, transactions: [] }));

    await expect(cancelStuck(kit, sequence)).rejects.toThrow(/asks for a higher fee than a cancel pays.*nothing was signed or sent/);
    expect(core.signSend).not.toHaveBeenCalled();
    expect(node.checkSend).not.toHaveBeenCalled();
    expect(node.sendRaw).not.toHaveBeenCalled();
    expect(sequence.addAttempt).toHaveBeenCalledTimes(1);
    expect(isCancel(CANCEL_HASH)).toBe(false);
  });

  it('signs the fees set on this phone, not the node’s quote, when the quote is below them', async () => {
    const tip = { height: 300 };
    const { kit, sequence, core, node } = stuckVanish(tip);
    await makeStuck(kit, sequence, tip);
    // A quote under the caps (3 and 23) is only a check: the caps are what is signed.
    node.maxPriorityFeePerGas.mockResolvedValue(3n);
    node.block.mockImplementation(async (height: number) => ({ height, hash: GENESIS, baseFeePerGas: 10n, transactions: [] }));

    await cancelStuck(kit, sequence);
    const [send] = core.signSend.mock.calls[0] as unknown as [Record<string, unknown>];
    expect(send).toMatchObject({ maxPriorityFeePerGas: 3n, maxFeePerGas: 23n });
  });

  it('cancels a plain send of the same gas whose fee bump rounds up, never refused for rounding', async () => {
    const tip = { height: 300 };
    // 1,000,000,002 wei per gas raised 15% is 1,150,000,002.3: rounded up per gas, the total must still pass.
    const send: AccountTx = {
      nonce: 7n,
      maxPriorityFeePerGas: 1n,
      maxFeePerGas: 1_000_000_002n,
      gas: 84_256n,
      to: RECIPIENT,
      value: 900n,
      data: '0x',
    };
    const { kit, sequence, core, node } = stuckVanish(tip, { tx: send, intent: sendIntent() });
    await makeStuck(kit, sequence, tip);

    await cancelStuck(kit, sequence);

    const [signed] = core.signSend.mock.calls[0] as unknown as [Record<string, unknown>];
    expect(signed).toMatchObject({ nonce: 7n, maxFeePerGas: 1_150_000_003n, maxPriorityFeePerGas: 2n, gasLimit: 84_256n });
    expect(node.sendRaw).toHaveBeenCalledTimes(1);
  });

  it('refuses a cancel whose gas would let it pay more than the stuck payment could', async () => {
    const tip = { height: 300 };
    const small: AccountTx = { ...VANISH_TX, gas: 50_000n };
    const { kit, sequence, core, node } = stuckVanish(tip, { tx: small, intent: vanishIntent() });
    await makeStuck(kit, sequence, tip);

    await expect(cancelStuck(kit, sequence)).rejects.toThrow(/cost more fee than this payment could/);
    expect(core.signSend).not.toHaveBeenCalled();
    expect(node.sendRaw).not.toHaveBeenCalled();
  });

  it('cancels a payment once at most, so its fee is never raised again and again', async () => {
    const tip = { height: 300 };
    const { kit, sequence, core } = stuckVanish(tip);
    await makeStuck(kit, sequence, tip);
    await cancelStuck(kit, sequence);
    // The cancel itself sits for 10 blocks too.
    await advance(kit.node, sequence, null, null);
    tip.height += STUCK_BLOCKS;
    expect((await advance(kit.node, sequence, null, null)).stuck).toBe(true);

    await expect(cancelStuck(kit, sequence)).rejects.toThrow(/already waiting/);
    expect(core.signSend).toHaveBeenCalledTimes(1);
  });

  it('sends nothing when the node refuses the cancel', async () => {
    const tip = { height: 300 };
    const { kit, sequence, node } = stuckVanish(tip);
    await makeStuck(kit, sequence, tip);
    node.checkSend.mockRejectedValueOnce(Object.assign(new Error('the node refused a call: replacement transaction underpriced'), { notSent: true, refused: true }));

    await expect(cancelStuck(kit, sequence)).rejects.toThrow(/underpriced/);
    expect(sequence.addAttempt).toHaveBeenCalledTimes(1);
    expect(node.sendRaw).not.toHaveBeenCalled();
    expect(isCancel(CANCEL_HASH)).toBe(false);
  });

  it('leaves the Phantom Key shown empty when the cancel is what is mined', async () => {
    const tip = { height: 300 };
    const { kit, sequence, node } = stuckVanish(tip);
    await makeStuck(kit, sequence, tip);
    await cancelStuck(kit, sequence);

    node.receipts.mockImplementation(async (hashes: string[]) =>
      hashes.map((hash) => (hash === CANCEL_HASH ? { transactionHash: hash, success: true, blockHash: GENESIS, blockHeight: 311 } : null)),
    );
    const view = await chainSnapshot(kit.node, sequence.record(), null);
    // The core marks a landed attempt whose effect did not apply as failed: never as coins in the key.
    expect(view.effectApplied(sequence.record().intent, arrayBuffer(CANCEL_HASH))).toBe(false);
    expect(view.effectApplied(sequence.record().intent, arrayBuffer(sequence.attemptHashes[0]))).toBe(true);
    expect(statusDetail('failed', 'vanish', 'Failed')).toContain('The Phantom Key holds nothing.');
  });
});
