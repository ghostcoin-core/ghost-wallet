// The node's `eth_estimateGas` has no reveal support: it reads a private
// transaction (type 0x50) as a contract creation with the 1.3 MB proof as its
// init code, and always refuses it ("max initcode size exceeded"). So the check
// before sending asks the node nothing for a reveal: the node checks a reveal
// when it is sent. An account transaction is still checked with eth_estimateGas.

import type { FetchLike } from '../../lib/node/rpc';
import { startReveal } from '../../lib/vanish/actions';
import { stoppedBeforeSend, vanishNode } from '../../lib/vanish/node';
import type { PaymentKit } from '../../lib/vanish/use-payment';
import { buildNetwork } from '../../lib/network/build-network';
import { bytesToHex, hexToBytes } from '../../modules/ghost-core/account-lookup';

jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));

const NODE_URL = 'http://127.0.0.1:8547';
const ACCOUNT = `0x${'aa'.repeat(20)}`;
const RECIPIENT = `0x${'bb'.repeat(20)}`;
const GENESIS = `0x${'47'.repeat(32)}`;
const SENT_HASH = `0x${'5e'.repeat(32)}`;
/** What the node's eth_estimateGas says of every reveal. */
const INITCODE_REFUSAL = 'max initcode size exceeded: code size 1311066 limit 49152';

type Call = { id: number; method: string; params: unknown[] };

/** A node like the real one: eth_estimateGas refuses any reveal, a send takes it. */
function fakeNode() {
  const calls: Call[] = [];
  const fetchImpl = jest.fn(async (_url: string, init: RequestInit) => {
    const batch = JSON.parse(String(init.body)) as Call[];
    calls.push(...batch);
    return {
      ok: true,
      status: 200,
      json: async () =>
        batch.map((call) => {
          if (call.method === 'eth_estimateGas') {
            const asked = call.params[0] as Record<string, string>;
            return asked.type === '0x50'
              ? { jsonrpc: '2.0', id: call.id, error: { code: -32000, message: INITCODE_REFUSAL } }
              : { jsonrpc: '2.0', id: call.id, result: '0x5208' };
          }
          if (call.method === 'eth_sendRawTransaction') {
            return { jsonrpc: '2.0', id: call.id, result: SENT_HASH };
          }
          return { jsonrpc: '2.0', id: call.id, error: { code: -32601, message: 'not in this test' } };
        }),
    } as unknown as Response;
  });
  return { fetchImpl, fetch: fetchImpl as unknown as FetchLike, methods: () => calls.map((call) => call.method), calls };
}

/** A signed private transaction: its type byte, then `size` bytes. */
function reveal(size: number): string {
  const bytes = new Uint8Array(size + 1).fill(0x5a);
  bytes[0] = 0x50;
  return bytesToHex(bytes);
}

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

const CALL_DATA = '0x0102030405';

function accountTx(): string {
  const fields: Rlp[] = [
    new Uint8Array([0x01]),
    new Uint8Array([0x04]),
    new Uint8Array([0x02]),
    new Uint8Array([0x14]),
    hexToBytes('0x07a120'),
    hexToBytes(RECIPIENT),
    new Uint8Array([0x05]),
    hexToBytes(CALL_DATA),
    [],
    new Uint8Array([0x00, 0x03]),
    new Uint8Array(1344).fill(0x11),
    new Uint8Array(2420).fill(0x22),
  ];
  return bytesToHex(concat([new Uint8Array([0x52]), rlp(fields)]));
}

describe('the check before sending a reveal', () => {
  it('resolves for a 1.3 MB Summon or Claim without calling fetch', async () => {
    const node = fakeNode();
    await expect(vanishNode(NODE_URL, node.fetch).checkSend(reveal(1_311_066), null)).resolves.toBeUndefined();
    expect(node.fetchImpl).not.toHaveBeenCalled();
  });

  it('resolves for a small reveal without calling fetch', async () => {
    const node = fakeNode();
    await vanishNode(NODE_URL, node.fetch).checkSend('0x50000102', null);
    expect(node.fetchImpl).not.toHaveBeenCalled();
  });

  it('still refuses bytes that are no transaction at all, asking nothing', async () => {
    const node = fakeNode();
    const checked = vanishNode(NODE_URL, node.fetch);
    await expect(checked.checkSend('0x50', null)).rejects.toMatchObject({ notSent: true, refused: false });
    await expect(checked.checkSend('not hex', null)).rejects.toMatchObject({ notSent: true, refused: false });
    expect(node.fetchImpl).not.toHaveBeenCalled();
  });
});

describe('the check before sending an account transaction', () => {
  it('still sends eth_estimateGas, as the call it makes from its sender', async () => {
    const node = fakeNode();
    await vanishNode(NODE_URL, node.fetch).checkSend(accountTx(), ACCOUNT);

    expect(node.methods()).toEqual(['eth_estimateGas']);
    const [call, block] = node.calls[0].params as [Record<string, string>, string];
    expect(block).toBe('latest');
    expect(call).toEqual({
      from: ACCOUNT,
      to: RECIPIENT,
      value: '0x5',
      gas: '0x7a120',
      maxFeePerGas: '0x14',
      maxPriorityFeePerGas: '0x2',
      input: CALL_DATA,
    });
  });

  it('still stops with the node’s reason when eth_estimateGas refuses it', async () => {
    const refusing = jest.fn(async (_url: string, init: RequestInit) => {
      const batch = JSON.parse(String(init.body)) as Call[];
      return {
        ok: true,
        status: 200,
        json: async () => batch.map((call) => ({ jsonrpc: '2.0', id: call.id, error: { code: -32000, message: 'insufficient funds' } })),
      } as unknown as Response;
    }) as unknown as FetchLike;

    const outcome = await vanishNode(NODE_URL, refusing)
      .checkSend(accountTx(), ACCOUNT)
      .then(() => null, (error: unknown) => error);

    expect(stoppedBeforeSend(outcome)).toBe(true);
    expect(outcome).toMatchObject({ refused: true });
    expect((outcome as Error).message).toContain('insufficient funds');
  });
});

describe('a Summon through the node that cannot estimate a reveal', () => {
  it('is saved and sent, with no eth_estimateGas asked', async () => {
    const node = fakeNode();
    const envelope = hexToBytes(reveal(64));
    const start = jest.fn(() => ({
      markBackedUp: jest.fn(),
      addAttempt: jest.fn(),
      markSent: jest.fn(() => envelope.buffer),
    }));
    const core = {
      feeWindow: () => ({ referenceHeight: 99n, validUntil: 120n }),
      proveKeyReveal: () => ({
        transactionHash: new ArrayBuffer(32),
        marker: new Uint8Array(32).fill(0x0b).buffer,
        envelope: envelope.buffer,
        feeWei: '10',
        outWei: '700',
        remainderWei: '0',
        proveMillis: 1n,
      }),
      PaymentSequence: { start },
    };
    const vanish = {
      ...vanishNode(NODE_URL, node.fetch),
      chainId: jest.fn(async () => buildNetwork.chainId),
      block: jest.fn(async (height: number) => ({ height, hash: GENESIS, baseFeePerGas: 7n, transactions: [] })),
    };
    const kit = { core, store: { list: () => [] }, node: vanish, nodeUrl: NODE_URL } as unknown as PaymentKit;
    const tree = { tree: { height: 100, hash: GENESIS, leaves: [], spent: [], spentBy: {} }, tip: 100, node: vanish };
    const useTree = jest.spyOn(jest.requireActual('../../lib/vanish/use-payment'), 'treeAtTip');
    useTree.mockResolvedValue(tree as never);

    try {
      await startReveal(kit, 'typed key words', ACCOUNT, null);
    } finally {
      useTree.mockRestore();
    }

    expect(start).toHaveBeenCalledTimes(1);
    expect(node.methods()).toEqual(['eth_sendRawTransaction']);
    expect(node.calls[0].params).toEqual([bytesToHex(envelope)]);
  });
});
