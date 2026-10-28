import {
  bigintToBytes,
  bytesToHex,
  hexToBytes,
  lookUpAccountAtTip,
  type CoreAccountLookup,
  type RestoreBindings,
} from '../../modules/ghost-core/account-lookup';
import { getAccountState, getTip, rpcBatch, type FetchLike } from '../../lib/node/rpc';

const ADDRESS = '0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd';
const TIP_HASH = '0x' + 'ab'.repeat(32);
const WORDS = 'test words';

// Stands in for the generated RestoreLookup: derives one fixed address and,
// like core/src/restore_scan.rs, asks the lookup at the tip hash and turns the
// big-endian balance into decimal wei.
function fakeBindings(log: string[]): RestoreBindings {
  class RestoreLookup {
    constructor(
      readonly words: string,
      readonly lookup: CoreAccountLookup,
      readonly tipHeight: bigint,
      readonly tipHash: ArrayBuffer,
    ) {
      log.push(`new ${words} ${tipHeight} ${bytesToHex(tipHash)}`);
    }
    deriveAccount(index: number) {
      log.push(`derive ${index}`);
      return { index, address: ADDRESS };
    }
    lookUpAccount(index: number) {
      log.push(`look up ${index}`);
      const state = this.lookup.accountState(hexToBytes(ADDRESS).buffer as ArrayBuffer, this.tipHash);
      const balance = BigInt(bytesToHex(state.balance) === '0x' ? 0 : bytesToHex(state.balance));
      return {
        index,
        address: ADDRESS,
        balance: balance.toString(),
        nonce: state.nonce,
        used: state.nonce > 0n || balance > 0n,
        unverified: true,
      };
    }
    uniffiDestroy() {
      log.push('destroy');
    }
  }
  return { RestoreLookup };
}

describe('lookUpAccountAtTip', () => {
  it('derives the address in the core, asks the node about it at the tip, then lets the core look it up', async () => {
    const log: string[] = [];
    const fetchState = jest.fn(async (address: string, blockHash: string) => {
      log.push(`node ${address} ${blockHash}`);
      return { balance: 3n * 10n ** 18n, nonce: 2n };
    });

    const account = await lookUpAccountAtTip(fakeBindings(log), WORDS, 0, { height: 120, hash: TIP_HASH }, fetchState);

    expect(account).toEqual({
      index: 0,
      address: ADDRESS,
      balance: '3000000000000000000',
      nonce: 2,
      tipHeight: 120,
      unverified: true,
    });
    expect(log).toEqual([
      `new ${WORDS} 120 ${TIP_HASH}`,
      'derive 0',
      `node ${ADDRESS} ${TIP_HASH}`,
      'look up 0',
      'destroy',
    ]);
  });

  it('refuses to answer the core about an address or block the node was not asked about', async () => {
    const log: string[] = [];
    const bindings = fakeBindings(log);
    const Original = bindings.RestoreLookup;
    const other = '0x' + '11'.repeat(20);
    bindings.RestoreLookup = class extends Original {
      deriveAccount(index: number) {
        super.deriveAccount(index);
        return { index, address: other };
      }
    };

    await expect(
      lookUpAccountAtTip(bindings, WORDS, 0, { height: 1, hash: TIP_HASH }, async () => ({ balance: 1n, nonce: 0n })),
    ).rejects.toThrow('not asked about');
    expect(log[log.length - 1]).toBe('destroy');
  });

  it('frees the core object when the node fails', async () => {
    const log: string[] = [];
    await expect(
      lookUpAccountAtTip(fakeBindings(log), WORDS, 0, { height: 1, hash: TIP_HASH }, async () => {
        throw new Error('offline');
      }),
    ).rejects.toThrow('offline');
    expect(log).not.toContain('look up 0');
    expect(log[log.length - 1]).toBe('destroy');
  });
});

describe('byte helpers', () => {
  it('writes amounts as minimal big-endian bytes', () => {
    expect(bytesToHex(bigintToBytes(0n))).toBe('0x');
    expect(bytesToHex(bigintToBytes(1n))).toBe('0x01');
    expect(bytesToHex(bigintToBytes(0x1234n))).toBe('0x1234');
    expect(bytesToHex(bigintToBytes(0xabcden))).toBe('0x0abcde');
    expect(() => bigintToBytes(-1n)).toThrow();
  });

  it('round-trips hex', () => {
    expect(bytesToHex(hexToBytes(TIP_HASH))).toBe(TIP_HASH);
    expect(() => hexToBytes('0x123')).toThrow('not hex');
    expect(() => hexToBytes('0xzz')).toThrow('not hex');
  });
});

function answering(handler: (calls: { id: number; method: string; params: unknown[] }[]) => unknown): {
  fetch: FetchLike;
  bodies: unknown[];
} {
  const bodies: unknown[] = [];
  return {
    bodies,
    fetch: async (_url, init) => {
      const calls = JSON.parse(String(init.body));
      bodies.push(calls);
      return { ok: true, status: 200, json: async () => handler(calls) } as Response;
    },
  };
}

describe('node calls', () => {
  it('reads the tip from the latest block', async () => {
    const node = answering((calls) => calls.map((c) => ({ id: c.id, result: { number: '0x78', hash: TIP_HASH.toUpperCase().replace('0X', '0x') } })));
    await expect(getTip('http://node', node.fetch)).resolves.toEqual({ height: 120, hash: TIP_HASH });
    expect(node.bodies[0]).toEqual([{ jsonrpc: '2.0', id: 0, method: 'eth_getBlockByNumber', params: ['latest', false] }]);
  });

  it('asks for the balance and nonce at one canonical block hash, in one batch', async () => {
    const node = answering((calls) =>
      [...calls].reverse().map((c) => ({ id: c.id, result: c.method === 'eth_getBalance' ? '0xde0b6b3a7640000' : '0x2' })),
    );
    await expect(getAccountState('http://node', ADDRESS, TIP_HASH, node.fetch)).resolves.toEqual({
      balance: 10n ** 18n,
      nonce: 2n,
    });
    const block = { blockHash: TIP_HASH, requireCanonical: true };
    expect(node.bodies[0]).toEqual([
      { jsonrpc: '2.0', id: 0, method: 'eth_getBalance', params: [ADDRESS, block] },
      { jsonrpc: '2.0', id: 1, method: 'eth_getTransactionCount', params: [ADDRESS, block] },
    ]);
  });

  it('turns node errors and malformed answers into errors', async () => {
    const refusing = answering((calls) => calls.map((c) => ({ id: c.id, error: { message: 'header not found' } })));
    await expect(getAccountState('http://node', ADDRESS, TIP_HASH, refusing.fetch)).rejects.toThrow('header not found');

    const malformed = answering((calls) => calls.map((c) => ({ id: c.id, result: '12' })));
    await expect(getAccountState('http://node', ADDRESS, TIP_HASH, malformed.fetch)).rejects.toThrow('malformed balance');

    const badHash = answering((calls) => calls.map((c) => ({ id: c.id, result: { number: '0x1', hash: '0x12' } })));
    await expect(getTip('http://node', badHash.fetch)).rejects.toThrow('malformed block hash');

    const missing = answering(() => []);
    await expect(rpcBatch('http://node', [['eth_blockNumber', []]], missing.fetch)).rejects.toThrow('unanswered');

    const http: FetchLike = async () => ({ ok: false, status: 502 }) as Response;
    await expect(rpcBatch('http://node', [['eth_blockNumber', []]], http)).rejects.toThrow('HTTP 502');
  });
});
