// The check before sending (`eth_estimateGas`) carries the signed bytes once,
// under `input` only. A reveal is about 1.3 MB, about 2.6 MB as hex: sent under
// both `input` and `data` the request body passes the node's fixed 5 MiB limit
// and the node answers HTTP 413, so a Summon or Claim could never be sent.

import type { FetchLike } from '../../lib/node/rpc';
import { estimateCall, vanishNode } from '../../lib/vanish/node';
import { bytesToHex, hexToBytes } from '../../modules/ghost-core/account-lookup';

const NODE_URL = 'http://127.0.0.1:8547';
/** The node's HTTP body limit (`rpc/http.go` `defaultBodyLimit`). */
const BODY_LIMIT = 5 * 1024 * 1024;
/** A reveal of about 1.3 MB: sent twice as hex its body would pass the limit. */
const REVEAL_BYTES = Math.ceil(1.3 * 1024 * 1024);
const ACCOUNT = `0x${'aa'.repeat(20)}`;
const RECIPIENT = `0x${'bb'.repeat(20)}`;

type Call = { id: number; method: string; params: unknown[] };

/** A node that, like the real one, answers 413 to a body over its limit. */
function limitedNode() {
  const bodies: string[] = [];
  const fetchImpl = jest.fn(async (_url: string, init: RequestInit) => {
    const body = String(init.body);
    bodies.push(body);
    if (new TextEncoder().encode(body).length > BODY_LIMIT) {
      return { ok: false, status: 413, json: async () => ({}), text: async () => 'request body too large' } as unknown as Response;
    }
    const batch = JSON.parse(body) as Call[];
    return {
      ok: true,
      status: 200,
      json: async () => batch.map((call) => ({ jsonrpc: '2.0', id: call.id, result: '0x5208' })),
    } as unknown as Response;
  });
  return { fetchImpl: fetchImpl as unknown as FetchLike, bodies };
}

/** A signed private transaction of `size` bytes after its type byte. */
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

function accountTx(callBytes: Uint8Array): string {
  const fields: Rlp[] = [
    new Uint8Array([0x01]),
    new Uint8Array([0x04]),
    new Uint8Array([0x02]),
    new Uint8Array([0x14]),
    hexToBytes('0x07a120'),
    hexToBytes(RECIPIENT),
    new Uint8Array([0x05]),
    callBytes,
    [],
    new Uint8Array([0x00, 0x03]),
    new Uint8Array(1344).fill(0x11),
    new Uint8Array(2420).fill(0x22),
  ];
  return bytesToHex(concat([new Uint8Array([0x52]), rlp(fields)]));
}

describe('the eth_estimateGas call of a signed transaction', () => {
  it('sends a 1.3 MB reveal once, under input only, in a body under 5 MiB', async () => {
    const signed = reveal(REVEAL_BYTES);
    const node = limitedNode();

    const outcome = await vanishNode(NODE_URL, node.fetchImpl)
      .checkSend(signed, null)
      .then(() => null, (error: unknown) => error);

    expect(node.bodies).toHaveLength(1);
    const body = node.bodies[0];
    expect(new TextEncoder().encode(body).length).toBeLessThan(BODY_LIMIT);
    expect(outcome).toBeNull();
    const [request] = JSON.parse(body) as Call[];
    expect(request.method).toBe('eth_estimateGas');
    const call = request.params[0] as Record<string, string>;
    expect(Object.keys(call).sort()).toEqual(['input', 'type']);
    expect(call).not.toHaveProperty('data');
    expect(call.type).toBe('0x50');
    expect(call.input).toBe(`0x${signed.slice(4)}`);
    expect(call.input.length).toBe(2 + REVEAL_BYTES * 2);
  });

  it('puts an account transaction’s call bytes under input only, with no data key', () => {
    const callBytes = new Uint8Array(REVEAL_BYTES).fill(0x33);
    const call = estimateCall(accountTx(callBytes), ACCOUNT);

    expect(call).not.toHaveProperty('data');
    expect(call.input).toBe(bytesToHex(callBytes));
    expect(call).toEqual({
      from: ACCOUNT,
      to: RECIPIENT,
      gas: '0x7a120',
      maxFeePerGas: '0x14',
      maxPriorityFeePerGas: '0x2',
      value: '0x5',
      input: bytesToHex(callBytes),
    });
    const body = JSON.stringify([{ jsonrpc: '2.0', id: 1, method: 'eth_estimateGas', params: [call, 'latest'] }]);
    expect(new TextEncoder().encode(body).length).toBeLessThan(BODY_LIMIT);
  });
});
