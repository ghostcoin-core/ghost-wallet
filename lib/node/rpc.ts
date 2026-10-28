// The few node calls home needs, as JSON-RPC over HTTP to the configured node.
// The node's answers are its report: nothing here proves them.

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

export type Tip = {
  height: number;
  /** The tip's block hash, `0x` and 64 hex digits. */
  hash: string;
};

export type NodeAccountState = {
  balance: bigint;
  nonce: bigint;
};

const TIMEOUT_MS = 10_000;

function quantity(value: unknown, what: string): bigint {
  if (typeof value !== 'string' || !/^0x[0-9a-f]+$/i.test(value)) {
    throw new Error(`the node sent a malformed ${what}`);
  }
  return BigInt(value);
}

/** Sends the calls as one JSON-RPC batch and returns their results in order. */
export async function rpcBatch(
  url: string,
  calls: [method: string, params: unknown[]][],
  fetchImpl: FetchLike = fetch,
): Promise<unknown[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let body: unknown;
  try {
    const response = await fetchImpl(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(calls.map(([method, params], id) => ({ jsonrpc: '2.0', id, method, params }))),
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`the node answered HTTP ${response.status}`);
    }
    body = await response.json();
  } catch (error) {
    if (controller.signal.aborted) {
      throw new Error('the node did not answer in time');
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
  if (!Array.isArray(body)) {
    throw new Error('the node sent a malformed answer');
  }
  return calls.map((_, id) => {
    const answer = body.find((entry: unknown) => (entry as { id?: unknown })?.id === id) as
      | { result?: unknown; error?: { message?: unknown } }
      | undefined;
    if (!answer) {
      throw new Error('the node left a call unanswered');
    }
    if (answer.error) {
      throw new Error(`the node refused a call: ${String(answer.error.message ?? 'no reason given')}`);
    }
    return answer.result;
  });
}

/** The node's latest block: its height and hash. */
export async function getTip(url: string, fetchImpl?: FetchLike): Promise<Tip> {
  const [block] = await rpcBatch(url, [['eth_getBlockByNumber', ['latest', false]]], fetchImpl);
  const { number, hash } = (block ?? {}) as { number?: unknown; hash?: unknown };
  if (typeof hash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(hash)) {
    throw new Error('the node sent a malformed block hash');
  }
  return { height: Number(quantity(number, 'block height')), hash: hash.toLowerCase() };
}

/**
 * An account's balance and nonce at one block hash (EIP-1898, canonical
 * only), in one batch so both belong to the same block.
 */
export async function getAccountState(
  url: string,
  address: string,
  blockHash: string,
  fetchImpl?: FetchLike,
): Promise<NodeAccountState> {
  const block = { blockHash, requireCanonical: true };
  const [balance, nonce] = await rpcBatch(
    url,
    [
      ['eth_getBalance', [address, block]],
      ['eth_getTransactionCount', [address, block]],
    ],
    fetchImpl,
  );
  return { balance: quantity(balance, 'balance'), nonce: quantity(nonce, 'transaction count') };
}
