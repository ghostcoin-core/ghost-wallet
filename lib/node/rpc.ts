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

/** How long a call may take: every read is small. */
export const TIMEOUT_MS = 10_000;
/**
 * How long sending a transaction may take: a Summon or Claim is about 1.3 MB,
 * and uploading it from a phone on a slow link takes far longer than a read.
 */
export const SEND_TIMEOUT_MS = 120_000;

const REFUSED = 'the node refused a call';

/**
 * Whether `error` is the node's own refusal of a call: it answered, and said
 * no. A timeout or a dropped connection is not one: the call may have reached it.
 */
export function isRefusal(error: unknown): boolean {
  return error instanceof Error && error.message.startsWith(REFUSED);
}

/** An error from the node layer, with the address of the node it came from. */
export type NodeError = Error & { nodeUrl?: string };

/**
 * Marks `error` as coming from the node at `url`, unless it already names a
 * node: the screens then name the node that failed, which may be a backup
 * node and not the one in Settings.
 */
export function fromNode<T>(error: T, url: string | undefined): T {
  if (error instanceof Error && url && failedNodeUrl(error) === null) {
    (error as NodeError).nodeUrl = url;
  }
  return error;
}

/** The address of the node `error` came from, or null when it does not say. */
export function failedNodeUrl(error: unknown): string | null {
  const url = error instanceof Error ? (error as NodeError).nodeUrl : undefined;
  return typeof url === 'string' && url !== '' ? url : null;
}

/** Runs `call` on the node at `url`; whatever it throws names that node. */
async function atNode<T>(url: string, call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (error) {
    throw fromNode(error, url);
  }
}

function quantity(value: unknown, what: string): bigint {
  if (typeof value !== 'string' || !/^0x[0-9a-f]+$/i.test(value)) {
    throw new Error(`the node sent a malformed ${what}`);
  }
  return BigInt(value);
}

/**
 * Sends the calls as one JSON-RPC batch and returns their results in order.
 * An error it throws carries `url` (`failedNodeUrl`).
 */
export function rpcBatch(
  url: string,
  calls: [method: string, params: unknown[]][],
  fetchImpl: FetchLike = fetch,
  timeoutMs: number = TIMEOUT_MS,
): Promise<unknown[]> {
  return atNode(url, () => batch(url, calls, fetchImpl, timeoutMs));
}

async function batch(
  url: string,
  calls: [method: string, params: unknown[]][],
  fetchImpl: FetchLike,
  timeoutMs: number,
): Promise<unknown[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
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
      throw new Error(`${REFUSED}: ${String(answer.error.message ?? 'no reason given')}`);
    }
    return answer.result;
  });
}

/** The node's chain id (`eth_chainId`). */
export function getChainId(url: string, fetchImpl?: FetchLike): Promise<bigint> {
  return atNode(url, async () => {
    const [id] = await rpcBatch(url, [['eth_chainId', []]], fetchImpl);
    return quantity(id, 'chain id');
  });
}

/** The node's latest block: its height and hash. */
export function getTip(url: string, fetchImpl?: FetchLike): Promise<Tip> {
  return atNode(url, async () => {
    const [block] = await rpcBatch(url, [['eth_getBlockByNumber', ['latest', false]]], fetchImpl);
    const { number, hash } = (block ?? {}) as { number?: unknown; hash?: unknown };
    if (typeof hash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(hash)) {
      throw new Error('the node sent a malformed block hash');
    }
    return { height: Number(quantity(number, 'block height')), hash: hash.toLowerCase() };
  });
}

/**
 * An account's balance and nonce at one block hash (EIP-1898, canonical
 * only), in one batch so both belong to the same block.
 */
export function getAccountState(
  url: string,
  address: string,
  blockHash: string,
  fetchImpl?: FetchLike,
): Promise<NodeAccountState> {
  const block = { blockHash, requireCanonical: true };
  return atNode(url, async () => {
    const [balance, nonce] = await rpcBatch(
      url,
      [
        ['eth_getBalance', [address, block]],
        ['eth_getTransactionCount', [address, block]],
      ],
      fetchImpl,
    );
    return { balance: quantity(balance, 'balance'), nonce: quantity(nonce, 'transaction count') };
  });
}
