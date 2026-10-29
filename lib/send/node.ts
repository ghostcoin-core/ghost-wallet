// The node calls a send needs beyond lib/vanish/node.ts: the account's nonce
// at a height, and the transaction that used one nonce. Together they find the
// payment that went first when another one from this account took a send's
// nonce, so the send shows as conflicted instead of waiting forever.
import { rpcBatch, type FetchLike } from '../node/rpc';
import { hexQuantity } from '../vanish/node';

function quantity(value: unknown, what: string): bigint {
  if (typeof value !== 'string' || !/^0x[0-9a-f]+$/i.test(value)) {
    throw new Error(`the node sent a malformed ${what}`);
  }
  return BigInt(value);
}

/** How many transactions `address` had sent as of block `height`. */
export async function nonceAt(url: string, address: string, height: number, fetchImpl?: FetchLike): Promise<bigint> {
  const [count] = await rpcBatch(url, [['eth_getTransactionCount', [address, hexQuantity(height)]]], fetchImpl);
  return quantity(count, 'transaction count');
}

/** The hash of the transaction from `address` with `nonce` in block `height`, if there is one. */
export async function transactionWithNonce(
  url: string,
  address: string,
  nonce: bigint,
  height: number,
  fetchImpl?: FetchLike,
): Promise<string | null> {
  const [block] = await rpcBatch(url, [['eth_getBlockByNumber', [hexQuantity(height), true]]], fetchImpl);
  const transactions = Array.isArray((block as { transactions?: unknown } | null)?.transactions)
    ? ((block as { transactions: unknown[] }).transactions as Record<string, unknown>[])
    : [];
  const from = address.toLowerCase();
  for (const tx of transactions) {
    if (
      typeof tx?.from === 'string' &&
      tx.from.toLowerCase() === from &&
      typeof tx.nonce === 'string' &&
      quantity(tx.nonce, 'transaction nonce') === nonce &&
      typeof tx.hash === 'string' &&
      /^0x[0-9a-f]{64}$/i.test(tx.hash)
    ) {
      return tx.hash.toLowerCase();
    }
  }
  return null;
}

/**
 * The transaction in a block that used `nonce` of `address`, if the chain at
 * `tip` has one. It looks from `fromHeight` (where the send was saved) and
 * finds the block by halving, so a long time offline costs a few calls only.
 */
export async function nonceUsedBy(
  url: string,
  address: string,
  nonce: bigint,
  fromHeight: number,
  tip: number,
  fetchImpl?: FetchLike,
): Promise<string | null> {
  if ((await nonceAt(url, address, tip, fetchImpl)) <= nonce) {
    return null;
  }
  let low = Math.max(0, Math.min(fromHeight, tip));
  if (low > 0 && (await nonceAt(url, address, low - 1, fetchImpl)) > nonce) {
    low = 0;
  }
  let high = tip;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if ((await nonceAt(url, address, middle, fetchImpl)) > nonce) {
      high = middle;
    } else {
      low = middle + 1;
    }
  }
  return transactionWithNonce(url, address, nonce, low, fetchImpl);
}
