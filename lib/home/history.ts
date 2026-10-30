// The account's recent payments, found on chain after a restore. The node
// serves no history by address, so this reads the most recent blocks with
// their transactions (as lib/send/node.ts does) and keeps those from or to the
// account, with their receipts. It is not the whole history: a payment older
// than the window is not listed.
import { rpcBatch, type FetchLike } from '../node/rpc';
import { hexQuantity } from '../vanish/node';
import type { ActivityItem, ActivityState } from './activity';

/** How many of the most recent blocks are read for the account's payments. */
export const HISTORY_WINDOW_BLOCKS = 2_000;

/** How many blocks one request asks for. */
const BLOCKS_PER_REQUEST = 50;

/** The account's payments in the blocks up to `tipHeight`, newest first, at most `limit`. */
export type ScanHistory = (nodeUrl: string, address: string, tipHeight: number, limit: number) => Promise<ActivityItem[]>;

type Found = { hash: string; from: string; to: string | null; value: bigint; at: number };

const HASH = /^0x[0-9a-f]{64}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const QUANTITY = /^0x[0-9a-f]+$/i;

function lower(value: unknown, pattern: RegExp): string | null {
  return typeof value === 'string' && pattern.test(value) ? value.toLowerCase() : null;
}

/** The transactions of `block` from or to `account`; any it cannot read are left out. */
function matches(block: unknown, account: string): Found[] {
  const raw = (block ?? {}) as Record<string, unknown>;
  const transactions = Array.isArray(raw.transactions) ? raw.transactions : [];
  const at = lower(raw.timestamp, QUANTITY) === null ? Date.now() : Number(BigInt(raw.timestamp as string)) * 1000;
  const found: Found[] = [];
  for (const entry of transactions) {
    const tx = (entry ?? {}) as Record<string, unknown>;
    const hash = lower(tx.hash, HASH);
    const from = lower(tx.from, ADDRESS);
    const to = lower(tx.to, ADDRESS);
    const value = lower(tx.value, QUANTITY);
    if (hash && from && value && (from === account || to === account)) {
      found.push({ hash, from, to, value: BigInt(value), at });
    }
  }
  return found;
}

/** Done only on a receipt that says success, failed on one that says failed, pending otherwise. */
function stateOf(receipt: unknown): ActivityState {
  const status = (receipt as { status?: unknown } | null | undefined)?.status;
  if (status === '0x1') {
    return 'done';
  }
  if (status === '0x0') {
    return 'failed';
  }
  return 'pending';
}

/**
 * The account's payments in the last `HISTORY_WINDOW_BLOCKS` blocks up to
 * `tipHeight`, newest first. Throws when a block cannot be read; a receipt it
 * cannot read leaves its payment pending.
 */
export async function scanHistory(
  nodeUrl: string,
  address: string,
  tipHeight: number,
  limit: number,
  fetchImpl?: FetchLike,
): Promise<ActivityItem[]> {
  const account = address.toLowerCase();
  const lowest = Math.max(0, tipHeight - HISTORY_WINDOW_BLOCKS + 1);
  const found: Found[] = [];
  // Newest blocks first, so a full list stops early.
  for (let high = tipHeight; high >= lowest && found.length < limit; high -= BLOCKS_PER_REQUEST) {
    const low = Math.max(lowest, high - BLOCKS_PER_REQUEST + 1);
    const heights = Array.from({ length: high - low + 1 }, (_, i) => high - i);
    const blocks = await rpcBatch(
      nodeUrl,
      heights.map((height): [string, unknown[]] => ['eth_getBlockByNumber', [hexQuantity(height), true]]),
      fetchImpl,
    );
    for (const block of blocks) {
      found.push(...matches(block, account).reverse());
    }
  }
  const kept = found.slice(0, limit);
  let receipts: unknown[] = [];
  if (kept.length > 0) {
    try {
      receipts = await rpcBatch(
        nodeUrl,
        kept.map((tx): [string, unknown[]] => ['eth_getTransactionReceipt', [tx.hash]]),
        fetchImpl,
      );
    } catch {
      // Without receipts nothing is known to be done: all stay pending.
      receipts = [];
    }
  }
  return kept.map((tx, i): ActivityItem => {
    const sent = tx.from === account;
    return {
      id: `tx-${tx.hash}`,
      direction: sent ? 'sent' : 'received',
      counterparty: sent ? tx.to : tx.from,
      amountWei: tx.value.toString(),
      state: stateOf(receipts[i]),
      at: tx.at,
      hash: tx.hash,
    };
  });
}
