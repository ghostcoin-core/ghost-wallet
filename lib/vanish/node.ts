// The node calls Vanish, Summon and Claim need, over the `eth` namespace the
// local test chain serves. The node's answers are its report: the core checks
// what it can (the proof, the leaves it rebuilds), and nothing here proves
// the rest.
import { rpcBatch, type FetchLike } from '../node/rpc';

export type NodeBlock = {
  height: number;
  hash: string;
  baseFeePerGas: bigint;
  transactions: NodeTransaction[];
};

export type NodeTransaction = {
  hash: string;
  type: number;
  to: string | null;
  input: string;
  value: bigint;
};

export type NodeReceipt = {
  transactionHash: string;
  success: boolean;
  blockHash: string;
  blockHeight: number;
};

function quantity(value: unknown, what: string): bigint {
  if (typeof value !== 'string' || !/^0x[0-9a-f]+$/i.test(value)) {
    throw new Error(`the node sent a malformed ${what}`);
  }
  return BigInt(value);
}

function hash(value: unknown, what: string): string {
  if (typeof value !== 'string' || !/^0x[0-9a-f]{64}$/i.test(value)) {
    throw new Error(`the node sent a malformed ${what}`);
  }
  return value.toLowerCase();
}

function data(value: unknown, what: string): string {
  if (typeof value !== 'string' || !/^0x([0-9a-f]{2})*$/i.test(value)) {
    throw new Error(`the node sent malformed ${what}`);
  }
  return value.toLowerCase();
}

export function hexQuantity(value: number | bigint): string {
  return `0x${value.toString(16)}`;
}

export function parseBlock(raw: unknown): NodeBlock {
  const block = (raw ?? {}) as Record<string, unknown>;
  const transactions = Array.isArray(block.transactions) ? block.transactions : [];
  return {
    height: Number(quantity(block.number, 'block height')),
    hash: hash(block.hash, 'block hash'),
    baseFeePerGas: block.baseFeePerGas === undefined ? 0n : quantity(block.baseFeePerGas, 'base fee'),
    transactions: transactions.map((entry: unknown) => {
      const tx = (entry ?? {}) as Record<string, unknown>;
      return {
        hash: hash(tx.hash, 'transaction hash'),
        type: tx.type === undefined ? 0 : Number(quantity(tx.type, 'transaction type')),
        to: typeof tx.to === 'string' ? tx.to.toLowerCase() : null,
        input: tx.input === undefined ? '0x' : data(tx.input, 'transaction data'),
        value: tx.value === undefined ? 0n : quantity(tx.value, 'transaction value'),
      };
    }),
  };
}

export function parseReceipt(raw: unknown): NodeReceipt | null {
  if (raw === null || raw === undefined) {
    return null;
  }
  const receipt = raw as Record<string, unknown>;
  return {
    transactionHash: hash(receipt.transactionHash, 'transaction hash'),
    success: quantity(receipt.status, 'receipt status') === 1n,
    blockHash: hash(receipt.blockHash, 'block hash'),
    blockHeight: Number(quantity(receipt.blockNumber, 'block height')),
  };
}

/** The block the coin tree is read as of: the tip when it was asked. */
export type NodeAnchor = { height: number; hash: string; coinTreeRoot: string };

/** One leaf of a tree page: its commitment, its note, and its salt when the chain shows it. */
export type NodePageEntry = { leaf: string; note: string; salt?: string };

/** A page of the coin tree: `filled` leaves from position `4096 × page` on. */
export type NodePage = { page: number; filled: number; entries: NodePageEntry[] };

export type NodeBucketEntry = NodePageEntry & { position: number };

/** The notes whose lookup tag starts with `prefix` (its first `bits` bits). */
export type NodeBucket = { bits: number; prefix: number; entries: NodeBucketEntry[] };

/** The tree kind of the coin tree, as `ghost_` calls name it. */
export const COIN_KIND = 'coin';
const NOTE_BYTES = 156;
const SALT_BYTES = 16;

function sized(value: unknown, bytes: number, what: string): string {
  const hex = data(value, what);
  if (hex.length !== 2 + 2 * bytes) {
    throw new Error(`the node sent malformed ${what}`);
  }
  return hex;
}

function smallNumber(value: unknown, what: string): number {
  const number = quantity(value, what);
  if (number > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`the node sent a malformed ${what}`);
  }
  return Number(number);
}

function parseEntry(raw: unknown): NodePageEntry {
  const entry = (raw ?? {}) as Record<string, unknown>;
  const parsed: NodePageEntry = {
    leaf: hash(entry.leaf, 'coin tree leaf'),
    note: sized(entry.note, NOTE_BYTES, 'coin note'),
  };
  if (entry.salt !== undefined && entry.salt !== null && entry.salt !== '0x') {
    parsed.salt = sized(entry.salt, SALT_BYTES, 'coin salt');
  }
  return parsed;
}

function checkTree(raw: Record<string, unknown>, treeIndex: number) {
  if (raw.kind !== COIN_KIND || smallNumber(raw.treeIndex, 'tree index') !== treeIndex) {
    throw new Error('the node sent a malformed coin tree page');
  }
}

/** A page of `ghost_getPageSet`, checked to be the page asked for and laid out as one. */
export function parsePage(raw: unknown, treeIndex: number, page: number): NodePage {
  const value = (raw ?? {}) as Record<string, unknown>;
  checkTree(value, treeIndex);
  const filled = smallNumber(value.filled, 'page fill');
  if (smallNumber(value.page, 'page number') !== page || !Array.isArray(value.entries) || value.entries.length !== filled) {
    throw new Error('the node sent a malformed coin tree page');
  }
  return { page, filled, entries: value.entries.map(parseEntry) };
}

/** A bucket of `ghost_getNoteBucket`, checked to be the bucket asked for. */
export function parseBucket(raw: unknown, treeIndex: number, bits: number, prefix: number): NodeBucket {
  const value = (raw ?? {}) as Record<string, unknown>;
  checkTree(value, treeIndex);
  if (
    smallNumber(value.bits, 'bucket size') !== bits ||
    smallNumber(value.prefix, 'bucket prefix') !== prefix ||
    !Array.isArray(value.entries)
  ) {
    throw new Error('the node sent a malformed note bucket');
  }
  return {
    bits,
    prefix,
    entries: value.entries.map((raw: unknown) => ({
      ...parseEntry(raw),
      position: smallNumber((raw as Record<string, unknown> | null)?.position, 'note position'),
    })),
  };
}

export type VanishNode = {
  chainId(): Promise<bigint>;
  /** The tip's header: its height, hash and `coinTreeRoot`. */
  anchor(): Promise<NodeAnchor>;
  /** The page roots of coin tree `treeIndex` as of block `anchorHash`. */
  pageRoots(treeIndex: number, anchorHash: string): Promise<string[]>;
  /** Each set of pages (`ghost_getPageSet`), all in one batch. */
  pageSets(treeIndex: number, sets: number[][], anchorHash: string): Promise<NodePage[][]>;
  /** The buckets of `prefixes` (`ghost_getNoteBucket`), all in one batch. */
  noteBuckets(treeIndex: number, bits: number, prefixes: number[], anchorHash: string): Promise<NodeBucket[]>;
  tipHeight(): Promise<number>;
  /** Blocks `from` to `to`, with their transactions, and every receipt of them. */
  blocks(from: number, to: number): Promise<{ block: NodeBlock; receipts: NodeReceipt[] }[]>;
  /** Block `height`'s header: its height, hash and base fee, with no transactions. */
  block(height: number): Promise<NodeBlock>;
  receipts(hashes: string[]): Promise<(NodeReceipt | null)[]>;
  /** Whether the node holds each transaction, in a block or not. */
  known(hashes: string[]): Promise<boolean[]>;
  rawTransaction(hash: string): Promise<string>;
  nonce(address: string): Promise<bigint>;
  maxPriorityFeePerGas(): Promise<bigint>;
  sendRaw(bytes: string): Promise<string>;
};

/** The node at `url`, through JSON-RPC batches. */
export function vanishNode(url: string, fetchImpl?: FetchLike): VanishNode {
  const call = (calls: [string, unknown[]][]) => rpcBatch(url, calls, fetchImpl);
  return {
    async chainId() {
      const [id] = await call([['eth_chainId', []]]);
      return quantity(id, 'chain id');
    },
    async tipHeight() {
      const [height] = await call([['eth_blockNumber', []]]);
      return Number(quantity(height, 'block height'));
    },
    async anchor() {
      const [raw] = await call([['eth_getBlockByNumber', ['latest', false]]]);
      const block = (raw ?? {}) as Record<string, unknown>;
      return {
        height: Number(quantity(block.number, 'block height')),
        hash: hash(block.hash, 'block hash'),
        coinTreeRoot: hash(block.coinTreeRoot, 'coin tree root'),
      };
    },
    async pageRoots(treeIndex, anchorHash) {
      const [roots] = await call([['ghost_getPageRoots', [COIN_KIND, hexQuantity(treeIndex), anchorHash]]]);
      if (!Array.isArray(roots)) {
        throw new Error('the node sent malformed coin page roots');
      }
      return roots.map((root: unknown) => hash(root, 'coin page root'));
    },
    async pageSets(treeIndex, sets, anchorHash) {
      if (sets.length === 0) {
        return [];
      }
      const answers = await call(
        sets.map((pages): [string, unknown[]] => [
          'ghost_getPageSet',
          [COIN_KIND, hexQuantity(treeIndex), pages.map(hexQuantity), anchorHash],
        ]),
      );
      return answers.map((answer, i) => {
        if (!Array.isArray(answer) || answer.length !== sets[i].length) {
          throw new Error('the node sent a malformed coin tree page');
        }
        return answer.map((page: unknown, j) => parsePage(page, treeIndex, sets[i][j]));
      });
    },
    async noteBuckets(treeIndex, bits, prefixes, anchorHash) {
      if (prefixes.length === 0) {
        return [];
      }
      const answers = await call(
        prefixes.map((prefix): [string, unknown[]] => [
          'ghost_getNoteBucket',
          [COIN_KIND, hexQuantity(treeIndex), hexQuantity(bits), hexQuantity(prefix), anchorHash],
        ]),
      );
      return answers.map((answer, i) => parseBucket(answer, treeIndex, bits, prefixes[i]));
    },
    async blocks(from, to) {
      const heights = Array.from({ length: Math.max(0, to - from + 1) }, (_, i) => hexQuantity(from + i));
      const answers = await call(
        heights.flatMap((height): [string, unknown[]][] => [
          ['eth_getBlockByNumber', [height, true]],
          ['eth_getBlockReceipts', [height]],
        ]),
      );
      return heights.map((_, i) => ({
        block: parseBlock(answers[2 * i]),
        receipts: (Array.isArray(answers[2 * i + 1]) ? (answers[2 * i + 1] as unknown[]) : [])
          .map(parseReceipt)
          .filter((receipt): receipt is NodeReceipt => receipt !== null),
      }));
    },
    async block(height) {
      const [block] = await call([['eth_getBlockByNumber', [hexQuantity(height), false]]]);
      // Asked without its transactions, the node lists only their hashes:
      // the header is read, and the block holds no transactions here.
      return parseBlock({ ...((block ?? {}) as Record<string, unknown>), transactions: [] });
    },
    async receipts(hashes) {
      if (hashes.length === 0) {
        return [];
      }
      const answers = await call(hashes.map((h): [string, unknown[]] => ['eth_getTransactionReceipt', [h]]));
      return answers.map(parseReceipt);
    },
    async known(hashes) {
      if (hashes.length === 0) {
        return [];
      }
      const answers = await call(hashes.map((h): [string, unknown[]] => ['eth_getTransactionByHash', [h]]));
      return answers.map((answer) => answer !== null && answer !== undefined);
    },
    async rawTransaction(txHash) {
      const [raw] = await call([['eth_getRawTransactionByHash', [txHash]]]);
      return data(raw, 'raw transaction');
    },
    async nonce(address) {
      const [count] = await call([['eth_getTransactionCount', [address, 'pending']]]);
      return quantity(count, 'transaction count');
    },
    async maxPriorityFeePerGas() {
      try {
        const [tip] = await call([['eth_maxPriorityFeePerGas', []]]);
        return quantity(tip, 'priority fee');
      } catch {
        return 1_000_000_000n;
      }
    },
    async sendRaw(bytes) {
      try {
        const [sent] = await call([['eth_sendRawTransaction', [bytes]]]);
        return hash(sent, 'transaction hash');
      } catch (error) {
        // Sending the same bytes again is what recovery does: not an error.
        if (error instanceof Error && /already known/i.test(error.message)) {
          return '';
        }
        throw error;
      }
    },
  };
}
