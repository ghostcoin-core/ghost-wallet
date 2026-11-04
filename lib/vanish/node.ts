// The node calls Vanish, Summon and Claim need, over the `eth` namespace the
// local test chain serves. The node's answers are its report: the core checks
// what it can (the proof, the leaves it rebuilds), and nothing here proves
// the rest.
import { fromNode, isRefusal, rpcBatch, SEND_TIMEOUT_MS, type FetchLike } from '../node/rpc';

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
/** The tree kind of the spent markers: pages of them are a hint, not checkable on their own. */
export const MARKER_KIND = 'coin-markers';
/**
 * A tree note as the node serves it: version 3, 380 bytes. A reveal's 156-byte
 * remainder note is served zero-padded to the same 380 bytes.
 */
export const NOTE_BYTES = 380;
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

/** The most markers a page of the marker tree holds: a page with fewer is its last. */
export const MARKER_PAGE_LEAVES = 4096;
/** The most marker pages read for one hint, so a node that never ends a list cannot hold it forever. */
const MAX_MARKER_PAGES = 4096;

/**
 * The markers of a `ghost_getTreePage` page of the marker tree, as the node
 * serves it: `{count, markers: [hash...]}`, `count` a hex quantity of at most
 * 4,096. Null when it is not laid out as one.
 */
export function parseMarkerPage(raw: unknown): string[] | null {
  const value = (raw ?? {}) as Record<string, unknown>;
  try {
    const count = smallNumber(value.count, 'marker count');
    if (count > MARKER_PAGE_LEAVES || !Array.isArray(value.markers) || value.markers.length !== count) {
      return null;
    }
    return value.markers.map((marker: unknown) => hash(marker, 'spent marker'));
  } catch {
    return null;
  }
}

/** The type byte of an account transaction (a send, a Vanish, a cancel). */
export const ACCOUNT_TX_TYPE = 0x52;
/** The type byte of a private transaction (a Summon or a Claim). */
export const PRIVATE_TX_TYPE = 0x50;

type RlpItem = Uint8Array | RlpItem[];

function rlpLength(bytes: Uint8Array, at: number, size: number): number {
  if (size > 6 || at + size > bytes.length) {
    throw new Error('the signed transaction does not read');
  }
  let length = 0;
  for (let i = 0; i < size; i++) {
    length = length * 256 + bytes[at + i];
  }
  return length;
}

/** One RLP item of `bytes` from `at`, and where it ends. */
function rlpItem(bytes: Uint8Array, at: number): { item: RlpItem; end: number } {
  if (at >= bytes.length) {
    throw new Error('the signed transaction does not read');
  }
  const first = bytes[at];
  let start: number;
  let length: number;
  let list: boolean;
  if (first < 0x80) {
    return { item: bytes.subarray(at, at + 1), end: at + 1 };
  } else if (first <= 0xb7) {
    [start, length, list] = [at + 1, first - 0x80, false];
  } else if (first <= 0xbf) {
    [start, length, list] = [at + 1 + (first - 0xb7), rlpLength(bytes, at + 1, first - 0xb7), false];
  } else if (first <= 0xf7) {
    [start, length, list] = [at + 1, first - 0xc0, true];
  } else {
    [start, length, list] = [at + 1 + (first - 0xf7), rlpLength(bytes, at + 1, first - 0xf7), true];
  }
  const end = start + length;
  if (end > bytes.length) {
    throw new Error('the signed transaction does not read');
  }
  if (!list) {
    return { item: bytes.subarray(start, end), end };
  }
  const items: RlpItem[] = [];
  for (let next = start; next < end; ) {
    const read = rlpItem(bytes, next);
    if (read.end > end) {
      throw new Error('the signed transaction does not read');
    }
    items.push(read.item);
    next = read.end;
  }
  return { item: items, end };
}

function bytesHex(bytes: Uint8Array): string {
  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

function rlpQuantity(item: RlpItem): bigint {
  if (!(item instanceof Uint8Array) || item.length > 32) {
    throw new Error('the signed transaction does not read');
  }
  return item.length === 0 ? 0n : BigInt(bytesHex(item));
}

function signedBytes(signed: string): Uint8Array {
  const hex = data(signed, 'signed transaction');
  const bytes = new Uint8Array((hex.length - 2) / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(2 + 2 * i, 4 + 2 * i), 16);
  }
  return bytes;
}

/**
 * What a signed account transaction (`0x52 || rlp([...])`) pays and does: the
 * fields of a type-2 transaction, in their order, as the node shows it. Throws
 * when the bytes are not one.
 */
export type AccountTxFields = {
  chainId: bigint;
  nonce: bigint;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  gas: bigint;
  to: string | null;
  value: bigint;
  data: string;
};

export function readAccountTx(signed: string): AccountTxFields {
  const bytes = signedBytes(signed);
  if (bytes[0] !== ACCOUNT_TX_TYPE) {
    throw new Error('the signed transaction is not an account transaction');
  }
  const { item, end } = rlpItem(bytes, 1);
  if (end !== bytes.length || !Array.isArray(item) || item.length < 8) {
    throw new Error('the signed transaction does not read');
  }
  const [chainId, nonce, priority, maxFee, gas, to, value, input] = item;
  if (!(to instanceof Uint8Array) || (to.length !== 0 && to.length !== 20) || !(input instanceof Uint8Array)) {
    throw new Error('the signed transaction does not read');
  }
  return {
    chainId: rlpQuantity(chainId),
    nonce: rlpQuantity(nonce),
    maxPriorityFeePerGas: rlpQuantity(priority),
    maxFeePerGas: rlpQuantity(maxFee),
    gas: rlpQuantity(gas),
    to: to.length === 0 ? null : bytesHex(to),
    value: rlpQuantity(value),
    data: bytesHex(input),
  };
}

/**
 * The `eth_estimateGas` call of a signed transaction: an account transaction
 * as the call it makes from `from` (its gas and fee caps included, so the
 * node checks the account can pay them), a private one as its type and payload.
 */
export function estimateCall(signed: string, from: string | null): Record<string, string> {
  const bytes = signedBytes(signed);
  if (bytes[0] === ACCOUNT_TX_TYPE) {
    if (!from || !/^0x[0-9a-f]{40}$/i.test(from)) {
      throw new Error('the sender of the signed transaction is not known');
    }
    const tx = readAccountTx(signed);
    const call: Record<string, string> = {
      from: from.toLowerCase(),
      gas: hexQuantity(tx.gas),
      maxFeePerGas: hexQuantity(tx.maxFeePerGas),
      maxPriorityFeePerGas: hexQuantity(tx.maxPriorityFeePerGas),
      value: hexQuantity(tx.value),
      input: tx.data,
      data: tx.data,
    };
    if (tx.to !== null) {
      call.to = tx.to;
    }
    return call;
  }
  if (bytes[0] === PRIVATE_TX_TYPE && bytes.length > 1) {
    const payload = bytesHex(bytes.subarray(1));
    return { type: hexQuantity(PRIVATE_TX_TYPE), input: payload, data: payload };
  }
  throw new Error('the signed transaction is of a type this app does not send');
}

/**
 * Why a payment was not sent: the node's check before sending refused it
 * (`refused`, its message the node's own reason), or the node could not be
 * asked. Either way nothing was sent.
 */
export type SendCheckError = Error & { notSent: true; refused: boolean };

export function sendCheckError(message: string, refused: boolean): SendCheckError {
  return Object.assign(new Error(message), { notSent: true as const, refused });
}

/** Whether `error` stopped a payment before it was sent (`checkSend`). */
export function stoppedBeforeSend(error: unknown): error is SendCheckError {
  return error instanceof Error && (error as Partial<SendCheckError>).notSent === true;
}

export type VanishNode = {
  /** The node's address: what notes and salts kept on this phone say they came from. */
  readonly url?: string;
  chainId(): Promise<bigint>;
  /** The tip's header: its height, hash and `coinTreeRoot`. */
  anchor(): Promise<NodeAnchor>;
  /** The page roots of coin tree `treeIndex` as of block `anchorHash`. */
  pageRoots(treeIndex: number, anchorHash: string): Promise<string[]>;
  /** Each set of pages (`ghost_getPageSet`), all in one batch. */
  pageSets(treeIndex: number, sets: number[][], anchorHash: string): Promise<NodePage[][]>;
  /** The buckets of `prefixes` (`ghost_getNoteBucket`), all in one batch. */
  noteBuckets(treeIndex: number, bits: number, prefixes: number[], anchorHash: string): Promise<NodeBucket[]>;
  /**
   * Every spent marker of tree `treeIndex` as of block `anchorHash`: its pages
   * (`ghost_getTreePage`) from 0 until one holds fewer than 4,096, so no
   * request names a marker. Unchecked: a hint only.
   */
  markerPages(treeIndex: number, anchorHash: string): Promise<string[]>;
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
  /**
   * Asks the node to run the signed transaction (`eth_estimateGas`) before it
   * is sent, `from` its sender (null for a Summon or Claim). Resolves when the
   * node would run it; throws a `SendCheckError` when it refuses (with its
   * reason) or cannot be asked. Every send goes through this first.
   */
  checkSend(bytes: string, from: string | null): Promise<void>;
  /** Sends a signed transaction, with the send time limit (`SEND_TIMEOUT_MS`), not a read's. */
  sendRaw(bytes: string): Promise<string>;
};

/** The node at `url`, through JSON-RPC batches. */
export function vanishNode(url: string, fetchImpl?: FetchLike): VanishNode {
  const call = (calls: [string, unknown[]][]) => rpcBatch(url, calls, fetchImpl);
  return {
    url,
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
    async markerPages(treeIndex, anchorHash) {
      // The marker list has no page roots (the node refuses `ghost_getPageRoots`
      // for it): its pages are read from 0 until one holds fewer than 4,096.
      const markers: string[] = [];
      for (let page = 0; page < MAX_MARKER_PAGES; page++) {
        const [answer] = await call([
          ['ghost_getTreePage', [MARKER_KIND, hexQuantity(treeIndex), hexQuantity(page), anchorHash]],
        ]);
        const onPage = parseMarkerPage(answer);
        if (onPage === null) {
          throw new Error('the node sent a malformed spent marker page');
        }
        markers.push(...onPage);
        if (onPage.length < MARKER_PAGE_LEAVES) {
          return markers;
        }
      }
      throw new Error('the node sent more spent marker pages than a hint reads');
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
    async checkSend(bytes, from) {
      let call: Record<string, string>;
      try {
        call = estimateCall(bytes, from);
      } catch (error) {
        throw fromNode(sendCheckError(`the node could not check it: ${(error as Error).message}`, false), url);
      }
      try {
        // A reveal is about 1.3 MB: its check gets the send time limit too.
        const [gas] = await rpcBatch(url, [['eth_estimateGas', [call, 'latest']]], fetchImpl, SEND_TIMEOUT_MS);
        quantity(gas, 'gas estimate');
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        // The node's refusal keeps its own words (`the node refused a call: …`).
        throw fromNode(
          isRefusal(error) ? sendCheckError(message, true) : sendCheckError(`the node could not check it: ${message}`, false),
          url,
        );
      }
    },
    async sendRaw(bytes) {
      try {
        // A reveal is about 1.3 MB: its upload gets the send time limit, not a read's.
        const [sent] = await rpcBatch(url, [['eth_sendRawTransaction', [bytes]]], fetchImpl, SEND_TIMEOUT_MS);
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
