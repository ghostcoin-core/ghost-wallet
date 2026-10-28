// The coin tree, rebuilt on the phone from public chain data. The local test
// chain serves only the `eth` namespace, so the phone reads every block from
// block 0: a successful Vanish (a transaction to the coin commit entry with
// 206 bytes of commit data) adds its leaf, and a successful reveal (a private
// transaction, type 0x50) spends its marker and adds its remainder leaf, in
// block and transaction order. The native core turns each into a leaf and
// looks keys up in the result.
//
// This finds keys whose coins this phone can see on the test chain, such as a
// key it just vanished into. Finding an old key's coins on a new phone is not
// done here; a key not in the tree is "not found yet", never zero.
import type { CoinLeaf, VanishBindings } from '../../modules/ghost-core';
import { bytesToHex, hexToBytes } from '../../modules/ghost-core/account-lookup';
import type { NodeReceipt, VanishNode } from './node';

export const PRIVATE_TX_TYPE = 0x50;
export const COMMIT_DATA_BYTES = 206;
const BLOCKS_PER_BATCH = 25;

export type CoinTree = {
  /** The last block read: the tree is as of its end. */
  height: number;
  hash: string;
  leaves: CoinLeaf[];
  /** Every spent marker, `0x` hex, in order. */
  spent: string[];
  /** Which transaction spent each marker. */
  spentBy: Record<string, string>;
};

export const EMPTY_TREE: CoinTree = { height: -1, hash: '', leaves: [], spent: [], spentBy: {} };

type TreeCore = Pick<VanishBindings, 'commitLeaf' | 'revealLeaf'>;

function buffer(hex: string): ArrayBuffer {
  const bytes = hexToBytes(hex);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/**
 * Reads blocks after `from` up to `tip` into the tree. Starts again from
 * block 0 when the block `from` ends at is no longer on the chain (a reorg).
 */
export async function extendCoinTree(
  core: TreeCore,
  node: VanishNode,
  commitEntry: string,
  from: CoinTree,
  tip: number,
): Promise<CoinTree> {
  let tree = from;
  if (tree.height >= 0) {
    const [still] = await node.blocks(tree.height, tree.height);
    if (still.block.hash !== tree.hash) {
      tree = EMPTY_TREE;
    }
  }
  const entry = commitEntry.toLowerCase();
  const leaves = [...tree.leaves];
  const spent = [...tree.spent];
  const spentBy = { ...tree.spentBy };
  let height = tree.height;
  let hash = tree.hash;
  for (let start = tree.height + 1; start <= tip; start += BLOCKS_PER_BATCH) {
    const end = Math.min(tip, start + BLOCKS_PER_BATCH - 1);
    for (const { block, receipts } of await node.blocks(start, end)) {
      const succeeded = new Map<string, NodeReceipt>(receipts.map((receipt) => [receipt.transactionHash, receipt]));
      for (const tx of block.transactions) {
        if (!succeeded.get(tx.hash)?.success) {
          continue;
        }
        if (tx.to === entry && (tx.input.length - 2) / 2 === COMMIT_DATA_BYTES) {
          leaves.push(core.commitLeaf(buffer(tx.input), tx.value.toString()));
        } else if (tx.type === PRIVATE_TX_TYPE) {
          const shown = core.revealLeaf(buffer(await node.rawTransaction(tx.hash)));
          const marker = bytesToHex(shown.marker);
          spent.push(marker);
          spentBy[marker] = tx.hash;
          leaves.push(shown.leaf);
        }
      }
      height = block.height;
      hash = block.hash;
    }
  }
  return { height, hash, leaves, spent, spentBy };
}

/** The trees read so far, one per node, kept while the app runs. */
const trees = new Map<string, CoinTree>();

/** The coin tree at `nodeUrl` up to `tip`, reading only blocks not read yet. */
export async function coinTreeAt(
  core: TreeCore,
  node: VanishNode,
  nodeUrl: string,
  commitEntry: string,
  tip: number,
): Promise<CoinTree> {
  const tree = await extendCoinTree(core, node, commitEntry, trees.get(nodeUrl) ?? EMPTY_TREE, tip);
  trees.set(nodeUrl, tree);
  return tree;
}

/** The spent markers as the core takes them. */
export function spentBuffers(tree: CoinTree): ArrayBuffer[] {
  return tree.spent.map(buffer);
}
