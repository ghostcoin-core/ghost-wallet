import { EMPTY_TREE, extendCoinTree } from '../../lib/vanish/coin-tree';
import type { NodeBlock, NodeReceipt, VanishNode } from '../../lib/vanish/node';
import { bytesToHex, hexToBytes } from '../../modules/ghost-core/account-lookup';

const ENTRY = '0x67686f7374000000000000000000000000000005';
const COMMIT = `0x0002${'11'.repeat(204)}`;
const hash = (n: number) => `0x${n.toString(16).padStart(64, '0')}`;

type Tx = { n: number; to?: string; input?: string; type?: number; value?: bigint; ok?: boolean };

function chain(blocks: Tx[][], salt = 0) {
  return blocks.map((txs, height) => ({
    block: {
      height,
      hash: hash(1000 * (salt + 1) + height),
      baseFeePerGas: 7n,
      transactions: txs.map((tx) => ({
        hash: hash(tx.n),
        type: tx.type ?? 0x52,
        to: tx.to ?? null,
        input: tx.input ?? '0x',
        value: tx.value ?? 0n,
      })),
    } satisfies NodeBlock,
    receipts: txs.map((tx) => ({
      transactionHash: hash(tx.n),
      success: tx.ok ?? true,
      blockHash: hash(1000 * (salt + 1) + height),
      blockHeight: height,
    })) satisfies NodeReceipt[],
  }));
}

function node(blocks: ReturnType<typeof chain>): VanishNode {
  return {
    blocks: async (from: number, to: number) => blocks.slice(from, to + 1),
    rawTransaction: async (txHash: string) => `0x50${txHash.slice(2)}`,
  } as unknown as VanishNode;
}

// The core turns a commit into a leaf named by its value, and a reveal into
// its marker and a remainder leaf named by the transaction.
const core = {
  commitLeaf: jest.fn((data: ArrayBuffer, amount: string) => ({
    commitment: hexToBytes(`0x${BigInt(amount).toString(16).padStart(2, '0')}`).buffer as ArrayBuffer,
    note: data,
  })),
  revealLeaf: jest.fn((envelope: ArrayBuffer) => ({
    marker: envelope.slice(1),
    leaf: { commitment: envelope.slice(32), note: new ArrayBuffer(0) },
  })),
};

const leafNames = (leaves: { commitment: ArrayBuffer }[]) => leaves.map((leaf) => bytesToHex(leaf.commitment));

describe('the coin tree, rebuilt from the chain', () => {
  it('adds each successful Vanish and reveal in block and transaction order', async () => {
    const blocks = chain([
      [{ n: 1, to: ENTRY, input: COMMIT, value: 5n }],
      [
        { n: 2, to: '0x00000000000000000000000000000000000000aa', value: 9n },
        { n: 3, type: 0x50 },
        { n: 4, to: ENTRY, input: COMMIT, value: 6n },
      ],
    ]);
    const tree = await extendCoinTree(core, node(blocks), ENTRY, EMPTY_TREE, 1);
    // The reveal's remainder (named by its transaction's last byte) sits between the two commits.
    expect(leafNames(tree.leaves)).toEqual(['0x05', '0x03', '0x06']);
    expect(tree.spent).toEqual([hash(3)]);
    expect(tree.spentBy[tree.spent[0]]).toBe(hash(3));
    expect(tree.height).toBe(1);
  });

  it('skips failed transactions and commit data of the wrong size', async () => {
    const blocks = chain([
      [
        { n: 1, to: ENTRY, input: COMMIT, value: 5n, ok: false },
        { n: 2, type: 0x50, ok: false },
        { n: 3, to: ENTRY, input: '0x0002', value: 6n },
        { n: 4, to: ENTRY, input: COMMIT, value: 7n },
      ],
    ]);
    const tree = await extendCoinTree(core, node(blocks), ENTRY, EMPTY_TREE, 0);
    expect(leafNames(tree.leaves)).toEqual(['0x07']);
    expect(tree.spent).toEqual([]);
  });

  it('reads only new blocks, and starts again from block 0 after a reorg', async () => {
    const first = chain([[{ n: 1, to: ENTRY, input: COMMIT, value: 5n }], []]);
    const tree = await extendCoinTree(core, node(first), ENTRY, EMPTY_TREE, 1);
    core.commitLeaf.mockClear();

    const grown = [...first, ...chain([[], [], [{ n: 2, to: ENTRY, input: COMMIT, value: 6n }]]).slice(2)];
    const more = await extendCoinTree(core, node(grown), ENTRY, tree, 2);
    expect(leafNames(more.leaves)).toEqual(['0x05', '0x06']);
    expect(core.commitLeaf).toHaveBeenCalledTimes(1);

    // Block 2 was replaced: the tree is read again from block 0.
    const reorged = chain([[{ n: 1, to: ENTRY, input: COMMIT, value: 5n }], [], [], []], 1);
    const after = await extendCoinTree(core, node(reorged), ENTRY, more, 3);
    expect(leafNames(after.leaves)).toEqual(['0x05']);
    expect(after.height).toBe(3);
  });
});
