// Where a Ghost card's coin stands on chain, read by this phone from Ghost
// nodes (never a Ghost server): whether a Vanish with exactly the card's
// commit data added its leaf to the coin tree, whether that leaf is buried
// under enough blocks, and whether its marker is spent. The coin tree pages
// are checked against the block headers each node sends, as every Summon's
// are, and every node the build lists must agree. The headers themselves are
// not yet checked against the phone's own header chain.
import { bytesToHex } from '../../modules/ghost-core/account-lookup';
import type { CoinLeaf } from '../../modules/ghost-core';
import { devicePageCache, readCoinTree, readSpentMarkers, type PageCache } from '../vanish/coin-pages';
import type { VanishNode } from '../vanish/node';
import { SETTLE_CONFIRMATIONS } from '../vanish/status-mapping';
import type { PaymentKit } from '../vanish/use-payment';

export type CoinOnChain = {
  /** buried: in the tree `SETTLE_CONFIRMATIONS` blocks deep; settling: only at the tip; absent: not in the tree. */
  status: 'buried' | 'settling' | 'absent';
  /** Whether the marker is among the spent ones; null when they could not be read. */
  spent: boolean | null;
  /** The coin's leaf as the checked pages hold it. */
  leaf: CoinLeaf | null;
};

const same = (leaf: CoinLeaf, commitment: string) => bytesToHex(leaf.commitment) === commitment;

/** What one node says of the coin, its pages checked against its own headers. */
async function fromNode(
  kit: PaymentKit,
  node: VanishNode,
  cache: PageCache,
  chainId: bigint,
  wanted: string,
  marker: string,
): Promise<CoinOnChain> {
  if ((await node.chainId()) !== chainId) {
    throw new Error('the node is not on the same Ghost network');
  }
  const atTip = await readCoinTree(kit.core, node, cache, { complete: true });
  const leaf = atTip.tree.leaves.find((l) => same(l, wanted)) ?? null;
  const markers = await readSpentMarkers(node, atTip.tree.hash);
  const spent = markers === null ? null : markers.map((m) => m.toLowerCase()).includes(marker);
  if (!leaf) {
    return { status: 'absent', spent, leaf: null };
  }
  const deep = atTip.tip - (SETTLE_CONFIRMATIONS - 1);
  if (deep < 0) {
    return { status: 'settling', spent, leaf };
  }
  const buried = await readCoinTree(kit.core, node, cache, { complete: true, atHeight: deep });
  return { status: buried.tree.leaves.some((l) => same(l, wanted)) ? 'buried' : 'settling', spent, leaf };
}

export const NODES_DISAGREE_TEXT = "the build's nodes disagree about this coin";

/**
 * The coin with leaf `commitment` and marker `marker`, as every node this
 * build lists says it is: each node's pages are checked against that node's
 * own headers, and every node that answers must say the same, or the call
 * fails. Throws when no node answers.
 */
export async function coinOnChain(
  kit: PaymentKit,
  chainId: bigint,
  commitment: Uint8Array,
  marker: Uint8Array,
): Promise<CoinOnChain> {
  const nodes = [kit.node, ...(kit.fallbackNodes ?? [])];
  const cache = kit.pages ?? devicePageCache(chainId);
  const wanted = bytesToHex(commitment);
  const markerHex = bytesToHex(marker);
  const answers: CoinOnChain[] = [];
  let first: unknown = null;
  for (const node of nodes) {
    try {
      answers.push(await fromNode(kit, node, cache, chainId, wanted, markerHex));
    } catch (error) {
      first = first ?? error;
    }
  }
  if (answers.length === 0) {
    throw first ?? new Error('no node answered');
  }
  const [one, ...rest] = answers;
  if (rest.some((a) => a.status !== one.status || a.spent !== one.spent || !sameLeaf(a.leaf, one.leaf))) {
    throw new Error(NODES_DISAGREE_TEXT);
  }
  return one;
}

function sameLeaf(a: CoinLeaf | null, b: CoinLeaf | null): boolean {
  if (a === null || b === null) {
    return a === b;
  }
  return (
    bytesToHex(a.commitment) === bytesToHex(b.commitment) &&
    bytesToHex(a.note) === bytesToHex(b.note) &&
    (a.salt ? bytesToHex(a.salt) : null) === (b.salt ? bytesToHex(b.salt) : null)
  );
}
