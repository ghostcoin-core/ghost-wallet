// Where a Ghost card's coin stands on chain, read by this phone from Ghost
// nodes (never a Ghost server): whether a Vanish with exactly the card's
// commit data added its leaf to the coin tree, whether that leaf is buried
// under enough blocks, and whether its marker is spent. The coin tree pages
// are checked against the block headers the nodes send, as every Summon's
// are; the spent markers are a hint (lib/vanish/coin-pages.ts).
import { bytesToHex } from '../../modules/ghost-core/account-lookup';
import type { CoinLeaf } from '../../modules/ghost-core';
import { devicePageCache, readCoinTreeFrom, readSpentMarkers } from '../vanish/coin-pages';
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

/** The coin with leaf `commitment` and marker `marker`, on the chain of `kit`. Throws when no node answers. */
export async function coinOnChain(
  kit: PaymentKit,
  chainId: bigint,
  commitment: Uint8Array,
  marker: Uint8Array,
): Promise<CoinOnChain> {
  const nodes = [kit.node, ...(kit.fallbackNodes ?? [])];
  const cache = kit.pages ?? devicePageCache(chainId);
  const wanted = bytesToHex(commitment);
  const atTip = await readCoinTreeFrom(kit.core, nodes, cache, chainId, { complete: true });
  const leaf = atTip.tree.leaves.find((l) => same(l, wanted)) ?? null;
  const markers = await readSpentMarkers(atTip.node, atTip.tree.hash);
  const spent = markers === null ? null : markers.map((m) => m.toLowerCase()).includes(bytesToHex(marker));
  if (!leaf) {
    return { status: 'absent', spent, leaf: null };
  }
  const deep = atTip.tip - (SETTLE_CONFIRMATIONS - 1);
  if (deep < 0) {
    return { status: 'settling', spent, leaf };
  }
  const buried = await readCoinTreeFrom(kit.core, nodes, cache, chainId, { complete: true, atHeight: deep });
  return { status: buried.tree.leaves.some((l) => same(l, wanted)) ? 'buried' : 'settling', spent, leaf };
}
