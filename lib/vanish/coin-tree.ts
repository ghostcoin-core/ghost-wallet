// The coin tree as a Summon or Claim uses it: the leaves the node's checked
// pages hold (lib/vanish/coin-pages.ts), as of one block. No block is read to
// make it.
import type { CoinLeaf } from '../../modules/ghost-core';
import { hexToBytes } from '../../modules/ghost-core/account-lookup';

export type CoinTree = {
  /** The anchor block: the tree is as of its end. */
  height: number;
  hash: string;
  /**
   * The leaves in position order: every leaf of the tree, or, for a lookup in
   * a large tree, the leaves of the checked pages holding the key's notes.
   */
  leaves: CoinLeaf[];
  /** Spent markers, `0x` hex: a hint only, and often empty. */
  spent: string[];
  /** Which transaction spent each marker: pages cannot tell, so it stays empty. */
  spentBy: Record<string, string>;
  /** False when `leaves` are only some pages of the tree: enough to find a key, not to prove. */
  complete?: boolean;
};

function buffer(hex: string): ArrayBuffer {
  const bytes = hexToBytes(hex);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/** The spent markers as the core takes them. */
export function spentBuffers(tree: CoinTree): ArrayBuffer[] {
  return tree.spent.map(buffer);
}
