// Finds a Phantom Key's coins from the node's coin tree pages (Ghost spec 05,
// section 8, "Wallet tree data"), never by reading blocks: the cost grows with
// the number of coins, one page per 4,096 of them, not with the chain.
//
// One lookup: the tip's header (its `coinTreeRoot`), the page-root list as of
// that block, then the pages. A tree of up to 8,191 notes is read whole, every
// page in one page set. A larger one first reads the note buckets of the
// typed key's 16 lookup tags (one batch, each prefix once), then the pages
// holding the notes found, as a set of 8 pages (the wanted ones and decoys,
// or every page of a tree of 8 pages or fewer). A bucket is a hint: a coin
// counts only from a page checked against the header, and when the buckets
// find nothing or disagree with the pages, every page is read.
//
// The native core checks every page against its root and the page roots
// against the header's `coinTreeRoot`; any mismatch ends the lookup and the
// node's data is dropped, never kept and never patched. Checked pages are kept
// on this phone by chain and tree, so a later lookup reads only pages whose
// root changed: the new last page, or the pages a reorg rewrote.
//
// A node whose data is refused is dropped and the read starts again at the
// next node the build lists (`readCoinTreeFrom`).
//
// Spent markers are read after a lookup, in the background, from every marker
// page: a hint shown as unchecked, never waited on. A coin already spent is
// refused by the node when it is summoned.
//
// No request names a coin, a leaf, a position or a marker.
import type { CoinLeaf, CoreCoinPage, VanishBindings } from '../../modules/ghost-core';
import { hexToBytes } from '../../modules/ghost-core/account-lookup';
import { jsonFile } from '../storage';
import type { CoinTree } from './coin-tree';
import type { NodeAnchor, NodeBucketEntry, NodePage, NodePageEntry, VanishNode } from './node';

export const PAGE_LEAVES = 4096;
/** Pages in one page set of a tree of more than 8 pages. */
export const PAGE_SET = 8;
/** Only the first coin tree is read. */
export const TREE_INDEX = 0;
const TREE_PAGES = 2 ** 20;
/** Page sets sent in one batch when many pages are read. */
const SETS_PER_BATCH = 4;

export const NO_PAGES_TEXT = 'the node does not serve coin tree pages, so the coins cannot be looked up there';
export const MISMATCH_TEXT = "the node's coin tree pages do not match its latest block, so they were not used";
export const TREE_FULL_TEXT = 'the first coin tree is full, and this app reads only that one';
const MALFORMED_TEXT = 'the node sent a malformed coin tree page';

export type PagesCore = Pick<VanishBindings, 'checkCoinPages' | 'noteBucketBits' | 'keyNoteBuckets' | 'keyBucketPositions'>;

/** A page checked against `root`, as kept on this phone. */
export type SavedPage = { page: number; root: string; filled: number; entries: NodePageEntry[] };
export type SavedPages = { roots: string[]; pages: SavedPage[] };

export type PageCache = {
  load(): SavedPages | null;
  save(saved: SavedPages): void;
};

export type PageReadOptions = {
  /** The typed key, for its note buckets in a large tree; null for a card's key. */
  keyText?: string | null;
  /** Every leaf of the tree, as proving needs: no buckets. */
  complete?: boolean;
};

function buffer(hex: string): ArrayBuffer {
  const bytes = hexToBytes(hex);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

const HEX32 = /^0x[0-9a-f]{64}$/;
const HEX = /^0x([0-9a-f]{2})*$/;

function readEntry(raw: unknown): NodePageEntry | null {
  const entry = (raw ?? {}) as Record<string, unknown>;
  if (typeof entry.leaf !== 'string' || !HEX32.test(entry.leaf) || typeof entry.note !== 'string' || !HEX.test(entry.note)) {
    return null;
  }
  if (entry.salt === undefined) {
    return { leaf: entry.leaf, note: entry.note };
  }
  return typeof entry.salt === 'string' && HEX.test(entry.salt) ? { leaf: entry.leaf, note: entry.note, salt: entry.salt } : null;
}

/** What a saved file holds, or null when it is not saved pages. */
export function readSavedPages(raw: unknown): SavedPages | null {
  const value = (raw ?? {}) as Record<string, unknown>;
  if (!Array.isArray(value.roots) || !Array.isArray(value.pages)) {
    return null;
  }
  const roots = value.roots.filter((root): root is string => typeof root === 'string' && HEX32.test(root));
  if (roots.length !== value.roots.length) {
    return null;
  }
  const pages: SavedPage[] = [];
  for (const rawPage of value.pages) {
    const page = (rawPage ?? {}) as Record<string, unknown>;
    if (
      typeof page.page !== 'number' ||
      typeof page.root !== 'string' ||
      typeof page.filled !== 'number' ||
      !Array.isArray(page.entries) ||
      page.entries.length !== page.filled
    ) {
      return null;
    }
    const entries = page.entries.map(readEntry);
    if (entries.some((entry) => entry === null)) {
      return null;
    }
    pages.push({ page: page.page, root: page.root, filled: page.filled, entries: entries as NodePageEntry[] });
  }
  return { roots, pages };
}

const kept = new Map<string, SavedPages>();

/** The checked pages of coin tree `treeIndex` on chain `chainId`: in memory, and in a file in Documents. */
export function devicePageCache(chainId: bigint, treeIndex: number = TREE_INDEX): PageCache {
  const name = `coin-pages-${chainId.toString()}-${treeIndex}.json`;
  const file = jsonFile(name);
  return {
    load() {
      const inMemory = kept.get(name);
      if (inMemory) {
        return inMemory;
      }
      const read = readSavedPages(file.read());
      if (read) {
        kept.set(name, read);
      }
      return read;
    },
    save(saved) {
      kept.set(name, saved);
      // The pages are public; a failed write only means reading them again.
      file.write(saved).catch(() => undefined);
    },
  };
}

/** Asks the node a `ghost_` call: a node that does not serve them says so in plain words. */
async function ask<T>(question: () => Promise<T>): Promise<T> {
  try {
    return await question();
  } catch (error) {
    if (error instanceof Error && /does not exist|not available|method not found/i.test(error.message)) {
      throw new Error(NO_PAGES_TEXT);
    }
    throw error;
  }
}

function range(count: number): number[] {
  return Array.from({ length: count }, (_, i) => i);
}

/**
 * The page sets that read `wanted`: every page when the tree has 8 pages or
 * fewer, otherwise sets of exactly 8 distinct pages in ascending order, the
 * wanted ones filled up with decoys drawn at random.
 */
export function pageSetsFor(wanted: number[], pageCount: number, random: () => number = Math.random): number[][] {
  if (wanted.length === 0) {
    return [];
  }
  if (pageCount <= PAGE_SET) {
    return [range(pageCount)];
  }
  const sorted = [...new Set(wanted)].sort((a, b) => a - b);
  const sets: number[][] = [];
  for (let start = 0; start < sorted.length; start += PAGE_SET) {
    const set = sorted.slice(start, start + PAGE_SET);
    const others = range(pageCount).filter((page) => !set.includes(page));
    while (set.length < PAGE_SET) {
      const pick = Math.min(others.length - 1, Math.floor(random() * others.length));
      set.push(others.splice(pick, 1)[0]);
    }
    sets.push(set.sort((a, b) => a - b));
  }
  return sets;
}

function leafOf(entry: NodePageEntry): CoinLeaf {
  const leaf: CoinLeaf = { commitment: buffer(entry.leaf), note: buffer(entry.note) };
  if (entry.salt !== undefined) {
    leaf.salt = buffer(entry.salt);
  }
  return leaf;
}

/**
 * The coin tree at the node's tip, from its pages, checked against the tip's
 * header. With `keyText` in a large tree, only the pages holding that key's
 * notes may be read (`complete` false in the result).
 */
export async function readCoinTree(
  core: PagesCore,
  node: VanishNode,
  cache: PageCache,
  options: PageReadOptions = {},
): Promise<{ tree: CoinTree; tip: number }> {
  const anchor: NodeAnchor = await node.anchor();
  const roots = await ask(() => node.pageRoots(TREE_INDEX, anchor.hash));
  if (roots.length >= TREE_PAGES) {
    throw new Error(TREE_FULL_TEXT);
  }
  const pageCount = roots.length;
  const last = pageCount - 1;
  const rootBuffers = roots.map(buffer);
  const headerRoot = buffer(anchor.coinTreeRoot);

  /** Pages already checked, still under the same root. */
  const pages = new Map<number, SavedPage>();
  const saved = cache.load();
  for (const page of saved?.pages ?? []) {
    if (page.page < pageCount && roots[page.page] === page.root) {
      pages.set(page.page, page);
    }
  }
  let fetched = false;

  const check = (fresh: NodePage[]) => {
    const checked: CoreCoinPage[] = fresh.map((page) => ({ page: page.page, leaves: page.entries.map((entry) => buffer(entry.leaf)) }));
    try {
      core.checkCoinPages(rootBuffers, checked, headerRoot);
    } catch {
      throw new Error(MISMATCH_TEXT);
    }
  };

  /** Reads and checks the page sets holding `wanted`; only checked pages are kept. */
  const read = async (wanted: number[]) => {
    const sets = pageSetsFor(wanted, pageCount);
    for (let start = 0; start < sets.length; start += SETS_PER_BATCH) {
      const batch = sets.slice(start, start + SETS_PER_BATCH);
      const answered = await ask(() => node.pageSets(TREE_INDEX, batch, anchor.hash));
      const fresh = answered.flat().filter((page) => !pages.has(page.page));
      for (const page of fresh) {
        const full = page.page < last;
        if (page.page > last || (full ? page.filled !== PAGE_LEAVES : page.filled < 1 || page.filled > PAGE_LEAVES)) {
          throw new Error(MALFORMED_TEXT);
        }
      }
      check(fresh);
      for (const page of fresh) {
        pages.set(page.page, { ...page, root: roots[page.page] });
      }
      fetched = fetched || fresh.length > 0;
    }
  };

  const readAll = () => read(range(pageCount).filter((page) => !pages.has(page)));

  /** The notes in the tree, from the last page; null when it is not read yet. */
  const noteCount = () => {
    const lastPage = pages.get(last);
    return lastPage ? last * PAGE_LEAVES + lastPage.filled : null;
  };

  /** The bucket bits of the tree, reading its last page when the page count alone cannot tell. */
  const bucketBits = async (): Promise<number> => {
    const known = noteCount();
    if (known !== null) {
      return core.noteBucketBits(BigInt(known));
    }
    const fewest = core.noteBucketBits(BigInt(last * PAGE_LEAVES + 1));
    const most = core.noteBucketBits(BigInt(pageCount * PAGE_LEAVES));
    if (fewest === most) {
      return fewest;
    }
    if (pageCount <= PAGE_SET) {
      // One page set is the whole tree anyway.
      return 0;
    }
    await read([last]);
    return core.noteBucketBits(BigInt(noteCount() ?? 0));
  };

  /** Reads the pages of the key's notes the buckets name; false when they cannot be relied on. */
  const viaBuckets = async (keyText: string): Promise<boolean> => {
    const count = noteCount() ?? pageCount * PAGE_LEAVES;
    const query = core.keyNoteBuckets(keyText, BigInt(noteCount() ?? last * PAGE_LEAVES + 1));
    if (query.bits === 0) {
      return false;
    }
    const buckets = await ask(() => node.noteBuckets(TREE_INDEX, query.bits, query.prefixes, anchor.hash));
    const hinted = new Map<number, NodeBucketEntry>();
    for (const entry of buckets.flatMap((bucket) => bucket.entries)) {
      hinted.set(entry.position, entry);
    }
    const positions = core.keyBucketPositions(
      keyText,
      [...hinted.values()].map((entry) => ({ position: entry.position, note: buffer(entry.note) })),
    );
    if (positions.length === 0 || positions.some((position) => position >= count)) {
      return false;
    }
    await read([...new Set(positions.map((position) => Math.floor(position / PAGE_LEAVES)))].filter((page) => !pages.has(page)));
    return positions.every((position) => {
      const entry = pages.get(Math.floor(position / PAGE_LEAVES))?.entries[position % PAGE_LEAVES];
      const hint = hinted.get(position);
      return entry !== undefined && hint !== undefined && entry.leaf === hint.leaf && entry.note === hint.note;
    });
  };

  if (range(pageCount).some((page) => !pages.has(page))) {
    const keyText = options.keyText ?? null;
    const bits = keyText !== null && !options.complete ? await bucketBits() : 0;
    if (bits === 0 || keyText === null || !(await viaBuckets(keyText))) {
      await readAll();
    }
  }
  if (!fetched) {
    // Every page was kept from before: the page roots are still checked against this header.
    check([]);
  }

  // Pages whose root changed (the old last page, or pages a reorg rewrote) are dropped.
  if (fetched || saved?.pages.length !== pages.size || saved?.roots.join() !== roots.join()) {
    cache.save({ roots, pages: [...pages.values()].sort((a, b) => a.page - b.page) });
  }

  const held = range(pageCount).filter((page) => pages.has(page));
  const leaves = held.flatMap((page) => (pages.get(page) as SavedPage).entries.map(leafOf));
  return {
    tree: { height: anchor.height, hash: anchor.hash, leaves, spent: [], spentBy: {}, complete: held.length === pageCount },
    tip: anchor.height,
  };
}

export const OTHER_CHAIN_TEXT = 'the node is not on the same Ghost network';

/**
 * The coin tree from the first of `nodes` whose pages check out. A node whose
 * data is refused (a mismatch, a malformed reply, no `ghost_` calls) or that
 * does not answer is dropped, and the whole read starts again at the next
 * node, from the pages this phone checked before: nothing of the refused
 * node's data is kept. A node after the first must report `chainId`. When no
 * node answers, the first node's error says why.
 */
export async function readCoinTreeFrom(
  core: PagesCore,
  nodes: readonly VanishNode[],
  cache: PageCache,
  chainId: bigint,
  options: PageReadOptions = {},
): Promise<{ tree: CoinTree; tip: number; node: VanishNode }> {
  let first: unknown = null;
  for (const [i, node] of nodes.entries()) {
    try {
      if (i > 0 && (await node.chainId()) !== chainId) {
        throw new Error(OTHER_CHAIN_TEXT);
      }
      return { ...(await readCoinTree(core, node, cache, options)), node };
    } catch (error) {
      first = first ?? error;
    }
  }
  throw first ?? new Error(NO_PAGES_TEXT);
}

/** What the spent markers say of a key's coins: never checked, so never a reason to block a Summon. */
export type SpentHint = {
  checked: false;
  /** True when the markers show the coins spent, false when not, null when they could not be read. */
  spent: boolean | null;
};

/**
 * The spent markers of the coin tree as of block `anchorHash`, read whole
 * from the marker pages: a hint, with no root to check it against. A failure
 * gives no markers. The key's own marker is never asked about.
 */
export async function readSpentMarkers(node: VanishNode, anchorHash: string): Promise<string[] | null> {
  try {
    return await node.markerPages(TREE_INDEX, anchorHash);
  } catch {
    return null;
  }
}
