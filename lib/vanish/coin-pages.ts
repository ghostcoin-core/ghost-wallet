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
// root changed: the new last page, or the pages a reorg rewrote. The roots
// cover only the leaves: the notes and salts kept with them are the word of the
// node that sent them, used again only with that node, and read again when a
// lookup on them finds nothing.
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

/**
 * What a node sent with a page's leaves: its notes and salts. No root covers
 * them, so they are kept as that node's word only (`source`), and never used
 * for a lookup on another node.
 */
export type PagePayload = { source: string; notes: string[]; salts: (string | null)[] };
/** A page kept on this phone: its leaves, checked against `root`, apart from the notes and salts of the node that sent them. */
export type SavedPage = { page: number; root: string; filled: number; leaves: string[]; payload: PagePayload };
/** The layout of the saved file: a file of any other layout is not read, and is written over. */
export const SAVED_PAGES_VERSION = 2;
export type SavedPages = { version: typeof SAVED_PAGES_VERSION; roots: string[]; pages: SavedPage[] };

export type PageCache = {
  load(): SavedPages | null;
  save(saved: SavedPages): void;
};

export type PageReadOptions = {
  /** The typed key, for its note buckets in a large tree; null for a card's key. */
  keyText?: string | null;
  /** Every leaf of the tree, as proving needs: no buckets. */
  complete?: boolean;
  /** Reads every page's notes and salts from the node again, whatever was kept. */
  freshNotes?: boolean;
};

/** Where a node's pages are said to come from: its address. */
function sourceOf(node: VanishNode): string {
  return node.url ?? '';
}

function buffer(hex: string): ArrayBuffer {
  const bytes = hexToBytes(hex);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

const HEX32 = /^0x[0-9a-f]{64}$/;
const HEX = /^0x([0-9a-f]{2})*$/;

const isHex32 = (value: unknown): value is string => typeof value === 'string' && HEX32.test(value);
const isHex = (value: unknown): value is string => typeof value === 'string' && HEX.test(value);

function readPayload(raw: unknown, filled: number): PagePayload | null {
  const payload = (raw ?? {}) as Record<string, unknown>;
  if (
    typeof payload.source !== 'string' ||
    !Array.isArray(payload.notes) ||
    !Array.isArray(payload.salts) ||
    payload.notes.length !== filled ||
    payload.salts.length !== filled ||
    !payload.notes.every(isHex) ||
    !payload.salts.every((salt) => salt === null || isHex(salt))
  ) {
    return null;
  }
  return { source: payload.source, notes: payload.notes, salts: payload.salts as (string | null)[] };
}

/**
 * What a saved file holds, or null when it is not saved pages of this layout:
 * a file of an older layout, which kept notes as if a root covered them, is
 * dropped whole.
 */
export function readSavedPages(raw: unknown): SavedPages | null {
  const value = (raw ?? {}) as Record<string, unknown>;
  if (value.version !== SAVED_PAGES_VERSION || !Array.isArray(value.roots) || !Array.isArray(value.pages)) {
    return null;
  }
  if (!value.roots.every(isHex32)) {
    return null;
  }
  const pages: SavedPage[] = [];
  for (const rawPage of value.pages) {
    const page = (rawPage ?? {}) as Record<string, unknown>;
    if (
      typeof page.page !== 'number' ||
      !isHex32(page.root) ||
      typeof page.filled !== 'number' ||
      !Array.isArray(page.leaves) ||
      page.leaves.length !== page.filled ||
      !page.leaves.every(isHex32)
    ) {
      return null;
    }
    const payload = readPayload(page.payload, page.filled);
    if (!payload) {
      return null;
    }
    pages.push({ page: page.page, root: page.root, filled: page.filled, leaves: page.leaves, payload });
  }
  return { version: SAVED_PAGES_VERSION, roots: value.roots, pages };
}

/** A checked page as kept: its leaves apart from what `source` sent with them. */
function savedPage(page: HeldPage): SavedPage {
  return {
    page: page.page,
    root: page.root,
    filled: page.filled,
    leaves: page.entries.map((entry) => entry.leaf),
    payload: { source: page.source, notes: page.entries.map((entry) => entry.note), salts: page.entries.map((entry) => entry.salt ?? null) },
  };
}

/** A kept page as a lookup reads it: each leaf with its node's note and salt. */
function heldPage(saved: SavedPage): HeldPage {
  const entries = saved.leaves.map((leaf, i): NodePageEntry => {
    const salt = saved.payload.salts[i];
    return salt === null ? { leaf, note: saved.payload.notes[i] } : { leaf, note: saved.payload.notes[i], salt };
  });
  return { page: saved.page, root: saved.root, filled: saved.filled, entries, source: saved.payload.source };
}

/** The tree at the tip; `reusedNotes` when some of its notes and salts were kept from an earlier read. */
export type CoinTreeRead = { tree: CoinTree; tip: number; reusedNotes?: boolean };

/** A page checked against `root` during a lookup, with the node it came from. */
type HeldPage = NodePage & { root: string; source: string };

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
): Promise<CoinTreeRead> {
  const anchor: NodeAnchor = await node.anchor();
  const roots = await ask(() => node.pageRoots(TREE_INDEX, anchor.hash));
  if (roots.length >= TREE_PAGES) {
    throw new Error(TREE_FULL_TEXT);
  }
  const pageCount = roots.length;
  const last = pageCount - 1;
  const rootBuffers = roots.map(buffer);
  const headerRoot = buffer(anchor.coinTreeRoot);

  const source = sourceOf(node);
  /** Pages already checked, still under the same root, with notes and salts this node sent. */
  const pages = new Map<number, HeldPage>();
  /**
   * Pages kept with another node's notes and salts (or set aside by
   * `freshNotes`): read again from this node before use, since no root
   * covers what came with the leaves, and kept as they were until then.
   */
  const others = new Map<number, SavedPage>();
  const saved = cache.load();
  for (const page of saved?.pages ?? []) {
    if (page.page < pageCount && roots[page.page] === page.root) {
      if (page.payload.source === source && !options.freshNotes) {
        pages.set(page.page, heldPage(page));
      } else {
        others.set(page.page, page);
      }
    }
  }
  /** Whether notes this node sent before are used again: then a key not found may be found in fresh ones. */
  const reusedNotes = pages.size > 0;
  let fetched = false;

  const check =(fresh: NodePage[]) => {
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
        pages.set(page.page, { ...page, root: roots[page.page], source });
        others.delete(page.page);
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

  // Pages whose root changed (the old last page, or pages a reorg rewrote) are
  // dropped; a page read again here keeps this node's notes and salts only.
  const keep = [...[...pages.values()].map(savedPage), ...others.values()].sort((a, b) => a.page - b.page);
  if (fetched || saved?.pages.length !== keep.length || saved?.roots.join() !== roots.join()) {
    cache.save({ version: SAVED_PAGES_VERSION, roots, pages: keep });
  }

  const held = range(pageCount).filter((page) => pages.has(page));
  const leaves = held.flatMap((page) => (pages.get(page) as HeldPage).entries.map(leafOf));
  return {
    tree: { height: anchor.height, hash: anchor.hash, leaves, spent: [], spentBy: {}, complete: held.length === pageCount },
    tip: anchor.height,
    reusedNotes,
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
): Promise<CoinTreeRead & { node: VanishNode }> {
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
