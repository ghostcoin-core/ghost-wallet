// Finding a Phantom Key's coins from the node's coin tree pages, through the
// real JSON-RPC client (lib/vanish/node.ts) against a fake node that answers
// in the shapes of Ghost's node (internal/ethapi/ghosttree.go and
// ghostbuckets.go): every number a hex quantity, every call as of an anchor
// block hash. The native core's hashing is covered by core/tests/coin_tree_check.rs;
// here a fake core with the same signatures stands in for it.
import { createHash } from 'crypto';

import { lookUpKey, proveReveal } from '../../lib/vanish/actions';
import {
  MISMATCH_TEXT,
  NO_PAGES_TEXT,
  PAGE_SET,
  pageSetsFor,
  OTHER_CHAIN_TEXT,
  readCoinTree,
  readCoinTreeFrom,
  readSavedPages,
  type PageCache,
  type PagesCore,
  type SavedPages,
} from '../../lib/vanish/coin-pages';
import { vanishNode } from '../../lib/vanish/node';
import type { PaymentKit } from '../../lib/vanish/use-payment';
import { buildNetwork } from '../../lib/network/build-network';
import type { CoinLeaf, CoreCoinPage, VanishBindings } from '../../modules/ghost-core';
import { bytesToHex } from '../../modules/ghost-core/account-lookup';

const URL = 'http://node.test:8545';
const TIP = 1_000_000;
const PAGE = 4096;
const OURS = 'synthetic phantom key words for this test only';
/** The fake key's lookup tags: its numbers 0 to 15. */
const OUR_TAGS = Array.from({ length: 16 }, (_, number) => 0xa0b000 + number * 0x011111);

const hex32 = (n: number, salt = 0) => `0x${(salt * 0x1000000 + n).toString(16).padStart(64, '0')}`;
const sha = (parts: string[]) => `0x${createHash('sha256').update(parts.join('|')).digest('hex')}`;
const tagOf = (note: string) => parseInt(note.slice(2, 8), 16);
const noteWith = (tag: number, filler: string) => `0x${tag.toString(16).padStart(6, '0')}${filler.repeat(153)}`;

function bucketBits(n: number): number {
  return n < 2 * PAGE ? 0 : Math.min(24, Math.floor(Math.log2(n / PAGE)));
}

// --- The fake core: the page and tree "hash" is SHA-256 of the parts in order.

const pageRootOf = (leaves: string[]) => sha(leaves);
const treeRootOf = (roots: string[]) => sha(['tree', ...roots]);
const hexOf = (bytes: ArrayBuffer) => bytesToHex(new Uint8Array(bytes));

function fakeCore() {
  return {
    checkCoinPages: jest.fn((roots: ArrayBuffer[], pages: CoreCoinPage[], header: ArrayBuffer) => {
      const listed = roots.map(hexOf);
      if (treeRootOf(listed) !== hexOf(header)) {
        throw new Error('Mismatch: the page roots do not make the block root');
      }
      for (const page of pages) {
        if (pageRootOf(page.leaves.map(hexOf)) !== listed[page.page]) {
          throw new Error('Mismatch: a page does not make its root');
        }
      }
    }),
    noteBucketBits: jest.fn((n: bigint) => bucketBits(Number(n))),
    keyNoteBuckets: jest.fn((key: string, n: bigint) => {
      expect(key).toBe(OURS);
      const bits = bucketBits(Number(n));
      return { bits, prefixes: [...new Set(OUR_TAGS.map((tag) => tag >> (24 - bits)))] };
    }),
    keyBucketPositions: jest.fn((key: string, notes: { position: number; note: ArrayBuffer }[]) =>
      key === OURS ? notes.filter((n) => OUR_TAGS.includes(tagOf(hexOf(n.note)))).map((n) => n.position).sort((a, b) => a - b) : [],
    ),
  } satisfies PagesCore;
}

/** The fake core's lookup: the key's coin is a leaf whose note carries one of its tags. */
function found(leaves: CoinLeaf[]) {
  return leaves.some((leaf) => OUR_TAGS.includes(tagOf(hexOf(leaf.note)))) ? 'found' : 'not-found';
}

// --- The fake node.

type Entry = { leaf: string; note: string; salt?: string };

function treeOf(count: number, ours: number[] = []): Entry[] {
  return Array.from({ length: count }, (_, i) => ({
    leaf: hex32(i + 1),
    // Other notes' tags never collide with the key's.
    note: ours.includes(i) ? noteWith(OUR_TAGS[ours.indexOf(i)], '11') : noteWith((i * 7919) % 0x900000, '22'),
    ...(i % 3 === 0 ? {} : { salt: `0x${'33'.repeat(16)}` }),
  }));
}

type Call = { method: string; params: unknown[] };

function fakeNode(
  initial: Entry[],
  options: { tamperPage?: number; wrongRoot?: boolean; noGhost?: boolean; markers?: string[]; chainId?: bigint; down?: boolean } = {},
) {
  let entries = initial;
  const requests: Call[][] = [];
  const anchorHash = hex32(TIP, 7);
  const q = (n: number) => `0x${n.toString(16)}`;
  const pageCount = () => Math.ceil(entries.length / PAGE);
  const pageEntries = (page: number) => entries.slice(page * PAGE, (page + 1) * PAGE);
  const roots = () => Array.from({ length: pageCount() }, (_, p) => pageRootOf(pageEntries(p).map((e) => e.leaf)));

  function answer({ method, params }: Call): { result?: unknown; error?: { code: number; message: string } } {
    const refuse = (message: string) => ({ error: { code: -32602, message } });
    if (method.startsWith('ghost_')) {
      if (options.noGhost) {
        return { error: { code: -32601, message: `the method ${method} does not exist/is not available` } };
      }
      if (params[0] === 'coin-markers') {
        // The marker tree's shape: pages of 32-byte markers, with no salt and no note.
        const markers = options.markers ?? [];
        const markerPages = Math.ceil(markers.length / PAGE);
        if (params[1] !== '0x0' || params[params.length - 1] !== anchorHash) {
          return refuse('unexpected tree or anchor');
        }
        if (method === 'ghost_getPageRoots') {
          return { result: Array.from({ length: markerPages }, (_, p) => pageRootOf(markers.slice(p * PAGE, (p + 1) * PAGE))) };
        }
        if (method === 'ghost_getTreePage') {
          const page = parseInt(params[2] as string, 16);
          const onPage = markers.slice(page * PAGE, (page + 1) * PAGE);
          return { result: { kind: 'coin-markers', treeIndex: '0x0', page: q(page), filled: q(onPage.length), entries: onPage.map((leaf) => ({ leaf })) } };
        }
        return refuse('the marker tree serves pages and page roots only');
      }
      if (params[0] !== 'coin' || params[1] !== '0x0' || params[params.length - 1] !== anchorHash) {
        return refuse('unexpected tree or anchor');
      }
    }
    switch (method) {
      case 'eth_chainId':
        return { result: q(Number(options.chainId ?? buildNetwork.chainId)) };
      case 'eth_getBlockByNumber': {
        const height = params[0] === 'latest' ? TIP : parseInt(params[0] as string, 16);
        const coinTreeRoot = options.wrongRoot ? hex32(1, 9) : treeRootOf(roots());
        return { result: { number: q(height), hash: height === TIP ? anchorHash : hex32(height, 3), baseFeePerGas: '0x7', coinTreeRoot, transactions: [] } };
      }
      case 'ghost_getPageRoots':
        return { result: roots() };
      case 'ghost_getPageSet': {
        const pages = (params[2] as string[]).map((page) => parseInt(page, 16));
        const count = pageCount();
        const every = count <= PAGE_SET;
        const ascending = pages.every((page, i) => i === 0 || page > pages[i - 1]);
        if (every ? pages.length !== count || !ascending : pages.length !== PAGE_SET || !ascending || pages.some((p) => p >= count)) {
          return refuse('a page set is every page of a small tree, or 8 distinct ascending pages');
        }
        return {
          result: pages.map((page) => ({
            kind: 'coin',
            treeIndex: '0x0',
            page: q(page),
            filled: q(pageEntries(page).length),
            entries: pageEntries(page).map((entry, i) =>
              page === options.tamperPage && i === 5 ? { ...entry, leaf: hex32(99_999) } : entry,
            ),
          })),
        };
      }
      case 'ghost_getNoteBucket': {
        const bits = parseInt(params[2] as string, 16);
        const prefix = parseInt(params[3] as string, 16);
        if (bits !== bucketBits(entries.length) || prefix >= 2 ** bits) {
          return refuse('wrong bucket bits or prefix');
        }
        const inBucket = entries
          .map((entry, position) => ({ ...entry, position: q(position) }))
          .filter((entry) => tagOf(entry.note) >> (24 - bits) === prefix);
        return { result: { kind: 'coin', treeIndex: '0x0', bits: q(bits), prefix: q(prefix), count: q(inBucket.length), entries: inBucket } };
      }
      default:
        return refuse(`the fake node does not serve ${method}`);
    }
  }

  const fetchImpl = jest.fn(async (_url: string, init: RequestInit) => {
    const calls = JSON.parse(init.body as string) as (Call & { id: number })[];
    requests.push(calls.map(({ method, params }) => ({ method, params })));
    if (options.down) {
      throw new Error('Network request failed');
    }
    return { ok: true, status: 200, json: async () => calls.map((call) => ({ jsonrpc: '2.0', id: call.id, ...answer(call) })) } as Response;
  });

  return {
    node: vanishNode(URL, fetchImpl),
    requests,
    methods: () => requests.flat().map((call) => call.method),
    grow(more: Entry[]) {
      entries = [...entries, ...more];
    },
    bodies: () => JSON.stringify(requests),
  };
}

function memoryCache(): PageCache & { saved: SavedPages | null; saves: number } {
  const cache = {
    saved: null as SavedPages | null,
    saves: 0,
    load: () => cache.saved,
    save(saved: SavedPages) {
      cache.saved = saved;
      cache.saves += 1;
    },
  };
  return cache;
}

function noBlockScan(methods: string[]) {
  expect(methods).not.toContain('eth_getBlockReceipts');
  expect(methods).not.toContain('eth_getRawTransactionByHash');
}

describe("finding a key's coins from the node's coin tree pages", () => {
  it('finds a coin among 10,000 leaves on a chain of 1,000,000 blocks in at most 4 round trips, with no block read', async () => {
    const leaves = treeOf(10_000, [9_500]);
    const fake = fakeNode(leaves);
    const core = fakeCore();
    const { tree, tip } = await readCoinTree(core, fake.node, memoryCache(), { keyText: OURS });

    expect(found(tree.leaves)).toBe('found');
    expect(tip).toBe(TIP);
    expect(tree.height).toBe(TIP);
    expect(fake.requests.length).toBeLessThanOrEqual(4);
    noBlockScan(fake.methods());
    // Only the anchor's header: never a block by its height.
    expect(fake.requests.flat().filter((call) => call.method === 'eth_getBlockByNumber')).toEqual([
      { method: 'eth_getBlockByNumber', params: ['latest', false] },
    ]);
    // Above 8,192 notes: the key's buckets (one batch), then the pages.
    expect(fake.methods()).toContain('ghost_getNoteBucket');
    // Three pages hold 8,193 to 12,288 notes: one bucket bit whatever the last page holds.
    expect(core.keyNoteBuckets.mock.results[0].value.bits).toBe(1);
    expect(fake.requests.flat().filter((call) => call.method === 'ghost_getNoteBucket').length).toBe(1);
    // The leaves come in position order, with their notes and salts.
    expect(tree.leaves).toHaveLength(10_000);
    expect(hexOf(tree.leaves[9_500].commitment)).toBe(leaves[9_500].leaf);
    expect(tree.leaves[0].salt).toBeUndefined();
    expect(hexOf(tree.leaves[1].salt as ArrayBuffer)).toBe(leaves[1].salt);
    expect(tree.complete).toBe(true);
    // Every page fetched was checked against the header's root.
    expect(core.checkCoinPages).toHaveBeenCalled();
    // No request names the key's coin, its leaf or its position.
    expect(fake.bodies()).not.toContain(leaves[9_500].leaf);
    expect(fake.bodies()).not.toContain(leaves[9_500].note);
    expect(fake.bodies()).not.toContain('0x251c');
  });

  it('makes at most 2 round trips for a second lookup on an unchanged chain', async () => {
    const fake = fakeNode(treeOf(10_000, [9_500]));
    const cache = memoryCache();
    await readCoinTree(fakeCore(), fake.node, cache, { keyText: OURS });
    fake.requests.length = 0;

    const core = fakeCore();
    const { tree } = await readCoinTree(core, fake.node, cache, { keyText: OURS });
    expect(found(tree.leaves)).toBe('found');
    expect(fake.requests.length).toBeLessThanOrEqual(2);
    expect(fake.methods()).toEqual(['eth_getBlockByNumber', 'ghost_getPageRoots']);
    // The roots are still checked against this header.
    expect(core.checkCoinPages).toHaveBeenCalledTimes(1);
  });

  it('keeps full pages and reads only the page whose root changed', async () => {
    const fake = fakeNode(treeOf(10_000, [9_500]));
    const cache = memoryCache();
    await readCoinTree(fakeCore(), fake.node, cache, { complete: true });
    fake.grow(treeOf(10_003).slice(10_000));
    fake.requests.length = 0;

    const core = fakeCore();
    const { tree } = await readCoinTree(core, fake.node, cache, { complete: true });
    expect(tree.leaves).toHaveLength(10_003);
    expect(fake.requests.length).toBe(3);
    // Only the new last page was checked; the kept full pages stay as they were.
    const checked = core.checkCoinPages.mock.calls.flatMap(([, pages]) => pages.map((page) => page.page));
    expect(checked).toEqual([2]);
    expect(cache.saved?.pages.map((page) => page.filled)).toEqual([PAGE, PAGE, 10_003 - 2 * PAGE]);
  });

  it('reads the whole tree as pages below 8,192 notes, with no bucket', async () => {
    const fake = fakeNode(treeOf(5_000, [4_200]));
    const core = fakeCore();
    const { tree } = await readCoinTree(core, fake.node, memoryCache(), { keyText: OURS });
    expect(found(tree.leaves)).toBe('found');
    expect(fake.methods()).not.toContain('ghost_getNoteBucket');
    expect(core.keyNoteBuckets).not.toHaveBeenCalled();
    expect(fake.requests.flat().find((call) => call.method === 'ghost_getPageSet')?.params[2]).toEqual(['0x0', '0x1']);
    expect(fake.requests.length).toBeLessThanOrEqual(3);
  });

  it('asks a large tree for 8 pages, the wanted one among decoys, never a single page', async () => {
    const fake = fakeNode(treeOf(40_000, [33_000]));
    const cache = memoryCache();
    const { tree } = await readCoinTree(fakeCore(), fake.node, cache, { keyText: OURS });
    expect(found(tree.leaves)).toBe('found');
    expect(tree.complete).toBe(false);
    const sets = fake.requests.flat().filter((call) => call.method === 'ghost_getPageSet');
    expect(sets).toHaveLength(1);
    const pages = (sets[0].params[2] as string[]).map((page) => parseInt(page, 16));
    expect(new Set(pages).size).toBe(PAGE_SET);
    expect(pages).toContain(Math.floor(33_000 / PAGE));
    expect([...pages].sort((a, b) => a - b)).toEqual(pages);
    expect(fake.requests.length).toBeLessThanOrEqual(4);

    // A proof needs every leaf: the rest is read in sets of 8, the kept pages not again.
    fake.requests.length = 0;
    const whole = await readCoinTree(fakeCore(), fake.node, cache, { keyText: OURS, complete: true });
    expect(whole.tree.leaves).toHaveLength(40_000);
    expect(whole.tree.complete).toBe(true);
    for (const call of fake.requests.flat().filter((c) => c.method === 'ghost_getPageSet')) {
      expect(call.params[2]).toHaveLength(PAGE_SET);
    }
  });

  it('reads every page when the buckets find nothing', async () => {
    const fake = fakeNode(treeOf(40_000));
    const { tree } = await readCoinTree(fakeCore(), fake.node, memoryCache(), { keyText: OURS });
    expect(found(tree.leaves)).toBe('not-found');
    expect(tree.complete).toBe(true);
    expect(fake.methods()).toContain('ghost_getNoteBucket');
  });

  it("reads a card key's tree (no lookup tags in JavaScript) as every page", async () => {
    const fake = fakeNode(treeOf(10_000, [9_500]));
    const { tree } = await readCoinTree(fakeCore(), fake.node, memoryCache(), { keyText: null });
    expect(tree.leaves).toHaveLength(10_000);
    expect(fake.methods()).not.toContain('ghost_getNoteBucket');
  });

  it("refuses a page whose leaves do not match its root, and keeps none of the node's data", async () => {
    const leaves = treeOf(10_000, [9_500]);
    const cache = memoryCache();
    const bad = fakeNode(leaves, { tamperPage: 2 });
    await expect(readCoinTree(fakeCore(), bad.node, cache, { keyText: OURS })).rejects.toThrow(MISMATCH_TEXT);
    expect(cache.saves).toBe(0);
    noBlockScan(bad.methods());

    // The next node's honest pages are found as usual.
    const good = fakeNode(leaves);
    const { tree } = await readCoinTree(fakeCore(), good.node, cache, { keyText: OURS });
    expect(found(tree.leaves)).toBe('found');
  });

  it("refuses page roots that do not match the header's coinTreeRoot", async () => {
    const cache = memoryCache();
    const fake = fakeNode(treeOf(5_000, [10]), { wrongRoot: true });
    await expect(readCoinTree(fakeCore(), fake.node, cache, {})).rejects.toThrow(MISMATCH_TEXT);
    expect(cache.saves).toBe(0);
  });

  it('refuses kept pages when the header no longer matches their roots', async () => {
    const cache = memoryCache();
    await readCoinTree(fakeCore(), fakeNode(treeOf(5_000, [10])).node, cache, {});
    const moved = fakeNode(treeOf(5_000, [10]), { wrongRoot: true });
    await expect(readCoinTree(fakeCore(), moved.node, cache, {})).rejects.toThrow(MISMATCH_TEXT);
  });

  it('says plainly when the node does not serve tree pages, and never reads blocks instead', async () => {
    const fake = fakeNode(treeOf(100), { noGhost: true });
    await expect(readCoinTree(fakeCore(), fake.node, memoryCache(), { keyText: OURS })).rejects.toThrow(NO_PAGES_TEXT);
    expect(NO_PAGES_TEXT).not.toMatch(/0x/);
    expect(MISMATCH_TEXT).not.toMatch(/0x/);
    noBlockScan(fake.methods());
  });

  it('refuses a page the node laid out wrong', async () => {
    // Page 0 of two pages must be full.
    const fake = fakeNode(treeOf(5_000));
    const node = { ...fake.node, pageSets: async () => [[{ page: 0, filled: 99, entries: treeOf(99) }]] };
    await expect(readCoinTree(fakeCore(), node, memoryCache(), {})).rejects.toThrow(/malformed/);
  });
});

describe('trying the next node when one is refused', () => {
  const CHAIN = buildNetwork.chainId;

  it('reads the next node when a page does not match its root, and keeps only what checked out', async () => {
    const leaves = treeOf(10_000, [9_500]);
    const cache = memoryCache();
    const bad = fakeNode(leaves, { tamperPage: 2 });
    const good = fakeNode(leaves);
    const { tree, node } = await readCoinTreeFrom(fakeCore(), [bad.node, good.node], cache, CHAIN, { keyText: OURS });
    expect(node).toBe(good.node);
    expect(found(tree.leaves)).toBe('found');
    expect(cache.saves).toBe(1);
    // The kept pages are the good node's.
    expect(cache.saved?.pages.find((page) => page.page === 2)?.entries[5].leaf).toBe(leaves[2 * PAGE + 5].leaf);
    // The next node was asked its chain before its pages were used.
    expect(good.methods()[0]).toBe('eth_chainId');
    noBlockScan([...bad.methods(), ...good.methods()]);
  });

  it("reads the next node when the page roots do not match the header's coinTreeRoot", async () => {
    const cache = memoryCache();
    const bad = fakeNode(treeOf(5_000, [10]), { wrongRoot: true });
    const good = fakeNode(treeOf(5_000, [10]));
    const { node } = await readCoinTreeFrom(fakeCore(), [bad.node, good.node], cache, CHAIN, {});
    expect(node).toBe(good.node);
    expect(cache.saves).toBe(1);
  });

  it('reads the next node when one does not serve pages or does not answer', async () => {
    const leaves = treeOf(5_000, [10]);
    const none = fakeNode(leaves, { noGhost: true });
    const down = fakeNode(leaves, { down: true });
    const good = fakeNode(leaves);
    const { node } = await readCoinTreeFrom(fakeCore(), [none.node, down.node, good.node], memoryCache(), CHAIN, {});
    expect(node).toBe(good.node);
  });

  it('never uses a next node on another chain, and says why the first node was refused', async () => {
    const leaves = treeOf(5_000, [10]);
    const cache = memoryCache();
    const bad = fakeNode(leaves, { tamperPage: 0 });
    const elsewhere = fakeNode(leaves, { chainId: CHAIN + 1n });
    await expect(readCoinTreeFrom(fakeCore(), [bad.node, elsewhere.node], cache, CHAIN, {})).rejects.toThrow(MISMATCH_TEXT);
    expect(elsewhere.methods()).toEqual(['eth_chainId']);
    expect(cache.saves).toBe(0);
    expect(OTHER_CHAIN_TEXT).not.toMatch(/0x/);
  });

  it("does not ask the next node when the first one's pages check out", async () => {
    const leaves = treeOf(5_000, [10]);
    const first = fakeNode(leaves);
    const next = fakeNode(leaves);
    const { node } = await readCoinTreeFrom(fakeCore(), [first.node, next.node], memoryCache(), CHAIN, {});
    expect(node).toBe(first.node);
    expect(next.requests).toHaveLength(0);
  });
});

describe('page sets and kept pages', () => {
  it('asks a small tree for every page and a large one for 8 distinct ascending pages', () => {
    expect(pageSetsFor([1], 3)).toEqual([[0, 1, 2]]);
    expect(pageSetsFor([], 3)).toEqual([]);
    const [set] = pageSetsFor([40], 100, () => 0.999);
    expect(set).toHaveLength(8);
    expect(set).toContain(40);
    expect(new Set(set).size).toBe(8);
    expect([...set].sort((a, b) => a - b)).toEqual(set);
    expect(pageSetsFor([0, 1, 2, 3, 4, 5, 6, 7, 8], 20, () => 0)).toEqual([
      [0, 1, 2, 3, 4, 5, 6, 7],
      [0, 1, 2, 3, 4, 5, 6, 8],
    ]);
  });

  it('reads back what it saved and nothing else', () => {
    const saved: SavedPages = {
      roots: [hex32(1)],
      pages: [{ page: 0, root: hex32(1), filled: 1, entries: [{ leaf: hex32(2), note: noteWith(1, '00') }] }],
    };
    expect(readSavedPages(JSON.parse(JSON.stringify(saved)))).toEqual(saved);
    expect(readSavedPages(null)).toBeNull();
    expect(readSavedPages({ roots: ['nope'], pages: [] })).toBeNull();
    expect(readSavedPages({ roots: [], pages: [{ page: 0, root: hex32(1), filled: 2, entries: [] }] })).toBeNull();
  });
});

describe('Summon and Claim on the pages', () => {
  /** The fake key's coin's spent marker, as the core would derive it. */
  const OUR_MARKER = hex32(4242, 5);

  function kit(fake: ReturnType<typeof fakeNode>, fallbackNodes: ReturnType<typeof fakeNode>[] = []) {
    const core = {
      ...fakeCore(),
      findKeyCoins: jest.fn((_key: string, _chain: bigint, leaves: CoinLeaf[], spent: ArrayBuffer[]) => ({
        status: spent.map(hexOf).includes(OUR_MARKER) ? 'spent' : found(leaves),
        amountWei: '9',
      })),
      proveKeyReveal: jest.fn((_key: string, _request: unknown, leaves: CoinLeaf[]) => ({
        transactionHash: new ArrayBuffer(32),
        marker: new Uint8Array(32).fill(1).buffer,
        envelope: new ArrayBuffer(4),
        feeWei: '1',
        outWei: '8',
        remainderWei: '0',
        proveMillis: BigInt(leaves.length),
      })),
      feeWindow: (tip: bigint) => ({ referenceHeight: tip - 1n, validUntil: tip + 3n }),
      revealFeeWei: () => '1',
    };
    return {
      core,
      kit: {
        core: core as unknown as VanishBindings,
        node: fake.node,
        nodeUrl: URL,
        store: {} as never,
        pages: memoryCache(),
        fallbackNodes: fallbackNodes.map((other) => other.node),
      } satisfies PaymentKit,
    };
  }

  it('looks a key up from the next node when the first one is refused', async () => {
    const leaves = treeOf(10_000, [9_500]);
    const bad = fakeNode(leaves, { tamperPage: 2 });
    const good = fakeNode(leaves);
    const { kit: tools } = kit(bad, [good]);
    const lookup = await lookUpKey(tools, OURS);
    expect(lookup.status).toBe('found');
    expect(good.methods()).toContain('ghost_getPageSet');

    // A proof's tree comes from the next node too.
    await proveReveal(tools, OURS, `0x${'55'.repeat(20)}`, null);
    expect(good.methods().filter((method) => method === 'ghost_getPageRoots').length).toBeGreaterThanOrEqual(2);
  });

  it('hints in the background, unchecked, that the coins were spent, never naming the marker or holding the lookup', async () => {
    const other = Array.from({ length: 5 }, (_, i) => hex32(i + 1, 6));
    const fake = fakeNode(treeOf(5_000, [10]), { markers: [...other, OUR_MARKER] });
    const { kit: tools } = kit(fake);
    const lookup = await lookUpKey(tools, OURS);
    // The lookup itself never waits on the markers: Summon stays open.
    expect(lookup.status).toBe('found');
    expect(lookup.spentHint).toBeDefined();
    const hint = await lookup.spentHint;
    expect(hint).toEqual({ checked: false, spent: true });
    expect(lookup.tree.spent).toEqual([...other, OUR_MARKER]);
    expect(lookup.tree.spentBy).toEqual({});
    // Every marker page is read; no request names the key's marker.
    const pageReads = fake.requests.flat().filter((call) => call.method === 'ghost_getTreePage');
    expect(pageReads.map((call) => call.params.slice(0, 3))).toEqual([['coin-markers', '0x0', '0x0']]);
    expect(fake.bodies()).not.toContain(OUR_MARKER);
  });

  it('hints unspent when the markers do not hold the coin, and no hint when they cannot be read', async () => {
    const fake = fakeNode(treeOf(5_000, [10]), { markers: [hex32(1, 6)] });
    const lookup = await lookUpKey(kit(fake).kit, OURS);
    await expect(lookup.spentHint).resolves.toEqual({ checked: false, spent: false });

    const broken = fakeNode(treeOf(5_000, [10]));
    const tools = kit(broken).kit;
    const failing = { ...tools, node: { ...broken.node, markerPages: async () => Promise.reject(new Error('down')) } };
    const without = await lookUpKey(failing, OURS);
    expect(without.status).toBe('found');
    await expect(without.spentHint).resolves.toEqual({ checked: false, spent: null });
    expect(without.tree.spent).toEqual([]);
  });

  it('looks a typed key up with no block scan, and proves over every leaf of the tree', async () => {
    const fake = fakeNode(treeOf(40_000, [33_000]));
    const { kit: tools, core } = kit(fake);
    const lookup = await lookUpKey(tools, OURS);
    expect(lookup.status).toBe('found');
    expect(lookup.tip).toBe(TIP);
    noBlockScan(fake.methods());

    await proveReveal(tools, OURS, `0x${'55'.repeat(20)}`, null);
    expect(core.proveKeyReveal.mock.calls[0][2]).toHaveLength(40_000);
    noBlockScan(fake.methods());
    // Blocks read by height are only the fee reference and block 0 (the proof's domain).
    const heights = fake.requests
      .flat()
      .filter((call) => call.method === 'eth_getBlockByNumber' && call.params[0] !== 'latest')
      .map((call) => call.params[0]);
    expect(new Set(heights)).toEqual(new Set([`0x${(TIP - 1).toString(16)}`, '0x0']));
  });

  it('reads every page when the buckets name pages with no unspent coin', async () => {
    const fake = fakeNode(treeOf(40_000, [33_000]));
    const { kit: tools, core } = kit(fake);
    core.findKeyCoins.mockImplementationOnce(() => ({ status: 'spent', amountWei: '0' }));
    const lookup = await lookUpKey(tools, OURS);
    expect(lookup.status).toBe('found');
    expect(core.findKeyCoins.mock.calls[1][2]).toHaveLength(40_000);
  });
});
