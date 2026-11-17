// A Ghost card's coin on chain (lib/ghost-card/chain.ts): every node the
// build lists is asked, each one's pages checked against its own headers, and
// they must agree.
import { coinOnChain, NODES_DISAGREE_TEXT } from '../../lib/ghost-card/chain';
import type { PaymentKit } from '../../lib/vanish/use-payment';

type Tree = { leaves: string[]; tip: number; markers: string[] | null };
const mockTrees = new Map<string, { atTip: Tree; old: string[] }>();

jest.mock('../../lib/vanish/coin-pages', () => ({
  devicePageCache: () => ({ load: () => null, save: () => {} }),
  readCoinTree: async (_core: unknown, node: { url: string }, _cache: unknown, options: { atHeight?: number }) => {
    const t = mockTrees.get(node.url);
    if (!t) {
      throw new Error('down');
    }
    const leaves = options.atHeight === undefined ? t.atTip.leaves : t.old;
    const hex = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16))).buffer;
    return {
      tree: { hash: '0xab', height: t.atTip.tip, leaves: leaves.map((c) => ({ commitment: hex(c), note: hex('00'), salt: hex('11') })), spent: [], spentBy: {} },
      tip: t.atTip.tip,
    };
  },
  readSpentMarkers: async (node: { url: string }) => mockTrees.get(node.url)?.atTip.markers ?? null,
}));

const C = 'c0'.repeat(32);
const M = 'e0'.repeat(32);
const node = (url: string, chainId = 1n) => ({ url, chainId: async () => chainId });
const kit = (...urls: string[]) =>
  ({ core: {}, node: node(urls[0]), fallbackNodes: urls.slice(1).map((u) => node(u)), nodeUrl: urls[0] }) as unknown as PaymentKit;
const commitment = new Uint8Array(32).fill(0xc0);
const marker = new Uint8Array(32).fill(0xe0);

beforeEach(() => mockTrees.clear());

it('says buried and unspent when every node agrees', async () => {
  mockTrees.set('a', { atTip: { leaves: [C], tip: 10, markers: [] }, old: [C] });
  mockTrees.set('b', { atTip: { leaves: [C], tip: 10, markers: [] }, old: [C] });
  expect(await coinOnChain(kit('a', 'b'), 1n, commitment, marker)).toMatchObject({ status: 'buried', spent: false });
});

it('says settling when the leaf is only at the tip, absent when nowhere, and spent from the markers', async () => {
  mockTrees.set('a', { atTip: { leaves: [C], tip: 10, markers: [`0x${M}`] }, old: [] });
  expect(await coinOnChain(kit('a'), 1n, commitment, marker)).toMatchObject({ status: 'settling', spent: true });
  mockTrees.set('a', { atTip: { leaves: [], tip: 10, markers: null }, old: [] });
  expect(await coinOnChain(kit('a'), 1n, commitment, marker)).toMatchObject({ status: 'absent', spent: null });
});

it('fails when the nodes disagree, and uses the nodes that answer', async () => {
  mockTrees.set('a', { atTip: { leaves: [C], tip: 10, markers: [] }, old: [C] });
  mockTrees.set('b', { atTip: { leaves: [], tip: 10, markers: [] }, old: [] });
  await expect(coinOnChain(kit('a', 'b'), 1n, commitment, marker)).rejects.toThrow(NODES_DISAGREE_TEXT);
  expect(await coinOnChain(kit('a', 'down'), 1n, commitment, marker)).toMatchObject({ status: 'buried' });
  await expect(coinOnChain(kit('down'), 1n, commitment, marker)).rejects.toThrow('down');
});
