// Reading the spent markers through the real JSON-RPC client
// (lib/vanish/node.ts) against a fake node that answers as Ghost's node does
// (internal/ethapi/ghosttree.go): the marker list has no page roots, and
// `ghost_getTreePage` for kind `coin-markers` answers `{count, markers}`,
// 4,096 markers to a full page.
import { readSpentMarkers } from '../../lib/vanish/coin-pages';
import { vanishNode } from '../../lib/vanish/node';

const URL = 'http://node.test:8545';
const ANCHOR = `0x${'ab'.repeat(32)}`;
const PAGE = 4096;

const marker = (n: number) => `0x${n.toString(16).padStart(64, '0')}`;
const markersOf = (count: number) => Array.from({ length: count }, (_, i) => marker(i + 1));

type Call = { method: string; params: unknown[] };
type Answer = { result?: unknown; error?: { code: number; message: string } };

function fakeNode(markers: string[], options: { page?: (page: number, onPage: string[]) => unknown } = {}) {
  const requests: Call[][] = [];
  const q = (n: number) => `0x${n.toString(16)}`;

  function answer({ method, params }: Call): Answer {
    const refuse = (message: string) => ({ error: { code: -32602, message } });
    if (params[0] !== 'coin-markers' || params[1] !== '0x0' || params[params.length - 1] !== ANCHOR) {
      return refuse('unexpected tree or anchor');
    }
    if (method === 'ghost_getPageRoots') {
      return refuse('a list of spent markers has no page roots: coin-markers');
    }
    if (method === 'ghost_getTreePage') {
      const page = parseInt(params[2] as string, 16);
      const onPage = markers.slice(page * PAGE, (page + 1) * PAGE);
      return { result: options.page ? options.page(page, onPage) : { count: q(onPage.length), markers: onPage } };
    }
    return refuse(`the fake node does not serve ${method}`);
  }

  const fetchImpl = jest.fn(async (_url: string, init: RequestInit) => {
    const calls = JSON.parse(init.body as string) as (Call & { id: number })[];
    requests.push(calls.map(({ method, params }) => ({ method, params })));
    return { ok: true, status: 200, json: async () => calls.map((call) => ({ jsonrpc: '2.0', id: call.id, ...answer(call) })) } as Response;
  });

  return {
    node: vanishNode(URL, fetchImpl),
    requests,
    pagesAsked: () => requests.flat().map((call) => [call.method, ...call.params]),
  };
}

describe('reading the spent markers', () => {
  it('reads one page when it holds fewer than 4,096 markers, with no page roots asked', async () => {
    const markers = markersOf(6);
    const fake = fakeNode(markers);
    await expect(fake.node.markerPages(0, ANCHOR)).resolves.toEqual(markers);
    expect(fake.pagesAsked()).toEqual([['ghost_getTreePage', 'coin-markers', '0x0', '0x0', ANCHOR]]);
  });

  it('reads page after page from 0 until one holds fewer than 4,096', async () => {
    const markers = markersOf(2 * PAGE + 10);
    const fake = fakeNode(markers);
    await expect(fake.node.markerPages(0, ANCHOR)).resolves.toEqual(markers);
    expect(fake.pagesAsked().map((call) => call.slice(0, 4))).toEqual([
      ['ghost_getTreePage', 'coin-markers', '0x0', '0x0'],
      ['ghost_getTreePage', 'coin-markers', '0x0', '0x1'],
      ['ghost_getTreePage', 'coin-markers', '0x0', '0x2'],
    ]);
  });

  it('reads the empty page after a full last page, and an empty list as no markers', async () => {
    const full = fakeNode(markersOf(PAGE));
    await expect(full.node.markerPages(0, ANCHOR)).resolves.toHaveLength(PAGE);
    expect(full.pagesAsked().map((call) => call[3])).toEqual(['0x0', '0x1']);

    const none = fakeNode([]);
    await expect(none.node.markerPages(0, ANCHOR)).resolves.toEqual([]);
    expect(none.requests).toHaveLength(1);
  });

  it('refuses a page not laid out as the node lays one out', async () => {
    const shapes: unknown[] = [
      { count: '0x2', markers: [marker(1)] },
      { count: '0x1', markers: ['0x1234'] },
      { count: 2, markers: [marker(1), marker(2)] },
      { kind: 'coin-markers', treeIndex: '0x0', page: '0x0', filled: '0x1', entries: [{ leaf: marker(1) }] },
      { count: '0x1001', markers: markersOf(PAGE + 1) },
      null,
    ];
    for (const shape of shapes) {
      const fake = fakeNode(markersOf(2), { page: () => shape });
      await expect(fake.node.markerPages(0, ANCHOR)).rejects.toThrow('malformed spent marker page');
    }
  });

  it('gives the hint its markers, and no markers when the node refuses, never naming one', async () => {
    const markers = markersOf(PAGE + 3);
    const fake = fakeNode(markers);
    await expect(readSpentMarkers(fake.node, ANCHOR)).resolves.toEqual(markers);
    const bodies = JSON.stringify(fake.requests);
    expect(bodies).not.toContain(markers[0]);
    expect(bodies).not.toContain(markers[PAGE + 2]);

    const refusing = fakeNode(markers);
    await expect(readSpentMarkers(refusing.node, `0x${'cd'.repeat(32)}`)).resolves.toBeNull();
  });
});
