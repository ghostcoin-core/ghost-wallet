import fs from 'fs';
import path from 'path';

import { GHOST_PUBLIC_TEST_CHAIN_ID, RELEASE_NODE_URLS } from '../../lib/network/build-network';

const ROOT = path.join(__dirname, '..', '..');
const source = fs.readFileSync(path.join(ROOT, 'seal', 'src', 'node_list.rs'), 'utf8');

/** The block 0 hash of the Ghost public test network, as the node project publishes it. */
const PUBLIC_TEST_GENESIS = 'dfe4271fd12d302e15c68e381ade8076207f70d3778eebd69604566fb6979436';

/** The text of the compiled-in list, its Rust string escapes (`\xNN`) decoded. */
function releaseListText(): string {
  const match = /pub const RELEASE_NODE_LIST: &str = "\\\n([\s\S]*?)";/.exec(source);
  if (!match) {
    throw new Error('seal/src/node_list.rs has no RELEASE_NODE_LIST');
  }
  if (/\\[^x]/.test(match[1])) {
    throw new Error('the list uses an escape this test does not decode');
  }
  return match[1].replace(/\\x([0-9a-fA-F]{2})/g, (_, code: string) => String.fromCharCode(parseInt(code, 16)));
}

type Entry = { name: string; host: string; port: number; path: string; vsockPort: number };

function parse(text: string): { chainId: bigint; genesis: string; nodes: Entry[] } {
  let chainId: bigint | null = null;
  let genesis = '';
  const nodes: Entry[] = [];
  for (const line of text.split('\n').filter((l) => l.length > 0)) {
    const fields = line.split(' ');
    if (fields[0] === 'network' && fields.length === 3) {
      chainId = BigInt(fields[1]);
      genesis = fields[2];
    } else if (fields[0] === 'node' && fields.length === 6) {
      nodes.push({
        name: fields[1],
        host: fields[2],
        port: Number(fields[3]),
        path: fields[4],
        vsockPort: Number(fields[5]),
      });
    } else {
      throw new Error(`a line that is neither a network nor a node: ${line}`);
    }
  }
  if (chainId === null) {
    throw new Error('no network line');
  }
  return { chainId, genesis, nodes };
}

describe('seal/src/node_list.rs', () => {
  const list = parse(releaseListText());

  it('follows the release network of the app', () => {
    expect(list.chainId).toBe(GHOST_PUBLIC_TEST_CHAIN_ID);
    expect(list.genesis).toBe(PUBLIC_TEST_GENESIS);
  });

  it('lists exactly the release nodes of the app, over HTTPS on port 443, in order', () => {
    const urls = list.nodes.map((n) => `https://${n.host}${n.port === 443 ? '' : `:${n.port}`}${n.path}`);
    expect(urls).toEqual([...RELEASE_NODE_URLS]);
    for (const node of list.nodes) {
      expect(node.port).toBe(443);
      expect(node.path).toBe('/ghost-rpc');
    }
  });

  it('names each node by its host and gives each its own vsock port', () => {
    expect(list.nodes.length).toBeGreaterThanOrEqual(2);
    expect(list.nodes.map((n) => n.name)).toEqual(list.nodes.map((n) => n.host.split('.')[0].replace(/-\d+$/, '')));
    expect(list.nodes.map((n) => n.vsockPort)).toEqual([5003, 5004]);
    expect(new Set(list.nodes.map((n) => n.name)).size).toBe(list.nodes.length);
    expect(new Set(list.nodes.map((n) => n.host)).size).toBe(list.nodes.length);
  });
});
