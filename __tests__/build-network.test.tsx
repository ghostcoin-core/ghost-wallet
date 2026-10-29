// The settings default per build: each test loads the modules afresh with
// EXPO_PUBLIC_GHOST_BUILD set as a build would have it inlined.
import { DEV_NETWORK, RELEASE_NETWORK } from '../lib/network/build-network';

const ORIGINAL_BUILD = process.env.EXPO_PUBLIC_GHOST_BUILD;

afterEach(() => {
  if (ORIGINAL_BUILD === undefined) {
    delete process.env.EXPO_PUBLIC_GHOST_BUILD;
  } else {
    process.env.EXPO_PUBLIC_GHOST_BUILD = ORIGINAL_BUILD;
  }
});

function loadBuild(build: string | undefined) {
  if (build === undefined) {
    delete process.env.EXPO_PUBLIC_GHOST_BUILD;
  } else {
    process.env.EXPO_PUBLIC_GHOST_BUILD = build;
  }
  let loaded!: {
    network: typeof import('../lib/network/build-network');
    settings: typeof import('../lib/settings/settings');
    testNetwork: typeof import('../lib/node/test-network');
    actions: typeof import('../lib/vanish/actions');
  };
  jest.isolateModules(() => {
    loaded = {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      network: require('../lib/network/build-network'),
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      settings: require('../lib/settings/settings'),
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      testNetwork: require('../lib/node/test-network'),
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      actions: require('../lib/vanish/actions'),
    };
  });
  return loaded;
}

/** A node that answers `eth_chainId` with `chainId`. */
function nodeOn(chainId: bigint) {
  return async (_url: string, init: RequestInit) => {
    const [call] = JSON.parse(String(init.body)) as { id: number; method: string }[];
    expect(call.method).toBe('eth_chainId');
    return { ok: true, status: 200, json: async () => [{ jsonrpc: '2.0', id: call.id, result: `0x${chainId.toString(16)}` }] } as Response;
  };
}

/** Just enough of a payment kit for the chain check: the node's chain id. */
function kitOn(chainId: bigint) {
  return { node: { chainId: async () => chainId } } as unknown as Parameters<typeof import('../lib/vanish/actions').checkedChainId>[0];
}

// Two public test network nodes, as a release build reaches them (chain 6777972).
const PUBLIC_NODES = ['https://node-a.example/ghost-rpc', 'https://node-b.example/ghost-rpc'];

describe('the chain a build expects its nodes to report', () => {
  it('is the public test network, 6777972, in a release build', async () => {
    const { network, settings, testNetwork, actions } = loadBuild('release');
    expect(network.buildNetwork.chainId).toBe(6777972n);
    expect(settings.TEST_CHAIN_ID).toBe(6777972n);
    for (const url of PUBLIC_NODES) {
      await expect(testNetwork.isTestNetwork(url, nodeOn(6777972n))).resolves.toBe(true);
      // The internal net is not the release build's chain.
      await expect(testNetwork.isTestNetwork(url, nodeOn(6777971n))).resolves.toBe(false);
    }
    await expect(actions.checkedChainId(kitOn(6777972n))).resolves.toBe(6777972n);
    await expect(actions.checkedChainId(kitOn(6777971n))).rejects.toThrow('the node is not the Ghost test network');
  });

  it.each([undefined, 'dev'])('is the internal test chain, 6777971, in a build of %p', async (build) => {
    const { network, settings, testNetwork, actions } = loadBuild(build);
    expect(network.buildNetwork.chainId).toBe(6777971n);
    expect(settings.TEST_CHAIN_ID).toBe(6777971n);
    await expect(testNetwork.isTestNetwork('http://192.168.1.36:8547', nodeOn(6777971n))).resolves.toBe(true);
    await expect(testNetwork.isTestNetwork(PUBLIC_NODES[0], nodeOn(6777972n))).resolves.toBe(false);
    await expect(actions.checkedChainId(kitOn(6777971n))).resolves.toBe(6777971n);
    await expect(actions.checkedChainId(kitOn(6777972n))).rejects.toThrow('the node is not the Ghost test network');
  });
});

describe('the default node of a build', () => {
  it('is the first public node in a release build', () => {
    const { network, settings } = loadBuild('release');
    expect(network.buildNetwork).toEqual(RELEASE_NETWORK);
    expect(settings.DEFAULT_SETTINGS.nodeUrl).toBe(RELEASE_NETWORK.nodeUrls[0]);
    expect(settings.parseSettings(null).nodeUrl).toBe(RELEASE_NETWORK.nodeUrls[0]);
    expect(settings.parseSettings({ nodeUrl: 'not a url' }).nodeUrl).toBe(RELEASE_NETWORK.nodeUrls[0]);
    // The dev default node stays as it was.
    expect(settings.DEFAULT_NODE_URL).toBe('http://192.168.1.36:8547');
  });

  it.each([undefined, 'dev'])('is the Mac Studio test chain in a build of %p', (build) => {
    const { network, settings } = loadBuild(build);
    expect(network.buildNetwork).toEqual(DEV_NETWORK);
    expect(settings.DEFAULT_SETTINGS.nodeUrl).toBe('http://192.168.1.36:8547');
  });
});
