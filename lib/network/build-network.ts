// Which Ghost network this build talks to, picked when the app is built.
// EXPO_PUBLIC_GHOST_BUILD=release selects the release network: independent
// public Ghost nodes over TLS. Anything else (unset, as in tests and dev
// builds) selects the Mac Studio test chain of scripts/test-chain.sh.

/** The internal net of scripts/test-chain.sh: the chain of dev builds. */
export const GHOST_DEV_CHAIN_ID = 6777971n;

/** The Ghost public test network (the internal net's id plus one): the chain of release builds. */
export const GHOST_PUBLIC_TEST_CHAIN_ID = 6777972n;

/** A block the header sync starts from instead of block 0. */
export type NetworkCheckpoint = {
  height: number;
  hashHex: string;
};

export type BuildNetwork = {
  name: 'dev' | 'release';
  /** The chain the nodes must report. */
  chainId: bigint;
  /** The nodes to ask, in order; the first is the default node in settings. */
  nodeUrls: readonly string[];
  /** Where the header sync starts; null starts at block 0. */
  checkpoint: NetworkCheckpoint | null;
  /** The lowest difficulty a spot-checked header may claim. */
  minimumDifficulty: bigint;
  /** True on a chain whose coins have value: Home never offers test GHOST there. */
  realValue: boolean;
};

/**
 * The Mac Studio test chain, as a phone on the same network reaches it.
 * 127.0.0.1 would be the phone itself, where no node runs. The same address
 * as DEFAULT_NODE_URL in lib/settings/settings.ts.
 */
export const DEV_NODE_URL = 'http://192.168.1.36:8547';

/**
 * The public nodes of the Ghost public test network, reached over TLS through
 * Tailscale Funnel. Both are run by the Ghost team today, so they count as one
 * operator, not the several independent ones release needs: add other
 * operators' nodes here as they come up.
 */
export const RELEASE_NODE_URLS: readonly string[] = [
  'https://spark-2912.tail11407b.ts.net/ghost-rpc',
  'https://kipp-vm.tail11407b.ts.net/ghost-rpc',
];

export const DEV_NETWORK: BuildNetwork = {
  name: 'dev',
  chainId: GHOST_DEV_CHAIN_ID,
  nodeUrls: [DEV_NODE_URL],
  // The test chain is short: the sync starts at block 0.
  checkpoint: null,
  // The test chain's floor (README, spot check).
  minimumDifficulty: 1n,
  realValue: false,
};

/**
 * Release builds target the Ghost public test network until mainnet meets its
 * security requirements (PLAN.md: no real funds before then). Switching to
 * mainnet means a new chain id, node list, checkpoint and difficulty here and
 * `realValue: true`, then a new build.
 */
export const RELEASE_NETWORK: BuildNetwork = {
  name: 'release',
  chainId: GHOST_PUBLIC_TEST_CHAIN_ID,
  nodeUrls: RELEASE_NODE_URLS,
  // Pinned once the public test network's checkpoint block is published.
  checkpoint: null,
  // The public test network's floor (ghost-node docs/public-testnet.md).
  minimumDifficulty: 4096n,
  realValue: false,
};

/** The network for a value of EXPO_PUBLIC_GHOST_BUILD. */
export function resolveBuildNetwork(build: string | undefined): BuildNetwork {
  return build === 'release' ? RELEASE_NETWORK : DEV_NETWORK;
}

// Written out in full so Expo inlines the variable at build time.
export const buildNetwork: BuildNetwork = resolveBuildNetwork(process.env.EXPO_PUBLIC_GHOST_BUILD);

/**
 * Whether Home offers "Get test GHOST": only when the node says it is the test
 * network, and never on a chain with real value, whatever the node says.
 */
export function offersTestGhost(network: Pick<BuildNetwork, 'realValue'>, nodeSaysTestNetwork: boolean): boolean {
  return !network.realValue && nodeSaysTestNetwork;
}
