// The app's settings: which node to ask, and whether the app locks.
import { useSyncExternalStore } from 'react';

import { DEV_NETWORK, RELEASE_NETWORK, buildNetwork, type BuildNetwork } from '../network/build-network';
import { jsonFile, type JsonFile } from '../storage';

export type Settings = {
  /** The Ghost node home asks for the balance. */
  nodeUrl: string;
  /** Whether the app asks for Face ID or the passcode when it opens. */
  appLock: boolean;
};

/**
 * The test chain (scripts/test-chain.sh) on the Mac Studio, as a phone on the
 * same network reaches it. 127.0.0.1 would be the phone itself, where no node
 * runs. Settings can point at another node. The default node of dev and test
 * builds; release builds default to their first public node.
 */
export const DEFAULT_NODE_URL = 'http://192.168.1.36:8547';

/**
 * The test chain this build's nodes must report: the internal net of
 * scripts/test-chain.sh in dev builds, the Ghost public test network in
 * release builds.
 */
export const TEST_CHAIN_ID = buildNetwork.chainId;

/** The node a build asks until settings name another. */
export function defaultNodeUrlFor(network: BuildNetwork): string {
  return network.nodeUrls[0];
}

export const DEFAULT_SETTINGS: Settings = { nodeUrl: defaultNodeUrlFor(buildNetwork), appLock: false };

/** A node address typed by hand, tidied; null if it is not an http(s) URL with a host. */
export function normaliseNodeUrl(text: string): string | null {
  const trimmed = text.trim();
  const match = /^(https?):\/\/([^/\s?#]+)(\/[^\s?#]*)?$/i.exec(trimmed);
  if (!match) {
    return null;
  }
  const [, scheme, host, path = ''] = match;
  return `${scheme.toLowerCase()}://${host}${path.replace(/\/+$/, '')}`;
}

/** Settings as saved: the node is kept with the chain of the build that saved it. */
export type StoredSettings = Settings & {
  /** The chain id, in decimal, of the build network the node was saved on. */
  nodeChainId: string;
};

const KNOWN_NETWORKS: readonly BuildNetwork[] = [DEV_NETWORK, RELEASE_NETWORK];

/**
 * Whether a saved node may be used on `network`. A node saved with a chain id
 * applies to that chain only. One saved before chain ids were kept is refused
 * when it is another network's own node, as a dev build's saved test chain is
 * for a release build installed over it; one typed in by hand stays.
 */
function nodeFitsNetwork(nodeUrl: string, nodeChainId: unknown, network: BuildNetwork): boolean {
  if (typeof nodeChainId === 'string') {
    return nodeChainId === network.chainId.toString();
  }
  if (network.nodeUrls.includes(nodeUrl)) {
    return true;
  }
  return !KNOWN_NETWORKS.some((other) => other.chainId !== network.chainId && other.nodeUrls.includes(nodeUrl));
}

/** A saved node `raw` names that `network` must not use, or null. */
function foreignNode(raw: unknown, network: BuildNetwork): string | null {
  const value = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>;
  const nodeUrl = typeof value.nodeUrl === 'string' ? normaliseNodeUrl(value.nodeUrl) : null;
  return nodeUrl !== null && !nodeFitsNetwork(nodeUrl, value.nodeChainId, network) ? nodeUrl : null;
}

export function parseSettings(raw: unknown, network: BuildNetwork = buildNetwork): Settings {
  const value = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>;
  const nodeUrl = typeof value.nodeUrl === 'string' ? normaliseNodeUrl(value.nodeUrl) : null;
  return {
    nodeUrl: nodeUrl !== null && foreignNode(raw, network) === null ? nodeUrl : defaultNodeUrlFor(network),
    appLock: typeof value.appLock === 'boolean' ? value.appLock : DEFAULT_SETTINGS.appLock,
  };
}

/** The settings as saved by a build of `network`. */
export function storedSettings(settings: Settings, network: BuildNetwork = buildNetwork): StoredSettings {
  return { ...settings, nodeChainId: network.chainId.toString() };
}

export type SettingsStore = {
  get(): Settings;
  update(change: Partial<Settings>): Promise<void>;
  subscribe(listener: () => void): () => void;
};

export function createSettingsStore(file: JsonFile, network: BuildNetwork = buildNetwork): SettingsStore {
  let current: Settings | null = null;
  const listeners = new Set<() => void>();
  const get = () => {
    if (current === null) {
      const raw = file.read();
      current = parseSettings(raw, network);
      if (foreignNode(raw, network) !== null) {
        // Another network's node: save this build's default in its place.
        file.write(storedSettings(current, network)).catch(() => {});
      }
    }
    return current;
  };
  return {
    get,
    async update(change) {
      // A node set here is set on this build's network.
      current = parseSettings({ ...storedSettings(get(), network), ...change }, network);
      for (const listener of listeners) {
        listener();
      }
      await file.write(storedSettings(current, network));
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
  };
}

export const settingsStore = createSettingsStore(jsonFile('settings.json'));

export function useSettings(store: SettingsStore = settingsStore): Settings {
  return useSyncExternalStore(store.subscribe, store.get);
}
