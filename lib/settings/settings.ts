// The app's settings: which node to ask, and whether the app locks.
import { useSyncExternalStore } from 'react';

import { buildNetwork, type BuildNetwork } from '../network/build-network';
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

export function parseSettings(raw: unknown): Settings {
  const value = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>;
  const nodeUrl = typeof value.nodeUrl === 'string' ? normaliseNodeUrl(value.nodeUrl) : null;
  return {
    nodeUrl: nodeUrl ?? DEFAULT_SETTINGS.nodeUrl,
    appLock: typeof value.appLock === 'boolean' ? value.appLock : DEFAULT_SETTINGS.appLock,
  };
}

export type SettingsStore = {
  get(): Settings;
  update(change: Partial<Settings>): Promise<void>;
  subscribe(listener: () => void): () => void;
};

export function createSettingsStore(file: JsonFile): SettingsStore {
  let current: Settings | null = null;
  const listeners = new Set<() => void>();
  const get = () => (current ??= parseSettings(file.read()));
  return {
    get,
    async update(change) {
      current = parseSettings({ ...get(), ...change });
      for (const listener of listeners) {
        listener();
      }
      await file.write(current);
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
