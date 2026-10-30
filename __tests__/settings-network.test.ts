// A saved node belongs to the network of the build that saved it: a release
// build installed over a dev build must not keep asking the dev node.
import { DEV_NETWORK, RELEASE_NETWORK } from '../lib/network/build-network';

const ORIGINAL_BUILD = process.env.EXPO_PUBLIC_GHOST_BUILD;

afterEach(() => {
  if (ORIGINAL_BUILD === undefined) {
    delete process.env.EXPO_PUBLIC_GHOST_BUILD;
  } else {
    process.env.EXPO_PUBLIC_GHOST_BUILD = ORIGINAL_BUILD;
  }
});

/** The settings module as a build of `build` has it, loaded afresh. */
function settingsOf(build: string | undefined): typeof import('../lib/settings/settings') {
  if (build === undefined) {
    delete process.env.EXPO_PUBLIC_GHOST_BUILD;
  } else {
    process.env.EXPO_PUBLIC_GHOST_BUILD = build;
  }
  let loaded!: typeof import('../lib/settings/settings');
  jest.isolateModules(() => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    loaded = require('../lib/settings/settings');
  });
  return loaded;
}

/** A settings file holding `stored`, recording what is written to it. */
function fileWith(stored: unknown) {
  const saved: unknown[] = [];
  return { saved, file: { read: () => stored, write: async (value: unknown) => void saved.push(value) } };
}

const HAND_NODE = 'https://my-node.example/ghost-rpc';

describe('a release build', () => {
  it('replaces the dev node an earlier dev build saved with its own default, and saves that', async () => {
    const settings = settingsOf('release');
    const { saved, file } = fileWith({ nodeUrl: 'http://192.168.1.36:8547' });
    const store = settings.createSettingsStore(file);

    expect(store.get().nodeUrl).toBe(RELEASE_NETWORK.nodeUrls[0]);
    await Promise.resolve();
    expect(saved).toEqual([{ nodeUrl: RELEASE_NETWORK.nodeUrls[0], appLock: false, nodeChainId: '6777972' }]);
    // Read once: the correction is saved once.
    store.get();
    await Promise.resolve();
    expect(saved).toHaveLength(1);
  });

  it('refuses a node saved on the dev chain, keeping the other settings', () => {
    const settings = settingsOf('release');
    expect(settings.parseSettings({ nodeUrl: 'http://10.0.0.7:8547', nodeChainId: '6777971', appLock: true })).toEqual({
      nodeUrl: RELEASE_NETWORK.nodeUrls[0],
      appLock: true,
    });
  });

  it('keeps a node typed in by hand on its network, and saves nothing on read', async () => {
    const settings = settingsOf('release');
    for (const stored of [{ nodeUrl: HAND_NODE }, { nodeUrl: HAND_NODE, nodeChainId: '6777972' }]) {
      const { saved, file } = fileWith(stored);
      const store = settings.createSettingsStore(file);
      expect(store.get().nodeUrl).toBe(HAND_NODE);
      await Promise.resolve();
      expect(saved).toEqual([]);
    }
    expect(settings.parseSettings({ nodeUrl: RELEASE_NETWORK.nodeUrls[1] }).nodeUrl).toBe(RELEASE_NETWORK.nodeUrls[1]);
  });

  it('keeps a node set in Settings, even another network’s, saved with its own chain', async () => {
    const settings = settingsOf('release');
    const { saved, file } = fileWith(null);
    const store = settings.createSettingsStore(file);
    await store.update({ nodeUrl: 'http://192.168.1.36:8547' });
    expect(store.get().nodeUrl).toBe('http://192.168.1.36:8547');
    expect(saved).toEqual([{ nodeUrl: 'http://192.168.1.36:8547', appLock: false, nodeChainId: '6777972' }]);
  });
});

describe.each([undefined, 'dev'])('a build of %p', (build) => {
  it('still defaults to and keeps the dev node', async () => {
    const settings = settingsOf(build);
    expect(settings.DEFAULT_SETTINGS.nodeUrl).toBe(DEV_NETWORK.nodeUrls[0]);
    const { saved, file } = fileWith({ nodeUrl: 'http://192.168.1.36:8547' });
    expect(settings.createSettingsStore(file).get().nodeUrl).toBe('http://192.168.1.36:8547');
    await Promise.resolve();
    expect(saved).toEqual([]);
  });

  it('refuses a public node or a node saved by a release build', () => {
    const settings = settingsOf(build);
    expect(settings.parseSettings({ nodeUrl: RELEASE_NETWORK.nodeUrls[0] }).nodeUrl).toBe(DEV_NETWORK.nodeUrls[0]);
    expect(settings.parseSettings({ nodeUrl: HAND_NODE, nodeChainId: '6777972' }).nodeUrl).toBe(DEV_NETWORK.nodeUrls[0]);
    expect(settings.parseSettings({ nodeUrl: 'http://10.0.0.7:8547' }).nodeUrl).toBe('http://10.0.0.7:8547');
  });
});
