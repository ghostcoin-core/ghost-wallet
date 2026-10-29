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
  };
  jest.isolateModules(() => {
    loaded = {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      network: require('../lib/network/build-network'),
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      settings: require('../lib/settings/settings'),
    };
  });
  return loaded;
}

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
