import {
  DEV_NETWORK,
  GHOST_DEV_CHAIN_ID,
  GHOST_PUBLIC_TEST_CHAIN_ID,
  RELEASE_NETWORK,
  RELEASE_NODE_URLS,
  offersTestGhost,
  resolveBuildNetwork,
} from '../lib/network/build-network';

/** True for a host a phone elsewhere cannot reach, or an address instead of a name. */
function isLocalOrLiteral(host: string): boolean {
  const name = host.toLowerCase();
  return (
    name === 'localhost' ||
    name.endsWith('.local') ||
    name.endsWith('.lan') ||
    name.endsWith('.internal') ||
    !name.includes('.') ||
    /^[\d.]+$/.test(name) ||
    name.startsWith('[') ||
    name.includes(':')
  );
}

describe('the release network', () => {
  it('is what a release build resolves to', () => {
    expect(resolveBuildNetwork('release')).toBe(RELEASE_NETWORK);
    expect(RELEASE_NETWORK.nodeUrls).toBe(RELEASE_NODE_URLS);
  });

  it('lists at least three distinct public nodes over TLS', () => {
    const urls = resolveBuildNetwork('release').nodeUrls;
    expect(urls.length).toBeGreaterThanOrEqual(3);
    const hosts = urls.map((url) => new URL(url).hostname);
    expect(new Set(hosts).size).toBe(urls.length);
    for (const url of urls) {
      const parsed = new URL(url);
      expect(parsed.protocol).toBe('https:');
      expect(isLocalOrLiteral(parsed.hostname)).toBe(false);
    }
  });

  it('targets the Ghost public test network, which has no value', () => {
    const network = resolveBuildNetwork('release');
    // The public test network is the internal net's 6777971 plus one.
    expect(network.chainId).toBe(6777972n);
    expect(network.chainId).toBe(GHOST_PUBLIC_TEST_CHAIN_ID);
    expect(network.chainId).not.toBe(DEV_NETWORK.chainId);
    expect(network.realValue).toBe(false);
    expect(network.minimumDifficulty).toBe(4096n);
  });

});

describe('the dev network', () => {
  it.each([undefined, '', 'dev', 'test', 'Release'])('is what a build of %p resolves to', (build) => {
    expect(resolveBuildNetwork(build)).toBe(DEV_NETWORK);
  });

  it('is the Mac Studio test chain', () => {
    expect(DEV_NETWORK.nodeUrls).toEqual(['http://192.168.1.36:8547']);
    expect(DEV_NETWORK.chainId).toBe(6777971n);
    expect(DEV_NETWORK.chainId).toBe(GHOST_DEV_CHAIN_ID);
    expect(DEV_NETWORK.minimumDifficulty).toBe(1n);
    expect(DEV_NETWORK.realValue).toBe(false);
  });

});

describe('offersTestGhost', () => {
  it('offers test GHOST only when the node is the test network and the chain has no value', () => {
    expect(offersTestGhost({ realValue: false }, true)).toBe(true);
    expect(offersTestGhost({ realValue: false }, false)).toBe(false);
    expect(offersTestGhost({ realValue: true }, true)).toBe(false);
    expect(offersTestGhost({ realValue: true }, false)).toBe(false);
  });
});
