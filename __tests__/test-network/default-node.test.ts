import fs from 'fs';
import path from 'path';

import { DEV_NETWORK } from '../../lib/network/build-network';
import { faucetUrlFor } from '../../lib/node/faucet';
import { DEFAULT_NODE_URL, DEFAULT_SETTINGS, TEST_CHAIN_ID, createSettingsStore, parseSettings } from '../../lib/settings/settings';

jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));

const ROOT = path.join(__dirname, '..', '..');

describe('the default node', () => {
  it('is the Mac Studio test chain on the LAN, not the phone itself', () => {
    expect(DEFAULT_NODE_URL).toBe('http://192.168.1.36:8547');
    expect(DEFAULT_SETTINGS.nodeUrl).toBe('http://192.168.1.36:8547');
    expect(parseSettings(null).nodeUrl).toBe('http://192.168.1.36:8547');
    expect(parseSettings({ nodeUrl: 'not a url' }).nodeUrl).toBe('http://192.168.1.36:8547');
  });

  it('stays editable: a saved node wins over the default', async () => {
    const store = createSettingsStore({ read: () => null, write: async () => {} });
    expect(store.get().nodeUrl).toBe(DEFAULT_NODE_URL);
    await store.update({ nodeUrl: 'http://10.0.0.7:8547' });
    expect(store.get().nodeUrl).toBe('http://10.0.0.7:8547');
  });

  it('is on the test network, chain 6777971, the chain of a dev build', () => {
    expect(TEST_CHAIN_ID).toBe(6777971n);
    expect(TEST_CHAIN_ID).toBe(DEV_NETWORK.chainId);
    const script = fs.readFileSync(path.join(ROOT, 'scripts/test-chain.sh'), 'utf8');
    expect(script).toMatch(/^CHAIN_ID=6777971$/m);
    expect(script).toMatch(/^PORT=8547$/m);
  });
});

describe('the faucet address', () => {
  it('is the node host on port 8548', () => {
    expect(faucetUrlFor(DEFAULT_NODE_URL)).toBe('http://192.168.1.36:8548/faucet');
    expect(faucetUrlFor('HTTPS://node.example/rpc')).toBe('https://node.example:8548/faucet');
    expect(faucetUrlFor('http://[fe80::1]:8547')).toBe('http://[fe80::1]:8548/faucet');
    expect(faucetUrlFor('not a url')).toBeNull();
  });
});

describe('app.json', () => {
  const plist = JSON.parse(fs.readFileSync(path.join(ROOT, 'app.json'), 'utf8')).expo.ios.infoPlist;

  it('says why it uses the local network', () => {
    expect(plist.NSLocalNetworkUsageDescription).toBe('Ghost Wallet connects to the Ghost test node on your network.');
  });

  it('allows local networking only, nothing wider', () => {
    expect(plist.NSAppTransportSecurity).toEqual({ NSAllowsLocalNetworking: true });
  });
});
