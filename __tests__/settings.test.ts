import { layoutFor } from '../lib/layout';
import { createTapCounter } from '../lib/settings/developer-entry';
import {
  DEFAULT_SETTINGS,
  createSettingsStore,
  normaliseNodeUrl,
  parseSettings,
} from '../lib/settings/settings';

describe('node address', () => {
  it('takes http and https URLs, tidied', () => {
    expect(normaliseNodeUrl(' http://127.0.0.1:8547/ ')).toBe('http://127.0.0.1:8547');
    expect(normaliseNodeUrl('HTTPS://node.example:443/rpc')).toBe('https://node.example:443/rpc');
  });

  it('refuses anything else', () => {
    expect(normaliseNodeUrl('127.0.0.1:8547')).toBeNull();
    expect(normaliseNodeUrl('ftp://node')).toBeNull();
    expect(normaliseNodeUrl('http://')).toBeNull();
    expect(normaliseNodeUrl('http://a b')).toBeNull();
  });
});

describe('settings', () => {
  it('fall back to the defaults for missing or malformed values', () => {
    expect(parseSettings(null)).toEqual(DEFAULT_SETTINGS);
    expect(parseSettings({ nodeUrl: 'nope', appLock: 'yes' })).toEqual(DEFAULT_SETTINGS);
    expect(parseSettings({ nodeUrl: 'http://10.0.0.2:8547', appLock: true })).toEqual({
      nodeUrl: 'http://10.0.0.2:8547',
      appLock: true,
    });
  });

  it('are saved and announced on change', async () => {
    const saved: unknown[] = [];
    const store = createSettingsStore({ read: () => ({ appLock: true }), write: async (v) => void saved.push(v) });
    const listener = jest.fn();
    store.subscribe(listener);

    expect(store.get()).toEqual({ ...DEFAULT_SETTINGS, appLock: true });
    await store.update({ nodeUrl: 'http://10.0.0.2:8547' });

    expect(listener).toHaveBeenCalledTimes(1);
    expect(saved).toEqual([{ nodeUrl: 'http://10.0.0.2:8547', appLock: true, nodeChainId: '6777971' }]);
    expect(store.get().nodeUrl).toBe('http://10.0.0.2:8547');
  });
});

describe('developer entry', () => {
  it('opens on the seventh tap within three seconds', () => {
    let now = 0;
    const tap = createTapCounter(() => now);
    for (let i = 0; i < 6; i++) {
      expect(tap()).toBe(false);
      now += 100;
    }
    expect(tap()).toBe(true);
    expect(tap()).toBe(false);
  });

  it('starts over after a pause', () => {
    let now = 0;
    const tap = createTapCounter(() => now);
    for (let i = 0; i < 6; i++) tap();
    now = 5_000;
    expect(tap()).toBe(false);
  });
});

describe('layout', () => {
  it('uses two columns on the open iPhone Duo only', () => {
    expect(layoutFor(393, 852).twoColumns).toBe(false);
    expect(layoutFor(466, 678).twoColumns).toBe(false);
    expect(layoutFor(626, 890).twoColumns).toBe(true);
  });
});
