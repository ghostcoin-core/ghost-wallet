import type { ActivityItem } from '../../lib/home/activity';
import {
  ACTIVITY_LIMIT,
  HomeLoader,
  SNAPSHOT_VERSION,
  applyReading,
  balanceStatus,
  readCachedSnapshot,
  type AccountReading,
  type HomeSnapshot,
  type SnapshotCache,
} from '../../lib/home/cache-refresh';

const NODE = 'http://127.0.0.1:8547';
const ADDRESS = '0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd';
const GHOST = 10n ** 18n;
const T0 = 1_800_000_000_000;

function snapshot(change: Partial<HomeSnapshot> = {}): HomeSnapshot {
  return {
    version: SNAPSHOT_VERSION,
    nodeUrl: NODE,
    address: ADDRESS,
    balanceWei: (5n * GHOST).toString(),
    nonce: 1,
    tipHeight: 100,
    checkedAt: T0 - 10 * 60_000,
    activity: [],
    ...change,
  };
}

function memoryCache(initial: unknown = null): SnapshotCache & { written: HomeSnapshot[] } {
  const written: HomeSnapshot[] = [];
  return {
    written,
    read: () => (written.length ? written[written.length - 1] : initial),
    write: (s) => {
      written.push(s);
    },
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const reading = (change: Partial<AccountReading> = {}): AccountReading => ({
  balanceWei: (7n * GHOST).toString(),
  nonce: 1,
  tipHeight: 120,
  ...change,
});

describe('cache first', () => {
  it('shows the cached balance before the node answers', () => {
    const answer = deferred<AccountReading>();
    const readAccount = jest.fn(() => answer.promise);
    const loader = new HomeLoader({ nodeUrl: NODE, address: ADDRESS, cache: memoryCache(snapshot()), readAccount, now: () => T0 });

    expect(loader.view()).toEqual({ snapshot: snapshot(), source: 'cache', refreshing: false, error: null });
    void loader.refresh();
    expect(loader.view().snapshot?.balanceWei).toBe((5n * GHOST).toString());
    expect(loader.view().refreshing).toBe(true);
    expect(balanceStatus(loader.view(), T0)).toBe('Last updated 10 minutes ago');
  });

  it('has nothing to show on the first launch, and asks the node', () => {
    const loader = new HomeLoader({
      nodeUrl: NODE,
      address: ADDRESS,
      cache: memoryCache(null),
      readAccount: () => new Promise(() => {}),
    });
    expect(loader.view()).toEqual({ snapshot: null, source: 'none', refreshing: false, error: null });
    void loader.refresh();
    expect(balanceStatus(loader.view(), T0)).toBe('Asking the node for your balance');
  });

  it('never shows a balance cached for another node or another account', () => {
    expect(readCachedSnapshot(snapshot(), 'http://10.0.0.2:8547', ADDRESS)).toBeNull();
    expect(readCachedSnapshot(snapshot(), NODE, '0x' + '1'.repeat(40))).toBeNull();
    expect(readCachedSnapshot(snapshot(), NODE, ADDRESS.toUpperCase().replace('0X', '0x'))).not.toBeNull();
  });

  it('ignores a cache it cannot read', () => {
    expect(readCachedSnapshot(null, NODE, ADDRESS)).toBeNull();
    expect(readCachedSnapshot('garbage', NODE, ADDRESS)).toBeNull();
    expect(readCachedSnapshot({ ...snapshot(), version: 99 }, NODE, ADDRESS)).toBeNull();
    expect(readCachedSnapshot({ ...snapshot(), balanceWei: '1.5' }, NODE, ADDRESS)).toBeNull();
    expect(readCachedSnapshot({ ...snapshot(), checkedAt: -1 }, NODE, ADDRESS)).toBeNull();

    const throwing: SnapshotCache = {
      read: () => {
        throw new Error('disk gone');
      },
      write: () => {},
    };
    const loader = new HomeLoader({ nodeUrl: NODE, address: ADDRESS, cache: throwing, readAccount: jest.fn() });
    expect(loader.view().snapshot).toBeNull();
  });

  it('drops malformed activity from the cache but keeps the rest', () => {
    const good: ActivityItem = {
      id: 'x',
      direction: 'sent',
      counterparty: ADDRESS,
      amountWei: '1',
      state: 'failed',
      at: T0,
    };
    const cached = readCachedSnapshot({ ...snapshot(), activity: [good, { id: 'bad' }] }, NODE, ADDRESS);
    expect(cached?.activity).toEqual([good]);
  });
});

describe('then refresh', () => {
  it('replaces the cached balance with the node answer and writes it to the cache', async () => {
    const cache = memoryCache(snapshot());
    const readAccount = jest.fn(async () => reading());
    const loader = new HomeLoader({ nodeUrl: NODE, address: ADDRESS, cache, readAccount, now: () => T0 });
    const seen: string[] = [];
    loader.subscribe(() => seen.push(`${loader.view().source}:${loader.view().refreshing}`));

    await loader.refresh();

    expect(readAccount).toHaveBeenCalledWith(NODE, ADDRESS);
    expect(loader.view()).toMatchObject({ source: 'node', refreshing: false, error: null });
    expect(loader.view().snapshot).toMatchObject({ balanceWei: (7n * GHOST).toString(), tipHeight: 120, checkedAt: T0 });
    expect(cache.written).toEqual([loader.view().snapshot]);
    expect(seen).toEqual(['cache:true', 'node:false']);
    expect(balanceStatus(loader.view(), T0 + 5_000)).toBe('Up to date, just now');
  });

  it('keeps the cached balance and says how old it is when the node fails', async () => {
    const cache = memoryCache(snapshot());
    const loader = new HomeLoader({
      nodeUrl: NODE,
      address: ADDRESS,
      cache,
      readAccount: async () => {
        throw new Error('the node did not answer in time');
      },
      now: () => T0,
    });

    await expect(loader.refresh()).resolves.toBeUndefined();

    expect(loader.view()).toEqual({
      snapshot: snapshot(),
      source: 'cache',
      refreshing: false,
      error: 'the node did not answer in time',
    });
    expect(cache.written).toEqual([]);
    expect(balanceStatus(loader.view(), T0)).toBe('Node not reachable, last updated 10 minutes ago');
  });

  it('says where to look when there is neither a cache nor a node', async () => {
    const loader = new HomeLoader({
      nodeUrl: NODE,
      address: ADDRESS,
      cache: memoryCache(null),
      readAccount: async () => {
        throw new Error('offline');
      },
    });
    await loader.refresh();
    expect(balanceStatus(loader.view(), T0)).toBe('Could not reach the node. Check it in Settings.');
  });

  it('clears the error once the node answers again', async () => {
    const answers = [Promise.reject(new Error('offline')), Promise.resolve(reading())];
    answers[0].catch(() => {});
    const loader = new HomeLoader({
      nodeUrl: NODE,
      address: ADDRESS,
      cache: memoryCache(snapshot()),
      readAccount: () => answers.shift()!,
      now: () => T0,
    });
    await loader.refresh();
    expect(loader.view().error).toBe('offline');
    await loader.refresh();
    expect(loader.view()).toMatchObject({ error: null, source: 'node' });
  });

  it('asks the node once for overlapping refreshes', async () => {
    const answer = deferred<AccountReading>();
    const readAccount = jest.fn(() => answer.promise);
    const loader = new HomeLoader({ nodeUrl: NODE, address: ADDRESS, cache: memoryCache(), readAccount });

    const first = loader.refresh();
    const second = loader.refresh();
    expect(second).toBe(first);
    answer.resolve(reading());
    await first;
    expect(readAccount).toHaveBeenCalledTimes(1);

    await loader.refresh();
    expect(readAccount).toHaveBeenCalledTimes(2);
  });

  it('changes nothing once stopped, even when a late answer arrives, and asks again once started', async () => {
    const answer = deferred<AccountReading>();
    const cache = memoryCache(snapshot());
    const readAccount = jest.fn(() => answer.promise);
    const loader = new HomeLoader({ nodeUrl: NODE, address: ADDRESS, cache, readAccount });
    const listener = jest.fn();
    loader.subscribe(listener);

    const pending = loader.refresh();
    listener.mockClear();
    loader.stop();
    answer.resolve(reading());
    await pending;
    await loader.refresh();

    expect(listener).not.toHaveBeenCalled();
    expect(cache.written).toEqual([]);
    expect(loader.view().snapshot).toEqual(snapshot());
    expect(readAccount).toHaveBeenCalledTimes(1);

    loader.start();
    await loader.refresh();
    expect(readAccount).toHaveBeenCalledTimes(2);
    expect(loader.view().snapshot?.balanceWei).toBe((7n * GHOST).toString());
  });

  it('still shows the new balance when the cache cannot be written', async () => {
    const cache: SnapshotCache = {
      read: () => snapshot(),
      write: async () => {
        throw new Error('disk full');
      },
    };
    const loader = new HomeLoader({ nodeUrl: NODE, address: ADDRESS, cache, readAccount: async () => reading() });
    await loader.refresh();
    expect(loader.view().snapshot?.balanceWei).toBe((7n * GHOST).toString());
  });
});

describe('applyReading', () => {
  it('keeps cached activity', () => {
    const kept: ActivityItem = {
      id: 'k',
      direction: 'sent',
      counterparty: ADDRESS,
      amountWei: '5',
      state: 'pending',
      at: T0 - 1,
    };
    const next = applyReading(snapshot({ activity: [kept] }), reading({ nonce: 2 }), NODE, ADDRESS, T0);
    expect(next.activity).toEqual([kept]);
  });

  it('adds a received payment when the balance went up and nothing was sent', () => {
    const next = applyReading(snapshot(), reading({ balanceWei: (8n * GHOST).toString(), nonce: 1 }), NODE, ADDRESS, T0);
    expect(next.activity).toEqual([
      {
        id: `received-120-${T0}`,
        direction: 'received',
        counterparty: null,
        amountWei: (3n * GHOST).toString(),
        state: 'done',
        at: T0,
      },
    ]);
  });

  it('adds nothing when the account also sent, when the balance fell, or on the first reading', () => {
    expect(applyReading(snapshot(), reading({ nonce: 2 }), NODE, ADDRESS, T0).activity).toEqual([]);
    expect(applyReading(snapshot(), reading({ balanceWei: GHOST.toString() }), NODE, ADDRESS, T0).activity).toEqual([]);
    expect(applyReading(snapshot(), reading({ balanceWei: (5n * GHOST).toString() }), NODE, ADDRESS, T0).activity).toEqual([]);
    expect(applyReading(null, reading(), NODE, ADDRESS, T0).activity).toEqual([]);
  });

  it('keeps at most the activity limit, newest first', () => {
    const many: ActivityItem[] = Array.from({ length: ACTIVITY_LIMIT }, (_, i) => ({
      id: `old-${i}`,
      direction: 'sent',
      counterparty: ADDRESS,
      amountWei: '1',
      state: 'done',
      at: i,
    }));
    const next = applyReading(snapshot({ activity: many }), reading({ balanceWei: (9n * GHOST).toString() }), NODE, ADDRESS, T0);
    expect(next.activity).toHaveLength(ACTIVITY_LIMIT);
    expect(next.activity[0].direction).toBe('received');
    expect(next.activity.map((a) => a.id)).not.toContain('old-0');
  });

  it('a snapshot written to the cache reads back the same', () => {
    const next = applyReading(snapshot(), reading({ balanceWei: (8n * GHOST).toString() }), NODE, ADDRESS, T0);
    expect(readCachedSnapshot(JSON.parse(JSON.stringify(next)), NODE, ADDRESS)).toEqual(next);
  });
});
