import type { ActivityItem } from '../../lib/home/activity';
import {
  ACTIVITY_LIMIT,
  HomeLoader,
  type AccountReading,
  type HomeSnapshot,
  type SnapshotCache,
} from '../../lib/home/cache-refresh';
import { HISTORY_WINDOW_BLOCKS, scanHistory, type ScanHistory } from '../../lib/home/history';
import type { FetchLike } from '../../lib/node/rpc';

const NODE = 'http://127.0.0.1:8547';
const ACCOUNT = '0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd';
const OTHER = '0x81d0' + '0'.repeat(32) + 'c7a4';
const FAUCET = '0x3a1c' + '0'.repeat(32) + '9b02';
const GHOST = 10n ** 18n;
const T0 = new Date(2026, 9, 28, 14, 30).getTime();
const TIP = 5_000;

function txHash(n: number): string {
  return '0x' + n.toString(16).padStart(64, '0');
}
function hex(value: number | bigint): string {
  return '0x' + value.toString(16);
}

type FakeTx = { hash: string; from: string; to: string | null; value: bigint };

/**
 * A node holding `blocks` (height to transactions) and `receipts` (hash to
 * status, absent for none). Every call it is asked is kept.
 */
function fakeNode(blocks: Record<number, FakeTx[]>, receipts: Record<string, '0x1' | '0x0' | 'odd'>) {
  const calls: { method: string; params: unknown[] }[] = [];
  const fetchImpl: FetchLike = async (_url, init) => {
    const batch = JSON.parse(String(init.body)) as { id: number; method: string; params: unknown[] }[];
    const answers = batch.map(({ id, method, params }) => {
      calls.push({ method, params });
      if (method === 'eth_getBlockByNumber') {
        const height = Number(BigInt(params[0] as string));
        return {
          id,
          result: {
            number: hex(height),
            hash: txHash(1_000_000 + height),
            timestamp: hex(Math.floor(T0 / 1000) - (TIP - height) * 2),
            transactions: (blocks[height] ?? []).map((tx) => ({
              hash: tx.hash,
              from: tx.from,
              to: tx.to,
              value: hex(tx.value),
              nonce: '0x0',
            })),
          },
        };
      }
      if (method === 'eth_getTransactionReceipt') {
        const status = receipts[params[0] as string];
        return {
          id,
          result: status === undefined ? null : { transactionHash: params[0], status: status === 'odd' ? '0x2' : status },
        };
      }
      return { id, error: { message: `unexpected ${method}` } };
    });
    return { ok: true, status: 200, json: async () => answers } as unknown as Response;
  };
  return { fetchImpl, calls };
}

function memoryCache(initial: unknown = null): SnapshotCache & { written: HomeSnapshot[] } {
  let value = initial;
  const written: HomeSnapshot[] = [];
  return {
    written,
    read: () => value,
    write: (snapshot) => {
      written.push(snapshot);
      value = JSON.parse(JSON.stringify(snapshot));
    },
  };
}

const READING: AccountReading = { balanceWei: ((41999828n * GHOST) / 1_000_000n).toString(), nonce: 2, tipHeight: TIP };

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

/** Lets timers due now run, and what they start. */
function nextTurn(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

function loader(cache: SnapshotCache, scan: ScanHistory, readAccount = async () => READING) {
  return new HomeLoader({ nodeUrl: NODE, address: ACCOUNT, cache, readAccount, scanHistory: scan, now: () => T0 });
}

const RECEIVED: FakeTx = { hash: txHash(1), from: FAUCET, to: ACCOUNT, value: 50n * GHOST };
const SENT: FakeTx = { hash: txHash(2), from: ACCOUNT, to: OTHER, value: 5n * GHOST };
const FAILED: FakeTx = { hash: txHash(3), from: ACCOUNT, to: OTHER, value: 7n * GHOST };
const UNSURE: FakeTx = { hash: txHash(4), from: ACCOUNT, to: OTHER, value: 1n * GHOST };
const STRANGERS: FakeTx = { hash: txHash(5), from: OTHER, to: FAUCET, value: 9n * GHOST };

describe('history after a restore', () => {
  it('fills Activity from the node on a clean start, with each state as its receipt says', async () => {
    const node = fakeNode(
      { [TIP - 30]: [RECEIVED], [TIP - 20]: [SENT, STRANGERS], [TIP - 10]: [FAILED], [TIP]: [UNSURE] },
      { [RECEIVED.hash]: '0x1', [SENT.hash]: '0x1', [FAILED.hash]: '0x0' },
    );
    const cache = memoryCache();
    const home = loader(cache, (url, address, tip, limit) => scanHistory(url, address, tip, limit, node.fetchImpl));

    await home.refresh();
    await home.historyLoaded();

    const activity = home.view().snapshot?.activity ?? [];
    const byHash = Object.fromEntries(activity.map((item) => [item.hash, item]));
    expect(activity).toHaveLength(4);
    expect(byHash[RECEIVED.hash]).toMatchObject({ direction: 'received', counterparty: FAUCET, state: 'done', amountWei: (50n * GHOST).toString() });
    expect(byHash[SENT.hash]).toMatchObject({ direction: 'sent', counterparty: OTHER, state: 'done', amountWei: (5n * GHOST).toString() });
    expect(byHash[FAILED.hash].state).toBe('failed');
    // No receipt: it may still land, so it is pending.
    expect(byHash[UNSURE.hash].state).toBe('pending');
    expect(byHash[STRANGERS.hash]).toBeUndefined();
    expect(home.view().snapshot?.balanceWei).toBe(READING.balanceWei);
    // Written to the cache, so the next launch does not look again.
    expect(cache.written[cache.written.length - 1]).toMatchObject({ historyHeight: TIP, activity });
  });

  it('shows an unclear receipt as pending, never as done', async () => {
    const node = fakeNode({ [TIP]: [SENT] }, { [SENT.hash]: 'odd' });
    expect((await scanHistory(NODE, ACCOUNT, TIP, ACTIVITY_LIMIT, node.fetchImpl))[0].state).toBe('pending');
  });

  it('reads only the blocks of the window, with the calls the app already makes', async () => {
    const node = fakeNode({ [TIP - HISTORY_WINDOW_BLOCKS]: [SENT], [TIP - HISTORY_WINDOW_BLOCKS + 1]: [RECEIVED] }, {});
    const found = await scanHistory(NODE, ACCOUNT, TIP, ACTIVITY_LIMIT, node.fetchImpl);

    expect(found.map((item) => item.hash)).toEqual([RECEIVED.hash]);
    const heights = node.calls.filter((call) => call.method === 'eth_getBlockByNumber').map((call) => Number(BigInt(call.params[0] as string)));
    expect(heights).toHaveLength(HISTORY_WINDOW_BLOCKS);
    expect(Math.min(...heights)).toBe(TIP - HISTORY_WINDOW_BLOCKS + 1);
    expect(Math.max(...heights)).toBe(TIP);
    expect(new Set(node.calls.map((call) => call.method))).toEqual(new Set(['eth_getBlockByNumber', 'eth_getTransactionReceipt']));
  });

  it('keeps at most the activity limit, the newest', async () => {
    const many: Record<number, FakeTx[]> = {};
    for (let i = 0; i < ACTIVITY_LIMIT + 10; i += 1) {
      many[TIP - i] = [{ hash: txHash(100 + i), from: FAUCET, to: ACCOUNT, value: 1n }];
    }
    const found = await scanHistory(NODE, ACCOUNT, TIP, ACTIVITY_LIMIT, fakeNode(many, {}).fetchImpl);
    expect(found).toHaveLength(ACTIVITY_LIMIT);
    expect(found[0].hash).toBe(txHash(100));
  });

  it('delivers the balance before the history answers', async () => {
    const history = deferred<ActivityItem[]>();
    const scan = jest.fn(() => history.promise);
    const home = loader(memoryCache(), scan);

    await home.refresh();
    await nextTurn();

    expect(scan).toHaveBeenCalledWith(NODE, ACCOUNT, TIP, ACTIVITY_LIMIT);
    expect(home.view()).toMatchObject({ source: 'node', refreshing: false, error: null });
    expect(home.view().snapshot?.balanceWei).toBe(READING.balanceWei);
    expect(home.view().snapshot?.activity).toEqual([]);

    history.resolve([
      { id: `tx-${SENT.hash}`, direction: 'sent', counterparty: OTHER, amountWei: '5', state: 'done', at: T0, hash: SENT.hash },
    ]);
    await home.historyLoaded();
    expect(home.view().snapshot?.activity.map((item) => item.hash)).toEqual([SENT.hash]);
  });

  it('starts the history only after the first balance answer', async () => {
    const reading = deferred<AccountReading>();
    const scan = jest.fn(async () => []);
    const home = loader(memoryCache(), scan, () => reading.promise);

    const refreshing = home.refresh();
    await nextTurn();
    expect(scan).not.toHaveBeenCalled();

    reading.resolve(READING);
    await refreshing;
    await nextTurn();
    expect(scan).toHaveBeenCalledTimes(1);
  });

  it('waits the delay before looking, and looks at the next refresh when stopped first', async () => {
    jest.useFakeTimers();
    try {
      const scan = jest.fn(async (): Promise<ActivityItem[]> => []);
      const home = new HomeLoader({
        nodeUrl: NODE,
        address: ACCOUNT,
        cache: memoryCache(),
        readAccount: async () => READING,
        scanHistory: scan,
        historyDelayMs: 2_000,
        now: () => T0,
      });
      await home.refresh();
      jest.advanceTimersByTime(1_999);
      await Promise.resolve();
      expect(scan).not.toHaveBeenCalled();

      home.stop();
      jest.advanceTimersByTime(5_000);
      await Promise.resolve();
      expect(scan).not.toHaveBeenCalled();

      home.start();
      await home.refresh();
      jest.advanceTimersByTime(2_000);
      await home.historyLoaded();
      expect(scan).toHaveBeenCalledTimes(1);
      expect(home.view().snapshot?.historyHeight).toBe(TIP);
    } finally {
      jest.useRealTimers();
    }
  });

  it('leaves the balance and Activity as they were when the history hangs', async () => {
    const kept: ActivityItem = { id: 'kept', direction: 'received', counterparty: null, amountWei: '7', state: 'done', at: T0 - 60_000 };
    const cache = memoryCache({
      version: 1,
      nodeUrl: NODE,
      address: ACCOUNT,
      balanceWei: READING.balanceWei,
      nonce: 2,
      tipHeight: TIP - 1,
      checkedAt: T0 - 60_000,
      activity: [kept],
    });
    const home = loader(cache, () => new Promise(() => {}));

    await home.refresh();
    await home.refresh();

    expect(home.view().snapshot).toMatchObject({ balanceWei: READING.balanceWei, activity: [kept] });
    expect(home.view().snapshot?.historyHeight).toBeUndefined();
    expect(home.view().error).toBeNull();
  });

  it('leaves the balance and Activity as they were when the history fails, and looks again later', async () => {
    const scan = jest.fn(async (): Promise<ActivityItem[]> => {
      throw new Error('the node refused a call');
    });
    const cache = memoryCache();
    const home = loader(cache, scan);

    await home.refresh();
    await home.historyLoaded();

    expect(home.view()).toMatchObject({ source: 'node', error: null });
    expect(home.view().snapshot).toMatchObject({ balanceWei: READING.balanceWei, activity: [] });
    expect(home.view().snapshot?.historyHeight).toBeUndefined();

    scan.mockImplementationOnce(async () => [
      { id: `tx-${SENT.hash}`, direction: 'sent', counterparty: OTHER, amountWei: '5', state: 'done', at: T0, hash: SENT.hash },
    ]);
    await home.refresh();
    await home.historyLoaded();
    expect(home.view().snapshot?.activity).toHaveLength(1);
    expect(scan).toHaveBeenCalledTimes(2);
  });

  it('does not look again once the history is in the cache', async () => {
    const scan = jest.fn(async (): Promise<ActivityItem[]> => []);
    const cache = memoryCache();
    const first = loader(cache, scan);
    await first.refresh();
    await first.historyLoaded();
    expect(cache.written[cache.written.length - 1].historyHeight).toBe(TIP);

    const next = loader(cache, scan);
    await next.refresh();
    await next.historyLoaded();
    expect(scan).toHaveBeenCalledTimes(1);
    expect(next.view().snapshot?.historyHeight).toBe(TIP);
  });

  it('shows a payment once when the cache and the chain both have it', async () => {
    const seen: ActivityItem = { id: 'seen', direction: 'sent', counterparty: OTHER, amountWei: '5', state: 'pending', at: T0 - 9_000, hash: SENT.hash };
    // Home saw the faucet's 50 come in as the balance going up, with no transaction.
    const grew: ActivityItem = { id: 'received-1', direction: 'received', counterparty: null, amountWei: (50n * GHOST).toString(), state: 'done', at: T0 - 8_000 };
    const cache = memoryCache({
      version: 1,
      nodeUrl: NODE,
      address: ACCOUNT,
      balanceWei: READING.balanceWei,
      nonce: 2,
      tipHeight: TIP,
      checkedAt: T0 - 10_000,
      activity: [seen, grew],
    });
    const node = fakeNode({ [TIP - 2]: [RECEIVED], [TIP - 1]: [SENT] }, { [RECEIVED.hash]: '0x1', [SENT.hash]: '0x1' });
    const home = loader(cache, (url, address, tip, limit) => scanHistory(url, address, tip, limit, node.fetchImpl));

    await home.refresh();
    await home.historyLoaded();

    const activity = home.view().snapshot?.activity ?? [];
    expect(activity.map((item) => item.hash)).toEqual([SENT.hash, RECEIVED.hash]);
    expect(activity.find((item) => item.hash === SENT.hash)?.state).toBe('done');
  });
});
