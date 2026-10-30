// Home's balance and activity: shown at once from the cache with its age, then
// refreshed from the node in the background. Nothing waits on the node: the
// cached view is there before the first answer, and a failed refresh keeps it
// and says how old it is.
import { mergeActivity, parseActivityItem, sortActivity, type ActivityItem } from './activity';
import { formatAge } from './balance-format';
import type { ScanHistory } from './history';

export const SNAPSHOT_VERSION = 1;

/** How many activity items the cache keeps. */
export const ACTIVITY_LIMIT = 50;

/** What home last knew about one account at one node. */
export type HomeSnapshot = {
  version: typeof SNAPSHOT_VERSION;
  nodeUrl: string;
  address: string;
  /** The balance in wei, as decimal digits. */
  balanceWei: string;
  nonce: number;
  tipHeight: number;
  /** When the node gave this balance, in milliseconds since 1970. */
  checkedAt: number;
  activity: ActivityItem[];
  /**
   * The tip up to which the account's recent payments were looked up on
   * chain (lib/home/history.ts); absent until then, and in older caches.
   */
  historyHeight?: number;
};

/** One answer of the node about the account, through the native core. */
export type AccountReading = {
  balanceWei: string;
  nonce: number;
  tipHeight: number;
};

export type HomeView = {
  snapshot: HomeSnapshot | null;
  /** Where the snapshot came from: nothing yet, the cache, or the node this session. */
  source: 'none' | 'cache' | 'node';
  refreshing: boolean;
  /** Why the last refresh failed; null once one succeeds. */
  error: string | null;
};

export type SnapshotCache = {
  /** The cached value, read at once; null when there is none. */
  read(): unknown;
  write(snapshot: HomeSnapshot): Promise<void> | void;
};

export type ReadAccount = (nodeUrl: string, address: string) => Promise<AccountReading>;

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

/**
 * The cached snapshot if it is well formed and belongs to this node and this
 * account; null otherwise. A balance from another node or account is never
 * shown.
 */
export function readCachedSnapshot(raw: unknown, nodeUrl: string, address: string): HomeSnapshot | null {
  if (typeof raw !== 'object' || raw === null) {
    return null;
  }
  const s = raw as Record<string, unknown>;
  if (
    s.version !== SNAPSHOT_VERSION ||
    s.nodeUrl !== nodeUrl ||
    typeof s.address !== 'string' ||
    s.address.toLowerCase() !== address.toLowerCase() ||
    typeof s.balanceWei !== 'string' ||
    !/^[0-9]+$/.test(s.balanceWei) ||
    !isCount(s.nonce) ||
    !isCount(s.tipHeight) ||
    !isCount(s.checkedAt) ||
    !Array.isArray(s.activity) ||
    (s.historyHeight !== undefined && !isCount(s.historyHeight))
  ) {
    return null;
  }
  const activity = s.activity.map(parseActivityItem).filter((item): item is ActivityItem => item !== null);
  return {
    version: SNAPSHOT_VERSION,
    nodeUrl,
    address: s.address,
    balanceWei: s.balanceWei,
    nonce: s.nonce,
    tipHeight: s.tipHeight,
    checkedAt: s.checkedAt,
    activity,
    ...(s.historyHeight === undefined ? {} : { historyHeight: s.historyHeight as number }),
  };
}

/**
 * The snapshot after a reading. Cached activity is kept. When the balance
 * went up while the account sent nothing (same nonce), the difference came in
 * and is added as a received payment from an unknown sender.
 */
export function applyReading(
  previous: HomeSnapshot | null,
  reading: AccountReading,
  nodeUrl: string,
  address: string,
  now: number,
): HomeSnapshot {
  let activity = previous?.activity ?? [];
  if (previous && reading.nonce === previous.nonce) {
    const gained = BigInt(reading.balanceWei) - BigInt(previous.balanceWei);
    if (gained > 0n) {
      const received: ActivityItem = {
        id: `received-${reading.tipHeight}-${now}`,
        direction: 'received',
        counterparty: null,
        amountWei: gained.toString(),
        state: 'done',
        at: now,
      };
      activity = [received, ...activity];
    }
  }
  return {
    version: SNAPSHOT_VERSION,
    nodeUrl,
    address,
    balanceWei: reading.balanceWei,
    nonce: reading.nonce,
    tipHeight: reading.tipHeight,
    checkedAt: now,
    activity: sortActivity(activity).slice(0, ACTIVITY_LIMIT),
    ...(previous?.historyHeight === undefined ? {} : { historyHeight: previous.historyHeight }),
  };
}

/** The snapshot with the payments found on chain up to `height` added, each once. */
export function applyHistory(snapshot: HomeSnapshot, found: readonly ActivityItem[], height: number): HomeSnapshot {
  return {
    ...snapshot,
    activity: sortActivity(mergeActivity(snapshot.activity, found)).slice(0, ACTIVITY_LIMIT),
    historyHeight: height,
  };
}

/** What the line under the balance says. */
export function balanceStatus(view: HomeView, now: number): string {
  const { snapshot } = view;
  if (!snapshot) {
    return view.error ? 'Could not reach the node. Check it in Settings.' : 'Asking the node for your balance';
  }
  const age = formatAge(snapshot.checkedAt, now);
  if (view.error) {
    return `Node not reachable, last updated ${age}`;
  }
  if (view.source === 'node') {
    return `Up to date, ${age}`;
  }
  return `Last updated ${age}`;
}

function message(error: unknown): string {
  return error instanceof Error && error.message ? error.message : 'the node did not answer';
}

type Listener = () => void;

/**
 * Home's data for one account at one node. The constructor reads the cache, so
 * `view()` has the cached balance at once; `refresh()` asks the node in the
 * background, updates the view and writes the cache. Overlapping refreshes
 * share one request. While stopped (`stop()`, until `start()`) nothing is
 * asked and a late answer changes nothing.
 */
export class HomeLoader {
  private state: HomeView;
  private readonly listeners = new Set<Listener>();
  private inFlight: Promise<void> | null = null;
  private history: Promise<void> | null = null;
  private historyTimer: ReturnType<typeof setTimeout> | null = null;
  private stopped = false;

  constructor(
    private readonly options: {
      nodeUrl: string;
      address: string;
      cache: SnapshotCache;
      readAccount: ReadAccount;
      /** Looks up the account's recent payments on chain once, after the first balance. */
      scanHistory?: ScanHistory;
      /** How long after the first balance the history lookup starts; 0 by default. */
      historyDelayMs?: number;
      now?: () => number;
    },
  ) {
    let cached: HomeSnapshot | null = null;
    try {
      cached = readCachedSnapshot(options.cache.read(), options.nodeUrl, options.address);
    } catch {
      cached = null;
    }
    this.state = { snapshot: cached, source: cached ? 'cache' : 'none', refreshing: false, error: null };
  }

  view(): HomeView {
    return this.state;
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /** Asks the node now; resolves when the answer (or the failure) is in the view. Never rejects. */
  refresh(): Promise<void> {
    if (this.stopped) {
      return Promise.resolve();
    }
    if (!this.inFlight) {
      this.inFlight = this.run().finally(() => {
        this.inFlight = null;
      });
    }
    return this.inFlight;
  }

  /** Stops refreshing: a refresh still in flight is dropped, and a history lookup not started yet waits for the next refresh. */
  stop(): void {
    this.stopped = true;
    if (this.historyTimer) {
      clearTimeout(this.historyTimer);
      this.historyTimer = null;
      this.history = null;
    }
  }

  start(): void {
    this.stopped = false;
  }

  private now(): number {
    return (this.options.now ?? Date.now)();
  }

  private set(next: Partial<HomeView>): void {
    if (this.stopped) {
      return;
    }
    this.state = { ...this.state, ...next };
    for (const listener of this.listeners) {
      listener();
    }
  }

  private async run(): Promise<void> {
    const { nodeUrl, address, cache, readAccount } = this.options;
    this.set({ refreshing: true });
    let reading: AccountReading;
    try {
      reading = await readAccount(nodeUrl, address);
    } catch (error) {
      this.set({ refreshing: false, error: message(error) });
      return;
    }
    if (this.stopped) {
      return;
    }
    const snapshot = applyReading(this.state.snapshot, reading, nodeUrl, address, this.now());
    this.set({ snapshot, source: 'node', refreshing: false, error: null });
    // Never awaited: the balance is shown and cached whatever the history does.
    this.startHistory(snapshot);
    try {
      await cache.write(snapshot);
    } catch {
      // The view already shows the new balance; the next refresh writes again.
    }
  }

  /** Resolves once the history lookup started, if any, is in the view or failed. Never rejects. */
  historyLoaded(): Promise<void> {
    return this.history ?? Promise.resolve();
  }

  /**
   * Looks up the account's recent payments on chain, in the background, when
   * this account has never had them looked up (a restore, or a cache from
   * before): up to the tip of the balance just shown.
   */
  private startHistory(snapshot: HomeSnapshot): void {
    const scan = this.options.scanHistory;
    if (!scan || this.history || snapshot.historyHeight !== undefined) {
      return;
    }
    const loading: Promise<void> = new Promise<void>((resolve) => {
      this.historyTimer = setTimeout(resolve, this.options.historyDelayMs ?? 0);
    })
      .then(() => {
        this.historyTimer = null;
        return this.stopped ? false : this.loadHistory(scan, snapshot.tipHeight);
      })
      .then((done) => {
        if (!done && this.history === loading) {
          // The next refresh looks again.
          this.history = null;
        }
      });
    this.history = loading;
  }

  /** Whether the history is in the view; false when it failed or came while stopped. */
  private async loadHistory(scan: ScanHistory, height: number): Promise<boolean> {
    const { nodeUrl, address, cache } = this.options;
    let found: ActivityItem[];
    try {
      found = await scan(nodeUrl, address, height, ACTIVITY_LIMIT);
    } catch {
      // Activity stays as it was.
      return false;
    }
    const current = this.state.snapshot;
    if (this.stopped || !current) {
      return false;
    }
    if (current.historyHeight !== undefined) {
      return true;
    }
    const snapshot = applyHistory(current, found, height);
    this.set({ snapshot });
    try {
      await cache.write(snapshot);
    } catch {
      // The view shows it; the next refresh writes the snapshot again.
    }
    return true;
  }
}
