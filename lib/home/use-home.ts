// Home's data in a component: the cached view at once, a refresh in the
// background when the screen opens, when the app comes back and every 20
// seconds while it shows. After a restore, the account's recent payments are
// looked up on chain in the background once the balance is shown.
import { useEffect, useMemo, useState, useSyncExternalStore } from 'react';
import { AppState } from 'react-native';

import { jsonFile } from '../storage';
import { subscribePending } from '../vanish/pending';
import { paymentKit } from '../vanish/use-payment';
import type { ActivityItem } from './activity';
import { ACTIVITY_LIMIT, HomeLoader, type HomeView, type ReadAccount, type SnapshotCache } from './cache-refresh';
import { scanHistory as scanRecentBlocks, type ScanHistory } from './history';
import { readAccountZero } from './read-account';
import { activityWithSaved, savedActivity, savedCredits, savedHashes } from './saved-activity';

export const REFRESH_EVERY_MS = 20_000;

/**
 * How long after the first balance the account's recent payments are looked
 * up on chain: the first screen's own calls to the node go first.
 */
export const HISTORY_DELAY_MS = 2_000;

const homeCache: SnapshotCache = jsonFile('home-cache.json');

const EMPTY: HomeView = { snapshot: null, source: 'none', refreshing: false, error: null };
const IDLE = { subscribe: () => () => {}, get: () => EMPTY };

export function useHome(
  nodeUrl: string,
  address: string | null,
  options: { cache?: SnapshotCache; readAccount?: ReadAccount; scanHistory?: ScanHistory } = {},
): { view: HomeView; refresh: () => Promise<void> } {
  const cache = options.cache ?? homeCache;
  const readAccount = options.readAccount ?? readAccountZero;
  const scanHistory = options.scanHistory ?? scanRecentBlocks;
  // One loader per node and account: it reads the cache as it is made, so the
  // first render already has the cached view.
  const loader = useMemo(
    () => (address ? new HomeLoader({ nodeUrl, address, cache, readAccount, scanHistory, historyDelayMs: HISTORY_DELAY_MS }) : null),
    [nodeUrl, address, cache, readAccount, scanHistory],
  );

  useEffect(() => {
    if (!loader) {
      return;
    }
    loader.start();
    void loader.refresh();
    const timer = setInterval(() => void loader.refresh(), REFRESH_EVERY_MS);
    const subscription = AppState.addEventListener('change', (state) => {
      if (state === 'active') {
        void loader.refresh();
      }
    });
    return () => {
      clearInterval(timer);
      subscription.remove();
      loader.stop();
    };
  }, [loader]);

  const store = useMemo(
    () => (loader ? { subscribe: (listener: () => void) => loader.subscribe(listener), get: () => loader.view() } : IDLE),
    [loader],
  );
  const view = useSyncExternalStore(store.subscribe, store.get);
  return { view, refresh: async () => loader?.refresh() };
}

function readSaved(kit: ReturnType<typeof paymentKit>) {
  return { items: savedActivity(kit), hashes: savedHashes(kit), credits: savedCredits(kit) };
}

/**
 * Activity besides the pending rows: `kept` (what Home cached) with the
 * sends, Vanishes, Summons and Claims this phone saved that settled, failed or
 * conflicted, read again whenever a payment moves.
 */
export function useActivity(nodeUrl: string, kept: readonly ActivityItem[]): ActivityItem[] {
  const kit = useMemo(() => paymentKit(nodeUrl), [nodeUrl]);
  const [saved, setSaved] = useState(() => readSaved(kit));

  useEffect(() => {
    const update = () => setSaved(readSaved(kit));
    update();
    return subscribePending(update);
  }, [kit]);

  return useMemo(() => activityWithSaved(kept, saved.items, saved.hashes, ACTIVITY_LIMIT, saved.credits), [kept, saved]);
}

/** The current time, ticking every `everyMs` so ages on screen stay right. */
export function useNow(everyMs = 15_000): number {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), everyMs);
    return () => clearInterval(timer);
  }, [everyMs]);
  return now;
}
