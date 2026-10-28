// Home's data in a component: the cached view at once, a refresh in the
// background when the screen opens, when the app comes back and every 20
// seconds while it shows.
import { useEffect, useMemo, useState, useSyncExternalStore } from 'react';
import { AppState } from 'react-native';

import { jsonFile } from '../storage';
import { HomeLoader, type HomeView, type ReadAccount, type SnapshotCache } from './cache-refresh';
import { readAccountZero } from './read-account';

export const REFRESH_EVERY_MS = 20_000;

const homeCache: SnapshotCache = jsonFile('home-cache.json');

const EMPTY: HomeView = { snapshot: null, source: 'none', refreshing: false, error: null };
const IDLE = { subscribe: () => () => {}, get: () => EMPTY };

export function useHome(
  nodeUrl: string,
  address: string | null,
  options: { cache?: SnapshotCache; readAccount?: ReadAccount } = {},
): { view: HomeView; refresh: () => void } {
  const cache = options.cache ?? homeCache;
  const readAccount = options.readAccount ?? readAccountZero;
  // One loader per node and account: it reads the cache as it is made, so the
  // first render already has the cached view.
  const loader = useMemo(
    () => (address ? new HomeLoader({ nodeUrl, address, cache, readAccount }) : null),
    [nodeUrl, address, cache, readAccount],
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
  return { view, refresh: () => void loader?.refresh() };
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
