// While Summon looks a Phantom Key's coins up in the coin tree, the screen
// says so. A long test chain makes the lookup slow; after a while the screen
// says that too, so a person does not think the app has stopped.
import { useEffect, useState } from 'react';

export const LOOKING_UP = "Looking up this key's coins…";
export const SLOW_NOTE = 'This can take a minute on a long chain.';
export const SLOW_AFTER_MS = 15_000;

/** True once `active` has stayed true for `afterMs`; false again as soon as it ends. */
export function useSlowAfter(active: boolean, afterMs: number = SLOW_AFTER_MS): boolean {
  const [slow, setSlow] = useState(false);
  useEffect(() => {
    if (!active) {
      return;
    }
    const timer = setTimeout(() => setSlow(true), afterMs);
    return () => {
      clearTimeout(timer);
      setSlow(false);
    };
  }, [active, afterMs]);
  return active && slow;
}
