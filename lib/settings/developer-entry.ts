// The hidden way to the bench screen: tap the version row seven times in a row.

export const DEVELOPER_TAPS = 7;
const WINDOW_MS = 3_000;

/** Returns a tap handler that answers true on the seventh tap within three seconds of the first. */
export function createTapCounter(now: () => number = Date.now, needed = DEVELOPER_TAPS): () => boolean {
  let taps = 0;
  let first = 0;
  return () => {
    const time = now();
    if (taps === 0 || time - first > WINDOW_MS) {
      taps = 0;
      first = time;
    }
    taps += 1;
    if (taps >= needed) {
      taps = 0;
      return true;
    }
    return false;
  };
}
