// Which layout a window gets: a regular iPhone (393 x 852 pt), the iPhone Duo
// folded (466 x 678 pt, shorter, so screens scroll) or open (626 x 890 pt, two
// columns where the mockups use two). Same breakpoint as docs/mockups. Only the
// open Duo is wide enough for two columns.
import { useWindowDimensions } from 'react-native';

export type Layout = {
  /** Two columns side by side (iPhone Duo open). */
  twoColumns: boolean;
  width: number;
  height: number;
};

export const TWO_COLUMN_MIN_WIDTH = 560;

export function layoutFor(width: number, height: number): Layout {
  return { twoColumns: width >= TWO_COLUMN_MIN_WIDTH, width, height };
}

export function useLayout(): Layout {
  const { width, height } = useWindowDimensions();
  return layoutFor(width, height);
}

export type ScreenLayout = 'one-column' | 'two-column';

export function screenLayout(width: number): ScreenLayout {
  return width >= TWO_COLUMN_MIN_WIDTH ? 'two-column' : 'one-column';
}

/** The space kept clear between the two columns, where the open Duo folds. */
export const FOLD_GAP = 32;

/**
 * How wide the left of two columns is, so the gap after it sits on the fold.
 * Held sideways the open Duo folds down the middle of the screen, which is
 * not the middle of the content: the side rail takes room on one edge. Held
 * upright the fold runs across the screen, so the columns are equal halves.
 */
export function leftColumnWidth(window: {
  width: number;
  height: number;
  insetLeft: number;
  insetRight: number;
  padding: number;
}): number {
  const { width, height, insetLeft, insetRight, padding } = window;
  const left =
    width > height
      ? width / 2 - insetLeft - padding - FOLD_GAP / 2
      : (width - insetLeft - insetRight - 2 * padding - FOLD_GAP) / 2;
  return Math.max(0, left);
}

/** How a screen sits around the fold: one column, or two parts either side of it. */
export type FoldMode = 'one' | 'sideways' | 'upright';

/**
 * Folded, or on a phone that does not fold: one column. Open and held
 * sideways, the fold runs down the screen; open and held upright, across it.
 */
export function foldMode(width: number, height: number): FoldMode {
  if (width < TWO_COLUMN_MIN_WIDTH) {
    return 'one';
  }
  return width > height ? 'sideways' : 'upright';
}

/**
 * Held upright, how tall the part above the fold is, so the gap after it sits
 * on the fold: half the screen, less what is above that part and half the gap.
 */
export function topOfFoldHeight(height: number, above: number): number {
  return Math.max(0, height / 2 - above - FOLD_GAP / 2);
}
