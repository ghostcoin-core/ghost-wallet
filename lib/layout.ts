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
