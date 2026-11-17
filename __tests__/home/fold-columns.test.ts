import { FOLD_GAP, leftColumnWidth } from '../../lib/layout';

describe('left column on the open Duo', () => {
  it('held sideways, ends half a gap before the middle of the screen, whatever the side rail takes', () => {
    const padding = 28;
    for (const insetRight of [0, 84]) {
      const left = leftColumnWidth({ width: 890, height: 626, insetLeft: 0, insetRight, padding });

      // The column starts after the padding; the gap after it is centred on the fold.
      expect(padding + left + FOLD_GAP / 2).toBe(890 / 2);
    }
  });

  it('held sideways, allows for a rail on the left edge', () => {
    const left = leftColumnWidth({ width: 890, height: 626, insetLeft: 84, insetRight: 0, padding: 28 });

    expect(84 + 28 + left + FOLD_GAP / 2).toBe(890 / 2);
  });

  it('held upright, is half of the content less the gap', () => {
    const left = leftColumnWidth({ width: 626, height: 890, insetLeft: 0, insetRight: 0, padding: 28 });

    expect(left * 2 + FOLD_GAP).toBe(626 - 2 * 28);
  });

  it('is never negative', () => {
    expect(leftColumnWidth({ width: 100, height: 50, insetLeft: 84, insetRight: 0, padding: 28 })).toBe(0);
  });
});
