import { FOLD_GAP, foldMode, leftColumnWidth, topOfFoldHeight } from '../../lib/layout';

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

describe('how a screen sits around the fold', () => {
  it('is one column on a phone and on the folded Duo', () => {
    expect(foldMode(393, 852)).toBe('one');
    expect(foldMode(466, 678)).toBe('one');
  });

  it('is sideways on the open Duo held sideways and upright when it is held upright', () => {
    expect(foldMode(890, 626)).toBe('sideways');
    expect(foldMode(626, 890)).toBe('upright');
  });

  it('held upright, ends the top part half a gap above the middle of the screen', () => {
    const above = 47 + 68;

    expect(above + topOfFoldHeight(890, above) + FOLD_GAP / 2).toBe(890 / 2);
    expect(topOfFoldHeight(100, 400)).toBe(0);
  });
});
