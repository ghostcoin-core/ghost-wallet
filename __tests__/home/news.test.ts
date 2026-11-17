import { newsColumns, newsRows, SAMPLE_NEWS } from '../../lib/home/news';

describe('news layout', () => {
  it('puts two stories side by side on a phone and on the folded or upright Duo', () => {
    expect(newsColumns(393, 852, false)).toBe(2);
    expect(newsColumns(466, 678, false)).toBe(2);
    expect(newsColumns(626, 890, true)).toBe(2);
  });

  it('puts four side by side on the open Duo held sideways', () => {
    expect(newsColumns(890, 626, true)).toBe(4);
  });

  it('splits the stories into rows in order, keeping a short last row', () => {
    const ids = (columns: number) => newsRows(SAMPLE_NEWS, columns).map((row) => row.map((story) => story.id));

    expect(ids(2)).toEqual([
      ['network-update', 'quantum-safe'],
      ['new-cards', 'vanish-summon'],
    ]);
    expect(ids(4)).toEqual([['network-update', 'quantum-safe', 'new-cards', 'vanish-summon']]);
    expect(ids(3)).toEqual([['network-update', 'quantum-safe', 'new-cards'], ['vanish-summon']]);
  });

  it('gives every sample story its own id', () => {
    expect(new Set(SAMPLE_NEWS.map((story) => story.id)).size).toBe(SAMPLE_NEWS.length);
  });
});
