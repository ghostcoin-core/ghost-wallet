// The stories under Home. There is no news feed yet, so these are fixed
// samples; a feed replaces this list without the screen changing.
export type NewsTint = 'violet' | 'mist';

export type NewsStory = {
  id: string;
  title: string;
  tint: NewsTint;
};

export const SAMPLE_NEWS: readonly NewsStory[] = [
  { id: 'network-update', title: 'Specter network update ships this week', tint: 'violet' },
  { id: 'quantum-safe', title: 'How quantum-safe accounts protect you', tint: 'mist' },
  { id: 'new-cards', title: 'A new batch of Specter cards is ready', tint: 'violet' },
  { id: 'vanish-summon', title: 'What Vanish and Summon do, in plain words', tint: 'mist' },
];

/** How many stories sit side by side: four on the open Duo held sideways, else two. */
export function newsColumns(width: number, height: number, twoColumns: boolean): 2 | 4 {
  return twoColumns && width > height ? 4 : 2;
}

/** The stories in rows of `columns`, in order. */
export function newsRows(stories: readonly NewsStory[], columns: number): NewsStory[][] {
  const rows: NewsStory[][] = [];
  for (let start = 0; start < stories.length; start += columns) {
    rows.push(stories.slice(start, start + columns));
  }
  return rows;
}
