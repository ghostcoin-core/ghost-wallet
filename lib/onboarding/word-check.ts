// Check words: after the backup screen, the person types three of their 24
// words from paper. The words themselves are compared by the native core; this
// file only picks which positions to ask for and reads the answers.

export const WORD_COUNT = 24;
export const CHECK_COUNT = 3;

/** A typed word as the core compares it: no surrounding spaces, lowercase. */
export function normaliseWord(typed: string): string {
  return typed.trim().toLowerCase();
}

/**
 * Picks `count` different positions (1 to `total`) to ask for, in ascending
 * order. `random` returns a number in [0, 1), like Math.random.
 */
export function pickCheckPositions(
  random: () => number = Math.random,
  count: number = CHECK_COUNT,
  total: number = WORD_COUNT,
): number[] {
  if (!Number.isInteger(count) || !Number.isInteger(total) || count < 1 || count > total) {
    throw new RangeError(`cannot pick ${count} of ${total} positions`);
  }
  // A partial Fisher-Yates shuffle of 1..total: every position is equally likely.
  const positions = Array.from({ length: total }, (_, index) => index + 1);
  for (let index = 0; index < count; index += 1) {
    const offset = Math.min(Math.floor(random() * (total - index)), total - index - 1);
    const swap = index + Math.max(offset, 0);
    [positions[index], positions[swap]] = [positions[swap], positions[index]];
  }
  return positions.slice(0, count).sort((a, b) => a - b);
}

export type WordCheckResult = {
  /** Every asked word was typed and matches. */
  passed: boolean;
  /** Positions left empty. */
  missing: number[];
  /** Positions typed but not matching the backup. */
  wrong: number[];
};

/**
 * Checks the typed answers. `matches(position, word)` asks the native core
 * whether the word at that position of the new account is `word`.
 */
export function checkTypedWords(
  positions: readonly number[],
  typed: Readonly<Record<number, string>>,
  matches: (position: number, word: string) => boolean,
): WordCheckResult {
  const missing: number[] = [];
  const wrong: number[] = [];
  for (const position of positions) {
    const word = normaliseWord(typed[position] ?? '');
    if (word === '') {
      missing.push(position);
    } else if (!matches(position, word)) {
      wrong.push(position);
    }
  }
  return { passed: positions.length > 0 && missing.length === 0 && wrong.length === 0, missing, wrong };
}

/** Whether every asked position has something typed, so Confirm can be pressed. */
export function allTyped(positions: readonly number[], typed: Readonly<Record<number, string>>): boolean {
  return positions.length > 0 && positions.every((position) => normaliseWord(typed[position] ?? '') !== '');
}
