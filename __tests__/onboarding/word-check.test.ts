import {
  allTyped,
  CHECK_COUNT,
  checkTypedWords,
  normaliseWord,
  pickCheckPositions,
  WORD_COUNT,
} from '../../lib/onboarding/word-check';

// Plain test words standing in for the 24 the native core would hold.
const HELD = Array.from({ length: WORD_COUNT }, (_, index) => `word${index + 1}`);
const matches = jest.fn((position: number, word: string) => HELD[position - 1] === word);

/** A fixed sequence of "random" numbers, repeated. */
function sequence(...values: number[]): () => number {
  let next = 0;
  return () => values[next++ % values.length];
}

describe('normaliseWord', () => {
  it('drops surrounding spaces and capitals, as the core compares words', () => {
    expect(normaliseWord('  Abandon \n')).toBe('abandon');
  });
});

describe('pickCheckPositions', () => {
  it('asks for three different positions between 1 and 24, in order', () => {
    for (let run = 0; run < 200; run += 1) {
      const positions = pickCheckPositions();
      expect(positions).toHaveLength(CHECK_COUNT);
      expect(new Set(positions).size).toBe(CHECK_COUNT);
      expect([...positions].sort((a, b) => a - b)).toEqual(positions);
      for (const position of positions) {
        expect(Number.isInteger(position)).toBe(true);
        expect(position).toBeGreaterThanOrEqual(1);
        expect(position).toBeLessThanOrEqual(WORD_COUNT);
      }
    }
  });

  it('follows the random source', () => {
    expect(pickCheckPositions(sequence(0))).toEqual([1, 2, 3]);
    // The highest value the source can return takes the last position left.
    expect(pickCheckPositions(sequence(0.999999))).toEqual([1, 2, 24]);
    expect(pickCheckPositions(sequence(3.5 / 24, 9.5 / 23, 16.5 / 22))).toEqual([4, 11, 19]);
  });

  it('can reach every position', () => {
    const seen = new Set<number>();
    for (let step = 0; step < WORD_COUNT; step += 1) {
      pickCheckPositions(sequence(step / WORD_COUNT, 0, 0)).forEach((position) => seen.add(position));
    }
    expect(seen.size).toBe(WORD_COUNT);
  });

  it('stays in range when the source misbehaves', () => {
    for (const value of [1, 1.5, -0.2]) {
      const positions = pickCheckPositions(sequence(value));
      expect(new Set(positions).size).toBe(CHECK_COUNT);
      positions.forEach((position) => {
        expect(position).toBeGreaterThanOrEqual(1);
        expect(position).toBeLessThanOrEqual(WORD_COUNT);
      });
    }
  });

  it('refuses counts it cannot fill', () => {
    expect(() => pickCheckPositions(Math.random, 0)).toThrow(RangeError);
    expect(() => pickCheckPositions(Math.random, 25)).toThrow(RangeError);
  });
});

describe('checkTypedWords', () => {
  const positions = [4, 11, 19];

  beforeEach(() => {
    matches.mockClear();
  });

  it('passes when every asked word matches the held words', () => {
    const result = checkTypedWords(positions, { 4: 'word4', 11: ' Word11 ', 19: 'word19' }, matches);

    expect(result).toEqual({ passed: true, missing: [], wrong: [] });
    expect(matches).toHaveBeenCalledWith(11, 'word11');
  });

  it('fails and names the word that does not match', () => {
    const result = checkTypedWords(positions, { 4: 'word4', 11: 'word12', 19: 'word19' }, matches);

    expect(result).toEqual({ passed: false, missing: [], wrong: [11] });
  });

  it('fails when a word from another position is typed', () => {
    const result = checkTypedWords(positions, { 4: 'word19', 11: 'word11', 19: 'word4' }, matches);

    expect(result.passed).toBe(false);
    expect(result.wrong).toEqual([4, 19]);
  });

  it('fails without asking the core about empty boxes', () => {
    const result = checkTypedWords(positions, { 4: 'word4', 11: '   ' }, matches);

    expect(result).toEqual({ passed: false, missing: [11, 19], wrong: [] });
    expect(matches).toHaveBeenCalledTimes(1);
  });

  it('never passes with nothing to check', () => {
    expect(checkTypedWords([], {}, matches).passed).toBe(false);
  });
});

describe('allTyped', () => {
  it('is true only when every asked box has a word', () => {
    expect(allTyped([4, 11], { 4: 'a', 11: 'b' })).toBe(true);
    expect(allTyped([4, 11], { 4: 'a', 11: ' ' })).toBe(false);
    expect(allTyped([4, 11], { 4: 'a' })).toBe(false);
    expect(allTyped([], {})).toBe(false);
  });
});
