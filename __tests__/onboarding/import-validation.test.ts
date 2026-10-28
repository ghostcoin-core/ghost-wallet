import {
  applyFieldText,
  emptyFields,
  importMessage,
  importStatus,
  joinWords,
  splitWords,
} from '../../lib/onboarding/import-validation';

// Ghost's public counting-bytes test words (modules/ghost-core/test-words.ts).
import { TEST_WORDS } from '../../modules/ghost-core/test-words';

const WORDS = TEST_WORDS.split(' ');
// A stand-in for the core's word list: the test words only.
const isWord = jest.fn((word: string) => WORDS.includes(word));

describe('splitWords', () => {
  it('splits on any spaces, new lines and commas, and normalises each word', () => {
    expect(splitWords('  Abandon\namount,  liar\t')).toEqual(['abandon', 'amount', 'liar']);
    expect(splitWords('   ')).toEqual([]);
  });
});

describe('applyFieldText', () => {
  it('fills all 24 boxes when the 24 words are pasted into the first', () => {
    const change = applyFieldText(emptyFields(), 0, TEST_WORDS);

    expect(change.fields).toEqual(WORDS);
    expect(change.focus).toBeNull();
  });

  it('spreads pasted words from the box they are pasted into', () => {
    const change = applyFieldText(emptyFields(), 5, 'abandon amount liar');

    expect(change.fields.slice(4, 9)).toEqual(['', 'abandon', 'amount', 'liar', '']);
    expect(change.focus).toBe(8);
  });

  it('drops pasted words past the last box', () => {
    const change = applyFieldText(emptyFields(), 22, 'abandon amount liar');

    expect(change.fields).toHaveLength(24);
    expect(change.fields.slice(22)).toEqual(['abandon', 'amount']);
    expect(change.focus).toBeNull();
  });

  it('keeps one typed word in its box without moving on', () => {
    const change = applyFieldText(emptyFields(), 2, 'Liar');

    expect(change.fields[2]).toBe('liar');
    expect(change.focus).toBeNull();
  });

  it('moves on to the next box after a word and a space', () => {
    const change = applyFieldText(emptyFields(), 2, 'liar ');

    expect(change.fields[2]).toBe('liar');
    expect(change.focus).toBe(3);
  });

  it('clears a box emptied by the person', () => {
    const fields = applyFieldText(emptyFields(), 0, TEST_WORDS).fields;
    const change = applyFieldText(fields, 3, '');

    expect(change.fields[3]).toBe('');
    expect(change.fields[4]).toBe(WORDS[4]);
  });

  it('does not change the fields it was given', () => {
    const fields = emptyFields();
    applyFieldText(fields, 0, TEST_WORDS);

    expect(fields).toEqual(emptyFields());
  });
});

describe('importStatus', () => {
  beforeEach(() => {
    isWord.mockClear();
  });

  it('is ready when all 24 boxes hold list words', () => {
    expect(importStatus(WORDS, isWord)).toEqual({ ready: true, empty: [], unknown: [] });
  });

  it('is not ready while boxes are empty, and names them', () => {
    const fields = [...WORDS];
    fields[0] = '';
    fields[23] = '  ';

    expect(importStatus(fields, isWord)).toEqual({ ready: false, empty: [1, 24], unknown: [] });
  });

  it('names words that are not in the list', () => {
    const fields = [...WORDS];
    fields[6] = 'cagee';
    fields[9] = 'notaword';

    const status = importStatus(fields, isWord);

    expect(status.ready).toBe(false);
    expect(status.unknown).toEqual([7, 10]);
  });

  it('asks the core about each word normalised, and never about empty boxes', () => {
    const fields = emptyFields();
    fields[0] = ' Abandon ';

    importStatus(fields, isWord);

    expect(isWord).toHaveBeenCalledTimes(1);
    expect(isWord).toHaveBeenCalledWith('abandon');
  });

  it('is not ready with fewer than 24 words', () => {
    expect(importStatus(WORDS.slice(0, 12), isWord).ready).toBe(false);
  });
});

describe('joinWords', () => {
  it('gives the core one normalised phrase', () => {
    expect(joinWords(WORDS.map((word) => ` ${word.toUpperCase()} `))).toBe(TEST_WORDS);
  });
});

describe('importMessage', () => {
  it('says nothing while nothing is wrong', () => {
    expect(importMessage({ ready: false, empty: [3], unknown: [] })).toBeNull();
  });

  it('names one or several unknown words by position, never by the word', () => {
    expect(importMessage({ ready: false, empty: [], unknown: [7] })).toBe(
      'Word 7 is not one of the backup words. Check its spelling.',
    );
    expect(importMessage({ ready: false, empty: [], unknown: [7, 10] })).toBe(
      'Words 7, 10 are not backup words. Check their spelling.',
    );
  });
});
