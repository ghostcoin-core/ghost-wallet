import {
  KEY_DIGIT_COUNT,
  KEY_WORD_COUNT,
  RECOVERY_WORDS_IN_KEY_FIELD,
  WRONG_FORMAT,
  keyShape,
  keyWords,
  keyWordsMessage,
  normaliseKeyText,
  parseWordsCheck,
  readyToCheck,
  typingMessage,
} from '../../lib/vanish/word-validation';

// Words from the public word list only: no real key or account.
const WORDS = Array.from({ length: 24 }, (_, i) => ['abandon', 'ability', 'able', 'about'][i % 4]);
const DIGITS = Array.from({ length: 21 }, (_, i) => String(1000 + i)).join(' ');

describe('the shape of a typed key', () => {
  it('reads letters without digits as words, ignoring case and spacing', () => {
    expect(keyShape(`  ${WORDS.join('   ').toUpperCase()}\n`)).toEqual({ kind: 'words', count: 24 });
    expect(keyWords(' Abandon\tABILITY  able ')).toEqual(['abandon', 'ability', 'able']);
  });

  it('reads digits with spaces or hyphens as digits', () => {
    expect(keyShape(DIGITS)).toEqual({ kind: 'digits', count: 84 });
    expect(keyShape(DIGITS.replace(/ /g, '-'))).toEqual({ kind: 'digits', count: 84 });
  });

  it('calls letters and digits together, or other marks, mixed', () => {
    expect(keyShape('abandon 1234')).toEqual({ kind: 'mixed' });
    expect(keyShape('abandon, ability')).toEqual({ kind: 'mixed' });
    expect(keyShape('1234/5678')).toEqual({ kind: 'mixed' });
  });

  it('is empty for nothing but spaces', () => {
    expect(keyShape('  \n ')).toEqual({ kind: 'empty' });
  });
});

describe('when the core is asked', () => {
  it('asks only once the text has a key length: 24 words or 84 digits', () => {
    expect(KEY_WORD_COUNT).toBe(24);
    expect(KEY_DIGIT_COUNT).toBe(84);
    expect(readyToCheck(WORDS.join(' '))).toBe(true);
    expect(readyToCheck(WORDS.slice(0, 23).join(' '))).toBe(false);
    expect(readyToCheck([...WORDS, 'able'].join(' '))).toBe(false);
    expect(readyToCheck(DIGITS)).toBe(true);
    expect(readyToCheck(DIGITS.slice(0, -1))).toBe(false);
    // The old 12- and 24-group digit keys are not keys.
    expect(readyToCheck('1234 '.repeat(12))).toBe(false);
    expect(readyToCheck('1234 '.repeat(24))).toBe(false);
  });

  it('hands the core one spelling of the key however it was typed', () => {
    expect(normaliseKeyText(`  ${WORDS.join('  ').toUpperCase()} `)).toBe(WORDS.join(' '));
    expect(normaliseKeyText(DIGITS.replace(/ /g, '-'))).toBe(DIGITS);
    expect(normaliseKeyText(DIGITS.replace(/ /g, ''))).toBe(DIGITS);
  });
});

describe('messages while typing', () => {
  it('says nothing while the text can still become a key', () => {
    expect(typingMessage('')).toBeNull();
    expect(typingMessage('abandon ability')).toBeNull();
    expect(typingMessage('1234 56')).toBeNull();
  });

  it('says at once when it cannot', () => {
    expect(typingMessage('abandon 1234')).toBe(WRONG_FORMAT);
    expect(typingMessage([...WORDS, 'able'].join(' '))).toBe(WRONG_FORMAT);
    expect(typingMessage(`${DIGITS} 1`)).toBe(WRONG_FORMAT);
  });
});

describe('messages about the core answer, in the Ghost web app words', () => {
  it('accepts a key without a message', () => {
    expect(keyWordsMessage({ verdict: 'phantom-key', position: 0 })).toBeNull();
  });

  it('names the unknown word by its position, never by the word', () => {
    const message = keyWordsMessage({ verdict: 'unknown-word', position: 7 });
    expect(message).toBe("Word 7 isn't a Phantom Key word. Check it against the key you saved.");
  });

  it('tells a failed word check from a failed digit check', () => {
    expect(keyWordsMessage({ verdict: 'word-check', position: 0 })).toBe(
      "This key doesn't pass its check. A word may be wrong or out of order: check it against the key you saved.",
    );
    expect(keyWordsMessage({ verdict: 'digit-check', position: 0 })).toBe(
      "These digits don't pass their check. A digit may be wrong: check them against the key you saved.",
    );
    expect(keyWordsMessage({ verdict: 'wrong-format', position: 0 })).toBe(WRONG_FORMAT);
  });

  it('refuses recovery words by name', () => {
    expect(keyWordsMessage({ verdict: 'account-words', position: 0 })).toBe(RECOVERY_WORDS_IN_KEY_FIELD);
    expect(RECOVERY_WORDS_IN_KEY_FIELD).toContain('not a Phantom Key');
  });

  it('reads the core answer, treating an unknown verdict as the wrong format', () => {
    expect(parseWordsCheck({ verdict: 'unknown-word', position: 3 })).toEqual({ verdict: 'unknown-word', position: 3 });
    expect(parseWordsCheck({ verdict: 'phantom-key', position: 9 })).toEqual({ verdict: 'phantom-key', position: 0 });
    expect(parseWordsCheck({ verdict: 'something-new', position: 0 })).toEqual({ verdict: 'wrong-format', position: 0 });
  });
});
