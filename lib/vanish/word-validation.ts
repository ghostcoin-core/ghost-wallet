// The Phantom Key field: the person types a key's 24 words (or its 21 groups
// of four digits). Whether the words make a key, and whether they are a
// wallet's recovery words instead, is decided by the native core
// (`check_key_words`); this file only shapes the input and words the answer,
// in the Ghost web app's own words.

export const KEY_WORD_COUNT = 24;
export const KEY_DIGIT_COUNT = 84;

/** What the native core says the typed text is (`WordsCheck` in core/src/vanish.rs). */
export type KeyVerdict =
  | 'empty'
  | 'account-words'
  | 'phantom-key'
  | 'wrong-format'
  | 'unknown-word'
  | 'word-check'
  | 'digit-check';

export type WordsCheck = {
  verdict: KeyVerdict;
  /** The word an `unknown-word` names, from 1; 0 otherwise. */
  position: number;
};

const VERDICTS: readonly KeyVerdict[] = [
  'empty',
  'account-words',
  'phantom-key',
  'wrong-format',
  'unknown-word',
  'word-check',
  'digit-check',
];

/** The core's answer, refusing one this code does not know. */
export function parseWordsCheck(raw: { verdict: string; position: number }): WordsCheck {
  const verdict = VERDICTS.find((known) => known === raw.verdict);
  if (!verdict) {
    return { verdict: 'wrong-format', position: 0 };
  }
  return { verdict, position: verdict === 'unknown-word' ? raw.position : 0 };
}

export type KeyShape =
  | { kind: 'empty' }
  | { kind: 'words'; count: number }
  | { kind: 'digits'; count: number }
  /** Something no key holds: letters and digits together, or other marks. */
  | { kind: 'mixed' };

/**
 * What the typed text looks like, as Ghost reads a key: no digit and some
 * letters is words; otherwise digits, with spaces and hyphens ignored.
 */
export function keyShape(text: string): KeyShape {
  const trimmed = text.trim();
  if (trimmed === '') {
    return { kind: 'empty' };
  }
  const hasDigit = /[0-9]/.test(trimmed);
  if (!hasDigit && /[a-z]/i.test(trimmed)) {
    if (!/^[a-z\s]+$/i.test(trimmed)) {
      return { kind: 'mixed' };
    }
    return { kind: 'words', count: keyWords(trimmed).length };
  }
  if (!/^[0-9\s-]+$/.test(trimmed)) {
    return { kind: 'mixed' };
  }
  return { kind: 'digits', count: trimmed.replace(/[\s-]/g, '').length };
}

/** The typed words, lowercase, in order. */
export function keyWords(text: string): string[] {
  return text
    .toLowerCase()
    .split(/\s+/)
    .filter((word) => word !== '');
}

/** Whether the text has a key's length, so the core can be asked about it. */
export function readyToCheck(text: string): boolean {
  const shape = keyShape(text);
  return (
    (shape.kind === 'words' && shape.count === KEY_WORD_COUNT) ||
    (shape.kind === 'digits' && shape.count === KEY_DIGIT_COUNT)
  );
}

/**
 * The text as the core reads it: words lowercase with single spaces, digits
 * in groups of four. Typing it another way is the same key.
 */
export function normaliseKeyText(text: string): string {
  const shape = keyShape(text);
  if (shape.kind === 'words') {
    return keyWords(text).join(' ');
  }
  if (shape.kind === 'digits') {
    return (text.replace(/[^0-9]/g, '').match(/.{1,4}/g) ?? []).join(' ');
  }
  return text.trim();
}

/**
 * What to tell the person while they type, before the core is asked: only
 * what is certainly wrong already. Null while it may still become a key.
 */
export function typingMessage(text: string): string | null {
  const shape = keyShape(text);
  switch (shape.kind) {
    case 'mixed':
      return WRONG_FORMAT;
    case 'words':
      return shape.count > KEY_WORD_COUNT ? WRONG_FORMAT : null;
    case 'digits':
      return shape.count > KEY_DIGIT_COUNT ? WRONG_FORMAT : null;
    default:
      return null;
  }
}

export const WRONG_FORMAT = "That doesn't look like a Phantom Key. It should be 24 words.";
export const RECOVERY_WORDS_IN_KEY_FIELD =
  'These are recovery words for a wallet, not a Phantom Key. Never type them here: a Phantom Key holds coins, not your wallet.';

/** What to tell the person about the core's answer; null for a good key. */
export function keyWordsMessage(check: WordsCheck): string | null {
  switch (check.verdict) {
    case 'phantom-key':
    case 'empty':
      return null;
    case 'account-words':
      return RECOVERY_WORDS_IN_KEY_FIELD;
    case 'unknown-word':
      return `Word ${check.position} isn't a Phantom Key word. Check it against the key you saved.`;
    case 'word-check':
      return "This key doesn't pass its check. A word may be wrong or out of order: check it against the key you saved.";
    case 'digit-check':
      return "These digits don't pass their check. A digit may be wrong: check them against the key you saved.";
    case 'wrong-format':
      return WRONG_FORMAT;
  }
}
