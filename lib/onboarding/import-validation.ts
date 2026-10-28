// Import: the person types their 24 words, one per box, or pastes all of them
// into one box. Whether a word is in the word list, and whether all 24 make a
// valid account, is decided by the native core; this file only shapes input.
import { normaliseWord, WORD_COUNT } from './word-check';

/** The words in typed or pasted text, normalised, in order. */
export function splitWords(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map(normaliseWord)
    .filter((word) => word !== '');
}

export function emptyFields(count: number = WORD_COUNT): string[] {
  return Array.from({ length: count }, () => '');
}

export type FieldChange = {
  fields: string[];
  /** The box to move the cursor to, or null to leave it where it is. */
  focus: number | null;
};

/**
 * Applies text typed or pasted into box `index` (0-based). Several words
 * spread over that box and the ones after it; words past the last box are
 * dropped. A word followed by a space moves on to the next box.
 */
export function applyFieldText(fields: readonly string[], index: number, text: string): FieldChange {
  const next = [...fields];
  const words = splitWords(text);
  if (words.length > 1) {
    words.slice(0, next.length - index).forEach((word, offset) => {
      next[index + offset] = word;
    });
    const last = Math.min(index + words.length, next.length) - 1;
    return { fields: next, focus: last + 1 < next.length ? last + 1 : null };
  }
  const word = words[0] ?? '';
  next[index] = word;
  const movesOn = word !== '' && /\s$/.test(text) && index + 1 < next.length;
  return { fields: next, focus: movesOn ? index + 1 : null };
}

export type ImportStatus = {
  /** All boxes filled with words from the word list. */
  ready: boolean;
  /** 1-based positions still empty. */
  empty: number[];
  /** 1-based positions holding a word that is not in the word list. */
  unknown: number[];
};

/** `isWord(word)` asks the native core whether the word is in the word list. */
export function importStatus(fields: readonly string[], isWord: (word: string) => boolean): ImportStatus {
  const empty: number[] = [];
  const unknown: number[] = [];
  fields.forEach((field, index) => {
    const word = normaliseWord(field);
    if (word === '') {
      empty.push(index + 1);
    } else if (!isWord(word)) {
      unknown.push(index + 1);
    }
  });
  return { ready: fields.length === WORD_COUNT && empty.length === 0 && unknown.length === 0, empty, unknown };
}

/** The 24 words as one phrase, for the native core to check and save. */
export function joinWords(fields: readonly string[]): string {
  return fields.map(normaliseWord).join(' ');
}

/** What to tell the person under the boxes, or null when nothing is wrong yet. */
export function importMessage(status: ImportStatus): string | null {
  if (status.unknown.length === 1) {
    return `Word ${status.unknown[0]} is not one of the backup words. Check its spelling.`;
  }
  if (status.unknown.length > 1) {
    return `Words ${status.unknown.join(', ')} are not backup words. Check their spelling.`;
  }
  return null;
}
