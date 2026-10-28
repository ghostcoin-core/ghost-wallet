// The two fields that take words, and what each refuses. The key field
// (Summon / Claim) takes only a Phantom Key and refuses a wallet's recovery
// words; the wallet field (import) takes only recovery words and refuses a
// Phantom Key. The native core tells the two apart (Ghost's seed parser
// refuses a Phantom Key, so no words are both); these rules decide what the
// screen does with its answer. Neither rule ever repeats the words.
import {
  keyWordsMessage,
  normaliseKeyText,
  readyToCheck,
  typingMessage,
  type WordsCheck,
} from './word-validation';

/** Asks the native core what the text is (`check_key_words`). */
export type CheckWords = (text: string) => WordsCheck;

export type FieldRule = {
  /** The field's button may be pressed with this text. */
  accept: boolean;
  /** What to tell the person, or null. */
  message: string | null;
};

const WAITING: FieldRule = { accept: false, message: null };

/** The Phantom Key field: a key passes; recovery words never do. */
export function keyFieldRule(text: string, check: CheckWords): FieldRule {
  const early = typingMessage(text);
  if (early) {
    return { accept: false, message: early };
  }
  if (!readyToCheck(text)) {
    // 24 words that are recovery words are refused as such, so they are
    // checked as soon as there are 24, like a key.
    return WAITING;
  }
  let answer: WordsCheck;
  try {
    answer = check(normaliseKeyText(text));
  } catch {
    return { accept: false, message: 'This phone cannot check keys in this build.' };
  }
  return { accept: answer.verdict === 'phantom-key', message: keyWordsMessage(answer) };
}

export const PHANTOM_KEY_IN_WALLET_FIELD =
  'These 24 words are a Phantom Key: it holds coins, not your wallet. Summon it from Home once your account is open.';

/**
 * The wallet field: a Phantom Key is refused by name. Anything else is left
 * to the field's own checks (the word list and the account checksum).
 */
export function walletFieldRule(words: string, check: CheckWords): FieldRule {
  let answer: WordsCheck;
  try {
    answer = check(words);
  } catch {
    // Without the core the import itself fails with its own message.
    return { accept: true, message: null };
  }
  if (answer.verdict === 'phantom-key') {
    return { accept: false, message: PHANTOM_KEY_IN_WALLET_FIELD };
  }
  return { accept: true, message: null };
}
