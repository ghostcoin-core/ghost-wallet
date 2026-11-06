// A Sealed card's Open PIN: optional, 4 to 8 digits, set at Fill and asked
// for before an Open. It goes to the Seal through the relay only: it is never
// stored or logged, and the screens clear it from their state as soon as the
// call that needed it is made. The Seal counts each try on the card before it
// compares the PIN, and a card with no tries left can never be opened.

export const PIN_MIN_DIGITS = 4;
export const PIN_MAX_DIGITS = 8;

export type PinRule =
  /** Nothing typed: no PIN (allowed at Fill only). */
  | { ok: true; pin: null }
  | { ok: true; pin: string }
  | { ok: false; message: string };

/** Checks a typed PIN, and at Fill its repeat. */
export function pinRule(text: string, again: string | null = null, optional = false): PinRule {
  if (text === '' && (again === null || again === '')) {
    return optional ? { ok: true, pin: null } : { ok: false, message: 'Enter the card’s PIN.' };
  }
  if (!/^[0-9]+$/.test(text) || text.length < PIN_MIN_DIGITS || text.length > PIN_MAX_DIGITS) {
    return { ok: false, message: `A PIN is ${PIN_MIN_DIGITS} to ${PIN_MAX_DIGITS} digits.` };
  }
  if (again !== null && again !== text) {
    return { ok: false, message: 'The two PINs are not the same.' };
  }
  return { ok: true, pin: text };
}

/** "3 tries left", "1 try left". */
export function triesText(tries: number): string {
  return `${tries} ${tries === 1 ? 'try' : 'tries'} left`;
}
