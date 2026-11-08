// What a Sealed card is, as the screens say it. A card is shown Secured only
// from an answer the native core just verified (lib/seal/verify-answer.ts);
// an answer that failed its check is always "Can't verify this card", in
// red, and never shows an amount.
import { CardCancelled } from '../../modules/ghost-nfc';
import { RELAY_PROBLEMS, SealRelayError, type RelayProblem } from '../../modules/ghost-nfc/relay';
import type { CheckedAnswer } from './verify-answer';

export type CardStatus =
  /** A verified Sealed answer: paid exactly, settled, unspent, never opened. */
  | { kind: 'secured'; uid: string; amountWei: bigint; pinRequired: boolean; pinTriesLeft: number }
  | { kind: 'filling' }
  /** Opened (or an Open is under way): the key left the card. */
  | { kind: 'opened'; finishing: boolean }
  /** Set up and empty: ready to fill. */
  | { kind: 'empty'; uid: string }
  /** Its coin was spent. */
  | { kind: 'spent' }
  /** Its Open PIN has no tries left: it can never be opened. */
  | { kind: 'locked' }
  | { kind: 'not-ghost' }
  | { kind: 'no-connection' }
  /** Why: a short code of the check that failed, and region ids; never a key, card data, a PIN or a challenge. */
  | { kind: 'cant-verify'; reason: string }
  /** Nothing was learned about the card: tap it again. */
  | { kind: 'retry'; message: string };

export const STATUS_TEXT = {
  filling: 'Filling, waiting to settle',
  opened: 'Opened, empty',
  empty: 'Empty, ready to fill',
  spent: 'Spent, empty',
  locked: 'Locked: its PIN has no tries left',
  'not-ghost': 'Not a Ghost card',
  'no-connection': "Can't check right now (no connection)",
  'cant-verify': "Can't verify this card",
} as const;

/** The longest reason shown. */
const REASON_CHARS = 160;

/**
 * A failed check's reason as the screen may show it: only letters, digits,
 * spaces and `-:;,()._`, no run of hex longer than 16 digits, at most 160
 * characters. The reasons are short codes and region ids already; this keeps
 * anything else out of the screen.
 */
export function reasonText(reason: string): string {
  const text = reason
    .replace(/[^A-Za-z0-9 :;,()._-]/g, '?')
    .replace(/[0-9A-Fa-f]{17,}/g, '?')
    .trim()
    .slice(0, REASON_CHARS);
  return text === '' ? 'unknown' : text;
}

/** "Can't verify this card", with why. */
export function cantVerify(reason: string): CardStatus {
  return { kind: 'cant-verify', reason: reasonText(reason) };
}

/** A wei amount in GHOST, with no trailing zeros: 5, 1.5, 0.001. */
export function ghostText(wei: bigint): string {
  const whole = wei / 10n ** 18n;
  const fraction = (wei % 10n ** 18n).toString().padStart(18, '0').replace(/0+$/, '');
  return fraction === '' ? whole.toString() : `${whole}.${fraction}`;
}

/** The status's main line. */
export function statusText(status: CardStatus): string {
  switch (status.kind) {
    case 'secured':
      return `Secured, ${ghostText(status.amountWei)} GHOST, never opened`;
    case 'retry':
      return status.message;
    default:
      return STATUS_TEXT[status.kind];
  }
}

/** A quieter second line, when there is more to say. */
export function statusDetail(status: CardStatus): string | null {
  switch (status.kind) {
    case 'secured':
      return status.pinRequired
        ? `Opening it needs its PIN: ${status.pinTriesLeft} ${status.pinTriesLeft === 1 ? 'try' : 'tries'} left. Accept it only if you were given the PIN.`
        : 'Whoever holds this card can open it. No PIN is set.';
    case 'opened':
      return status.finishing ? 'An Open of this card is under way.' : null;
    case 'cant-verify':
      return `The Seal’s answer did not pass this iPhone’s checks. Do not accept this card.\nReason: ${reasonText(status.reason)}`;
    case 'no-connection':
      return 'The Seal or the chain could not be reached. Try again with a connection.';
    default:
      return null;
  }
}

/** Whether the status is shown in red. */
export function statusIsAlarm(status: CardStatus): boolean {
  return status.kind === 'cant-verify';
}

/** What a verified answer says about the card. */
export function statusOfAnswer(answer: CheckedAnswer): CardStatus {
  switch (answer.state) {
    case 'sealed':
      return {
        kind: 'secured',
        uid: answer.uid,
        amountWei: answer.amountWei,
        pinRequired: answer.pinRequired,
        pinTriesLeft: answer.pinTriesLeft,
      };
    case 'opening':
      return { kind: 'opened', finishing: true };
    case 'opened':
      return { kind: 'opened', finishing: false };
    default:
      return { kind: 'empty', uid: answer.uid };
  }
}

const PROBLEM_STATUS: Partial<Record<RelayProblem, CardStatus>> = {
  'not-a-ghost-card': { kind: 'not-ghost' },
  // A refusal with no reason: the Seal does not hold this card's keys.
  'seal-refused': { kind: 'not-ghost' },
  filling: { kind: 'filling' },
  'cant-check-now': { kind: 'no-connection' },
  'seal-unreachable': { kind: 'no-connection' },
  'session-expired': { kind: 'no-connection' },
  'pin-locked': { kind: 'locked' },
  spent: { kind: 'spent' },
  // An answer that is not over this challenge about this card: an old one replayed.
  'bad-answer': { kind: 'cant-verify', reason: 'bad-answer' },
};

/** What a failed relay says about the card; null when the person closed the card sheet. */
export function statusOfFailure(error: unknown): CardStatus | null {
  if (error instanceof CardCancelled) {
    return null;
  }
  if (error instanceof SealRelayError) {
    return PROBLEM_STATUS[error.problem] ?? { kind: 'retry', message: RELAY_PROBLEMS[error.problem] };
  }
  return { kind: 'retry', message: RELAY_PROBLEMS.failed };
}
