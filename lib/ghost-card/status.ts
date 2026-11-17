// What a Ghost Java card is, as the screens say it (docs/bearer-card-spec.md,
// "Seal check on every tap"). A card is shown Sealed only from a statement
// the native core just verified (its certificate under a pinned issuer, its
// LMS signature over this tap's challenge) and a coin the chain shows buried
// and unspent. Every other answer is one of the "not safe to accept" states.
import { ghostText } from '../seal/card-status';

export type GhostCardStatus =
  /** Every check passed: the coin is buried on chain, unspent, and the key never left the card. */
  | {
      kind: 'sealed';
      fill: number;
      amountWei: bigint;
      checksLeft: number;
      cardNumber: string;
      /** Whether an open code was confirmed with this Check. */
      codeConfirmed: boolean;
    }
  /** Sealed, and its Vanish is in the coin tree but not yet buried under enough blocks. */
  | { kind: 'settling'; fill: number; amountWei: bigint; cardNumber: string }
  /** Sealed, but no Vanish with exactly its commit data is on chain. */
  | { kind: 'not-on-chain'; fill: number; amountWei: bigint; cardNumber: string }
  /** Sealed, and its coin's marker is spent: the card is broken. */
  | { kind: 'spent-while-sealed'; cardNumber: string }
  /** The key was released; `spent` says whether the chain shows its coin taken off. */
  | { kind: 'opened'; fill: number; cardNumber: string; spent: boolean | null }
  | { kind: 'blank'; fill: number; checksLeft: number; cardNumber: string }
  /** The open code handed over does not open this fill. */
  | { kind: 'code-wrong'; cardNumber: string }
  /** Sealed, with no seal checks left: it can still be opened, never checked. */
  | { kind: 'no-checks'; cardNumber: string }
  /** A signature failed, or the issuer is unknown or revoked. `reason` is a short code. */
  | { kind: 'not-genuine'; reason: string }
  /** An NTAG 424 DNA card. */
  | { kind: 'carry-to-claim' }
  | { kind: 'no-connection' }
  /** Nothing was learned about the card: tap it again. */
  | { kind: 'retry'; message: string };

const NOT_SAFE = 'not safe to accept';

/** The status's main line. */
export function ghostStatusText(status: GhostCardStatus): string {
  switch (status.kind) {
    case 'sealed':
      return `Sealed (fill ${status.fill}): holds ${ghostText(status.amountWei)} GHOST`;
    case 'settling':
      return `Settling (fill ${status.fill}): ${NOT_SAFE} yet`;
    case 'not-on-chain':
      return `Not on the chain yet: ${NOT_SAFE}`;
    case 'spent-while-sealed':
      return `Spent while sealed: ${NOT_SAFE}`;
    case 'opened':
      return `Opened: ${NOT_SAFE}`;
    case 'blank':
      return `Blank (fill ${status.fill}): holds nothing`;
    case 'code-wrong':
      return `Open code wrong: ${NOT_SAFE}`;
    case 'no-checks':
      return `No seal checks left: ${NOT_SAFE}`;
    case 'not-genuine':
      return `Not a genuine Ghost card: ${NOT_SAFE}`;
    case 'carry-to-claim':
      return `Carry to Claim: ${NOT_SAFE}`;
    case 'no-connection':
      return "Can't check the chain right now";
    case 'retry':
      return status.message;
  }
}

/** A quieter second line, when there is more to say. */
export function ghostStatusDetail(status: GhostCardStatus): string | null {
  switch (status.kind) {
    case 'sealed':
      return [
        `Card ${status.cardNumber}. Check it matches the number printed on the card.`,
        status.codeConfirmed
          ? 'The open code you were given opens this card.'
          : 'Ask for the open code and check it before you accept the card.',
        `${status.checksLeft} seal ${status.checksLeft === 1 ? 'check' : 'checks'} left.`,
      ].join('\n');
    case 'settling':
      return `It holds ${ghostText(status.amountWei)} GHOST once its payment is buried under a few more blocks. Check again in a minute.`;
    case 'not-on-chain':
      return `The card says it holds ${ghostText(status.amountWei)} GHOST, but no payment of exactly that is on the chain.`;
    case 'spent-while-sealed':
      return 'Its coin was spent while the card says sealed. The card is broken: please report it.';
    case 'opened':
      return status.spent
        ? 'Its coins were taken off. Whoever has its open code can reuse the card.'
        : 'Its key was released to whoever opened it.';
    case 'blank':
      return `Card ${status.cardNumber}. ${status.checksLeft} seal checks left. Ready to fill.`;
    case 'code-wrong':
      return 'The open code you were given does not open this card.';
    case 'no-checks':
      return 'The card can no longer prove what it holds. Whoever has its open code can still open it.';
    case 'not-genuine':
      return `Reason: ${status.reason}`;
    case 'carry-to-claim':
      return 'An NTAG 424 card holds a key anyone who taps it can copy: claim it into your wallet, never accept it as cash.';
    case 'no-connection':
      return 'The card checked out, but the chain could not be reached to see its coin. Try again with a connection.';
    default:
      return null;
  }
}

/** Whether the status is shown in red. */
export function ghostStatusIsAlarm(status: GhostCardStatus): boolean {
  return status.kind === 'not-genuine' || status.kind === 'spent-while-sealed' || status.kind === 'code-wrong';
}

/** Whether a receiver may accept the card. */
export function safeToAccept(status: GhostCardStatus): boolean {
  return status.kind === 'sealed';
}
