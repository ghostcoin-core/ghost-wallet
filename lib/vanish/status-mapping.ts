// Where a Vanish, Summon or Claim stands, as its screen shows it. The native
// core's step sequence (`core/src/step_sequence.rs`) saves every step; this
// file maps its steps, and what `recover` says to do next, to the progress the
// person sees: proving, sent, not mined yet, in a block, settled, or failed.
import { failureReason } from '../node/failure-reason';

export type RevealKind = 'vanish' | 'summon' | 'claim';

/** Every kind of payment this phone saves: these and plain sends (lib/send/). */
export type SavedKind = RevealKind | 'send';

/**
 * `stuck`: the node took it, but `STUCK_BLOCKS` blocks went by and it is in
 * none. It is never shown as plain Sent then.
 */
export type PaymentStatus = 'proving' | 'sent' | 'stuck' | 'in-block' | 'settled' | 'failed';

/** How many blocks a payment the node took may go unmined before it shows as not mined yet. */
export const STUCK_BLOCKS = 10;

/** The label of a payment the node took but has not mined in `STUCK_BLOCKS` blocks. */
export const NOT_MINED_LABEL = 'Not mined yet';

/** The core's `Step`, in its declared order. */
export const STEP_NAMES = [
  'Prepared',
  'BackedUp',
  'Signed',
  'Sent',
  'Included',
  'Settled',
  'Failed',
  'Conflicted',
] as const;

export type StepName = (typeof STEP_NAMES)[number];

/**
 * The step's name, from the generated bindings' value: the enum's index or
 * its name (any case). Null for one this code does not know.
 */
export function stepName(step: number | string): StepName | null {
  if (typeof step === 'number') {
    return Number.isInteger(step) ? (STEP_NAMES[step] ?? null) : null;
  }
  const flat = step.replace(/[\s_-]/g, '').toLowerCase();
  return STEP_NAMES.find((name) => name.toLowerCase() === flat) ?? null;
}

/**
 * The status of a saved step. Until it is sent, a payment is still being
 * made (signed, or proved on the phone). Failed and Conflicted both failed:
 * nothing more is ever sent for them.
 */
export function statusOfStep(step: number | string): PaymentStatus {
  switch (stepName(step)) {
    case 'Prepared':
    case 'BackedUp':
    case 'Signed':
      return 'proving';
    case 'Sent':
      return 'sent';
    case 'Included':
      return 'in-block';
    case 'Settled':
      return 'settled';
    case 'Failed':
    case 'Conflicted':
      return 'failed';
    default:
      // A step this code does not know is shown as a problem, never as done.
      return 'failed';
  }
}

/** What the core's `recover` said to do (`Recovery`'s variant). */
export type RecoveryTag = 'BackUp' | 'Sign' | 'Send' | 'Rebuild' | 'Wait' | 'Done';

/** The status while the app does what `recover` said, from the saved step. */
export function statusOfRecovery(tag: RecoveryTag, step: number | string): PaymentStatus {
  switch (tag) {
    case 'BackUp':
    case 'Sign':
    case 'Rebuild':
      // A rebuild is a new proof (or signature) for the new fee window.
      return 'proving';
    case 'Send':
      return 'sent';
    case 'Wait':
    case 'Done':
      return statusOfStep(step);
  }
}

/** Whether the screen keeps asking the chain. */
export function isFinal(status: PaymentStatus): boolean {
  return status === 'settled' || status === 'failed';
}

export function statusLabel(status: PaymentStatus, kind: RevealKind): string {
  switch (status) {
    case 'proving':
      return kind === 'vanish' ? 'Signing' : 'Proving on this phone';
    case 'sent':
      return 'Sent';
    case 'stuck':
      return NOT_MINED_LABEL;
    case 'in-block':
      return 'In a block';
    case 'settled':
      return 'Settled';
    case 'failed':
      return 'Failed';
  }
}

const PROGRESS: readonly PaymentStatus[] = ['proving', 'sent', 'in-block', 'settled'];
/** The same stages for a payment not mined yet: it stands where Sent would. */
const STUCK_PROGRESS: readonly PaymentStatus[] = ['proving', 'stuck', 'in-block', 'settled'];

export type ProgressRow = {
  status: PaymentStatus;
  label: string;
  state: 'done' | 'current' | 'waiting';
};

/** The progress list: each stage done, current or still to come. */
export function progressRows(status: PaymentStatus, kind: RevealKind): ProgressRow[] {
  if (status === 'failed') {
    return [{ status: 'failed', label: statusLabel('failed', kind), state: 'current' }];
  }
  const stages = status === 'stuck' ? STUCK_PROGRESS : PROGRESS;
  const at = stages.indexOf(status);
  return stages.map((stage, index) => ({
    status: stage,
    label: statusLabel(stage, kind),
    state: index < at || (stage === 'settled' && status === 'settled') ? 'done' : index === at ? 'current' : 'waiting',
  }));
}

/**
 * How many blocks deep a payment is before it shows as Settled. Display only:
 * the rule itself is the core's `SETTLE_CONFIRMATIONS`
 * (`core/src/step_sequence.rs`), and the two must agree.
 */
export const SETTLE_CONFIRMATIONS = 3;

/** How far settling is, `confirmations` blocks deep. */
export function settlingLine(confirmations: number): string {
  return `Settling: ${confirmations} of ${SETTLE_CONFIRMATIONS} confirmations`;
}

/**
 * Whether the screen is done with the payment: once it is in a block the
 * person may go (settling goes on, and Activity shows Settled later), and once
 * it settled or failed. Before the first block it is not.
 */
export function screenDone(status: PaymentStatus): boolean {
  return status === 'in-block' || isFinal(status);
}

/**
 * The success line once the coins have arrived: from the first block, as from
 * Settled. Null before the first block, and once failed.
 */
export function arrivedText(status: PaymentStatus, kind: RevealKind): string | null {
  switch (status) {
    case 'in-block':
      return kind === 'vanish' ? 'The coins are in the Phantom Key.' : 'The coins are in your account.';
    case 'settled':
      return kind === 'vanish' ? 'The coins are in the Phantom Key.' : 'The coins are back in your account.';
    default:
      return null;
  }
}

/** The line under the progress. */
export function statusDetail(status: PaymentStatus, kind: RevealKind, step?: number | string): string {
  switch (status) {
    case 'proving':
      return kind === 'vanish'
        ? 'Signing the Vanish with your account.'
        : 'Making the proof on this phone. This can take a minute.';
    case 'sent':
      return 'Safe to close the app. It never pays twice.';
    case 'stuck':
      return notMinedText(kind);
    case 'in-block':
      // In a block is one confirmation; no live count is asked of the node.
      return kind === 'vanish' ? `${arrivedText(status, kind)} ${settlingLine(1)}` : settlingLine(1);
    case 'settled':
      return arrivedText(status, kind) ?? '';
    case 'failed':
      if (step !== undefined && stepName(step) === 'Conflicted') {
        return 'Another payment used these coins first. Nothing more is sent.';
      }
      // A Vanish that never landed (or whose cancel did) put nothing in its key.
      return kind === 'vanish'
        ? 'The chain did not take it. Nothing more is sent. The Phantom Key holds nothing.'
        : 'The chain did not take it. Nothing more is sent.';
  }
}

/**
 * What a payment not mined in `STUCK_BLOCKS` blocks says. A Vanish's Phantom
 * Key holds nothing until its commit is in a block, and it can be cancelled;
 * a Summon or Claim has no place in an account to replace, so it cannot.
 */
export function notMinedText(kind: SavedKind): string {
  const late = `Not mined yet: ${STUCK_BLOCKS} blocks went by and it is in none of them.`;
  switch (kind) {
    case 'vanish':
      return `${late} The Phantom Key holds nothing until it is. Cancel sends 1 wei to your own account in its place, at a higher fee.`;
    case 'send':
      return `${late} No GHOST has moved yet.`;
    default:
      return `${late} The coins are still in the Phantom Key.`;
  }
}

/** What the Vanish screen says while its cancel waits for a block. */
export const CANCEL_SENT_TEXT = 'Cancel sent. The Phantom Key holds nothing; whichever is mined first counts.';

/**
 * Why a payment was not sent, from an error of the check before sending
 * (lib/vanish/node.ts `checkSend`): the node's own reason when it refused it,
 * or that the node could not be asked. Any other error reads as usual.
 */
export function notSentReason(error: unknown, nodeUrl: string): string {
  const reason = failureReason(error, nodeUrl);
  const check = error as { notSent?: unknown; refused?: unknown } | null;
  if (!(error instanceof Error) || check?.notSent !== true) {
    return reason;
  }
  return check.refused === true
    ? `Not sent: the test node checked it first and would not take it. ${reason}`
    : `Not sent: the test node could not check it first, so nothing was sent. ${reason}`;
}

/** What the coin lookup found (`KeyCoins.status` in core/src/vanish.rs). */
export type LookupStatus = 'found' | 'spent' | 'not-found';

export const NOT_FOUND_MESSAGE = "Can't find this key's coins yet.";

/**
 * What to say about the lookup. A key whose coins this phone cannot find is
 * never shown as holding zero.
 */
export function lookupMessage(status: string): string | null {
  switch (status) {
    case 'found':
      return null;
    case 'spent':
      return 'The coins of this key have been summoned already.';
    case 'not-found':
      return `${NOT_FOUND_MESSAGE} This phone finds keys made on the test network it can see.`;
    default:
      return NOT_FOUND_MESSAGE;
  }
}
