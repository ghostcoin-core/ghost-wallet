// Where a Vanish, Summon or Claim stands, as its screen shows it. The native
// core's step sequence (`core/src/step_sequence.rs`) saves every step; this
// file maps its steps, and what `recover` says to do next, to the progress the
// person sees: proving, sent, in a block, settled, or failed.

export type RevealKind = 'vanish' | 'summon' | 'claim';

export type PaymentStatus = 'proving' | 'sent' | 'in-block' | 'settled' | 'failed';

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
    case 'in-block':
      return 'In a block';
    case 'settled':
      return 'Settled';
    case 'failed':
      return 'Failed';
  }
}

const PROGRESS: readonly PaymentStatus[] = ['proving', 'sent', 'in-block', 'settled'];

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
  const at = PROGRESS.indexOf(status);
  return PROGRESS.map((stage, index) => ({
    status: stage,
    label: statusLabel(stage, kind),
    state: index < at || (stage === 'settled' && status === 'settled') ? 'done' : index === at ? 'current' : 'waiting',
  }));
}

/** The line under the progress. */
export function statusDetail(status: PaymentStatus, kind: RevealKind, step?: number | string): string {
  switch (status) {
    case 'proving':
      return kind === 'vanish'
        ? 'Signing the Vanish with your account.'
        : 'Making the proof on this phone. This can take a minute.';
    case 'sent':
    case 'in-block':
      return 'Safe to close the app. It never pays twice.';
    case 'settled':
      return kind === 'vanish' ? 'The coins are in the Phantom Key.' : 'The coins are back in your account.';
    case 'failed':
      return step !== undefined && stepName(step) === 'Conflicted'
        ? 'Another payment used these coins first. Nothing more is sent.'
        : 'The chain did not take it. Nothing more is sent.';
  }
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
