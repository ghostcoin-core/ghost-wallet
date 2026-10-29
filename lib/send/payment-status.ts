// Where a send stands, as the payment screen shows it (docs/mockups/payment.html).
// The native core's step sequence (`core/src/step_sequence.rs`) saves every
// step; this file maps a saved step, and whether the node is known to hold the
// send, to what the person sees: queued, sent, in a block, settled, failed or
// conflicted.
//
// "Sent" means the node said it holds the send. A send saved while the node
// was out of reach, or whose broadcast did not get through, is queued: it goes
// out by itself once the node answers, and never twice.
import { stepName } from '../vanish/status-mapping';

export type SendStatus = 'queued' | 'sent' | 'in-block' | 'settled' | 'failed' | 'conflicted';

/**
 * The status of a send at saved step `step`. `reached` is whether the node
 * has said it holds the newest attempt (it took the broadcast, or lists it).
 */
export function sendStatusOf(step: number | string, reached: boolean): SendStatus {
  switch (stepName(step)) {
    case 'Prepared':
    case 'BackedUp':
    case 'Signed':
      return 'queued';
    case 'Sent':
      return reached ? 'sent' : 'queued';
    case 'Included':
      return 'in-block';
    case 'Settled':
      return 'settled';
    case 'Failed':
      return 'failed';
    case 'Conflicted':
      return 'conflicted';
    default:
      // A step this code does not know is shown as a problem, never as done.
      return 'failed';
  }
}

/** Whether nothing more happens to the send: the screen stops asking the chain. */
export function isFinalSend(status: SendStatus): boolean {
  return status === 'settled' || status === 'failed' || status === 'conflicted';
}

export function sendStatusLabel(status: SendStatus): string {
  switch (status) {
    case 'queued':
      return 'Queued';
    case 'sent':
      return 'Sent';
    case 'in-block':
      return 'In a block';
    case 'settled':
      return 'Settled';
    case 'failed':
      return 'Failed';
    case 'conflicted':
      return 'Conflicted';
  }
}

/** The quiet line under each stage of the progress. */
export function sendStageNote(status: SendStatus): string {
  switch (status) {
    case 'queued':
      return 'Saved on this phone. It goes out when the test node can be reached.';
    case 'sent':
      return 'The test node has it';
    case 'in-block':
      return 'Usually in under a minute';
    case 'settled':
      return 'Final, cannot be undone';
    case 'failed':
      return 'The chain ran it and it failed. The amount did not move.';
    case 'conflicted':
      return 'Another payment from this account went first. This one never goes out.';
  }
}

export type SendProgressRow = {
  status: SendStatus;
  label: string;
  note: string;
  state: 'done' | 'current' | 'waiting';
};

const PROGRESS: readonly SendStatus[] = ['sent', 'in-block', 'settled'];

/**
 * The progress list of the mockup: sent, in a block, settled. A queued send
 * shows Queued first; a failed one shows where it stopped; a conflicted one
 * shows only that, as it never landed.
 */
export function sendProgressRows(status: SendStatus): SendProgressRow[] {
  const row = (stage: SendStatus, state: SendProgressRow['state']): SendProgressRow => ({
    status: stage,
    label: sendStatusLabel(stage),
    note: sendStageNote(stage),
    state,
  });
  switch (status) {
    case 'queued':
      return [row('queued', 'current'), ...PROGRESS.map((stage) => row(stage, 'waiting'))];
    case 'failed':
      return [row('sent', 'done'), row('in-block', 'done'), row('failed', 'current')];
    case 'conflicted':
      return [row('conflicted', 'current')];
    default: {
      const at = PROGRESS.indexOf(status);
      return PROGRESS.map((stage, index) =>
        row(stage, index < at || (stage === 'settled' && status === 'settled') ? 'done' : index === at ? 'current' : 'waiting'),
      );
    }
  }
}

export const SAFE_TO_CLOSE = 'Safe to close the app. It never pays twice.';

/** The line in the highlight box: why it is safe to leave, or what happened. */
export function sendStatusDetail(status: SendStatus): string {
  switch (status) {
    case 'queued':
      return `Queued, not sent yet. ${SAFE_TO_CLOSE}`;
    case 'sent':
    case 'in-block':
      return SAFE_TO_CLOSE;
    case 'settled':
      return 'Settled. The GHOST is with the recipient.';
    case 'failed':
      return 'The send failed in its block. The amount did not move; the fee was paid. Nothing more is sent.';
    case 'conflicted':
      return 'Another payment from this account used its place first. Nothing was sent and nothing more will be.';
  }
}

/** The headline verb over the amount. */
export function sendHeadline(status: SendStatus): string {
  switch (status) {
    case 'queued':
      return 'You are sending';
    case 'failed':
    case 'conflicted':
      return 'You tried to send';
    default:
      return 'You sent';
  }
}
