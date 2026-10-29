// A send on the payment screen: moved one step every few seconds until it is
// settled, failed or conflicted. Leaving the screen stops its moves, not the
// send: it is saved, Home goes on moving it (lib/home/use-pending.ts) and
// reopening the screen resumes it.
import { useEffect, useState } from 'react';

import type { CorePaymentSequence } from '../../modules/ghost-core';
import { failureReason } from '../node/failure-reason';
import { moveAlone } from '../vanish/pending';
import { MOVE_EVERY_MS } from '../vanish/use-payment';
import { isFinalSend, type SendStatus } from './payment-status';
import { advanceSend, savedSendStatus, type SendKit } from './send-payment';

export type SendView = {
  status: SendStatus;
  step: number | string;
  /** Why the last move did not get through; the next one tries again. */
  error: string | null;
};

function savedView(sequence: CorePaymentSequence): SendView {
  return { status: savedSendStatus(sequence), step: sequence.step(), error: null };
}

export function useSendPayment(kit: SendKit | null, sequence: CorePaymentSequence | null): SendView | null {
  // The view, with the send it belongs to: a view of another send is never shown.
  const [moved, setMoved] = useState<{ of: CorePaymentSequence; view: SendView } | null>(null);

  useEffect(() => {
    if (!kit || !sequence) {
      return;
    }
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    async function move(payment: CorePaymentSequence, tools: SendKit) {
      try {
        // Home may be moving this send right now: then this move waits for the next.
        const next = await moveAlone(payment.record().id, () => advanceSend(tools, payment));
        if (stopped) {
          return;
        }
        const view = next ? { ...next, error: null } : savedView(payment);
        setMoved({ of: payment, view });
        if (isFinalSend(view.status)) {
          return;
        }
      } catch (error) {
        if (stopped) {
          return;
        }
        // The send is saved; the next move tries again.
        setMoved({ of: payment, view: { ...savedView(payment), error: failureReason(error, tools.nodeUrl) } });
      }
      timer = setTimeout(() => void move(payment, tools), MOVE_EVERY_MS);
    }

    void move(sequence, kit);
    return () => {
      stopped = true;
      if (timer) {
        clearTimeout(timer);
      }
    };
  }, [kit, sequence]);

  if (!kit || !sequence) {
    return null;
  }
  return moved?.of === sequence ? moved.view : savedView(sequence);
}
