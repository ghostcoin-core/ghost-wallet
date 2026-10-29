// Home's list of Vanish, Summon and Claim payments still going. A payment
// left mid-way keeps going here: every few seconds Home moves each one the
// screen is not moving (lib/vanish/pending.ts keeps two from moving the same
// payment at once), so its row shows the step it is at until it settles or
// fails. A Summon whose fee window passed waits here for its key, typed again
// on its screen.
import { useEffect, useMemo, useState } from 'react';
import { AppState } from 'react-native';

import { signVanishAgain } from '../vanish/actions';
import { advance } from '../vanish/payments';
import { moveAlone, openShared, pendingPayments, subscribePending, type PendingPayment } from '../vanish/pending';
import { paymentKit, treeAtTip, type PaymentKit } from '../vanish/use-payment';

export const MOVE_PENDING_EVERY_MS = 10_000;

/** Moves each pending payment once; a failed move is tried again next time. */
async function movePending(kit: PaymentKit, pending: readonly PendingPayment[]) {
  for (const payment of pending) {
    if (payment.held) {
      // Nothing is signed before the key is written down.
      continue;
    }
    const sequence = openShared(kit, payment.id);
    if (!sequence) {
      continue;
    }
    try {
      await moveAlone(payment.id, async () => {
        if (payment.kind === 'vanish') {
          return advance(kit.node, sequence, signVanishAgain(kit, sequence), null);
        }
        return advance(kit.node, sequence, null, (await treeAtTip(kit)).tree);
      });
    } catch {
      // The payment is saved; the next move tries again.
    }
  }
}

export function usePendingPayments(nodeUrl: string): PendingPayment[] {
  const kit = useMemo(() => paymentKit(nodeUrl), [nodeUrl]);
  const [pending, setPending] = useState<PendingPayment[]>(() => pendingPayments(kit));

  useEffect(() => {
    const read = () => setPending(pendingPayments(kit));
    read();
    return subscribePending(read);
  }, [kit]);

  useEffect(() => {
    if (!kit) {
      return;
    }
    let running = false;
    const move = () => {
      if (running) {
        return;
      }
      running = true;
      void movePending(kit, pendingPayments(kit)).finally(() => {
        running = false;
      });
    };
    move();
    const timer = setInterval(move, MOVE_PENDING_EVERY_MS);
    const subscription = AppState.addEventListener('change', (state) => {
      if (state === 'active') {
        move();
      }
    });
    return () => {
      clearInterval(timer);
      subscription.remove();
    };
  }, [kit]);

  return pending;
}
