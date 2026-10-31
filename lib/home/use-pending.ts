// Home's list of sends, Vanishes, Summons and Claims still going. A payment
// left mid-way keeps going here: every few seconds Home moves each one the
// screen is not moving (lib/vanish/pending.ts keeps two from moving the same
// payment at once), so its row shows the step it is at until it settles or
// fails. A Summon whose fee window passed waits here for its key, typed again
// on its screen.
import { useEffect, useMemo, useState } from 'react';
import { AppState } from 'react-native';

import { advanceSend, asSendKit } from '../send/send-payment';
import { signVanishAgain } from '../vanish/actions';
import { advance } from '../vanish/payments';
import {
  moveAlone,
  openShared,
  pendingPayments,
  stopIfShort,
  stoppedVanish,
  subscribePending,
  type PendingPayment,
} from '../vanish/pending';
import { paymentKit, type PaymentKit } from '../vanish/use-payment';

export const MOVE_PENDING_EVERY_MS = 10_000;

/** Moves each pending payment once; a failed move is tried again next time. */
async function movePending(kit: PaymentKit, pending: readonly PendingPayment[]) {
  for (const payment of pending) {
    if (payment.held || payment.otherNetwork || stoppedVanish(payment.id, kit.store) !== null) {
      // Nothing is signed before the key is written down, nor for another
      // chain, nor again for a Vanish the account could not pay for.
      continue;
    }
    const sequence = openShared(kit, payment.id);
    if (!sequence) {
      continue;
    }
    try {
      await moveAlone(payment.id, async () => {
        if (payment.kind === 'send') {
          // A queued send goes out from here too, once the node can be reached.
          const sends = asSendKit(kit);
          return sends ? advanceSend(sends, sequence) : null;
        }
        if (payment.kind === 'vanish') {
          return advance(kit.node, sequence, signVanishAgain(kit, sequence), null);
        }
        // A reveal moves on the receipts of its saved attempts; no coin tree is read.
        return advance(kit.node, sequence, null, null);
      });
    } catch (error) {
      // The payment is saved; the next move tries again, unless the account
      // cannot pay for this Vanish: then it is held stopped.
      stopIfShort(payment.id, error, kit.nodeUrl, kit.store);
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
