// Home's balance with the card changes still going through counted as done
// (lib/ghost-card/vault.ts, pendingCardChange): adding to a card takes the
// amount off the wallet at once, and taking off a card adds it at once.
import { useEffect, useMemo, useState } from 'react';

import { fileChanges, pendingCardChange, subscribeChanges, type PaymentAtReading } from '../ghost-card/vault';
import { openShared, subscribePending } from '../vanish/pending';
import { statusOfStep } from '../vanish/status-mapping';
import { paymentKit, type PaymentKit } from '../vanish/use-payment';

function atReading(kit: PaymentKit | null, tipHeight: number, id: string): PaymentAtReading {
  const sequence = kit ? openShared(kit, id) : null;
  if (!sequence) {
    // Gone from this phone: never made, so nothing of it is to come.
    return 'failed';
  }
  try {
    if (statusOfStep(sequence.step()) === 'failed') {
      return 'failed';
    }
    const inclusion = sequence.record().inclusion;
    return inclusion && Number(inclusion.blockHeight) <= tipHeight ? 'in-reading' : 'not-yet';
  } catch {
    return 'not-yet';
  }
}

/** `balanceWei`, read at `tipHeight`, as it will be once the card changes finish. */
export function useCardBalance(nodeUrl: string, balanceWei: string | null, tipHeight: number | null): string | null {
  const kit = useMemo(() => paymentKit(nodeUrl), [nodeUrl]);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const bump = () => setTick((n) => n + 1);
    const stopChanges = subscribeChanges(bump);
    const stopPending = subscribePending(bump);
    return () => {
      stopChanges();
      stopPending();
    };
  }, []);
  return useMemo(() => {
    if (balanceWei === null || tipHeight === null) {
      return balanceWei;
    }
    let change = 0n;
    try {
      change = pendingCardChange(fileChanges().read(), (id) => atReading(kit, tipHeight, id));
    } catch {
      change = 0n;
    }
    const shown = BigInt(balanceWei) + change;
    return (shown < 0n ? 0n : shown).toString();
    // `tick`: read again whenever a change or a payment moves.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kit, balanceWei, tipHeight, tick]);
}
