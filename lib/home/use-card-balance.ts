// Home's balance with the card changes still going through counted as done
// (lib/ghost-card/vault.ts, pendingCardChange): adding to a card takes the
// amount off the wallet at once, and taking off a card adds it at once.
import { useEffect, useMemo, useState } from 'react';

import { fileChanges, pendingCardChange, subscribeChanges, type PaymentAtReading } from '../ghost-card/vault';
import { openShared, subscribePending } from '../vanish/pending';
import { statusOfStep } from '../vanish/status-mapping';
import { paymentKit, type PaymentKit } from '../vanish/use-payment';

/**
 * Whether a payment's effect is in a balance read at `tipHeight` with the
 * account at `nonce`. A Vanish is judged by its account nonce, which the
 * reading itself carries, so a block dropped from the chain cannot fool it.
 * A Summon has no account nonce: it counts once its record says it is in a
 * block (or settled) at or below the reading's tip; the payment's own moves
 * take that back within seconds if its block is dropped.
 */
function atReading(kit: PaymentKit | null, tipHeight: number, nonce: number, id: string): PaymentAtReading {
  const sequence = kit ? openShared(kit, id) : null;
  if (!sequence) {
    // Gone from this phone: never made, so nothing of it is to come.
    return 'failed';
  }
  try {
    const status = statusOfStep(sequence.step());
    if (status === 'failed') {
      return 'failed';
    }
    const record = sequence.record();
    const identity = record.intent.identity;
    if (identity.tag === 'AccountNonce') {
      return BigInt(nonce) > identity.inner.nonce ? 'in-reading' : 'not-yet';
    }
    const inclusion = record.inclusion;
    return (status === 'in-block' || status === 'settled') && inclusion && Number(inclusion.blockHeight) <= tipHeight
      ? 'in-reading'
      : 'not-yet';
  } catch {
    return 'not-yet';
  }
}

/** `balanceWei`, read at `tipHeight` with the account at `nonce`, as it will be once the card changes finish. */
export function useCardBalance(
  nodeUrl: string,
  balanceWei: string | null,
  tipHeight: number | null,
  nonce: number | null,
): string | null {
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
    if (balanceWei === null || tipHeight === null || nonce === null) {
      return balanceWei;
    }
    let change = 0n;
    try {
      change = pendingCardChange(fileChanges().read(), (id) => atReading(kit, tipHeight, nonce, id));
    } catch {
      change = 0n;
    }
    const shown = BigInt(balanceWei) + change;
    return (shown < 0n ? 0n : shown).toString();
    // `tick`: read again whenever a change or a payment moves.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kit, balanceWei, tipHeight, nonce, tick]);
}
