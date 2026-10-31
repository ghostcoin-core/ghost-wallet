// A payment on screen: the core's step sequence moved one step every few
// seconds until it is settled or failed. Leaving the screen stops its moves,
// not the payment: it is saved, Home goes on moving it (lib/home/use-pending.ts)
// and reopening the screen resumes it.
import { useEffect, useRef, useState } from 'react';

import { vanishCore, type CorePaymentSequence, type CorePaymentStore, type VanishBindings } from '../../modules/ghost-core';
import { failureReason } from '../node/failure-reason';
import { coinTreeAt, type CoinTree } from './coin-tree';
import { vanishNode, type VanishNode } from './node';
import { advance, type Rebuild } from './payments';
import { documentPaymentFiles, paymentStore } from './payment-store';
import { moveAlone, stopIfShort, stoppedVanish } from './pending';
import { isFinal, statusOfStep, type PaymentStatus } from './status-mapping';

export const MOVE_EVERY_MS = 3_000;

export type PaymentKit = {
  core: VanishBindings;
  store: CorePaymentStore;
  node: VanishNode;
  nodeUrl: string;
  /** Reads an account's balance at a block; the node's `eth_getBalance` when not set. */
  balance?: (account: string, blockHash: string) => Promise<bigint>;
};

/** The core, the store and the node; null in a build without the native core. */
export function paymentKit(nodeUrl: string): PaymentKit | null {
  try {
    const core = vanishCore();
    const files = documentPaymentFiles();
    if (!files) {
      return null;
    }
    return { core, store: paymentStore(core, files), node: vanishNode(nodeUrl), nodeUrl };
  } catch {
    return null;
  }
}

/** The coin tree at the node's tip. */
export async function treeAtTip(kit: PaymentKit): Promise<{ tree: CoinTree; tip: number }> {
  const tip = await kit.node.tipHeight();
  const tree = await coinTreeAt(kit.core, kit.node, kit.nodeUrl, kit.core.commitEntryAddress(), tip);
  return { tree, tip };
}

export type PaymentView = {
  status: PaymentStatus;
  step: number | string;
  needsKey: boolean;
  error: string | null;
  /** A Vanish the account could not pay for: held stopped, `error` says why. */
  stopped?: boolean;
};

/**
 * Moves `sequence` until it is final. `rebuild` makes a new attempt when the
 * fee window passed; `withTree` reads the coin tree for a reveal's marker.
 */
export function usePayment(
  kit: PaymentKit | null,
  sequence: CorePaymentSequence | null,
  rebuild: Rebuild | null,
  withTree: boolean,
): PaymentView | null {
  // The view, with the sequence it belongs to: a view of another payment is
  // never shown.
  const [moved, setMoved] = useState<{ of: CorePaymentSequence; view: PaymentView } | null>(null);
  const rebuildRef = useRef(rebuild);

  useEffect(() => {
    rebuildRef.current = rebuild;
  }, [rebuild]);

  useEffect(() => {
    if (!kit || !sequence) {
      return;
    }
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    async function move(payment: CorePaymentSequence, tools: PaymentKit) {
      let id = '';
      try {
        id = payment.record().id;
        const stoppedWhy = stoppedVanish(id);
        if (stoppedWhy !== null) {
          // Held stopped (here or by Home): never moved again.
          const step = payment.step();
          setMoved({ of: payment, view: { ...initialView(step), error: stoppedWhy, stopped: true } });
          return;
        }
        // Home may be moving this payment right now: then this move waits for the next.
        const next = await moveAlone(id, async () => {
          const tree = withTree ? (await treeAtTip(tools)).tree : null;
          return advance(tools.node, payment, rebuildRef.current, tree);
        });
        if (stopped) {
          return;
        }
        if (next) {
          setMoved({ of: payment, view: { ...next, error: null } });
          if (isFinal(next.status)) {
            return;
          }
        } else {
          const step = payment.step();
          setMoved((current) => (current?.of === payment && current.view.step === step ? current : { of: payment, view: initialView(step) }));
          if (isFinal(statusOfStep(step))) {
            return;
          }
        }
      } catch (error) {
        if (stopped) {
          return;
        }
        // The payment is saved; the next move tries again, unless the account
        // cannot pay for this Vanish: then it stops here.
        const message = failureReason(error, tools.nodeUrl);
        const stop = stopIfShort(id, error, tools.nodeUrl);
        const step = payment.step();
        setMoved((current) => ({
          of: payment,
          view: {
            ...(current?.of === payment ? current.view : initialView(step)),
            error: message,
            ...(stop ? { stopped: true } : {}),
          },
        }));
        if (stop) {
          return;
        }
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
  }, [kit, sequence, withTree]);

  if (!kit || !sequence) {
    return null;
  }
  return moved?.of === sequence ? moved.view : initialView(sequence.step());
}

function initialView(step: number | string): PaymentView {
  return { status: statusOfStep(step), step, needsKey: false, error: null };
}
