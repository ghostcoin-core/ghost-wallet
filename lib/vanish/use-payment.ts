// A payment on screen: the core's step sequence moved one step every few
// seconds until it is settled or failed. Leaving the screen stops the moves,
// not the payment: it is saved, and reopening the screen resumes it.
import { useEffect, useRef, useState } from 'react';

import { vanishCore, type CorePaymentSequence, type CorePaymentStore, type VanishBindings } from '../../modules/ghost-core';
import { coinTreeAt, type CoinTree } from './coin-tree';
import { vanishNode, type VanishNode } from './node';
import { advance, type Rebuild } from './payments';
import { documentPaymentFiles, paymentStore } from './payment-store';
import { isFinal, statusOfStep, type PaymentStatus } from './status-mapping';

export const MOVE_EVERY_MS = 3_000;

export type PaymentKit = {
  core: VanishBindings;
  store: CorePaymentStore;
  node: VanishNode;
  nodeUrl: string;
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
      try {
        const tree = withTree ? (await treeAtTip(tools)).tree : null;
        const next = await advance(tools.node, payment, rebuildRef.current, tree);
        if (stopped) {
          return;
        }
        setMoved({ of: payment, view: { ...next, error: null } });
        if (isFinal(next.status)) {
          return;
        }
      } catch (error) {
        if (stopped) {
          return;
        }
        // The payment is saved; the next move tries again.
        const message = error instanceof Error ? error.message : 'the node could not be asked';
        const step = payment.step();
        setMoved((current) => ({
          of: payment,
          view: current?.of === payment ? { ...current.view, error: message } : { ...initialView(step), error: message },
        }));
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
