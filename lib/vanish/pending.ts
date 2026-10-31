// Vanish, Summon and Claim payments left mid-way. Leaving a progress screen
// (or closing the app) never stops a payment: its record is saved at every
// step, Home lists it as pending with the step it is at, and tapping it opens
// its screen again on that payment.
//
// A new Phantom Key is held by the native core until its words are checked
// (or it is on a card, or the person skipped the check): that key is never
// lost by leaving. Which step the
// Vanish was at (the words shown, the check, the card) is kept here while the
// core holds the key, so reopening the Vanish returns to it. The words stay
// in this memory only as long as the core holds the key: they go when the
// key is confirmed written down or the Vanish is cancelled, and with the app.
import type { CorePaymentSequence, CorePaymentStore, VanishBindings } from '../../modules/ghost-core';
import { failureReason } from '../node/failure-reason';
import { OTHER_NETWORK_TEXT, decodeDetails, onOtherChain } from './payments';
import { sendStatusLabel, sendStatusOf } from '../send/payment-status';
import { hasReached } from '../send/reached';
import { isFinal, statusLabel, statusOfStep, stepName, type PaymentStatus, type SavedKind } from './status-mapping';

/** Where a Vanish stood while the core still held its new key. */
export type HeldStep = 'save' | 'check' | 'card';

export type HeldVanish = {
  /** The payment id of the Vanish (`vanish-…`). */
  id: string;
  step: HeldStep;
  words: string[];
  /** The three positions asked at the check, kept so they do not change. */
  positions: number[] | null;
  /** At the card step: whether the three words were typed back first (a card needs no check). */
  checked?: boolean;
};

type Kit = { core: Pick<VanishBindings, 'PaymentSequence'>; store: CorePaymentStore };

let held: HeldVanish | null = null;
let reopened: string | null = null;
const sequences = new Map<string, CorePaymentSequence>();
const moving = new Set<string>();
/** Vanishes the node refused for lack of funds, with why: never moved again here. */
const stopped = new Map<string, string>();
const listeners = new Set<() => void>();

function notify() {
  for (const listener of listeners) {
    listener();
  }
}

/** Calls `listener` whenever a pending payment changes here. */
export function subscribePending(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Something moved a payment: Home reads the list again. */
export function paymentsChanged() {
  notify();
}

export function holdVanish(next: HeldVanish) {
  held = next;
  notify();
}

/** The Vanish whose new key the core holds, if any. */
export function heldKey(): HeldVanish | null {
  return held;
}

/** The held step of Vanish `id`, if the core still holds its key. */
export function heldVanish(id: string): HeldVanish | null {
  return held && held.id === id ? held : null;
}

/** Drops what is kept of the held key (the core's key is confirmed or forgotten apart). */
export function releaseHeldVanish() {
  held = null;
  notify();
}

/** One object per saved payment, so that two screens never move two copies of it. */
export function shared(sequence: CorePaymentSequence): CorePaymentSequence {
  let id: string;
  try {
    id = sequence.record().id;
  } catch {
    return sequence;
  }
  const known = sequences.get(id);
  if (known) {
    return known;
  }
  sequences.set(id, sequence);
  return sequence;
}

/** The saved payment `id`, opened once. */
export function openShared(kit: Kit, id: string): CorePaymentSequence | null {
  const known = sequences.get(id);
  if (known) {
    return known;
  }
  try {
    return shared(kit.core.PaymentSequence.open(kit.store, id));
  } catch {
    // A record that fails its checks is left for the core to report.
    return null;
  }
}

/** The newest saved payment of these kinds, opened once. */
export function newestShared(kit: Kit, kinds: readonly SavedKind[]): CorePaymentSequence | null {
  const [newest] = kit.store
    .list()
    .filter((id) => kinds.some((kind) => id.startsWith(`${kind}-`)))
    .sort((a, b) => idTime(b) - idTime(a));
  return newest ? openShared(kit, newest) : null;
}

function idTime(id: string): number {
  const at = parseInt(id.split('-')[1] ?? '', 36);
  return Number.isFinite(at) ? at : 0;
}

/** Forgets the object of a payment whose record is removed. */
export function forgetShared(id: string) {
  sequences.delete(id);
  stopped.delete(id);
  notify();
}

/**
 * Holds Vanish `id` stopped: the account was short of its amount and fee.
 * Neither its screen nor Home moves it again, so a later top-up does not send
 * it by itself; the person can only cancel it.
 */
export function stopVanish(id: string, reason: string) {
  stopped.set(id, reason);
  notify();
}

/** Whether the node (or the balance check before signing) found the account short of funds. */
export function shortOfFunds(error: unknown): boolean {
  const message = error instanceof Error ? error.message : typeof error === 'string' ? error : '';
  return /insufficient ?(funds|balance)|not enough|exceeds balance|balance too low/.test(message.toLowerCase());
}

/**
 * After a failed move of payment `id`: a Vanish the account is short of funds
 * for is held stopped (true); anything else is tried again (false).
 */
export function stopIfShort(id: string, error: unknown, nodeUrl: string): boolean {
  if (kindOfId(id) !== 'vanish' || !shortOfFunds(error)) {
    return false;
  }
  stopVanish(id, failureReason(error, nodeUrl));
  return true;
}

/** Why Vanish `id` was stopped, or null when it was not. */
export function stoppedVanish(id: string): string | null {
  return stopped.get(id) ?? null;
}

/** How Home lists a Vanish held stopped. */
export const STOPPED_TEXT = 'Stopped, not enough GHOST. Open it to cancel.';

/** Asks the next screen of its kind to open payment `id`. */
export function reopenPayment(id: string) {
  reopened = id;
}

/** The payment Home asked to open, if it is of one of these kinds. */
export function takeReopened(kinds: readonly SavedKind[]): string | null {
  const id = reopened;
  if (id && kinds.some((kind) => id.startsWith(`${kind}-`))) {
    reopened = null;
    return id;
  }
  return null;
}

/**
 * Runs one move of payment `id`, unless another move of it is running (Home
 * and its screen both move payments): then nothing, and null.
 */
export async function moveAlone<T>(id: string, move: () => Promise<T>): Promise<T | null> {
  if (moving.has(id)) {
    return null;
  }
  moving.add(id);
  try {
    return await move();
  } finally {
    moving.delete(id);
    notify();
  }
}

export function kindOfId(id: string): SavedKind | null {
  const kind = id.split('-')[0];
  return kind === 'vanish' || kind === 'summon' || kind === 'claim' || kind === 'send' ? kind : null;
}

/** The amount the payment moves, from its saved details. */
export function paymentAmountWei(sequence: CorePaymentSequence): bigint | null {
  try {
    const details = decodeDetails(sequence.record().intent.details);
    return details ? BigInt(details.amountWei) : null;
  } catch {
    return null;
  }
}

function paymentAt(sequence: CorePaymentSequence, id: string): number {
  try {
    const details = decodeDetails(sequence.record().intent.details);
    if (details) {
      return details.at;
    }
  } catch {
    // The id holds the time too.
  }
  return idTime(id);
}

/** A payment still going, as Home lists it. */
export type PendingPayment = {
  id: string;
  kind: SavedKind;
  amountWei: string | null;
  at: number;
  status: PaymentStatus;
  /** Set while the core still holds the Vanish's new key. */
  held: HeldStep | null;
  /** Saved for another chain than this build's: listed, never moved. */
  otherNetwork: boolean;
  /** The step it is at, in words. */
  stepText: string;
};

function savedOnOtherChain(sequence: CorePaymentSequence): boolean {
  try {
    return onOtherChain(sequence.record());
  } catch {
    return false;
  }
}

export function heldStepText(step: HeldStep): string {
  return step === 'card' ? 'Put the Phantom Key on a card' : 'Write down the Phantom Key';
}

/**
 * Every saved send, Vanish, Summon and Claim not settled or failed yet, newest
 * first. A Vanish still waiting for its key to be written down shows only
 * while the core holds that key. A send reads queued until the node holds it.
 */
export function pendingPayments(kit: Kit | null): PendingPayment[] {
  if (!kit) {
    return [];
  }
  let ids: string[];
  try {
    ids = kit.store.list();
  } catch {
    return [];
  }
  const pending: PendingPayment[] = [];
  for (const id of ids) {
    const kind = kindOfId(id);
    if (!kind) {
      continue;
    }
    const sequence = openShared(kit, id);
    if (!sequence) {
      continue;
    }
    const step = sequence.step();
    const status = statusOfStep(step);
    if (isFinal(status)) {
      continue;
    }
    const keyStep = kind === 'vanish' ? (heldVanish(id)?.step ?? null) : null;
    if (stepName(step) === 'Prepared' && !keyStep) {
      continue;
    }
    const amount = paymentAmountWei(sequence);
    const otherNetwork = savedOnOtherChain(sequence);
    pending.push({
      id,
      kind,
      amountWei: amount === null ? null : amount.toString(),
      at: paymentAt(sequence, id),
      status,
      held: keyStep,
      otherNetwork,
      stepText: otherNetwork
        ? OTHER_NETWORK_TEXT
        : stopped.has(id)
          ? STOPPED_TEXT
          : keyStep
            ? heldStepText(keyStep)
            : kind === 'send'
              ? sendStatusLabel(sendStatusOf(step, hasReached(id)))
              : statusLabel(status, kind),
    });
  }
  return pending.sort((a, b) => b.at - a.at);
}

/** Clears everything kept here; for tests. */
export function resetPending() {
  held = null;
  reopened = null;
  sequences.clear();
  moving.clear();
  stopped.clear();
}
