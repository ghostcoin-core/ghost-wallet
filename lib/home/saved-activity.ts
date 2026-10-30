// The payments this phone made, read back from their saved records
// (lib/vanish/payment-store.ts): every send, Vanish, Summon and Claim stays
// saved once it settles or fails, so Activity lists it with its final state.
// One still going is not listed here: Home shows it as a pending row with the
// step it is at (lib/vanish/pending.ts), so no payment shows twice.
import type { CorePaymentRecord, CorePaymentStore, VanishBindings } from '../../modules/ghost-core';
import { bytesToHex } from '../../modules/ghost-core/account-lookup';
import { decodeDetails } from '../vanish/payments';
import { kindOfId, openShared } from '../vanish/pending';
import { stepName } from '../vanish/status-mapping';
import { activityStateFromStep, sortActivity, type ActivityItem } from './activity';

type Kit = { core: Pick<VanishBindings, 'PaymentSequence'>; store: CorePaymentStore };

function savedIds(kit: Kit | null): string[] {
  if (!kit) {
    return [];
  }
  try {
    return kit.store.list().filter((id) => kindOfId(id) !== null);
  } catch {
    return [];
  }
}

function recordOf(kit: Kit, id: string): CorePaymentRecord | null {
  try {
    return openShared(kit, id)?.record() ?? null;
  } catch {
    return null;
  }
}

/** Every transaction the record names: its attempts and the one included. */
function hashesOf(record: CorePaymentRecord): string[] {
  const hashes = (record.attempts ?? []).map((attempt) => bytesToHex(attempt.transactionHash));
  if (record.inclusion) {
    hashes.push(bytesToHex(record.inclusion.transactionHash));
  }
  return hashes;
}

/** The transaction that stands for the payment: the included one, else the last attempt. */
function hashOf(record: CorePaymentRecord): string | undefined {
  if (record.inclusion) {
    return bytesToHex(record.inclusion.transactionHash);
  }
  const last = record.attempts?.[record.attempts.length - 1];
  return last ? bytesToHex(last.transactionHash) : undefined;
}

/**
 * The item a saved payment shows as, or null while it is still going (its
 * pending row shows it) or when its details do not read. A step this code
 * does not know is shown pending, never done.
 */
export function savedActivityItem(id: string, record: CorePaymentRecord, step: number | string): ActivityItem | null {
  const kind = kindOfId(id);
  const name = stepName(step);
  if (!kind || (name !== null && name !== 'Settled' && name !== 'Failed' && name !== 'Conflicted')) {
    return null;
  }
  const details = decodeDetails(record.intent.details);
  if (!details || details.kind !== kind || !/^[0-9]+$/.test(details.amountWei) || !Number.isFinite(details.at)) {
    return null;
  }
  const hash = hashOf(record);
  return {
    id,
    direction: kind === 'send' || kind === 'vanish' ? 'sent' : 'received',
    counterparty: details.kind === 'send' && /^0x[0-9a-f]{40}$/i.test(details.to) ? details.to.toLowerCase() : null,
    amountWei: details.amountWei,
    state: name === null ? 'pending' : activityStateFromStep(name),
    at: details.at,
    kind,
    ...(hash ? { hash } : {}),
  };
}

/** The settled, failed and conflicted payments this phone saved, as Activity lists them. */
export function savedActivity(kit: Kit | null): ActivityItem[] {
  const items: ActivityItem[] = [];
  for (const id of savedIds(kit)) {
    const sequence = kit ? openShared(kit, id) : null;
    if (!sequence) {
      continue;
    }
    try {
      const item = savedActivityItem(id, sequence.record(), sequence.step());
      if (item) {
        items.push(item);
      }
    } catch {
      // A record that fails its checks is left for the core to report.
    }
  }
  return items;
}

/**
 * Every transaction a saved payment made, still going or not: one found on
 * chain is the same payment and is not listed again.
 */
export function savedHashes(kit: Kit | null): Set<string> {
  const hashes = new Set<string>();
  for (const id of savedIds(kit)) {
    const record = kit ? recordOf(kit, id) : null;
    for (const hash of record ? hashesOf(record) : []) {
      hashes.add(hash);
    }
  }
  return hashes;
}

/**
 * What Activity lists besides the pending rows: the saved payments, and what
 * Home keeps (received payments and those found on chain) less any saved
 * payment's own transaction. Pending first, then the newest; at most `limit`.
 */
export function activityWithSaved(
  kept: readonly ActivityItem[],
  saved: readonly ActivityItem[],
  hashes: ReadonlySet<string>,
  limit: number,
): ActivityItem[] {
  const others = kept.filter((item) => item.hash === undefined || !hashes.has(item.hash));
  const savedIdSet = new Set(saved.map((item) => item.id));
  return sortActivity([...saved, ...others.filter((item) => !savedIdSet.has(item.id))]).slice(0, limit);
}
