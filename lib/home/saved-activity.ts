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
 * What each saved Summon and Claim may have put in the account, by payment
 * id: its amount, and its amount less its fee. Home sees such a credit only
 * as the balance going up.
 */
export function savedCredits(kit: Kit | null): Map<string, string[]> {
  const credits = new Map<string, string[]>();
  for (const id of savedIds(kit)) {
    const record = kit ? recordOf(kit, id) : null;
    const details = record ? decodeDetails(record.intent.details) : null;
    if (!details || (details.kind !== 'summon' && details.kind !== 'claim') || !/^[0-9]+$/.test(details.amountWei)) {
      continue;
    }
    const amounts = [details.amountWei];
    if (/^[0-9]+$/.test(details.feeWei) && BigInt(details.amountWei) > BigInt(details.feeWei)) {
      amounts.push((BigInt(details.amountWei) - BigInt(details.feeWei)).toString());
    }
    credits.set(id, amounts);
  }
  return credits;
}

/** A received payment Home saw only as the balance going up: no transaction, no sender, no saved payment. */
function balanceCredit(item: ActivityItem): boolean {
  return item.direction === 'received' && item.hash === undefined && item.counterparty === null && item.kind === undefined;
}

/**
 * What Activity lists besides the pending rows: the saved payments, and what
 * Home keeps (received payments and those found on chain) less any saved
 * payment's own transaction. A settled Summon or Claim also stands for the
 * balance going up by what it credited, once it settled: that credit is not
 * listed again. Pending first, then the newest; at most `limit`.
 */
export function activityWithSaved(
  kept: readonly ActivityItem[],
  saved: readonly ActivityItem[],
  hashes: ReadonlySet<string>,
  limit: number,
  credits: ReadonlyMap<string, readonly string[]> = new Map(),
): ActivityItem[] {
  let others = kept.filter((item) => item.hash === undefined || !hashes.has(item.hash));
  const incoming = saved
    .filter((item) => item.direction === 'received' && item.state === 'done')
    .sort((a, b) => a.at - b.at);
  for (const payment of incoming) {
    const amounts = credits.get(payment.id) ?? [payment.amountWei];
    // The oldest credit at or after the payment, of what it may have credited.
    const match = others
      .filter((item) => balanceCredit(item) && item.at >= payment.at && amounts.includes(item.amountWei))
      .sort((a, b) => a.at - b.at)[0];
    if (match) {
      others = others.filter((item) => item !== match);
    }
  }
  const savedIdSet = new Set(saved.map((item) => item.id));
  return sortActivity([...saved, ...others.filter((item) => !savedIdSet.has(item.id))]).slice(0, limit);
}
