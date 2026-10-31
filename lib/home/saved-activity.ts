// The payments this phone made, read back from their saved records
// (lib/vanish/payment-store.ts): every send, Vanish, Summon and Claim stays
// saved once it settles or fails, so Activity lists it with its final state.
// One still going is not listed here: Home shows it as a pending row with the
// step it is at (lib/vanish/pending.ts), so no payment shows twice.
import type { CorePaymentRecord, CorePaymentStore, VanishBindings } from '../../modules/ghost-core';
import { bytesToHex } from '../../modules/ghost-core/account-lookup';
import { decodeDetails, onOtherChain } from '../vanish/payments';
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
      const record = sequence.record();
      if (onOtherChain(record)) {
        // It settled (or failed) on another chain than the one this build shows.
        continue;
      }
      const item = savedActivityItem(id, record, sequence.step());
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

/** What a saved Summon or Claim may have put in the account, and the block it landed in. */
export type SavedCredit = {
  /** Its amount, and its amount less its fee: either may be what came in. */
  amounts: string[];
  /** The block it was included in; null when the record does not say. */
  height: number | null;
};

/**
 * What each saved Summon and Claim may have put in the account, by payment
 * id. Home sees such a credit only as the balance going up.
 */
export function savedCredits(kit: Kit | null): Map<string, SavedCredit> {
  const credits = new Map<string, SavedCredit>();
  for (const id of savedIds(kit)) {
    const record = kit ? recordOf(kit, id) : null;
    const details = record ? decodeDetails(record.intent.details) : null;
    if (
      !record ||
      !details ||
      (details.kind !== 'summon' && details.kind !== 'claim') ||
      !/^[0-9]+$/.test(details.amountWei) ||
      // A credit on another chain explains nothing in this one's balance.
      onOtherChain(record)
    ) {
      continue;
    }
    const amounts = [details.amountWei];
    if (/^[0-9]+$/.test(details.feeWei) && BigInt(details.amountWei) > BigInt(details.feeWei)) {
      amounts.push((BigInt(details.amountWei) - BigInt(details.feeWei)).toString());
    }
    credits.set(id, { amounts, height: record.inclusion ? Number(record.inclusion.blockHeight) : null });
  }
  return credits;
}

/** A received payment Home saw only as the balance going up: no transaction, no sender, no saved payment. */
function balanceCredit(item: ActivityItem): boolean {
  return item.direction === 'received' && item.hash === undefined && item.counterparty === null && item.kind === undefined;
}

/** How many saved payments one balance increase is matched against at most. */
const MOST_IN_ONE_READING = 8;

/**
 * Of `candidates` (each crediting one of its amounts, or not in this
 * increase), the ones explaining the most of `increase` without going over,
 * and what they explain; on a tie, the choice with more payments.
 */
function explain(increase: bigint, candidates: readonly bigint[][]): { used: number[]; explained: bigint } {
  let best = { used: [] as number[], explained: 0n };
  const walk = (index: number, used: number[], sum: bigint) => {
    if (sum > increase) {
      return;
    }
    if (index === candidates.length) {
      if (sum > best.explained || (sum === best.explained && used.length > best.used.length)) {
        best = { used: [...used], explained: sum };
      }
      return;
    }
    walk(index + 1, used, sum);
    for (const amount of candidates[index]) {
      used.push(index);
      walk(index + 1, used, sum + amount);
      used.pop();
    }
  };
  walk(0, [], 0n);
  return best;
}

/**
 * Balance increases less what settled Summons and Claims explain. One reading
 * may hold several of them, and other payments too: each increase is matched
 * against the Summons and Claims landed in its blocks (or, when either side
 * does not say, started by then); what they explain goes, and the rest stays
 * listed as received.
 */
function lessSavedCredits(
  others: readonly ActivityItem[],
  incoming: readonly ActivityItem[],
  credits: ReadonlyMap<string, SavedCredit>,
): ActivityItem[] {
  const unmatched = [...incoming].sort((a, b) => a.at - b.at);
  const byCredit = new Map<ActivityItem, ActivityItem | null>();
  const increases = others.filter(balanceCredit).sort((a, b) => a.at - b.at);
  for (const increase of increases) {
    const inWindow = unmatched
      .filter((payment) => {
        const height = credits.get(payment.id)?.height ?? null;
        return increase.blocks && height !== null
          ? height > increase.blocks.after && height <= increase.blocks.upTo
          : payment.at <= increase.at;
      })
      .slice(0, MOST_IN_ONE_READING);
    if (inWindow.length === 0) {
      continue;
    }
    const total = BigInt(increase.amountWei);
    const { used, explained } = explain(
      total,
      inWindow.map((payment) => (credits.get(payment.id)?.amounts ?? [payment.amountWei]).map((amount) => BigInt(amount))),
    );
    for (const index of used) {
      unmatched.splice(unmatched.indexOf(inWindow[index]), 1);
    }
    if (explained > 0n) {
      byCredit.set(increase, explained === total ? null : { ...increase, amountWei: (total - explained).toString() });
    }
  }
  return others.flatMap((item) => {
    if (!byCredit.has(item)) {
      return [item];
    }
    const left = byCredit.get(item);
    return left ? [left] : [];
  });
}

/**
 * What Activity lists besides the pending rows: the saved payments, and what
 * Home keeps (received payments and those found on chain) less any saved
 * payment's own transaction. A settled Summon or Claim also stands for the
 * balance going up by what it credited: that part of the increase is not
 * listed again. Pending first, then the newest; at most `limit`.
 */
export function activityWithSaved(
  kept: readonly ActivityItem[],
  saved: readonly ActivityItem[],
  hashes: ReadonlySet<string>,
  limit: number,
  credits: ReadonlyMap<string, SavedCredit> = new Map(),
): ActivityItem[] {
  const incoming = saved.filter((item) => item.direction === 'received' && item.state === 'done');
  const others = lessSavedCredits(
    kept.filter((item) => item.hash === undefined || !hashes.has(item.hash)),
    incoming,
    credits,
  );
  const savedIdSet = new Set(saved.map((item) => item.id));
  return sortActivity([...saved, ...others.filter((item) => !savedIdSet.has(item.id))]).slice(0, limit);
}
