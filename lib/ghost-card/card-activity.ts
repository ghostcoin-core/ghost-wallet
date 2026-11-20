// What Activity says about a card's changes of balance (./vault.ts): one row
// for each Add or Take off, with the amount added or taken off. The payments
// a change makes underneath (the old coin's Summon into the wallet, then the
// Vanish of the new total onto the card) are not listed on their own: a card
// holding 1 that has 2 added shows "Added to card −2", never a Summon of 1 and
// a Vanish of 3. The rows stay after the change finishes, in a JSON file of
// public data (amounts and payment ids).
import { jsonFile } from '../storage';
import type { ActivityItem } from '../home/activity';

export type CardActivityEntry = {
  /** The change's id. */
  id: string;
  kind: 'add' | 'take';
  /** What was added or taken off, in wei. */
  amountWei: string;
  at: number;
  /** The payments the change made: listed as this one row, never on their own. */
  paymentIds: string[];
  /** The change finished: its payments settled. */
  done: boolean;
};

export type CardActivityStore = {
  read(): CardActivityEntry[];
  write(entries: CardActivityEntry[]): Promise<void>;
};

/** How many rows are kept; the oldest go first. */
const MOST = 200;

const FILE = 'card-activity.json';
let cached: CardActivityEntry[] | null = null;
let writing: Promise<unknown> = Promise.resolve();
const listeners = new Set<() => void>();

function isEntry(value: unknown): value is CardActivityEntry {
  const e = value as Partial<CardActivityEntry> | null;
  return (
    !!e &&
    typeof e.id === 'string' &&
    (e.kind === 'add' || e.kind === 'take') &&
    typeof e.amountWei === 'string' &&
    /^[0-9]+$/.test(e.amountWei) &&
    typeof e.at === 'number' &&
    Number.isFinite(e.at) &&
    Array.isArray(e.paymentIds) &&
    e.paymentIds.every((id) => typeof id === 'string') &&
    typeof e.done === 'boolean'
  );
}

/** The app's card rows, in a JSON file. */
export function fileCardActivity(): CardActivityStore {
  const file = jsonFile(FILE);
  return {
    read() {
      if (cached === null) {
        const raw = file.read();
        cached = Array.isArray(raw) ? raw.filter(isEntry) : [];
      }
      return cached;
    },
    write(entries) {
      const next = writing.then(async () => {
        await file.write(entries);
        cached = entries;
        listeners.forEach((listener) => listener());
      });
      writing = next.catch(() => undefined);
      return next;
    },
  };
}

/** Calls `listener` whenever the card rows change. */
export function subscribeCardActivity(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** The change a row stands for, as the vault saves it. */
export type ChangeForActivity = {
  id: string;
  beforeWei: string;
  afterWei: string;
  at: number;
  summonId: string | null;
  vanishId: string | null;
};

let journal: Promise<unknown> = Promise.resolve();

/**
 * Writes the row for `change` (made if new), with its payments so far, and
 * `done` once it finished. A payment once listed stays hidden under the row,
 * even one that failed and was made again.
 */
export function noteChange(store: CardActivityStore, change: ChangeForActivity, done: boolean): Promise<void> {
  const next = journal.then(() => {
    const entries = store.read();
    const before = BigInt(change.beforeWei);
    const after = BigInt(change.afterWei);
    const old = entries.find((e) => e.id === change.id);
    const ids = new Set(old?.paymentIds ?? []);
    for (const id of [change.summonId, change.vanishId]) {
      if (id && id !== 'gone') {
        ids.add(id);
      }
    }
    const entry: CardActivityEntry = {
      id: change.id,
      kind: after >= before ? 'add' : 'take',
      amountWei: (after >= before ? after - before : before - after).toString(),
      at: old?.at ?? change.at,
      paymentIds: [...ids],
      done: done || (old?.done ?? false),
    };
    if (
      old &&
      old.done === entry.done &&
      old.paymentIds.length === entry.paymentIds.length &&
      old.amountWei === entry.amountWei
    ) {
      return;
    }
    const rest = entries.filter((e) => e.id !== change.id);
    return store.write([...rest, entry].sort((a, b) => a.at - b.at).slice(-MOST));
  });
  journal = next.catch(() => undefined);
  return next;
}

/** Every payment a card row stands for. */
export function cardPaymentIds(entries: readonly CardActivityEntry[]): Set<string> {
  return new Set(entries.flatMap((e) => e.paymentIds));
}

/** The card rows as Activity items: one for each Add or Take off. */
export function cardActivityItems(entries: readonly CardActivityEntry[]): ActivityItem[] {
  return entries
    .filter((e) => e.amountWei !== '0')
    .map((e) => ({
      id: `card-${e.id}`,
      direction: e.kind === 'add' ? 'sent' : 'received',
      counterparty: null,
      amountWei: e.amountWei,
      state: e.done ? 'done' : 'pending',
      at: e.at,
      card: e.kind,
    }));
}

/**
 * Activity with the card rows: each change's own payments go, and its one
 * row takes their place.
 */
export function withCardActivity(items: readonly ActivityItem[], entries: readonly CardActivityEntry[]): ActivityItem[] {
  const hidden = cardPaymentIds(entries);
  return [...items.filter((item) => !hidden.has(item.id)), ...cardActivityItems(entries)];
}
