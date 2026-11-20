// A Ghost card as a vault: it holds one balance, GHOST is added to it and
// any amount is taken off it (docs/bearer-card-spec.md, "A card as a vault").
//
// The card holds one coin, made from a key the card drew itself. Changing
// its balance gives the card a new key for the new total, in one hold:
//
// 1. Open: the card releases its key; the native core checks it makes the
//    card's coin, and it is kept in this phone's Keychain (never shown).
// 2. Remake: in the same hold the card is cleared and makes a new key for
//    the new total, and signs that it holds it.
// 3. In the background: the old coin is Summoned into the wallet with the
//    kept key, then a Vanish pays the new total into the card's new coin.
//
// So the card stays a bearer object (no phone ever has the key of the coin
// on it), and whoever taps it sees the one balance it holds. Every step after
// the hold is saved here (public data only: the card id, the coins' public
// markers and commit data, amounts and payment ids) and carries on after a
// restart, until the new coin settles. An empty card (blank, or opened with
// its coin already taken) is simply filled; a card whose last change is still
// going through is changed again on top of it.
import { bytesToHex } from '../../modules/ghost-core/account-lookup';
import { hexToBytes, type CardKeyStore } from '../../modules/ghost-nfc/java-card';
import { jsonFile } from '../storage';
import { noteChange, squareRows, type CardActivityStore } from './card-activity';
import type { CoinOnChain } from './chain';
import {
  checkGhostCard,
  openGhostCard,
  refillGhostCard,
  remakeGhostCard,
  type CheckResult,
  type GhostCardDeps,
} from './flows';
import { ghostText } from '../seal/card-status';
import type { GhostCardStatus } from './status';

/** One change of a card's balance, saved from the hold until its new coin settles. */
export type CardChange = {
  /** This change's own id: a card can have several going at once. */
  id: string;
  /** The card's id (hex) and the fill it was at when the change began. */
  cardId: string;
  cardNumber: string;
  oldFill: number;
  /** The old coin to Summon into the wallet (its marker, hex); null when there is none. */
  oldMarker: string | null;
  /** The old coin's commit data (hex), when its own Vanish was still on its way at the hold. */
  oldCommitData: string | null;
  /**
   * Whether the old coin counts in `beforeWei`. A coin nobody had paid at the
   * hold does not, but its key is kept all the same: a Vanish from another
   * phone may still land on it, and is then brought home to the wallet.
   */
  oldCounted: boolean;
  /** What the card held before the change. */
  beforeWei: string;
  /** What it holds after: 0 when it was emptied. */
  afterWei: string;
  /** The new coin's commit data (hex), once the card made it; null until then, or when emptied. */
  commitData: string | null;
  newFill: number | null;
  /** The Summon of the old coin: a payment id, or 'gone' when the chain shows it already taken. */
  summonId: string | null;
  /** The Vanish into the new coin. */
  vanishId: string | null;
  at: number;
};

/** Where a saved payment is. */
export type PaymentState = 'moving' | 'in-block' | 'settled' | 'failed' | 'missing';

/** The wallet side of a change; each replaced by a fake in the tests. */
export type VaultPayments = {
  /** The coin of the card key the native core holds. Throws when no node answers. */
  lookUpHeldKey(): Promise<'found' | 'spent' | 'not-found'>;
  /** Starts (or joins) the Summon of the held card key's whole coin into the wallet: its payment id. */
  summonHeldKey(): Promise<string>;
  /** Moves Summon `id` once; a new proof uses the held card key. */
  moveSummon(id: string): Promise<void>;
  paymentState(id: string): PaymentState;
  /** Starts (or finds) the Vanish of exactly `amountWei` into `commitData`: its payment id. */
  startVanish(amountWei: bigint, commitData: Uint8Array): Promise<string>;
  /** Whether a Vanish into `commitData` is saved on this phone and not failed. */
  vanishSavedInto(commitDataHex: string): boolean;
  /** Wipes the card key the native core holds. */
  forgetHeldKey(): void;
};

export type ChangeStore = {
  read(): CardChange[];
  write(changes: CardChange[]): Promise<void>;
};

export type VaultDeps = {
  card: GhostCardDeps;
  keys: CardKeyStore | null;
  payments: VaultPayments | null;
  changes: ChangeStore;
  /** Activity's card rows; absent, none are written. */
  activity?: CardActivityStore;
};

/** Add `amountWei` to the card, or take `amountWei` off it (null: all of it). */
export type ChangeRequest = { kind: 'add'; amountWei: bigint } | { kind: 'take'; amountWei: bigint | null };

export type ChangeResult =
  | { ok: true; cardNumber: string; beforeWei: bigint; afterWei: bigint }
  /** `message` is null when the sheet was closed. Nothing was taken from the card. */
  | { ok: false; message: string | null; alarm?: boolean };

/** What a card holds, as the screens say it. */
export type CardBalance =
  /** `updating`: a change is still going through; the balance is what it will hold. */
  /** `warning`: why it is not safe to accept, while its owner can still take it off. */
  | { kind: 'holds'; cardNumber: string; amountWei: bigint; updating: boolean; warning?: string }
  | { kind: 'empty'; cardNumber: string }
  | { kind: 'problem'; message: string; alarm: boolean };

/** How often a coin no one had paid is looked for: a lookup reads the coin tree. */
const STRAY_LOOK_EVERY_MS = 5 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
const lastLooked = new Map<string, number>();

/** Whether to look for the change's old coin on this move. */
function lookNow(change: CardChange): boolean {
  if (change.oldCounted) {
    return true;
  }
  const now = Date.now();
  // After its first day, once a day.
  const every = now - change.at > DAY_MS ? DAY_MS : STRAY_LOOK_EVERY_MS;
  if (now - (lastLooked.get(change.id) ?? 0) < every) {
    return false;
  }
  lastLooked.set(change.id, now);
  return true;
}

const CANNOT_READ = 'This iPhone cannot read Ghost cards in this build.';
const NO_NETWORK = "Can't reach the Ghost network. Nothing was changed. Try again in a moment.";
const OPENED_ELSEWHERE =
  "This card was opened on another phone, so someone else may be able to take its GHOST. Don't accept it. If it's yours, take it all off now.";
const SAVE_FAILED = 'Something went wrong on this iPhone. Hold the card again to finish.';
const NOT_CHANGED = 'The card was not changed. Hold it still near the top of the iPhone and try again.';

// ---------------------------------------------------------------------------
// The saved changes

const FILE = 'card-changes.json';
let cached: CardChange[] | null = null;
let writing: Promise<unknown> = Promise.resolve();
const listeners = new Set<() => void>();

function isChange(value: unknown): value is CardChange {
  const c = value as Partial<CardChange> | null;
  return (
    !!c &&
    typeof c.id === 'string' &&
    typeof c.cardId === 'string' &&
    typeof c.oldFill === 'number' &&
    typeof c.beforeWei === 'string' &&
    typeof c.afterWei === 'string'
  );
}

/** The app's saved changes, in a JSON file of public data. */
export function fileChanges(): ChangeStore {
  const file = jsonFile(FILE);
  return {
    read() {
      if (cached === null) {
        const raw = file.read();
        // A change saved before `oldCounted` existed counted its old coin.
        cached = Array.isArray(raw)
          ? raw.filter(isChange).map((c) => ({ ...c, oldCounted: typeof c.oldCounted === 'boolean' ? c.oldCounted : true }))
          : [];
      }
      return cached;
    },
    write(changes) {
      // One write at a time, and what is read changes only once it is on
      // disk: a failed save never looks saved to the next hold.
      const next = writing.then(async () => {
        await file.write(changes);
        cached = changes;
        listeners.forEach((listener) => listener());
      });
      writing = next.catch(() => undefined);
      return next;
    },
  };
}

/** Calls `listener` whenever the saved changes change. */
export function subscribeChanges(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

// Every save reads the saved changes and writes them back, one at a time, so
// no save starts from a list another save is still writing.
let journal: Promise<unknown> = Promise.resolve();

function mutate(store: ChangeStore, edit: (changes: CardChange[]) => CardChange[]): Promise<void> {
  const next = journal.then(() => store.write(edit(store.read())));
  journal = next.catch(() => undefined);
  return next;
}

function save(store: ChangeStore, change: CardChange): Promise<void> {
  return mutate(store, (changes) => [...changes.filter((c) => c.id !== change.id), change]);
}

function drop(store: ChangeStore, change: CardChange): Promise<void> {
  return mutate(store, (changes) => changes.filter((c) => c.id !== change.id));
}

/** The payment ids the changes move themselves (Home leaves them alone). */
export function changePaymentIds(store: ChangeStore): Set<string> {
  const ids = new Set<string>();
  for (const c of store.read()) {
    if (c.summonId && c.summonId !== 'gone') {
      ids.add(c.summonId);
    }
  }
  return ids;
}

// ---------------------------------------------------------------------------
// The card key slot

// The native core holds one card key at a time: every use of it (an Open,
// a lookup, a proof) runs here, one after another.
let slot: Promise<unknown> = Promise.resolve();

function withCardKey<T>(run: () => Promise<T>): Promise<T> {
  const next = slot.then(run, run);
  slot = next.catch(() => undefined);
  return next;
}

// ---------------------------------------------------------------------------
// The hold

/** An id no saved change has, nor any change Activity lists. */
function newChangeId(store: ChangeStore, activity?: CardActivityStore): string {
  const taken = new Set([...store.read().map((c) => c.id), ...(activity?.read().map((e) => e.id) ?? [])]);
  let id = `change-${Date.now()}`;
  for (let n = 1; taken.has(id); n++) {
    id = `change-${Date.now()}-${n}`;
  }
  return id;
}

/**
 * A change whose card made its new key but which was not saved as made (the
 * app was killed in between): the card is sealed at the next fill, for the
 * change's new total, with the commit data its signed statement covers. That
 * is the change's new coin, so it is saved as made and finishes as usual.
 */
async function adoptMade(deps: VaultDeps, cardId: string, fill: number, amountWei: bigint | null, commitData: Uint8Array) {
  const made = deps.changes
    .read()
    .find(
      (c) =>
        c.cardId === cardId &&
        c.commitData === null &&
        c.afterWei !== '0' &&
        c.oldFill + 1 === fill &&
        amountWei !== null &&
        BigInt(c.afterWei) === amountWei,
    );
  if (made) {
    await save(deps.changes, { ...made, commitData: bytesToHex(commitData), newFill: fill });
  }
}

/** Whether a saved change already brings the coin with `marker` home. */
function claimed(deps: Pick<VaultDeps, 'changes'>, marker: string): boolean {
  return deps.changes.read().some((c) => c.oldMarker === marker && !(c.commitData === null && c.afterWei !== '0'));
}

/** A change whose hold did not finish: the card was opened (or cleared) but has no new coin yet. */
function unfinishedOn(changes: readonly CardChange[], cardId: string, fill: number): CardChange | null {
  return changes.find((c) => c.cardId === cardId && c.oldFill === fill && c.commitData === null && c.afterWei !== '0') ?? null;
}

/** Whether a coin the chain does not show yet is on its way: a change or a Vanish on this phone pays it. */
function onItsWay(deps: Pick<VaultDeps, 'changes' | 'payments'>, commitData: Uint8Array | null, besides?: CardChange): boolean {
  if (!commitData) {
    return false;
  }
  const hex = bytesToHex(commitData);
  return (
    deps.changes.read().some((c) => c !== besides && c.commitData === hex && !changeFailed(deps, c)) ||
    (deps.payments?.vanishSavedInto(hex) ?? false)
  );
}

/** A change whose Vanish failed: its coin will never be paid. */
function changeFailed(deps: Pick<VaultDeps, 'payments'>, change: CardChange): boolean {
  const state = change.vanishId && deps.payments ? deps.payments.paymentState(change.vanishId) : null;
  return state === 'failed' || state === 'missing';
}

/** The new total, or why it cannot be. */
function newTotal(before: bigint, request: ChangeRequest, minimumWei: bigint): bigint | string {
  let after: bigint;
  if (request.kind === 'add') {
    after = before + request.amountWei;
  } else if (request.amountWei === null) {
    after = 0n;
  } else if (request.amountWei > before) {
    return before === 0n ? 'This card is empty.' : `This card holds only ${ghostText(before)} GHOST.`;
  } else {
    after = before - request.amountWei;
  }
  if (after > 0n && after < minimumWei) {
    return `A card holds at least ${ghostText(minimumWei)} GHOST. Take it all off, or leave more on it.`;
  }
  return after;
}

/**
 * Adds to or takes from the next card tapped, in one hold. Nothing leaves
 * the card unless its key is kept on this phone first, and the card is given
 * its new key only once the change is saved. `minimumWei` is the smallest
 * balance a card can hold (the smallest Vanish).
 */
export async function changeCard(deps: VaultDeps, request: ChangeRequest, minimumWei: bigint): Promise<ChangeResult> {
  const { keys, payments } = deps;
  if (!deps.card.core || !deps.card.nfc || !keys || !payments) {
    return { ok: false, message: CANNOT_READ };
  }
  const nfc = deps.card.nfc;
  return withCardKey(async () => {
    // One hold, one sheet: the Check, Open and new key run with the card
    // kept connected, never a sheet closing and another opening mid-hold.
    nfc.javaCardHold?.(true, null, null);
    let result: ChangeResult = { ok: false, message: SAVE_FAILED };
    try {
      result = await hold(deps, keys, payments, request, minimumWei);
      return result;
    } catch {
      // A save that failed: whatever the card did is picked up at its next hold.
      return result;
    } finally {
      // Closes the sheet if a step after a tap stopped the hold.
      nfc.javaCardHold?.(false, result.ok ? 'Done.' : null, result.ok ? null : result.message);
      payments.forgetHeldKey();
      if (result.ok) {
        // Activity's row for this change shows at once.
        await noteRow(deps, false);
      }
    }
  });
}

async function hold(
  deps: VaultDeps,
  keys: CardKeyStore,
  payments: VaultPayments,
  request: ChangeRequest,
  minimumWei: bigint,
): Promise<ChangeResult> {
  let only: { cardId: Uint8Array; fill: number } | undefined;
  if (deps.changes.read().some((c) => c.commitData === null && c.afterWei !== '0')) {
    // A change on this phone may have made its card's new key without saving
    // it. The card is read first, without opening it, so that coin is saved
    // before anything can open it; then only that card is opened.
    const checked = await checkGhostCard(deps.card);
    if (checked === null) {
      return { ok: false, message: null };
    }
    const s = checked.statement;
    if (!s) {
      return failure(checked.status);
    }
    if (s.state === 'sealed') {
      if (!checked.commitData) {
        return { ok: false, message: NOT_CHANGED };
      }
      await adoptMade(deps, bytesToHex(s.cardId), s.fill, BigInt(s.amountWei), checked.commitData);
    }
    only = { cardId: new Uint8Array(s.cardId), fill: s.fill };
  }
  const opened = await openGhostCard(deps.card, only);
  let cardId: Uint8Array;
  let fill: number;
  let cardNumber: string;
  // What the card holds now, and the coin to Summon for it.
  let before = 0n;
  let oldMarker: string | null = null;
  // The old coin's commit data, when its own Vanish is still on its way.
  let oldCommitData: string | null = null;
  // A change whose hold was cut off on this coin: this one takes its place.
  let resumed: CardChange | null = null;
  let oldCounted = true;

  if (opened.ok) {
    cardId = opened.cardId;
    fill = opened.fill;
    cardNumber = opened.cardNumber;
    const coin = opened.coin;
    if (coin?.state === 'sealed' && coin.commitData) {
      await adoptMade(deps, bytesToHex(cardId), fill, opened.amountWei, coin.commitData);
    }
    let chain: CoinOnChain | null = null;
    if (coin) {
      try {
        chain = await deps.card.coinOnChain(coin.commitment, coin.marker);
      } catch {
        chain = null;
      }
    }
    const unfinished = unfinishedOn(deps.changes.read(), bytesToHex(cardId), fill);
    if (unfinished) {
      // A hold cut off before: the same coin, the balance it had.
      resumed = unfinished;
      before = BigInt(unfinished.beforeWei);
      oldMarker = unfinished.oldMarker;
      oldCommitData = unfinished.oldCommitData;
      oldCounted = unfinished.oldCounted;
    } else if (!coin) {
      // No seal checks left: it cannot prove what it holds. Nothing was changed.
      return { ok: false, message: 'This card is worn out. Use Settings, Cards, to move its GHOST to your wallet.' };
    } else if (chain === null) {
      // Whether the coin is there cannot be read: nothing is changed. The
      // card answers an Open again with the same key, so it is still safe.
      return { ok: false, message: NO_NETWORK };
    } else if (chain.spent === true) {
      return { ok: false, message: 'This card is broken: its GHOST was taken without the card.', alarm: true };
    } else if (claimed(deps, bytesToHex(coin.marker))) {
      // An earlier change (all of it taken off, its card not cleared) is
      // already bringing this coin home: the card holds nothing more.
      before = 0n;
    } else if (chain.status !== 'absent') {
      before = opened.amountWei ?? 0n;
      oldMarker = bytesToHex(coin.marker);
    } else if (onItsWay(deps, coin.commitData)) {
      // Its last change is still going through: this one goes on top of it.
      before = opened.amountWei ?? 0n;
      oldMarker = bytesToHex(coin.marker);
      oldCommitData = coin.commitData ? bytesToHex(coin.commitData) : null;
    } else {
      // Sealed, but nothing has paid into it yet: it holds nothing. Its key
      // is kept anyway, in case a payment from another phone still lands.
      before = 0n;
      oldMarker = bytesToHex(coin.marker);
      oldCommitData = coin.commitData ? bytesToHex(coin.commitData) : null;
      oldCounted = false;
    }
  } else if (opened.blank) {
    cardId = opened.blank.cardId;
    fill = opened.blank.fill;
    cardNumber = opened.blank.cardNumber;
    const unfinished = unfinishedOn(deps.changes.read(), bytesToHex(cardId), fill);
    if (unfinished) {
      // Cleared in a hold cut off before it made the new key.
      resumed = unfinished;
      before = BigInt(unfinished.beforeWei);
      oldMarker = unfinished.oldMarker;
      oldCommitData = unfinished.oldCommitData;
      oldCounted = unfinished.oldCounted;
    }
  } else if (opened.reuse) {
    // Opened before, its coin already taken off: an empty card.
    cardId = opened.reuse.cardId;
    fill = opened.reuse.fill;
    cardNumber = opened.status?.kind === 'opened' ? opened.status.cardNumber : '';
    // A hold cut off here before is over: its coin was taken off elsewhere.
    const unfinished = unfinishedOn(deps.changes.read(), bytesToHex(cardId), fill);
    if (unfinished) {
      if (unfinished.oldMarker) {
        keys.forgetKeptCardKey(tagOf(unfinished.oldMarker));
      }
      await drop(deps.changes, unfinished);
    }
  } else {
    return failure(opened.status);
  }

  const after = newTotal(before, request, minimumWei);
  if (typeof after === 'string') {
    return { ok: false, message: after };
  }
  if (request.kind === 'take' && before === 0n) {
    return { ok: false, message: 'This card is empty.' };
  }

  // The old coin's key goes to the Keychain before the card is cleared.
  if (oldMarker !== null && opened.ok) {
    try {
      keys.keepCardKey(tagOf(oldMarker));
    } catch {
      return { ok: false, message: 'This iPhone could not keep the card safe to change. Nothing was changed.' };
    }
  } else if (oldMarker !== null && !keys.hasKeptCardKey(tagOf(oldMarker))) {
    return { ok: false, message: NOT_CHANGED };
  }
  payments.forgetHeldKey();

  const change: CardChange = {
    id: resumed?.id ?? newChangeId(deps.changes, deps.activity),
    cardId: bytesToHex(cardId),
    cardNumber,
    oldFill: fill,
    oldMarker,
    oldCommitData,
    oldCounted,
    beforeWei: before.toString(),
    afterWei: after.toString(),
    commitData: null,
    newFill: null,
    summonId: null,
    vanishId: null,
    at: Date.now(),
  };
  await save(deps.changes, change);

  if (after === 0n) {
    // Emptied: the card is cleared now (its coin is going to the wallet),
    // so it reads as empty at once. A clear that did not go through changes
    // nothing: the card is opened, its coin is taken all the same.
    if (opened.ok) {
      await refillGhostCard(deps.card, { cardId, fill });
    }
    return { ok: true, cardNumber, beforeWei: before, afterWei: 0n };
  }

  const made = await remakeGhostCard(deps.card, { cardId, fill }, after);
  if (!made.ok) {
    // The change stays saved as cut off: the next hold of this card carries
    // on from the same balance, and nothing of the old coin moves till then.
    return made.status === null ? { ok: false, message: null } : { ok: false, message: NOT_CHANGED };
  }
  await save(deps.changes, { ...change, commitData: bytesToHex(made.commitData), newFill: made.fill, cardNumber: made.cardNumber });
  return { ok: true, cardNumber: made.cardNumber, beforeWei: before, afterWei: after };
}

function failure(status: GhostCardStatus | null): ChangeResult {
  if (status === null) {
    return { ok: false, message: null };
  }
  const balance = balanceOfStatus(status);
  return balance.kind === 'problem' ? { ok: false, message: balance.message, alarm: balance.alarm } : { ok: false, message: NOT_CHANGED };
}

// ---------------------------------------------------------------------------
// In the background

/**
 * Moves every saved change one step: the old coin's Summon (with its kept
 * key), then, once it is in a block, the Vanish of the new total into the
 * card's new coin. A change whose hold was cut off waits for the card. A
 * change is forgotten once its new coin and its Summon have settled.
 */
export function moveChanges(deps: VaultDeps): Promise<void> {
  // Home and a screen may both ask: one round of moves at a time.
  moving ??= moveAll(deps).finally(() => {
    moving = null;
  });
  return moving;
}

let moving: Promise<void> | null = null;

async function moveAll(deps: VaultDeps): Promise<void> {
  const { keys, payments } = deps;
  if (!keys || !payments) {
    return;
  }
  if (deps.activity) {
    try {
      await squareRows(
        deps.activity,
        deps.changes.read().map((c) => ({ id: c.id, cutOff: cutOff(c) })),
      );
    } catch {
      // Squared at the next move.
    }
  }
  for (const saved of [...deps.changes.read()]) {
    // Read again: a hold may have replaced it meanwhile.
    const change = deps.changes.read().find((c) => c.id === saved.id);
    if (!change) {
      continue;
    }
    try {
      await moveChange(deps, keys, payments, change);
    } catch {
      // Saved: the next move tries again.
    }
  }
}

/**
 * Activity's rows for the saved changes: each change's own payments under its
 * one row. With `id`, only that change; `done` marks it finished. A row that
 * cannot be written is tried again at the next move.
 */
async function noteRow(deps: VaultDeps, done: boolean, change?: CardChange, failed = false) {
  if (!deps.activity) {
    return;
  }
  // A change cut off before the card made its new key has moved nothing: no row.
  const changes = (change ? [change] : deps.changes.read()).filter((c) => !cutOff(c));
  for (const c of changes) {
    try {
      await noteChange(deps.activity, c, done, failed);
    } catch {
      // Written at the next move.
    }
  }
}

/** Cut off before the card made its new key: nothing has moved for it yet. */
function cutOff(c: CardChange): boolean {
  return c.afterWei !== '0' && c.commitData === null;
}

async function moveChange(deps: VaultDeps, keys: CardKeyStore, payments: VaultPayments, saved: CardChange) {
  await noteRow(deps, false, saved);
  let latest = saved;
  try {
    await moveChangeSteps(deps, keys, payments, saved, (c) => {
      latest = c;
    });
  } finally {
    const now = deps.changes.read().find((c) => c.id === saved.id);
    const c = now ?? latest;
    const state = (id: string | null) => (id === null ? null : id === 'gone' ? 'settled' : payments.paymentState(id));
    // An Add or a partial Take off is done once the card's new coin is paid;
    // a change dropped with that Vanish failed put nothing onto the card. A
    // change can stay saved after it is done, watching its old coin.
    const vanish = state(c.vanishId);
    const failed = c.afterWei !== '0' && now === undefined && vanish !== 'settled';
    const done =
      now === undefined || (c.afterWei === '0' ? c.oldMarker === null || state(c.summonId) === 'settled' : vanish === 'settled');
    await noteRow(deps, done, c, failed);
  }
}

async function moveChangeSteps(
  deps: VaultDeps,
  keys: CardKeyStore,
  payments: VaultPayments,
  saved: CardChange,
  seen: (change: CardChange) => void,
) {
  let change = saved;
  const after = BigInt(change.afterWei);
  if (after > 0n && change.commitData === null) {
    return;
  }

  // The old coin, into the wallet.
  if (change.oldMarker !== null && change.summonId === null && lookNow(change)) {
    const marker = change.oldMarker;
    const summonId = await withCardKey(async () => {
      try {
        if (!keys.restoreCardKey(tagOf(marker))) {
          return 'gone';
        }
        const found = await payments.lookUpHeldKey();
        if (found === 'spent') {
          return 'gone';
        }
        if (found === 'found') {
          return await payments.summonHeldKey();
        }
        // Not on chain yet. A coin no one had paid at the hold is watched, with
        // its key kept, for as long as a payment from another phone may land. A counted coin
        // waits for its own Vanish, unless that failed (then it was never paid).
        if (!change.oldCounted) {
          return null;
        }
        return change.oldCommitData !== null && onItsWay(deps, hexToBytes(change.oldCommitData), change) ? null : 'gone';
      } finally {
        payments.forgetHeldKey();
      }
    });
    if (summonId !== null) {
      change = { ...change, summonId };
      seen(change);
      await noteRow(deps, false, change);
      await save(deps.changes, change);
    }
  }
  let summoned = change.oldMarker === null || change.summonId === 'gone' || !change.oldCounted;
  if (change.summonId !== null && change.summonId !== 'gone') {
    const id = change.summonId;
    let state = payments.paymentState(id);
    // Moved here until it settles: Home leaves it alone, and a block that is
    // dropped may need a new proof, made with the kept key.
    if (state === 'moving' || state === 'in-block') {
      await withCardKey(async () => {
        try {
          keys.restoreCardKey(tagOf(change.oldMarker ?? ''));
          await payments.moveSummon(id);
        } finally {
          payments.forgetHeldKey();
        }
      });
      state = payments.paymentState(id);
    }
    if (state === 'failed' || state === 'missing') {
      // Proved again on the next move.
      await save(deps.changes, { ...change, summonId: null });
      return;
    }
    summoned = summoned || state === 'in-block' || state === 'settled';
    if (state === 'settled' && change.oldMarker) {
      keys.forgetKeptCardKey(tagOf(change.oldMarker));
    }
  }
  if (!summoned) {
    return;
  }

  // The new total, onto the card's new coin.
  if (change.commitData !== null && change.vanishId === null) {
    const vanishId = await payments.startVanish(after, hexToBytes(change.commitData));
    change = { ...change, vanishId };
    seen(change);
    await noteRow(deps, false, change);
    await save(deps.changes, change);
  }
  const summonSettled =
    change.oldMarker === null ||
    change.summonId === 'gone' ||
    (change.summonId !== null && payments.paymentState(change.summonId) === 'settled');
  const vanish = change.vanishId === null ? 'settled' : payments.paymentState(change.vanishId);
  if (summonSettled && (vanish === 'settled' || vanish === 'failed' || vanish === 'missing')) {
    if (change.oldMarker) {
      keys.forgetKeptCardKey(tagOf(change.oldMarker));
    }
    await drop(deps.changes, change);
  }
}

/** The Keychain tag of a coin's key: its marker, as 64 hex digits. */
function tagOf(marker: string): string {
  return marker.startsWith('0x') ? marker.slice(2) : marker;
}

// ---------------------------------------------------------------------------
// What a card holds

/** What a status alone says, for the statuses that are not a balance. */
function balanceOfStatus(status: GhostCardStatus): CardBalance {
  switch (status.kind) {
    case 'sealed':
      return { kind: 'holds', cardNumber: status.cardNumber, amountWei: status.amountWei, updating: false };
    case 'settling':
      return { kind: 'holds', cardNumber: status.cardNumber, amountWei: status.amountWei, updating: true };
    case 'blank':
      return { kind: 'empty', cardNumber: status.cardNumber };
    case 'opened':
      return { kind: 'empty', cardNumber: status.cardNumber };
    case 'not-on-chain':
      return { kind: 'empty', cardNumber: status.cardNumber };
    case 'spent-while-sealed':
      return { kind: 'problem', message: 'This card is broken: its GHOST was taken without the card.', alarm: true };
    case 'no-checks':
      return { kind: 'problem', message: 'This card is worn out. Use Settings, Cards, to move its GHOST to your wallet.', alarm: false };
    case 'not-genuine':
      return { kind: 'problem', message: "This isn't a Ghost card.", alarm: true };
    case 'carry-to-claim':
      return { kind: 'problem', message: 'This is an older NTAG 424 card. Use Settings, Older cards.', alarm: false };
    case 'no-connection':
      return { kind: 'problem', message: "Can't reach the Ghost network. Try again in a moment.", alarm: false };
    case 'retry':
      return { kind: 'problem', message: status.message, alarm: false };
  }
}

/**
 * What a card holds, from its Check and this phone's saved changes: one
 * balance, never a card state. A card whose last change is still going
 * through shows the balance it will hold.
 */
export function cardBalance(deps: Pick<VaultDeps, 'changes' | 'payments'>, check: CheckResult): CardBalance {
  const { status, statement } = check;
  if (!statement) {
    return balanceOfStatus(status);
  }
  const cardId = bytesToHex(statement.cardId);
  const unfinished = unfinishedOn(deps.changes.read(), cardId, statement.fill);
  if (unfinished && (status.kind === 'blank' || status.kind === 'opened')) {
    // A hold cut off before it made the new key: the old balance, still safe.
    return { kind: 'holds', cardNumber: statement.cardNumber, amountWei: BigInt(unfinished.beforeWei), updating: false };
  }
  if (status.kind === 'opened' && status.spent !== true) {
    if (claimed(deps, bytesToHex(statement.marker))) {
      // All of it is on its way to this phone's wallet.
      return { kind: 'empty', cardNumber: statement.cardNumber };
    }
    if (status.spent === null) {
      return balanceOfStatus({ kind: 'no-connection' });
    }
    // Its key left the card on some phone, and that phone may still hold it:
    // whoever has it can take the GHOST without the card.
    return {
      kind: 'holds',
      cardNumber: statement.cardNumber,
      amountWei: BigInt(statement.amountWei),
      updating: false,
      warning: OPENED_ELSEWHERE,
    };
  }
  const made = deps.changes
    .read()
    .find((c) => c.cardId === cardId && c.commitData === null && c.afterWei !== '0' && c.oldFill + 1 === statement.fill);
  if (status.kind === 'not-on-chain' && made && BigInt(made.afterWei) === status.amountWei) {
    // Made its new key just before the app was stopped: finished at the next hold.
    return { kind: 'holds', cardNumber: status.cardNumber, amountWei: status.amountWei, updating: true };
  }
  if (status.kind === 'not-on-chain') {
    return onItsWay(deps, check.commitData)
      ? { kind: 'holds', cardNumber: status.cardNumber, amountWei: status.amountWei, updating: true }
      : { kind: 'empty', cardNumber: status.cardNumber };
  }
  return balanceOfStatus(status);
}

/** Why `take` of `held` cannot be taken off, or null when it can. */
export function takeProblem(
  take: bigint | null,
  held: bigint,
  minimum: bigint | null,
  wallet: bigint | null,
  fees: { summon: bigint; vanish: bigint } | null,
): string | null {
  if (take === null || take <= 0n) {
    return null;
  }
  if (take > held) {
    return `The card holds ${ghostText(held)} GHOST.`;
  }
  const left = held - take;
  if (left > 0n && minimum !== null && left < minimum) {
    return `Leave at least ${ghostText(minimum)} GHOST on the card, or take it all.`;
  }
  if (fees && wallet !== null && left > 0n) {
    // The card's coin comes home less the Summon fee, and what is left goes back with the Vanish fee.
    const cost = fees.summon + fees.vanish;
    if (wallet + take < cost) {
      return `Take off at least ${ghostText(cost - wallet)} GHOST to cover the fee.`;
    }
  }
  return null;
}

/** The balance's main line. */
export function balanceText(balance: CardBalance): string {
  switch (balance.kind) {
    case 'holds':
      return `${ghostText(balance.amountWei)} GHOST`;
    case 'empty':
      return 'Empty';
    case 'problem':
      return balance.message;
  }
}

// ---------------------------------------------------------------------------
// The wallet as it will be

/** Where one of a change's payments stands against a balance reading. */
export type PaymentAtReading = 'in-reading' | 'not-yet' | 'failed';

/**
 * How far the wallet's balance, read at a block, is from what it will be once
 * every saved change finishes: the old coin's Summon still to come in, less
 * the new total still to go onto the card. Home adds it, so a balance never
 * jumps up while a card change goes through: adding 2 to a card holding 3
 * shows the wallet down 2 at once, never up 3 and then down 5. Fees are left
 * out; they show when the payments land.
 */
export function pendingCardChange(changes: readonly CardChange[], at: (paymentId: string) => PaymentAtReading): bigint {
  let total = 0n;
  for (const c of changes) {
    const after = BigInt(c.afterWei);
    if (after > 0n && c.commitData === null) {
      // Cut off before the card made its new key: nothing has moved yet.
      continue;
    }
    const comesIn =
      c.oldMarker !== null && c.oldCounted && c.summonId !== 'gone' && (c.summonId === null || at(c.summonId) !== 'in-reading');
    const goesOut = after > 0n && (c.vanishId === null || at(c.vanishId) === 'not-yet');
    total += (comesIn ? BigInt(c.beforeWei) : 0n) - (goesOut ? after : 0n);
  }
  return total;
}
