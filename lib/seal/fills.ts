// The Ghost Sealed cards this iPhone filled whose Fill the Seal has not yet
// confirmed. Until it does, the Seal answers a Check of such a card as Empty
// (it holds a key, but no coin the Seal has seen paid), so this phone shows
// it as Filling instead. Only public data is kept: the card's UID and the
// amount. Never a key, words or a PIN. A Check or confirmation that answers
// Sealed (or Opened) forgets the card.
import { jsonFile, type JsonFile } from '../storage';

type Fills = Record<string, { amountWei: string; at: number }>;

let file: JsonFile | null = null;

function store(): JsonFile {
  file ??= jsonFile('sealed-card-fills.json');
  return file;
}

function read(): Fills {
  const value = store().read();
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  const fills: Fills = {};
  for (const [uid, entry] of Object.entries(value as Record<string, unknown>)) {
    const { amountWei, at } = (entry ?? {}) as { amountWei?: unknown; at?: unknown };
    if (/^[0-9A-F]{14}$/.test(uid) && typeof amountWei === 'string' && /^[0-9]+$/.test(amountWei) && typeof at === 'number') {
      fills[uid] = { amountWei, at };
    }
  }
  return fills;
}

/** Notes that this phone filled card `uid` with `amountWei`, waiting for the Seal to confirm it. */
export async function noteFill(uid: string, amountWei: bigint, now: number = Date.now()): Promise<void> {
  const fills = read();
  fills[uid] = { amountWei: amountWei.toString(), at: now };
  await store().write(fills);
}

/** The amount this phone filled card `uid` with, while its Fill waits; null otherwise. */
export function pendingFill(uid: string): bigint | null {
  const entry = read()[uid];
  return entry ? BigInt(entry.amountWei) : null;
}

/** Forgets card `uid`: its Fill was confirmed, or it was opened. */
export async function clearFill(uid: string): Promise<void> {
  const fills = read();
  if (uid in fills) {
    delete fills[uid];
    await store().write(fills);
  }
}
