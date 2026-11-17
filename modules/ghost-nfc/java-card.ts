// A Ghost Java card (card-applet/), as JavaScript sees it: four native flows
// (ios/JavaCard.swift), each one tap. The card's commands and answers stay
// in native code; each flow resolves with public parts only, as hex: the
// card's Identify, its certificate, a seal statement and its signature, the
// commit data and Make's fill and commitment. An Open's answer goes from the
// card to the native core, never here. The card is a bearer object: no flow
// takes a code or PIN.
import { requireOptionalNativeModule } from 'expo';

import { CardCancelled } from './index';

/** The applet's AID; also in the app's ISO 7816 select identifiers (app.json). */
export const GHOST_CARD_AID = 'A000000847474341524401';

export const COMMIT_DATA_BYTES = 430;
export const STATEMENT_BYTES = 193;
export const SIGNATURE_BYTES = 2508;
export const IDENTIFY_BYTES = 29;
export const MAKE_BYTES = 4 + 32 + COMMIT_DATA_BYTES;

/** The Swift module's Ghost card functions (ios/GhostNfcModule.swift). */
export type GhostCardNative = {
  javaCardCheck(alert: string, challenge: Uint8Array, commitData: boolean): Promise<NativeTap>;
  /** `make`: the amount (12 bytes), chain id (8) and writer nonce (32). */
  javaCardFill(alert: string, make: Uint8Array, challenge: Uint8Array): Promise<NativeTap>;
  javaCardOpen(alert: string, checkChallenge: Uint8Array): Promise<NativeTap>;
  /** Refills only the opened card `cardId` (16 bytes) at `fill`; any other card is refused untouched. */
  javaCardRefill(alert: string, cardId: Uint8Array, fill: number): Promise<NativeTap>;
};

/** What a native flow resolves with: hex strings, numbers and flags. */
export type NativeTap = Record<string, unknown>;

/** A tap's public parts, read and sized. */
export type CardTap =
  | { kind: 'ntag' }
  | {
      kind: 'ghost';
      identify: Uint8Array;
      certificate: Uint8Array | null;
      statement: Uint8Array | null;
      signature: Uint8Array | null;
      commitData: Uint8Array | null;
      make: Uint8Array | null;
      /** Open only: whether the card released its key to the native core. */
      opened: boolean | null;
      /** The whole tap and its Check, in milliseconds. */
      ms: number;
      checkMs: number | null;
      reconnects: number;
    };

/** Why a tap failed, as the screens say it. */
export type CardProblem =
  | 'no-nfc'
  | 'card-lost'
  | 'busy'
  | 'not-ready'
  | 'wrong-state'
  | 'no-checks'
  | 'other-card'
  | 'refused'
  | 'bad-tap'
  | 'failed';

export const CARD_PROBLEMS: Record<CardProblem, string> = {
  'no-nfc': 'This iPhone cannot read cards.',
  'card-lost': 'The card moved away. Hold it still near the top of the iPhone and try again.',
  busy: 'Another card tap is under way.',
  'not-ready': 'This card was never finished at its loading station.',
  'wrong-state': 'The card is not in the state this needs.',
  'no-checks': 'This card has no seal checks left.',
  'other-card': 'This is not the card that was checked. Tap the same card again.',
  refused: 'The card refused a command.',
  'bad-tap': 'The card gave an answer of the wrong size.',
  failed: 'The card could not be read. Hold it still and try again.',
};

export class GhostCardError extends Error {
  constructor(
    readonly problem: CardProblem,
    /** The card's own words for a refusal (a state or a status word); never a secret. */
    readonly detail: string | null = null,
  ) {
    super(CARD_PROBLEMS[problem]);
    this.name = 'GhostCardError';
  }
}

const NATIVE_PROBLEMS: Record<string, CardProblem> = {
  ERR_NFC_UNAVAILABLE: 'no-nfc',
  ERR_NFC_SESSION: 'card-lost',
  ERR_GHOST_CARD_BUSY: 'busy',
  ERR_GHOST_CARD_NOT_READY: 'not-ready',
  ERR_GHOST_CARD_STATE: 'wrong-state',
  ERR_GHOST_CARD_NO_CHECKS: 'no-checks',
  ERR_GHOST_CARD_OTHER_CARD: 'other-card',
  ERR_GHOST_CARD_FAILED: 'refused',
  ERR_GHOST_CARD_BAD_INPUT: 'failed',
};

/** A native rejection as a `GhostCardError`, or `CardCancelled` for a closed sheet. */
export function cardFailure(error: unknown): Error {
  const code = (error as { code?: unknown } | null)?.code;
  if (code === 'ERR_NFC_CANCELLED') {
    return new CardCancelled();
  }
  const problem = (typeof code === 'string' && NATIVE_PROBLEMS[code]) || 'failed';
  let detail: string | null = null;
  if (problem === 'wrong-state' || problem === 'refused') {
    const match = /The card is (blank|sealed|opened)|\(([0-9A-F]{2} [0-9A-F]{4}|not a Ghost card)\)/.exec(
      String((error as { message?: unknown } | null)?.message ?? ''),
    );
    detail = match ? (match[1] ?? match[2] ?? null) : null;
  }
  return new GhostCardError(problem, detail);
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new GhostCardError('bad-tap');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

function part(value: unknown, length: number | null): Uint8Array | null {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== 'string') {
    throw new GhostCardError('bad-tap');
  }
  const bytes = hexToBytes(value);
  if (length !== null && bytes.length !== length) {
    throw new GhostCardError('bad-tap');
  }
  return bytes;
}

function count(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

/** Reads a native flow's result; throws `GhostCardError('bad-tap')` for parts of the wrong size. */
export function readTap(raw: NativeTap): CardTap {
  if (raw.kind === 'ntag') {
    return { kind: 'ntag' };
  }
  if (raw.kind !== 'ghost') {
    throw new GhostCardError('bad-tap');
  }
  const identify = part(raw.identify, IDENTIFY_BYTES);
  if (!identify) {
    throw new GhostCardError('bad-tap');
  }
  return {
    kind: 'ghost',
    identify,
    certificate: part(raw.certificate, null),
    statement: part(raw.statement, STATEMENT_BYTES),
    signature: part(raw.signature, SIGNATURE_BYTES),
    commitData: part(raw.commitData, COMMIT_DATA_BYTES),
    make: part(raw.make, MAKE_BYTES),
    opened: typeof raw.opened === 'boolean' ? raw.opened : null,
    ms: count(raw.ms),
    checkMs: typeof raw.checkMs === 'number' ? raw.checkMs : null,
    reconnects: count(raw.reconnects),
  };
}

/** The native flows, or null in a build without them (the simulator, tests). */
export function ghostCardNative(): GhostCardNative | null {
  const nfc = requireOptionalNativeModule<Partial<GhostCardNative> & { isSupported?(): boolean }>('GhostNfc');
  if (!nfc || typeof nfc.javaCardCheck !== 'function' || !(nfc.isSupported?.() ?? false)) {
    return null;
  }
  return nfc as GhostCardNative;
}

/** Runs one native flow and reads its result, with failures as `GhostCardError` or `CardCancelled`. */
export async function tap(run: () => Promise<NativeTap>): Promise<CardTap> {
  let raw: NativeTap;
  try {
    raw = await run();
  } catch (error) {
    throw cardFailure(error);
  }
  return readTap(raw);
}
