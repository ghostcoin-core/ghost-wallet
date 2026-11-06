// A Check of a Ghost Sealed card through the Seal (docs/seal-relay.md).
//
// The phone carries the card traffic between the Seal and the card, natively
// (ios/SealRelay.swift): it opens the NFC session and the connection to the
// Seal, passes every command and every card answer through as opaque bytes,
// never decrypts them and holds no card key. JavaScript calls one function
// here and sees only the result: the card's UID, its state and amount (read
// from the Seal's signed answer bytes), the signed answer itself and the time
// of each round trip. No native function of the relay hands JavaScript any
// card traffic.
//
// The signature is not verified here: the Check screen verifies it against
// the Seal's pinned key and code measurement. The speed screen only times the
// relay.
import { requireOptionalNativeModule } from 'expo';

import { CardCancelled } from './index';

/** One round trip of a relayed Check: to the card over NFC, or to the Seal over the network. */
export type RelayRound = { kind: 'card' | 'seal'; ms: number };

/** A card's state, as the Seal's signed answer gives it. */
export type SealCardState = 'empty' | 'sealed' | 'opening' | 'opened';

/** What a Check through the Seal hands back. Nothing else crosses to JavaScript. */
export type SealCheck = {
  /** The card's UID, upper-case hex. */
  uid: string;
  state: SealCardState;
  /** The coin's amount in wei (0 for an empty card). */
  amountWei: bigint;
  /** The Seal's signed answer bytes (203 bytes, seal/src/answer.rs). */
  answer: Uint8Array;
  /** The Seal's ML-DSA-65 signature over `answer`. */
  signature: Uint8Array;
  /** Each round trip, in order. */
  rounds: RelayRound[];
  /** From the card connecting to the signed answer, in milliseconds. */
  totalMs: number;
};

/** What the native relay resolves with (ios/SealRelay.swift). */
export type NativeSealCheck = {
  uid: string;
  challenge: string;
  answer: string;
  signature: string;
  rounds: { kind: string; ms: number }[];
  totalMs: number;
};

/**
 * The Swift module's relay function (ios/GhostNfcModule.swift). It is kept
 * apart from `GhostNfcNative` so the card code's type does not change.
 */
export type GhostNfcRelayNative = {
  isSupported(): boolean;
  /** Runs one Check through the Seal at `sealUrl` on the next card tapped. */
  relayCheck(sealUrl: string, alert: string): Promise<NativeSealCheck>;
};

export const RELAY_PROBLEMS = {
  'no-nfc': 'This iPhone cannot read cards.',
  'bad-address': 'Enter the Seal address, starting with https://.',
  busy: 'A Check is already running.',
  'seal-unreachable': 'The Seal could not be reached. Check the address and the network.',
  'seal-refused': 'The Seal refused this card.',
  'session-expired': 'The Seal stopped waiting for the card. Tap the card again.',
  'card-lost': 'The card moved away. Hold it still and try again.',
  'bad-answer': 'The Seal did not answer a Check of this card.',
  failed: 'The card could not be checked. Try again.',
} as const;

export type RelayProblem = keyof typeof RELAY_PROBLEMS;

/** A Check through the Seal failed; the message is plain text for the screen. */
export class SealRelayError extends Error {
  readonly problem: RelayProblem;

  constructor(problem: RelayProblem) {
    super(RELAY_PROBLEMS[problem]);
    this.name = 'SealRelayError';
    this.problem = problem;
  }
}

const NATIVE_PROBLEMS: Record<string, RelayProblem> = {
  ERR_NFC_UNAVAILABLE: 'no-nfc',
  ERR_NFC_SESSION: 'card-lost',
  ERR_SEAL_ADDRESS: 'bad-address',
  ERR_SEAL_RELAY_BUSY: 'busy',
  ERR_SEAL_UNREACHABLE: 'seal-unreachable',
  ERR_SEAL_REFUSED: 'seal-refused',
  ERR_SEAL_EXPIRED: 'session-expired',
  ERR_SEAL_BAD_ANSWER: 'bad-answer',
};

const ALERT = 'Hold the Ghost card near the top of the iPhone.';

// The signed answer's layout (seal/src/answer.rs).
const ANSWER_BYTES = 203;
const ANSWER_DOMAIN = 'ghost-seal/v1/answer';
const KIND_CHECK = 1;
const STATES: readonly SealCardState[] = ['empty', 'sealed', 'opening', 'opened'];

function relayNative(): GhostNfcRelayNative | null {
  return requireOptionalNativeModule<GhostNfcRelayNative>('GhostNfc');
}

/** The Seal address, or null when it is not an http(s) address. */
export function sealAddress(text: string): string | null {
  const trimmed = text.trim();
  return /^https?:\/\/[^\s/?#]+(\/[^\s?#]*)?$/i.test(trimmed) ? trimmed : null;
}

/**
 * Runs one Check of the next card tapped through the Seal at `sealUrl` and
 * returns only its result and timings. Throws `CardCancelled` when the card
 * sheet is closed and `SealRelayError` for everything else.
 */
export async function checkWithSeal(
  sealUrl: string,
  nfc: GhostNfcRelayNative | null = relayNative(),
): Promise<SealCheck> {
  const address = sealAddress(sealUrl);
  if (address === null) {
    throw new SealRelayError('bad-address');
  }
  let supported = false;
  try {
    supported = nfc?.isSupported() ?? false;
  } catch {
    supported = false;
  }
  if (!nfc || !supported) {
    throw new SealRelayError('no-nfc');
  }
  let result: NativeSealCheck;
  try {
    result = await nfc.relayCheck(address, ALERT);
  } catch (error) {
    const code = (error as { code?: unknown } | null)?.code;
    if (code === 'ERR_NFC_CANCELLED') {
      throw new CardCancelled();
    }
    throw new SealRelayError((typeof code === 'string' && NATIVE_PROBLEMS[code]) || 'failed');
  }
  return readResult(result);
}

/** Checks the native result and keeps only what JavaScript may see. */
export function readResult(result: NativeSealCheck): SealCheck {
  const uid = bytesOf(result?.uid, 7);
  const challenge = bytesOf(result?.challenge, 32);
  const answer = bytesOf(result?.answer, ANSWER_BYTES);
  const signature = bytesOf(result?.signature);
  const rounds = roundsOf(result?.rounds);
  const totalMs = result?.totalMs;
  if (!uid || !challenge || !answer || !signature || signature.length === 0 || !rounds) {
    throw new SealRelayError('bad-answer');
  }
  if (typeof totalMs !== 'number' || !Number.isFinite(totalMs) || totalMs < 0) {
    throw new SealRelayError('bad-answer');
  }
  const domain = Array.from(answer.slice(0, 20), (byte) => String.fromCharCode(byte)).join('');
  const state: SealCardState | undefined = STATES[answer[144]];
  if (
    domain !== ANSWER_DOMAIN ||
    answer[20] !== KIND_CHECK ||
    !sameBytes(answer.slice(21, 53), challenge) ||
    !sameBytes(answer.slice(53, 60), uid) ||
    state === undefined
  ) {
    throw new SealRelayError('bad-answer');
  }
  let amountWei = 0n;
  for (const byte of answer.slice(145, 161)) {
    amountWei = (amountWei << 8n) | BigInt(byte);
  }
  return { uid: hexOf(uid), state, amountWei, answer, signature, rounds, totalMs };
}

function roundsOf(value: unknown): RelayRound[] | null {
  if (!Array.isArray(value)) {
    return null;
  }
  const rounds: RelayRound[] = [];
  for (const round of value) {
    const { kind, ms } = (round ?? {}) as { kind?: unknown; ms?: unknown };
    if ((kind !== 'card' && kind !== 'seal') || typeof ms !== 'number' || !Number.isFinite(ms) || ms < 0) {
      return null;
    }
    rounds.push({ kind, ms });
  }
  return rounds;
}

function bytesOf(text: unknown, length?: number): Uint8Array | null {
  if (typeof text !== 'string' || text.length % 2 !== 0 || /[^0-9a-fA-F]/.test(text)) {
    return null;
  }
  const bytes = Uint8Array.from({ length: text.length / 2 }, (_, i) => parseInt(text.slice(2 * i, 2 * i + 2), 16));
  return length === undefined || bytes.length === length ? bytes : null;
}

function hexOf(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).toUpperCase().padStart(2, '0')).join('');
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}
