// Check, Fill and Open of a Ghost Sealed card through the Seal
// (docs/seal-relay.md).
//
// The phone carries the card traffic between the Seal and the card, natively
// (ios/SealRelay.swift): it opens the NFC session and the connection to the
// Seal, passes every command and every card answer through as opaque bytes,
// never decrypts them and holds no card key. JavaScript calls one function
// per flow here and sees only the result: the card's UID, the challenge the
// relay sent (made natively, 32 random bytes), the Seal's signed answer, the
// time of each round trip and, for a Fill, the coin's public commit data. An
// Open's release package goes from the relay straight to the native core
// (core/src/seal_open.rs); it never reaches JavaScript. No native function of
// the relay hands JavaScript any card traffic.
//
// The signature is not verified here: the native core verifies it against
// the Seal's pinned key and code measurement (lib/seal/verify-answer.ts). The
// state and amount read here are only for the speed screen's timings.
import { requireOptionalNativeModule } from 'expo';

import { CardCancelled, type GhostNfcSealPinNative } from './index';

/** One round trip of a relayed flow: to the card over NFC, or to the Seal over the network. */
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

/** A relayed answer with the challenge the relay sent: what the answer's check needs. */
export type RelayedAnswer = SealCheck & {
  /** The 32 random bytes the native relay sent with the request. */
  challenge: Uint8Array;
};

/** What a Fill through the Seal hands back: the answer and the coin's public commit data. */
export type RelayedFill = RelayedAnswer & {
  /** The coin's commit data (430 bytes), for the Vanish that pays it. Public. */
  commitData: Uint8Array;
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

/** What the native relay resolves a Fill with. */
export type NativeSealFill = NativeSealCheck & { commitData: string };

/**
 * The Swift module's relay function (ios/GhostNfcModule.swift). It is kept
 * apart from `GhostNfcNative` so the card code's type does not change.
 */
export type GhostNfcRelayNative = {
  isSupported(): boolean;
  /** Runs one Check through the Seal at `sealUrl` on the next card tapped. */
  relayCheck(sealUrl: string, alert: string): Promise<NativeSealCheck>;
};

/**
 * The relay's Fill and Open, and the Keychain of the Open's phone key. The
 * Open's key pair is made by the native core; the module only keeps its seed
 * in the Keychain (this device only) and gives it back to the core.
 */
export type GhostNfcSealNative = GhostNfcRelayNative & {
  /** Runs a Fill of `amountWei` (decimal digits), with an Open PIN or `""` for none. */
  relayFill(sealUrl: string, alert: string, amountWei: string, pin: string): Promise<NativeSealFill>;
  /** Asks the Seal to mark a filled card Sealed once its payment settled. */
  relayFillConfirm(sealUrl: string, alert: string): Promise<NativeSealCheck>;
  /**
   * Runs an Open to `phoneKey` (hex, the core's ML-KEM-768 encapsulation key), with the card's
   * Open PIN or `""`. The release package goes to the native core, not here.
   */
  relayOpen(sealUrl: string, alert: string, phoneKey: string, pin: string): Promise<NativeSealCheck>;
  /** Copies the core's Open phone key into the Keychain, this device only. */
  keepOpenKey(): void;
  /** Gives a phone key kept in the Keychain back to the core; false when none is kept. */
  restoreOpenKey(): boolean;
  /** Deletes the kept phone key from the Keychain. */
  forgetOpenKey(): void;
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
  'not-a-ghost-card': 'Not a Ghost card.',
  filling: 'The card is filling, waiting for its payment to settle.',
  'cant-check-now': 'The Seal cannot check the chain right now.',
  'pin-required': 'This card needs its PIN to open.',
  'wrong-pin': 'Wrong PIN.',
  'pin-locked': 'This card is locked: its PIN has no tries left.',
  spent: 'This card was emptied.',
  'wrong-state': 'This card cannot do that now.',
  'fill-pending': 'This card is already being filled with another amount or PIN.',
  failed: 'The card could not be checked. Try again.',
} as const;

export type RelayProblem = keyof typeof RELAY_PROBLEMS;

/** A flow through the Seal failed; the message is plain text for the screen. */
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
  ERR_SEAL_NOT_GHOST_CARD: 'not-a-ghost-card',
  ERR_SEAL_FILLING: 'filling',
  ERR_SEAL_CANT_CHECK: 'cant-check-now',
  ERR_SEAL_PIN_REQUIRED: 'pin-required',
  ERR_SEAL_WRONG_PIN: 'wrong-pin',
  ERR_SEAL_PIN_LOCKED: 'pin-locked',
  ERR_SEAL_SPENT: 'spent',
  ERR_SEAL_WRONG_STATE: 'wrong-state',
  ERR_SEAL_FILL_PENDING: 'fill-pending',
};

const ALERT = 'Hold the Ghost card near the top of the iPhone.';

// The signed answer's layout (seal/src/answer.rs).
const ANSWER_BYTES = 203;
const ANSWER_DOMAIN = 'ghost-seal/v1/answer';
/** The answer kinds: 1 Check, 2 Fill, 3 Open. */
export const ANSWER_KINDS = { check: 1, fill: 2, open: 3 } as const;
export type AnswerKind = keyof typeof ANSWER_KINDS;
const STATES: readonly SealCardState[] = ['empty', 'sealed', 'opening', 'opened'];
/** A coin's commit data (core/src/vanish.rs). */
const COMMIT_DATA_BYTES = 430;
/** An ML-KEM-768 encapsulation key. */
const PHONE_KEY_BYTES = 1184;

function relayNative(): GhostNfcSealNative | null {
  return requireOptionalNativeModule<GhostNfcSealNative>('GhostNfc');
}

/** The Seal address, or null when it is not an http(s) address. */
export function sealAddress(text: string): string | null {
  const trimmed = text.trim();
  return /^https?:\/\/[^\s/?#]+(\/[^\s?#]*)?$/i.test(trimmed) ? trimmed : null;
}

/** Checks the address and that this iPhone reads cards, before any card sheet opens. */
function ready<T extends GhostNfcRelayNative>(sealUrl: string, nfc: T | null): { address: string; nfc: T } {
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
  return { address, nfc };
}

/** Runs a native relay call; the sheet closed is `CardCancelled`, anything else a `SealRelayError`. */
async function relayed<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    const code = (error as { code?: unknown } | null)?.code;
    if (code === 'ERR_NFC_CANCELLED') {
      throw new CardCancelled();
    }
    throw new SealRelayError((typeof code === 'string' && NATIVE_PROBLEMS[code]) || 'failed');
  }
}

/**
 * Runs one Check of the next card tapped through the Seal at `sealUrl` and
 * returns only its result, the challenge and the timings. Throws
 * `CardCancelled` when the card sheet is closed and `SealRelayError` for
 * everything else.
 */
export async function checkWithSeal(
  sealUrl: string,
  nfc: GhostNfcRelayNative | null = relayNative(),
): Promise<RelayedAnswer> {
  const relay = ready(sealUrl, nfc);
  const result = await relayed(() => relay.nfc.relayCheck(relay.address, ALERT));
  return readResult(result);
}

/** An Open PIN for the wire: 4 to 8 digits, or `""` for none. Never kept. */
function pinText(pin: string | null): string {
  if (pin === null) {
    return '';
  }
  if (!/^[0-9]{4,8}$/.test(pin)) {
    throw new SealRelayError('wrong-pin');
  }
  return pin;
}

/**
 * Fills the next card tapped through the Seal: the Seal writes a fresh key to
 * it and hands back the coin's commit data for `amountWei`. `pin`, when set,
 * becomes the card's Open PIN; it goes to the Seal only.
 */
export async function fillWithSeal(
  sealUrl: string,
  amountWei: bigint,
  pin: string | null,
  nfc: GhostNfcSealNative | null = relayNative(),
): Promise<RelayedFill> {
  const relay = ready(sealUrl, nfc);
  if (amountWei <= 0n) {
    throw new SealRelayError('failed');
  }
  const wire = pinText(pin);
  const result = await relayed(() =>
    relay.nfc.relayFill(relay.address, 'Hold the empty Ghost card near the top of the iPhone.', amountWei.toString(), wire),
  );
  const answer = readAnswerResult(result, 'fill');
  const commitData = bytesOf(result?.commitData, COMMIT_DATA_BYTES);
  if (!commitData) {
    throw new SealRelayError('bad-answer');
  }
  return { ...answer, commitData };
}

/** Asks the Seal, through the next card tapped, to mark a filled card Sealed once its payment settled. */
export async function confirmFillWithSeal(
  sealUrl: string,
  nfc: GhostNfcSealNative | null = relayNative(),
): Promise<RelayedAnswer> {
  const relay = ready(sealUrl, nfc);
  const result = await relayed(() => relay.nfc.relayFillConfirm(relay.address, ALERT));
  return readAnswerResult(result, 'fill');
}

/**
 * Opens the next card tapped through the Seal, releasing its key to
 * `phoneKey` (the native core's ML-KEM-768 encapsulation key). The release
 * goes to the native core; this returns the signed answer only.
 */
export async function openWithSeal(
  sealUrl: string,
  phoneKey: Uint8Array,
  pin: string | null,
  nfc: GhostNfcSealNative | null = relayNative(),
): Promise<RelayedAnswer> {
  const relay = ready(sealUrl, nfc);
  if (phoneKey.length !== PHONE_KEY_BYTES) {
    throw new SealRelayError('failed');
  }
  const wire = pinText(pin);
  const result = await relayed(() => relay.nfc.relayOpen(relay.address, ALERT, hexOf(phoneKey).toLowerCase(), wire));
  return readAnswerResult(result, 'open');
}

/** The native module's Keychain of the Open's phone key; null in a build without it. */
export function openKeyKeeper(nfc: GhostNfcSealNative | null = relayNative()): Pick<
  GhostNfcSealNative,
  'keepOpenKey' | 'restoreOpenKey' | 'forgetOpenKey'
> | null {
  if (!nfc || typeof nfc.keepOpenKey !== 'function') {
    return null;
  }
  return nfc;
}

/** The Seal's attestation as the native fetch hands it over: public bytes only. */
export type FetchedSealAttestation = {
  /** The `GPA2` phone attestation, checked only by the native core. */
  attestation: Uint8Array;
  /** SHA-256 of the DER of the leaf certificate the connection presented (32 bytes). */
  certSha256: Uint8Array;
};

/** The longest attestation the native fetch takes. */
const MAX_ATTESTATION_BYTES = 32 * 1024;

function pinNative(): GhostNfcSealPinNative | null {
  return requireOptionalNativeModule<GhostNfcSealPinNative>('GhostNfc');
}

/**
 * Fetches the Seal's attestation for `challenge` (32 bytes) natively, with
 * the hash of the certificate its connection presented. Throws
 * `SealRelayError` when there is no fetch in this build, the address is not
 * https://, or anything fails; nothing it returns is trusted until the core
 * checks it.
 */
export async function fetchSealAttestation(
  sealUrl: string,
  challenge: Uint8Array,
  nfc: GhostNfcSealPinNative | null = pinNative(),
): Promise<FetchedSealAttestation> {
  const address = sealAddress(sealUrl);
  if (address === null || !/^https:/i.test(address)) {
    throw new SealRelayError('bad-address');
  }
  if (!nfc || typeof nfc.fetchSealAttestation !== 'function') {
    throw new SealRelayError('seal-unreachable');
  }
  if (challenge.length !== 32) {
    throw new SealRelayError('failed');
  }
  const native: GhostNfcSealPinNative = nfc;
  const result = await relayed(() => native.fetchSealAttestation(address, hexOf(challenge).toLowerCase()));
  const attestation = bytesOf(result?.attestation);
  const certSha256 = bytesOf(result?.certSha256, 32);
  if (!attestation || attestation.length === 0 || attestation.length > MAX_ATTESTATION_BYTES || !certSha256) {
    throw new SealRelayError('bad-answer');
  }
  return { attestation, certSha256 };
}

/**
 * Pins the relay to the Seal at `sealUrl`: it connects only when the leaf
 * certificate's SHA-256 is `certSha256`. `null` drops the pin. Set only
 * after the native core verified the attestation that binds it. False when
 * the pin could not be set (no module, a bad address or hash).
 */
export function setSealPin(
  sealUrl: string,
  certSha256: Uint8Array | null,
  nfc: GhostNfcSealPinNative | null = pinNative(),
): boolean {
  if (!nfc || typeof nfc.setSealPin !== 'function') {
    return false;
  }
  const address = sealAddress(sealUrl);
  if (address === null || (certSha256 !== null && certSha256.length !== 32)) {
    return false;
  }
  try {
    nfc.setSealPin(address, certSha256 === null ? '' : hexOf(certSha256).toLowerCase());
    return true;
  } catch {
    return false;
  }
}

/** Checks the native result of a Check and keeps only what JavaScript may see. */
export function readResult(result: NativeSealCheck): RelayedAnswer {
  return readAnswerResult(result, 'check');
}

/** Checks the native result of a flow of `kind` and keeps only what JavaScript may see. */
export function readAnswerResult(result: NativeSealCheck, kind: AnswerKind): RelayedAnswer {
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
    answer[20] !== ANSWER_KINDS[kind] ||
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
  return { uid: hexOf(uid), state, amountWei, answer, signature, rounds, totalMs, challenge };
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
