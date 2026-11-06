// The phone's check of a Seal answer, run in the native core
// (core/src/seal_answer.rs): the ML-DSA-65 signature under the Seal's key,
// the Seal's measurement on the app's pinned list, the challenge the relay
// just sent, the card tapped and the expiry. Nothing here is cryptography:
// this only gathers what the core checks the answer against and reads its
// verdict. A refused answer gives nothing back: no state, no amount.
import type { CoreSealAnswer, CoreSealAnswerCheck, CoreSealAnswerVerdict, SealBindings } from '../../modules/ghost-core';
import type { AnswerKind, RelayedAnswer, RelayedFill, SealCardState } from '../../modules/ghost-nfc/relay';
import { PINNED_MEASUREMENTS, type MeasurementList } from './pinned-measurements';
import type { TrustedSeal } from './trusted-seal';

/** An answer the core accepted: what the screens may show. */
export type CheckedAnswer = {
  kind: AnswerKind;
  /** The card's UID, upper-case hex. */
  uid: string;
  state: SealCardState;
  amountWei: bigint;
  pinRequired: boolean;
  pinTriesLeft: number;
  /** Unix seconds. */
  expiresAt: number;
  generation: number;
};

export type AnswerVerdict = { ok: true; answer: CheckedAnswer } | { ok: false; refusal: string };

/** Where the check takes its time from, and the list it pins. */
export type VerifyOptions = {
  /** Milliseconds since the Unix epoch. */
  now?: () => number;
  list?: MeasurementList;
};

const STATES: readonly SealCardState[] = ['empty', 'sealed', 'opening', 'opened'];
const KINDS: readonly AnswerKind[] = ['check', 'fill', 'open'];

function bytes(hex: string): Uint8Array {
  return Uint8Array.from({ length: hex.length / 2 }, (_, i) => parseInt(hex.slice(2 * i, 2 * i + 2), 16));
}

function buffer(view: Uint8Array): ArrayBuffer {
  return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength) as ArrayBuffer;
}

function hexOf(data: ArrayBuffer): string {
  return Array.from(new Uint8Array(data), (byte) => byte.toString(16).toUpperCase().padStart(2, '0')).join('');
}

/**
 * The Seal answer measurements the app accepts: the PCR0 of every allowed
 * build of the pinned list. A revoked build is never among them, and an
 * empty list (today's) accepts no Seal.
 */
export function pinnedAnswerMeasurements(list: MeasurementList = PINNED_MEASUREMENTS): Uint8Array[] {
  return list.builds.filter((build) => build.status === 'allowed').map((build) => bytes(build.pcr0));
}

/** What the core checks a relayed answer of `kind` against. */
export function answerCheck(
  seal: TrustedSeal,
  relayed: RelayedAnswer,
  kind: AnswerKind,
  options: VerifyOptions = {},
): CoreSealAnswerCheck {
  const now = (options.now ?? Date.now)();
  return {
    verifyingKey: buffer(seal.verifyingKey),
    measurement: buffer(seal.measurement),
    pinnedMeasurements: pinnedAnswerMeasurements(options.list).map(buffer),
    answer: buffer(relayed.answer),
    signature: buffer(relayed.signature),
    // The challenge the native relay made and sent, never one of the answer's own.
    challenge: buffer(relayed.challenge),
    uid: buffer(bytes(relayed.uid)),
    now: BigInt(Math.floor(now / 1000)),
    kind,
  };
}

/** Reads the core's verdict: an accepted answer, or why it was refused. */
export function readVerdict(verdict: CoreSealAnswerVerdict | null | undefined): AnswerVerdict {
  const answer = verdict?.answer;
  if (!verdict || verdict.refusal !== '' || !answer) {
    return { ok: false, refusal: verdict?.refusal || 'no-verdict' };
  }
  const read = readAnswer(answer);
  return read ? { ok: true, answer: read } : { ok: false, refusal: 'malformed' };
}

function readAnswer(answer: CoreSealAnswer): CheckedAnswer | null {
  const state = STATES.find((s) => s === answer.state);
  const kind = KINDS.find((k) => k === answer.kind);
  if (!state || !kind || !/^[0-9]+$/.test(answer.amountWei)) {
    return null;
  }
  return {
    kind,
    uid: hexOf(answer.uid),
    state,
    amountWei: BigInt(answer.amountWei),
    pinRequired: answer.pinRequired,
    pinTriesLeft: answer.pinRequired ? answer.pinTriesLeft : 0,
    expiresAt: Number(answer.expiresAt),
    generation: answer.generation,
  };
}

/** Has the core check a relayed Check answer. A core that throws refuses it. */
export function verifyCheckAnswer(
  core: SealBindings,
  seal: TrustedSeal,
  relayed: RelayedAnswer,
  options: VerifyOptions = {},
): AnswerVerdict {
  try {
    return readVerdict(core.verifySealAnswer(answerCheck(seal, relayed, 'check', options)));
  } catch {
    return { ok: false, refusal: 'core-failed' };
  }
}

/**
 * Has the core check a relayed Fill answer: also that it binds exactly the
 * commit data handed back with it, for `amountWei`, with an Open PIN exactly
 * when one was asked for.
 */
export function verifyFillAnswer(
  core: SealBindings,
  seal: TrustedSeal,
  relayed: RelayedFill,
  expected: { amountWei: bigint; pin: boolean },
  options: VerifyOptions = {},
): AnswerVerdict {
  let verdict: AnswerVerdict;
  try {
    verdict = readVerdict(core.verifySealFillAnswer(answerCheck(seal, relayed, 'fill', options), buffer(relayed.commitData)));
  } catch {
    return { ok: false, refusal: 'core-failed' };
  }
  if (!verdict.ok) {
    return verdict;
  }
  const { answer } = verdict;
  if (answer.state !== 'empty' || answer.amountWei !== expected.amountWei) {
    return { ok: false, refusal: 'wrong-fill' };
  }
  if (answer.pinRequired !== expected.pin) {
    return { ok: false, refusal: 'wrong-pin-status' };
  }
  return verdict;
}

/** Has the core check a Fill's confirmation (a Fill answer that hands nothing over). */
export function verifyConfirmAnswer(
  core: SealBindings,
  seal: TrustedSeal,
  relayed: RelayedAnswer,
  options: VerifyOptions = {},
): AnswerVerdict {
  try {
    return readVerdict(core.verifySealAnswer(answerCheck(seal, relayed, 'fill', options)));
  } catch {
    return { ok: false, refusal: 'core-failed' };
  }
}
