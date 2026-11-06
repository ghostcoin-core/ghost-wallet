// Check, Fill and Open of a Ghost Sealed card, as the screens run them: the
// native relay carries the card's traffic to the Seal (modules/ghost-nfc/
// relay.ts), the native core checks the Seal's signed answer
// (core/src/seal_answer.rs) and, for an Open, opens the release with its
// ML-KEM key and holds the card's key for the Claim (core/src/seal_open.rs).
// No key, seed or words are ever in JavaScript; a PIN is passed through to
// the relay and kept nowhere.
import { sealCore, type SealBindings } from '../../modules/ghost-core';
import {
  checkWithSeal,
  confirmFillWithSeal,
  fillWithSeal,
  openKeyKeeper,
  openWithSeal,
  type GhostNfcSealNative,
  type RelayedAnswer,
  type RelayedFill,
} from '../../modules/ghost-nfc/relay';
import { statusOfAnswer, statusOfFailure, type CardStatus } from './card-status';
import { clearFill, noteFill, pendingFill } from './fills';
import { refreshTrustedSeal, trustedSeal, type TrustedSeal } from './trusted-seal';
import {
  answerCheck,
  readVerdict,
  verifyCheckAnswer,
  verifyConfirmAnswer,
  verifyFillAnswer,
  type AnswerVerdict,
  type VerifyOptions,
} from './verify-answer';

type Keeper = Pick<GhostNfcSealNative, 'keepOpenKey' | 'restoreOpenKey' | 'forgetOpenKey'>;

/** What the flows run on: each replaced by a fake in the tests. */
export type SealDeps = VerifyOptions & {
  /** The Seal as it was when the screen opened, used only when there is no `refresh`. */
  seal: TrustedSeal | null;
  /** Fetches and checks the Seal's attestation when its cached check ran out; never throws. */
  refresh?: () => Promise<TrustedSeal | null>;
  core: SealBindings | null;
  check: (url: string) => Promise<RelayedAnswer>;
  fill: (url: string, amountWei: bigint, pin: string | null) => Promise<RelayedFill>;
  confirm: (url: string) => Promise<RelayedAnswer>;
  open: (url: string, phoneKey: Uint8Array, pin: string | null) => Promise<RelayedAnswer>;
  keeper: Keeper | null;
};

function optionalCore(): SealBindings | null {
  try {
    return sealCore();
  } catch {
    return null;
  }
}

/** The app's Seal, core and relay. */
export function sealDeps(): SealDeps {
  return {
    seal: trustedSeal(),
    refresh: () => refreshTrustedSeal(),
    core: optionalCore(),
    check: (url) => checkWithSeal(url),
    fill: (url, amountWei, pin) => fillWithSeal(url, amountWei, pin),
    confirm: (url) => confirmFillWithSeal(url),
    open: (url, phoneKey, pin) => openWithSeal(url, phoneKey, pin),
    keeper: openKeyKeeper(),
  };
}

/**
 * The Seal and core at the start of a card flow, or null when either is
 * missing: then no card can be verified. The Seal's attestation is fetched
 * and checked again here (`refresh`) when its cached check has run out; this
 * is the only place the app waits on it.
 */
async function readyNow(deps: SealDeps): Promise<{ seal: TrustedSeal; core: SealBindings } | null> {
  let seal = deps.seal;
  if (deps.refresh) {
    try {
      seal = await deps.refresh();
    } catch {
      seal = null;
    }
  }
  return seal && deps.core ? { seal, core: deps.core } : null;
}

/**
 * Checks the next card tapped: a fresh challenge goes through the relay and
 * the Seal's signed answer is verified. Null when the card sheet was closed.
 */
export async function checkCard(deps: SealDeps): Promise<CardStatus | null> {
  const parts = await readyNow(deps);
  if (!parts) {
    return { kind: 'cant-verify' };
  }
  let relayed: RelayedAnswer;
  try {
    relayed = await deps.check(parts.seal.url);
  } catch (error) {
    return statusOfFailure(error);
  }
  const verdict = verifyCheckAnswer(parts.core, parts.seal, relayed, deps);
  if (!verdict.ok) {
    return { kind: 'cant-verify' };
  }
  return afterAnswer(verdict.answer.uid, statusOfAnswer(verdict.answer));
}

/**
 * A verified answer, with what this phone knows of its own Fills: a card it
 * filled that the Seal still answers Empty is Filling, and a card answered
 * Sealed or Opened is no longer waiting.
 */
function afterAnswer(uid: string, status: CardStatus): CardStatus {
  if (status.kind === 'empty') {
    return pendingFill(uid) !== null ? { kind: 'filling' } : status;
  }
  void clearFill(uid);
  return status;
}

export type FillResult =
  /** The Seal wrote a fresh key to the card: pay exactly `amountWei` to `commitData`. */
  | { ok: true; uid: string; commitData: Uint8Array; amountWei: bigint }
  | { ok: false; status: CardStatus | null };

/**
 * Fills the next card tapped (it must be set up and empty) with a fresh key
 * the Seal makes on the card, and returns only the public commit data to pay.
 * `pin`, when set, becomes the card's Open PIN.
 */
export async function fillCard(deps: SealDeps, amountWei: bigint, pin: string | null): Promise<FillResult> {
  const parts = await readyNow(deps);
  if (!parts) {
    return { ok: false, status: { kind: 'cant-verify' } };
  }
  let relayed: RelayedFill;
  try {
    relayed = await deps.fill(parts.seal.url, amountWei, pin);
  } catch (error) {
    return { ok: false, status: statusOfFailure(error) };
  }
  const verdict = verifyFillAnswer(parts.core, parts.seal, relayed, { amountWei, pin: pin !== null }, deps);
  if (!verdict.ok) {
    return { ok: false, status: { kind: 'cant-verify' } };
  }
  // Only a hint for this phone's own Checks: a failed write changes nothing on the card.
  await noteFill(verdict.answer.uid, verdict.answer.amountWei).catch(() => {});
  return { ok: true, uid: verdict.answer.uid, commitData: relayed.commitData, amountWei: verdict.answer.amountWei };
}

/**
 * Asks the Seal, on the next card tapped, to mark a filled card Sealed: it
 * does once the chain check finds its coin paid exactly and settled. Until
 * then the card is Filling.
 */
export async function confirmFill(deps: SealDeps): Promise<CardStatus | null> {
  const parts = await readyNow(deps);
  if (!parts) {
    return { kind: 'cant-verify' };
  }
  let relayed: RelayedAnswer;
  try {
    relayed = await deps.confirm(parts.seal.url);
  } catch (error) {
    return statusOfFailure(error);
  }
  const verdict = verifyConfirmAnswer(parts.core, parts.seal, relayed, deps);
  if (!verdict.ok) {
    return { kind: 'cant-verify' };
  }
  if (verdict.answer.state === 'empty') {
    return { kind: 'filling' };
  }
  return afterAnswer(verdict.answer.uid, statusOfAnswer(verdict.answer));
}

/** Whether this phone holds (or kept in the Keychain) the phone key of an Open not yet claimed. */
export function openUnderWay(deps: Pick<SealDeps, 'core' | 'keeper'>): boolean {
  if (!deps.core) {
    return false;
  }
  try {
    deps.keeper?.restoreOpenKey();
  } catch {
    // An unreadable Keychain is no Open under way; the next Open says so.
  }
  try {
    return deps.core.hasSealOpenKey();
  } catch {
    return false;
  }
}

export type OpenResult =
  /** The card's key is in the native core: Claim it now. */
  | { ok: true; uid: string; amountWei: bigint }
  | { ok: false; status: CardStatus | null; wrongPin?: boolean; pinRequired?: boolean };

/**
 * Opens the next card tapped into this phone's native core: the core makes
 * (or reuses) its ML-KEM phone key, the Seal releases the card's key to it,
 * the core checks the signed Open answer, opens the release and holds the
 * key for the Claim. The phone key is kept in the Keychain before it is sent,
 * so an Open cut off can be asked again with it; it is wiped once the Claim
 * settles (`finishOpenClaim`).
 */
export async function openCard(deps: SealDeps, pin: string | null): Promise<OpenResult> {
  const parts = await readyNow(deps);
  if (!parts) {
    return { ok: false, status: { kind: 'cant-verify' } };
  }
  let phoneKey: Uint8Array;
  try {
    deps.keeper?.restoreOpenKey();
    phoneKey = new Uint8Array(parts.core.sealOpenPhoneKey());
    if (!deps.keeper) {
      throw new Error('no Keychain for the phone key');
    }
    deps.keeper.keepOpenKey();
  } catch {
    return { ok: false, status: { kind: 'retry', message: 'This iPhone could not make the key to open the card with.' } };
  }
  let relayed: RelayedAnswer;
  try {
    relayed = await deps.open(parts.seal.url, phoneKey, pin);
  } catch (error) {
    const status = statusOfFailure(error);
    const problem = (error as { problem?: string } | null)?.problem;
    return { ok: false, status, wrongPin: problem === 'wrong-pin', pinRequired: problem === 'pin-required' };
  }
  let verdict: AnswerVerdict;
  try {
    verdict = readVerdict(parts.core.finishSealOpen(answerCheck(parts.seal, relayed, 'open', deps)));
  } catch {
    verdict = { ok: false, refusal: 'core-failed' };
  }
  if (!verdict.ok || verdict.answer.state !== 'opened') {
    return { ok: false, status: { kind: 'cant-verify' } };
  }
  return { ok: true, uid: verdict.answer.uid, amountWei: verdict.answer.amountWei };
}

/**
 * The Claim of an opened card settled: the phone key is wiped from the core
 * and the Keychain, and the card's key from the core.
 */
export function finishOpenClaim(deps: Pick<SealDeps, 'core' | 'keeper'>, forgetCardKey: () => void) {
  try {
    deps.core?.forgetSealOpenKey();
  } finally {
    try {
      deps.keeper?.forgetOpenKey();
    } finally {
      forgetCardKey();
    }
  }
}
