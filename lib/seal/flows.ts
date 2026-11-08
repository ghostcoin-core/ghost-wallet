// Check, Fill and Open of a Ghost Sealed card, as the screens run them: the
// native relay carries the card's traffic to the Seal (modules/ghost-nfc/
// relay.ts), the native core checks the Seal's signed answer
// (core/src/seal_answer.rs) and, for an Open, opens the release with its
// ML-KEM key and holds the card's key for the Claim (core/src/seal_open.rs).
// No key, seed or words are ever in JavaScript; a PIN is passed through to
// the relay and kept nowhere.
//
// Each card is served by one Seal region, its home. A flow starts by checking
// every listed region's attestation (`refreshTrustedSeals`) and goes on to
// the card only when at least one region verified. The native relay then
// reads the card's UID, chooses its home region and runs the flow there
// (`HOME_REGION`); JavaScript never chooses a region. The answer is checked
// with the Seal of the region that answered it, and only that region's key,
// measurement and pin: a region with no verified Seal, or one not listed, is
// "Can't verify this card". A `wrong-region` refusal is shown as a plain
// message; nothing is sent again, to that region or to any other.
import { sealCore, type SealBindings } from '../../modules/ghost-core';
import {
  checkWithSeal,
  confirmFillWithSeal,
  fillWithSeal,
  HOME_REGION,
  openKeyKeeper,
  openWithSeal,
  type GhostNfcSealNative,
  type RelayedAnswer,
  type RelayedFill,
} from '../../modules/ghost-nfc/relay';
import { cantVerify, statusOfAnswer, statusOfFailure, type CardStatus } from './card-status';
import { clearFill, noteFill, pendingFill } from './fills';
import { SEAL_REGIONS } from './seal-config';
import {
  noSealReason,
  refreshTrustedSeals,
  regionFailure,
  trustedSeal,
  type TrustedSeal,
  type TrustedSeals,
} from './trusted-seal';
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
  /** The verified Seals by region id as they were when the screen opened, used only when there is no `refresh`. */
  seals: TrustedSeals;
  /** Checks every region's attestation whose cached check ran out, and gives the verified ones; never throws. */
  refresh?: () => Promise<TrustedSeals>;
  core: SealBindings | null;
  /** Each relay call runs on the next card tapped, in the card's home region, chosen natively. */
  check: () => Promise<RelayedAnswer>;
  fill: (amountWei: bigint, pin: string | null) => Promise<RelayedFill>;
  confirm: () => Promise<RelayedAnswer>;
  open: (phoneKey: Uint8Array, pin: string | null) => Promise<RelayedAnswer>;
  keeper: Keeper | null;
};

function optionalCore(): SealBindings | null {
  try {
    return sealCore();
  } catch {
    return null;
  }
}

/** The verified Seals cached now, by region id; nothing is fetched. */
function cachedSeals(): TrustedSeals {
  const seals = new Map<string, TrustedSeal>();
  for (const region of SEAL_REGIONS) {
    const seal = trustedSeal(region.id);
    if (seal) {
      seals.set(region.id, seal);
    }
  }
  return seals;
}

/** The app's Seals, core and relay. */
export function sealDeps(): SealDeps {
  return {
    seals: cachedSeals(),
    refresh: () => refreshTrustedSeals(),
    core: optionalCore(),
    check: () => checkWithSeal(HOME_REGION),
    fill: (amountWei, pin) => fillWithSeal(HOME_REGION, amountWei, pin),
    confirm: () => confirmFillWithSeal(HOME_REGION),
    open: (phoneKey, pin) => openWithSeal(HOME_REGION, phoneKey, pin),
    keeper: openKeyKeeper(),
  };
}

type Ready = { seals: TrustedSeals; core: SealBindings };

/**
 * The verified Seals and the core at the start of a card flow, or why there
 * are none: no region verified (each region's first failure) or the core is
 * missing. Then no card can be verified, and no card sheet opens. Every
 * region's attestation is fetched and checked again here (`refresh`) when its
 * cached check has run out; this is the only place the app waits on it.
 */
async function readyNow(deps: SealDeps): Promise<{ ok: true; parts: Ready } | { ok: false; status: CardStatus }> {
  let seals: TrustedSeals = deps.seals;
  if (deps.refresh) {
    try {
      seals = await deps.refresh();
    } catch {
      return { ok: false, status: cantVerify('refresh-failed') };
    }
  }
  if (!seals || seals.size === 0) {
    return { ok: false, status: cantVerify(noSealReason(seals ?? null)) };
  }
  if (!deps.core) {
    return { ok: false, status: cantVerify('no-answer-core') };
  }
  return { ok: true, parts: { seals, core: deps.core } };
}

/**
 * The Seal to check `relayed` with: the verified Seal of the region that
 * answered it, or null for a region with no verified Seal or not listed.
 */
function sealOfAnswer(parts: Ready, relayed: RelayedAnswer): TrustedSeal | null {
  const region = relayed.region;
  const seal = region ? parts.seals.get(region) : undefined;
  return seal && seal.region === region ? seal : null;
}

/** Why the region that answered `relayed` has no Seal to check it with. */
function noSealOfAnswer(parts: Ready, relayed: RelayedAnswer): CardStatus {
  const region = relayed.region;
  if (!region) {
    return cantVerify('seal-of-answer (no region)');
  }
  const failure = regionFailure(parts.seals, region);
  return cantVerify(failure ? `seal-of-answer (${region}: ${failure})` : `seal-of-answer (${region})`);
}

/**
 * Checks the next card tapped: a fresh challenge goes through the relay and
 * the Seal's signed answer is verified. Null when the card sheet was closed.
 */
export async function checkCard(deps: SealDeps): Promise<CardStatus | null> {
  const ready = await readyNow(deps);
  if (!ready.ok) {
    return ready.status;
  }
  const parts = ready.parts;
  let relayed: RelayedAnswer;
  try {
    relayed = await deps.check();
  } catch (error) {
    return statusOfFailure(error);
  }
  const seal = sealOfAnswer(parts, relayed);
  if (!seal) {
    return noSealOfAnswer(parts, relayed);
  }
  const verdict = verifyCheckAnswer(parts.core, seal, relayed, deps);
  if (!verdict.ok) {
    return cantVerify(verdict.refusal);
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
  const ready = await readyNow(deps);
  if (!ready.ok) {
    return { ok: false, status: ready.status };
  }
  const parts = ready.parts;
  let relayed: RelayedFill;
  try {
    relayed = await deps.fill(amountWei, pin);
  } catch (error) {
    return { ok: false, status: statusOfFailure(error) };
  }
  const seal = sealOfAnswer(parts, relayed);
  if (!seal) {
    return { ok: false, status: noSealOfAnswer(parts, relayed) };
  }
  const verdict = verifyFillAnswer(parts.core, seal, relayed, { amountWei, pin: pin !== null }, deps);
  if (!verdict.ok) {
    return { ok: false, status: cantVerify(verdict.refusal) };
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
  const ready = await readyNow(deps);
  if (!ready.ok) {
    return ready.status;
  }
  const parts = ready.parts;
  let relayed: RelayedAnswer;
  try {
    relayed = await deps.confirm();
  } catch (error) {
    return statusOfFailure(error);
  }
  const seal = sealOfAnswer(parts, relayed);
  if (!seal) {
    return noSealOfAnswer(parts, relayed);
  }
  const verdict = verifyConfirmAnswer(parts.core, seal, relayed, deps);
  if (!verdict.ok) {
    return cantVerify(verdict.refusal);
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
  const ready = await readyNow(deps);
  if (!ready.ok) {
    return { ok: false, status: ready.status };
  }
  const parts = ready.parts;
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
    relayed = await deps.open(phoneKey, pin);
  } catch (error) {
    // A refusal (`wrong-region` too) released nothing: no card key is held.
    const status = statusOfFailure(error);
    const problem = (error as { problem?: string } | null)?.problem;
    return { ok: false, status, wrongPin: problem === 'wrong-pin', pinRequired: problem === 'pin-required' };
  }
  const seal = sealOfAnswer(parts, relayed);
  if (!seal) {
    // The release stays sealed in the core, unopened: only that region's checked answer opens it.
    return { ok: false, status: noSealOfAnswer(parts, relayed) };
  }
  let verdict: AnswerVerdict;
  try {
    verdict = readVerdict(parts.core.finishSealOpen(answerCheck(seal, relayed, 'open', deps)));
  } catch {
    verdict = { ok: false, refusal: 'core-failed' };
  }
  if (!verdict.ok) {
    return { ok: false, status: cantVerify(verdict.refusal) };
  }
  if (verdict.answer.state !== 'opened') {
    return { ok: false, status: cantVerify('not-opened') };
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
