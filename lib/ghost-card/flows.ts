// Check, Fill, Open and Refill of a Ghost Java card, as the screens run them
// (docs/bearer-card-spec.md). No Seal and no Ghost server: each flow is one
// tap between the card and this phone (modules/ghost-nfc/java-card.ts), then
// the native core verifies what the card said (core/src/java_card.rs) and
// this phone reads the coin's state from Ghost nodes (./chain.ts).
//
// The card is a bearer object, like cash: whoever holds it can open it. No
// flow asks for a code, PIN or anything else but the card.
import { CardCancelled } from '../../modules/ghost-nfc';
import { bytesToHex } from '../../modules/ghost-core/account-lookup';
import type { CoreJavaCardStatement, JavaCardBindings } from '../../modules/ghost-core';
import {
  COMMIT_DATA_BYTES,
  GhostCardError,
  tap,
  type CardTap,
  type GhostCardNative,
} from '../../modules/ghost-nfc/java-card';
import type { CoinOnChain } from './chain';
import type { GhostCardStatus } from './status';

/** What the flows run on: each replaced by a fake in the tests. */
export type GhostCardDeps = {
  core: JavaCardBindings | null;
  nfc: GhostCardNative | null;
  /** This build's chain. */
  chainId: bigint;
  /** The coin's state on chain; throws when no node answers. */
  coinOnChain: (commitment: Uint8Array, marker: Uint8Array) => Promise<CoinOnChain>;
};

const ALERT = {
  check: 'Hold the Ghost card near the top of the iPhone.',
  fill: 'Hold the empty Ghost card near the top of the iPhone, and keep it there.',
  open: 'Hold the Ghost card near the top of the iPhone, and keep it there.',
  refill: 'Hold the opened Ghost card near the top of the iPhone.',
  remake: 'Keep holding the card near the top of the iPhone.',
} as const;

function buffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function bytes(value: ArrayBuffer): Uint8Array {
  return new Uint8Array(value);
}

function sameBytes(a: Uint8Array | ArrayBuffer, b: Uint8Array | ArrayBuffer): boolean {
  return bytesToHex(a) === bytesToHex(b);
}

/** A big-endian number of `length` bytes. */
export function beBytes(value: bigint, length: number): Uint8Array {
  if (value < 0n || value >= 1n << BigInt(8 * length)) {
    throw new Error('out of range');
  }
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** What a failed tap says about the card; null when the sheet was closed. */
export function statusOfTapFailure(error: unknown): GhostCardStatus | null {
  if (error instanceof CardCancelled) {
    return null;
  }
  if (error instanceof GhostCardError) {
    if (error.problem === 'refused' && error.detail === 'not a Ghost card') {
      return { kind: 'not-genuine', reason: 'not-a-ghost-card' };
    }
    if (error.problem === 'not-ready') {
      return { kind: 'not-genuine', reason: 'not-loaded' };
    }
    if (error.problem === 'bad-tap') {
      return { kind: 'not-genuine', reason: 'bad-answer' };
    }
    return { kind: 'retry', message: error.message };
  }
  return { kind: 'retry', message: 'The card could not be read. Hold it still and try again.' };
}

type Verified = { ok: true; statement: CoreJavaCardStatement } | { ok: false; status: GhostCardStatus };

/** The native core's verdict on one tap's Check. */
function verify(core: JavaCardBindings, deps: GhostCardDeps, card: CardTap, challenge: Uint8Array, commitData: Uint8Array | null): Verified {
  if (card.kind !== 'ghost' || !card.certificate || !card.statement || !card.signature) {
    return { ok: false, status: { kind: 'not-genuine', reason: 'no-statement' } };
  }
  const verdict = core.verifyJavaCardCheck({
    certificate: buffer(card.certificate),
    statement: buffer(card.statement),
    signature: buffer(card.signature),
    challenge: buffer(challenge),
    commitData: commitData ? buffer(commitData) : undefined,
    chainId: deps.chainId,
  });
  if (verdict.refusal !== '' || !verdict.statement) {
    return { ok: false, status: { kind: 'not-genuine', reason: verdict.refusal || 'no-statement' } };
  }
  return { ok: true, statement: verdict.statement };
}

/** What a verified statement and the chain say about the card. */
export async function statusOfStatement(deps: GhostCardDeps, statement: CoreJavaCardStatement): Promise<GhostCardStatus> {
  const cardNumber = statement.cardNumber;
  if (statement.state === 'blank') {
    return { kind: 'blank', fill: statement.fill, checksLeft: statement.checksLeft, cardNumber };
  }
  let chain: CoinOnChain;
  try {
    chain = await deps.coinOnChain(bytes(statement.commitment), bytes(statement.marker));
  } catch {
    return statement.state === 'opened'
      ? { kind: 'opened', fill: statement.fill, cardNumber, spent: null }
      : { kind: 'no-connection' };
  }
  if (statement.state === 'opened') {
    return { kind: 'opened', fill: statement.fill, cardNumber, spent: chain.spent };
  }
  const amountWei = BigInt(statement.amountWei);
  if (chain.spent === true) {
    return { kind: 'spent-while-sealed', cardNumber };
  }
  if (chain.spent === null) {
    // Unspent is never assumed: a card is Sealed only when the markers were read.
    return { kind: 'no-connection' };
  }
  if (chain.status === 'absent') {
    return { kind: 'not-on-chain', fill: statement.fill, amountWei, cardNumber };
  }
  // The leaf on chain must be exactly the Vanish of this card's commit data:
  // its digest is signed by the card, the leaf's own note and salt are not.
  if (statement.leaf && chain.leaf && !sameLeaf(statement.leaf, chain.leaf)) {
    return { kind: 'not-on-chain', fill: statement.fill, amountWei, cardNumber };
  }
  if (chain.status === 'settling') {
    return { kind: 'settling', fill: statement.fill, amountWei, cardNumber };
  }
  return {
    kind: 'sealed',
    fill: statement.fill,
    amountWei,
    checksLeft: statement.checksLeft,
    cardNumber,
  };
}

function sameLeaf(a: { commitment: ArrayBuffer; note: ArrayBuffer; salt?: ArrayBuffer }, b: typeof a): boolean {
  return (
    sameBytes(a.commitment, b.commitment) &&
    sameBytes(a.note, b.note) &&
    (a.salt === undefined || b.salt === undefined || sameBytes(a.salt, b.salt))
  );
}

export type CheckResult = {
  status: GhostCardStatus;
  /** The verified statement, when there is one. */
  statement: CoreJavaCardStatement | null;
  /** How long the tap took, in milliseconds. */
  ms: number | null;
  /** A sealed card's commit data, checked against its signed digest: what its Vanish pays into. */
  commitData: Uint8Array | null;
};

/**
 * Checks the next card tapped: a fresh challenge, the card's signed
 * statement verified by the native core, and its coin read from the chain.
 * Null when the sheet was closed. An NTAG 424 card is "Carry to Claim".
 */
export async function checkGhostCard(deps: GhostCardDeps): Promise<CheckResult | null> {
  const { core, nfc } = deps;
  if (!core || !nfc) {
    return { status: { kind: 'retry', message: 'This iPhone cannot read Ghost cards in this build.' }, statement: null, ms: null, commitData: null };
  }
  const challenge = bytes(core.javaCardRandom());
  let card: CardTap;
  try {
    card = await tap(() => nfc.javaCardCheck(ALERT.check, challenge, true));
  } catch (error) {
    const status = statusOfTapFailure(error);
    return status ? { status, statement: null, ms: null, commitData: null } : null;
  }
  if (card.kind === 'ntag') {
    return { status: { kind: 'carry-to-claim' }, statement: null, ms: null, commitData: null };
  }
  const verified = verify(core, deps, card, challenge, card.commitData);
  if (!verified.ok) {
    return { status: verified.status, statement: null, ms: card.ms, commitData: null };
  }
  return {
    status: await statusOfStatement(deps, verified.statement),
    statement: verified.statement,
    ms: card.ms,
    commitData: verified.statement.leaf ? card.commitData : null,
  };
}

export type FillResult =
  | {
      ok: true;
      /** Pay exactly `amountWei` to this commit data with a Vanish. */
      commitData: Uint8Array;
      amountWei: bigint;
      fill: number;
      cardNumber: string;
      checksLeft: number;
      ms: number;
    }
  | { ok: false; status: GhostCardStatus | null };

/**
 * Fills the next card tapped (it must be blank) with `amountWei`: Make with
 * a fresh writer nonce, then in the same tap the writer's own Check. Only a
 * statement that says Sealed
 * at Make's fill, with Make's commitment, the amount, this chain and a digest
 * of exactly the commit data Make returned, gives commit data to pay.
 */
export async function fillGhostCard(deps: GhostCardDeps, amountWei: bigint): Promise<FillResult> {
  const { core, nfc } = deps;
  if (!core || !nfc) {
    return { ok: false, status: { kind: 'retry', message: 'This iPhone cannot read Ghost cards in this build.' } };
  }
  const challenge = bytes(core.javaCardRandom());
  const make = makeInput(core, deps, amountWei);
  let card: CardTap;
  try {
    card = await tap(() => nfc.javaCardFill(ALERT.fill, make, challenge));
  } catch (error) {
    return { ok: false, status: statusOfTapFailure(error) };
  }
  return checkMade(core, deps, card, challenge, amountWei);
}

/** Make's input: the amount (12 bytes), this chain (8) and a fresh writer nonce (32). */
function makeInput(core: JavaCardBindings, deps: GhostCardDeps, amountWei: bigint): Uint8Array {
  const make = new Uint8Array(52);
  make.set(beBytes(amountWei, 12), 0);
  make.set(beBytes(deps.chainId, 8), 12);
  make.set(bytes(core.javaCardRandom()), 20);
  return make;
}

/**
 * A Make and its Check in one tap, checked: only a statement that says
 * Sealed at Make's fill, with Make's commitment, the amount, this chain and a
 * digest of exactly the commit data Make returned, gives commit data to pay.
 */
function checkMade(
  core: JavaCardBindings,
  deps: GhostCardDeps,
  card: CardTap,
  challenge: Uint8Array,
  amountWei: bigint,
): FillResult {
  if (card.kind === 'ntag') {
    return { ok: false, status: { kind: 'carry-to-claim' } };
  }
  if (!card.make) {
    return { ok: false, status: { kind: 'not-genuine', reason: 'no-make' } };
  }
  const commitData = card.make.slice(36, 36 + COMMIT_DATA_BYTES);
  const verified = verify(core, deps, card, challenge, commitData);
  if (!verified.ok) {
    return { ok: false, status: verified.status };
  }
  const s = verified.statement;
  const fill = new DataView(card.make.buffer, card.make.byteOffset, 4).getUint32(0);
  const madeCommitment = card.make.slice(4, 36);
  const commitmentKnown = madeCommitment.some((b) => b !== 0);
  const reason =
    s.state !== 'sealed'
      ? 'fill-not-sealed'
      : s.fill !== fill
        ? 'fill-other-fill'
        : commitmentKnown && !sameBytes(madeCommitment, s.commitment)
          ? 'fill-other-commitment'
          : BigInt(s.amountWei) !== amountWei
            ? 'fill-other-amount'
            : s.chainId !== deps.chainId
              ? 'fill-other-chain'
              : null;
  if (reason) {
    return { ok: false, status: { kind: 'not-genuine', reason } };
  }
  return { ok: true, commitData, amountWei, fill, cardNumber: s.cardNumber, checksLeft: s.checksLeft, ms: card.ms };
}

/**
 * Gives the card `target` a new key for `amountWei` in one hold: the card,
 * opened at `target.fill` (its key released, checked and kept on this phone)
 * or blank at it, is cleared and makes the new key, then signs its Check.
 * The result is checked exactly as a Fill's. Any other card is refused before
 * anything is sent to it.
 */
export async function remakeGhostCard(deps: GhostCardDeps, target: RefillTarget, amountWei: bigint): Promise<FillResult> {
  const { core, nfc } = deps;
  if (!core || !nfc) {
    return { ok: false, status: { kind: 'retry', message: 'This iPhone cannot read Ghost cards in this build.' } };
  }
  const challenge = bytes(core.javaCardRandom());
  const make = makeInput(core, deps, amountWei);
  let card: CardTap;
  try {
    card = await tap(() => nfc.javaCardRemake(ALERT.remake, target.cardId, target.fill, make, challenge));
  } catch (error) {
    return { ok: false, status: statusOfTapFailure(error) };
  }
  if (card.kind === 'ghost' && !sameBytes(core.javaCardIdentity(buffer(card.identify)).cardId, target.cardId)) {
    return { ok: false, status: { kind: 'retry', message: 'Hold the same card to the iPhone again.' } };
  }
  return checkMade(core, deps, card, challenge, amountWei);
}

/** The coin an Open released, as its verified statement named it; null with no seal checks left. */
export type OpenedCoin = {
  /** What the card said before this tap. */
  state: 'sealed' | 'opened';
  commitment: Uint8Array;
  marker: Uint8Array;
  /** A sealed card's commit data: what its Vanish pays into. */
  commitData: Uint8Array | null;
};

export type OpenResult =
  /** The card's Phantom Key is in the native core, checked against the card's coin: Summon now. */
  | {
      ok: true;
      amountWei: bigint | null;
      cardId: Uint8Array;
      fill: number;
      cardNumber: string;
      ms: number;
      coin: OpenedCoin | null;
    }
  /**
   * `reuse` is set for a card opened before whose coin the chain shows taken
   * off: it can only be reused. `blank` is set for a blank card: nothing was
   * opened and no check was used.
   */
  | { ok: false; status: GhostCardStatus | null; reuse?: RefillTarget; blank?: RefillTarget & { cardNumber: string } };

/**
 * Opens the next card tapped: the card's Check (and its commit data while
 * sealed), then Open, which needs nothing but the card and whose answer goes
 * to the native core. The core recomputes the coin from what the card released
 * and holds the key only when it is the coin the verified statement names.
 * For an opened card whose commit data is gone, the coin's salt and note come
 * from its leaf on chain; when the chain shows that coin already taken off,
 * nothing is summoned and the card is offered for reuse instead.
 */
export async function openGhostCard(deps: GhostCardDeps): Promise<OpenResult> {
  const { core, nfc } = deps;
  if (!core || !nfc) {
    return { ok: false, status: { kind: 'retry', message: 'This iPhone cannot read Ghost cards in this build.' } };
  }
  const checkChallenge = bytes(core.javaCardRandom());
  core.forgetJavaCardRelease();
  let card: CardTap;
  try {
    card = await tap(() => nfc.javaCardOpen(ALERT.open, checkChallenge));
  } catch (error) {
    return { ok: false, status: statusOfTapFailure(error) };
  }
  if (card.kind === 'ntag') {
    return { ok: false, status: { kind: 'carry-to-claim' } };
  }
  const identity = core.javaCardIdentity(buffer(card.identify));
  if (identity.state === 'blank' && card.opened !== true) {
    core.forgetJavaCardRelease();
    return {
      ok: false,
      status: { kind: 'blank', fill: identity.fill, checksLeft: identity.checksLeft, cardNumber: identity.cardNumber },
      blank: { cardId: bytes(identity.cardId), fill: identity.fill, cardNumber: identity.cardNumber },
    };
  }

  if (!card.statement) {
    // No seal checks left: nothing to check the release against but the chain.
    if (card.opened !== true || !card.certificate) {
      core.forgetJavaCardRelease();
      return { ok: false, status: { kind: 'not-genuine', reason: 'open-refused' } };
    }
    const refusal = core.finishJavaCardOpenUnchecked(buffer(card.certificate), deps.chainId, identity.fill);
    return refusal === ''
      ? {
          ok: true,
          amountWei: null,
          cardId: bytes(identity.cardId),
          fill: identity.fill,
          cardNumber: identity.cardNumber,
          ms: card.ms,
          coin: null,
        }
      : { ok: false, status: { kind: 'not-genuine', reason: refusal } };
  }

  const verified = verify(core, deps, card, checkChallenge, card.commitData);
  if (!verified.ok) {
    core.forgetJavaCardRelease();
    return { ok: false, status: verified.status };
  }
  const s = verified.statement;
  if (card.opened !== true) {
    return { ok: false, status: { kind: 'not-genuine', reason: 'open-refused' } };
  }
  let leaf = s.leaf ?? null;
  if (!leaf || s.state === 'opened') {
    let chain: CoinOnChain | null = null;
    try {
      chain = await deps.coinOnChain(bytes(s.commitment), bytes(s.marker));
    } catch {
      chain = null;
    }
    if (s.state === 'opened' && chain?.spent === true) {
      // Opened before, and its coin already summoned: nothing left to take.
      core.forgetJavaCardRelease();
      return {
        ok: false,
        status: { kind: 'opened', fill: s.fill, cardNumber: s.cardNumber, spent: true },
        reuse: { cardId: bytes(s.cardId), fill: s.fill },
      };
    }
    leaf = leaf ?? chain?.leaf ?? null;
  }
  if (!leaf || !leaf.salt) {
    core.forgetJavaCardRelease();
    return { ok: false, status: { kind: 'not-on-chain', fill: s.fill, amountWei: BigInt(s.amountWei), cardNumber: s.cardNumber } };
  }
  const refusal = core.finishJavaCardOpen({
    cardId: s.cardId,
    fill: s.fill,
    amountWei: s.amountWei,
    commitment: s.commitment,
    marker: s.marker,
    digest: s.digest,
    salt: leaf.salt,
    note: leaf.note,
  });
  if (refusal !== '') {
    return { ok: false, status: { kind: 'not-genuine', reason: refusal } };
  }
  return {
    ok: true,
    amountWei: BigInt(s.amountWei),
    cardId: bytes(s.cardId),
    fill: s.fill,
    cardNumber: s.cardNumber,
    ms: card.ms,
    coin: {
      state: s.state === 'opened' ? 'opened' : 'sealed',
      commitment: bytes(s.commitment),
      marker: bytes(s.marker),
      commitData: s.state === 'sealed' ? card.commitData : null,
    },
  };
}

export type RefillResult = { ok: true; fill: number; ms: number } | { ok: false; status: GhostCardStatus | null };

/** The card a Refill may touch: the opened one whose coin was seen spent. */
export type RefillTarget = { cardId: Uint8Array; fill: number };

/**
 * Refills the next card tapped: the opened card `target`, and no other, goes
 * back to blank, ready for the next Fill. With no code on the card, its id
 * and fill are what keep a Refill off another opened card whose coin is
 * still unspent; the native flow refuses any other card before sending it
 * anything. The screens offer it only once the
 * chain shows the opened coin's marker spent.
 */
export async function refillGhostCard(deps: GhostCardDeps, target: RefillTarget): Promise<RefillResult> {
  const { core, nfc } = deps;
  if (!core || !nfc) {
    return { ok: false, status: { kind: 'retry', message: 'This iPhone cannot read Ghost cards in this build.' } };
  }
  let card: CardTap;
  try {
    card = await tap(() => nfc.javaCardRefill(ALERT.refill, target.cardId, target.fill));
  } catch (error) {
    return { ok: false, status: statusOfTapFailure(error) };
  }
  if (card.kind === 'ntag') {
    return { ok: false, status: { kind: 'carry-to-claim' } };
  }
  const identity = core.javaCardIdentity(buffer(card.identify));
  if (!sameBytes(identity.cardId, target.cardId)) {
    return { ok: false, status: { kind: 'retry', message: 'This is not the card that was checked. Tap the same card again.' } };
  }
  if (identity.state !== 'blank') {
    return { ok: false, status: { kind: 'retry', message: 'The card was not refilled. Tap it again.' } };
  }
  return { ok: true, fill: identity.fill, ms: card.ms };
}
