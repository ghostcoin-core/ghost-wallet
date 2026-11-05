// Moves a Vanish, Summon or Claim through the native core's step sequence
// (core/src/step_sequence.rs): every step is saved before its effect, so a
// payment survives the app being killed, lands at most once (its identity is
// the account nonce of a Vanish or the coin marker of a reveal) and, when its
// fee window passes, is proved or signed again rather than resent.
//
// The core asks the chain through synchronous callbacks, so the node is asked
// first and the callbacks answer from that snapshot.
import type {
  CoreChainView,
  CoreIdentity,
  CorePaymentIntent,
  CorePaymentRecord,
  CorePaymentSequence,
  CorePaymentStore,
  CoreReceipt,
  VanishBindings,
} from '../../modules/ghost-core';
import { bytesToHex, hexToBytes } from '../../modules/ghost-core/account-lookup';
import { GHOST_DEV_CHAIN_ID, buildNetwork } from '../network/build-network';
import type { CoinTree } from './coin-tree';
import type { NodeReceipt, VanishNode } from './node';
import { isCancel, noteNotUnmined, noteUnmined } from './pending';
import {
  refusedByCheck,
  statusOfRecovery,
  statusOfStep,
  stepName,
  type PaymentStatus,
  type RecoveryTag,
  type RevealKind,
  type SavedKind,
} from './status-mapping';

/** `PaymentKind` and `ReceiptStatus` as the generated bindings number them. */
export const PAYMENT_KIND = { send: 0, vanish: 1, summon: 2, claim: 3 } as const;
const RECEIPT_SUCCESS = 0;
const RECEIPT_FAILED = 1;

export function buffer(hex: string): ArrayBuffer {
  const bytes = hexToBytes(hex);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/**
 * What a payment needs to be rebuilt, saved in its intent. Public data only.
 * `chainId` is the chain it was made for, in decimal; one saved before it
 * was written down is a dev-chain payment.
 */
export type PaymentDetails =
  | { kind: 'vanish'; commitData: string; amountWei: string; nonce: string; at: number; chainId?: string }
  | { kind: 'summon' | 'claim'; amountWei: string; feeWei: string; marker: string; at: number; chainId?: string }
  | SendDetails;

/**
 * A plain send. `maxFeePerGas` is the fee rate the person reviewed, never
 * exceeded when it is signed; null when it was saved with the node out of
 * reach. `fromHeight` is the tip known when it was saved.
 */
export type SendDetails = {
  kind: 'send';
  to: string;
  amountWei: string;
  nonce: string;
  maxFeePerGas: string | null;
  fromHeight: number;
  at: number;
  chainId?: string;
};

/**
 * The chain a payment was saved for: the dev chain when its details do not
 * say, null when they say something that is not a chain id.
 */
export function savedChainId(details: Pick<PaymentDetails, 'chainId'>): bigint | null {
  const saved = details.chainId;
  if (saved === undefined) {
    return GHOST_DEV_CHAIN_ID;
  }
  return typeof saved === 'string' && /^[0-9]{1,20}$/.test(saved) ? BigInt(saved) : null;
}

/**
 * Whether `record` was saved for another chain than this build's: such a
 * payment is kept, but never signed or sent from here. A record whose
 * details do not read is left to the core, as before.
 */
export function onOtherChain(record: Pick<CorePaymentRecord, 'intent'>, chainId: bigint = buildNetwork.chainId): boolean {
  const details = decodeDetails(record.intent.details);
  return details !== null && savedChainId(details) !== chainId;
}

/** How Home lists a payment saved for another chain. */
export const OTHER_NETWORK_TEXT = 'Saved on another network. Not sent.';

export function encodeDetails(details: PaymentDetails): ArrayBuffer {
  const bytes = new TextEncoder().encode(JSON.stringify(details));
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export function decodeDetails(bytes: ArrayBuffer): PaymentDetails | null {
  try {
    const raw = JSON.parse(new TextDecoder().decode(new Uint8Array(bytes))) as PaymentDetails;
    return raw && (raw.kind === 'vanish' || raw.kind === 'summon' || raw.kind === 'claim' || raw.kind === 'send')
      ? raw
      : null;
  } catch {
    return null;
  }
}

export function vanishIntent(account: string, nonce: bigint, details: PaymentDetails): CorePaymentIntent {
  return {
    kind: PAYMENT_KIND.vanish,
    identity: { tag: 'AccountNonce', inner: { account: buffer(account), nonce } },
    details: encodeDetails(details),
  };
}

export function revealIntent(kind: 'summon' | 'claim', marker: string, details: PaymentDetails): CorePaymentIntent {
  return {
    kind: PAYMENT_KIND[kind],
    identity: { tag: 'RevealMarker', inner: { marker: buffer(marker) } },
    details: encodeDetails(details),
  };
}

export function coreReceipt(receipt: NodeReceipt): CoreReceipt {
  return {
    status: receipt.success ? RECEIPT_SUCCESS : RECEIPT_FAILED,
    blockHash: buffer(receipt.blockHash),
    blockHeight: BigInt(receipt.blockHeight),
  };
}

/**
 * What the chain says about `record` now, as the core's `ChainView`. With a
 * coin tree that knows its spent markers, a reveal's marker is looked up in
 * it; the app moves payments with none (`tree` null), and the receipts of the
 * saved attempts decide.
 */
export async function chainSnapshot(node: VanishNode, record: CorePaymentRecord, tree: CoinTree | null): Promise<CoreChainView> {
  const marker =
    record.intent.identity.tag === 'RevealMarker' ? bytesToHex(record.intent.identity.inner.marker) : null;
  const usedBy = marker && tree ? (tree.spentBy[marker] ?? null) : null;
  const hashes = [
    ...new Set(
      [
        ...record.attempts.map((attempt) => bytesToHex(attempt.transactionHash)),
        record.inclusion ? bytesToHex(record.inclusion.transactionHash) : null,
        usedBy,
      ].filter((hash): hash is string => hash !== null),
    ),
  ];
  const [tip, receipts] = await Promise.all([node.tipHeight(), node.receipts(hashes)]);
  const byHash = new Map<string, NodeReceipt>();
  hashes.forEach((hash, index) => {
    const receipt = receipts[index];
    if (receipt) {
      byHash.set(hash, receipt);
    }
  });
  const newest = record.attempts.length > 0 ? bytesToHex(record.attempts[record.attempts.length - 1].transactionHash) : null;
  const [newestKnown] = newest && !byHash.has(newest) ? await node.known([newest]) : [false];

  return {
    receipt(transactionHash) {
      const receipt = byHash.get(bytesToHex(transactionHash));
      return receipt ? coreReceipt(receipt) : undefined;
    },
    pending(transactionHash) {
      return bytesToHex(transactionHash) === newest && newestKnown;
    },
    identityUsedBy(identity: CoreIdentity) {
      // A Vanish's nonce taken by another transaction shows as a refused send.
      return identity.tag === 'RevealMarker' && usedBy ? buffer(usedBy) : undefined;
    },
    effectApplied(intent, transactionHash) {
      if (isCancel(bytesToHex(transactionHash))) {
        // A cancel in a block is the payment not done: the amount did not move.
        return false;
      }
      if (intent.identity.tag === 'RevealMarker' && tree && marker) {
        // The marker is spent in the tree as of a block at or after the receipt.
        return tree.spent.includes(marker) || tree.height < tip;
      }
      return true;
    },
    tipHeight() {
      return BigInt(tip);
    },
  };
}

/** Makes a new attempt: a Vanish signed again, or a reveal proved again. */
export type Rebuild = (tip: number) => Promise<{ signed: ArrayBuffer; validUntil?: bigint }>;

/** The account that signs `record`'s transactions; null for a Summon or Claim, which have none. */
export function senderOf(record: Pick<CorePaymentRecord, 'intent'>): string | null {
  const { identity } = record.intent;
  return identity.tag === 'AccountNonce' ? bytesToHex(identity.inner.account) : null;
}

/**
 * Sends a new attempt: the node checks the signed bytes first
 * (`VanishNode.checkSend`), and only once it would take them are they saved
 * as an attempt, marked sent and broadcast. A refusal leaves the payment as
 * it was, never marked sent.
 */
export async function sendAttempt(
  node: VanishNode,
  sequence: CorePaymentSequence,
  signed: ArrayBuffer,
  validUntil?: bigint,
): Promise<void> {
  await node.checkSend(bytesToHex(signed), senderOf(sequence.record()));
  sequence.addAttempt(signed, validUntil);
  await node.sendRaw(bytesToHex(sequence.markSent()));
}

/**
 * Sends the newest saved attempt again, checked by the node first. It was
 * checked before it was saved; a payment saved signed but not sent (the app
 * was closed in between) is marked sent here, as the bytes are only read so.
 */
export async function resendNewest(node: VanishNode, sequence: CorePaymentSequence): Promise<void> {
  const bytes = bytesToHex(sequence.markSent());
  await node.checkSend(bytes, senderOf(sequence.record()));
  await node.sendRaw(bytes);
}

/**
 * Runs `send`; when the node's check refuses it, marks the error `neverSent`
 * if no attempt saved before (`attempts`, by hash) reached the node: `recover`
 * asked for a send, so none is in a block, and the node holds none of them.
 * A node that cannot be asked leaves it unmarked.
 */
async function noteRefusal(node: VanishNode, attempts: readonly string[], send: () => Promise<void>): Promise<void> {
  try {
    await send();
  } catch (error) {
    if (refusedByCheck(error)) {
      Object.assign(error as Error, { neverSent: await noneHeld(node, attempts) });
    }
    throw error;
  }
}

async function noneHeld(node: VanishNode, attempts: readonly string[]): Promise<boolean> {
  if (attempts.length === 0) {
    return true;
  }
  try {
    const held = await node.known([...attempts]);
    return held.length === attempts.length && held.every((known) => known === false);
  } catch {
    return false;
  }
}

export type Advance = {
  status: PaymentStatus;
  step: number | string;
  /** The payment needs a new attempt, and only the key (typed again) can make it. */
  needsKey: boolean;
  /** `recover` asked for a backup this screen can no longer give. */
  needsBackup: boolean;
  /** Saved for another chain than this build's: nothing was asked, signed or sent. */
  otherNetwork?: boolean;
  /** Sent, and in no block `STUCK_BLOCKS` blocks on (status `stuck`). */
  stuck?: boolean;
  /** Stuck, with an account nonce a cancel can take: the screen offers Cancel. */
  cancellable?: boolean;
};

/**
 * After a move of `sequence`: whether it is sent and still in no block, noted
 * at tip `tip`. Only a payment the node took (sent, with no receipt) counts.
 */
export function noteMove(sequence: CorePaymentSequence, tip: number): { stuck: boolean; cancellable: boolean } {
  const record = sequence.record();
  if (stepName(record.step) !== 'Sent') {
    noteNotUnmined(record.id);
    return { stuck: false, cancellable: false };
  }
  const nonce = record.intent.identity.tag === 'AccountNonce';
  const stuck = noteUnmined(record.id, record.attempts.length, tip, nonce);
  return { stuck, cancellable: stuck && nonce };
}

export function recoveryTag(tag: string): RecoveryTag {
  const known: RecoveryTag[] = ['BackUp', 'Sign', 'Send', 'Rebuild', 'Wait', 'Done'];
  const found = known.find((name) => name.toLowerCase() === tag.replace(/[\s_-]/g, '').toLowerCase());
  if (!found) {
    throw new Error('the core asked for a step this app does not know');
  }
  return found;
}

/**
 * One move of the payment: read the chain, let the core save what it says,
 * then do what it asks (sign or prove, send, or wait).
 */
export async function advance(
  node: VanishNode,
  sequence: CorePaymentSequence,
  rebuild: Rebuild | null,
  tree: CoinTree | null,
): Promise<Advance> {
  const record = sequence.record();
  if (onOtherChain(record)) {
    const step = sequence.step();
    return { status: statusOfStep(step), step, needsKey: false, needsBackup: false, otherNetwork: true };
  }
  const view = await chainSnapshot(node, record, tree);
  const recovery = sequence.recover(view);
  const tag = recoveryTag(recovery.tag);
  const tip = Number(view.tipHeight());
  const result = (needsKey = false, needsBackup = false): Advance => {
    const step = sequence.step();
    if (needsKey || needsBackup) {
      return { status: statusOfRecovery(tag, step), step, needsKey, needsBackup };
    }
    const { stuck, cancellable } = noteMove(sequence, tip);
    return { status: stuck ? 'stuck' : statusOfStep(step), step, needsKey, needsBackup, stuck, cancellable };
  };
  const before = record.attempts.map((attempt) => bytesToHex(attempt.transactionHash));
  switch (tag) {
    case 'BackUp':
      return result(false, true);
    case 'Sign':
    case 'Rebuild': {
      if (!rebuild) {
        return result(true);
      }
      const { signed, validUntil } = await rebuild(tip);
      // Checked by the node before it is saved: a refusal is never marked sent.
      await noteRefusal(node, before, () => sendAttempt(node, sequence, signed, validUntil));
      return result();
    }
    case 'Send':
      await noteRefusal(node, before, () => resendNewest(node, sequence));
      return result();
    case 'Wait':
    case 'Done':
      return result();
  }
}

/** Payment ids are the kind and the time: letters, digits and hyphens. */
export function newPaymentId(kind: SavedKind, now: number = Date.now()): string {
  return `${kind}-${now.toString(36)}`;
}

/** The newest payment of these kinds this phone saved, if any. */
export function newestPayment(
  core: Pick<VanishBindings, 'PaymentSequence'>,
  store: CorePaymentStore,
  kinds: readonly RevealKind[],
): CorePaymentSequence | null {
  const ids = store
    .list()
    .filter((id) => kinds.some((kind) => id.startsWith(`${kind}-`)))
    .sort((a, b) => parseInt(b.split('-')[1], 36) - parseInt(a.split('-')[1], 36));
  for (const id of ids) {
    try {
      return core.PaymentSequence.open(store, id);
    } catch {
      // A record that fails its checks is left for the core to report; the
      // screen starts no payment on top of it.
      return null;
    }
  }
  return null;
}
