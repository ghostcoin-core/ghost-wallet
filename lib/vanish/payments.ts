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
import type { CoinTree } from './coin-tree';
import type { NodeReceipt, VanishNode } from './node';
import { statusOfRecovery, statusOfStep, type PaymentStatus, type RecoveryTag, type RevealKind } from './status-mapping';

/** `PaymentKind` and `ReceiptStatus` as the generated bindings number them. */
export const PAYMENT_KIND = { send: 0, vanish: 1, summon: 2, claim: 3 } as const;
const RECEIPT_SUCCESS = 0;
const RECEIPT_FAILED = 1;

export function buffer(hex: string): ArrayBuffer {
  const bytes = hexToBytes(hex);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/** What a payment needs to be rebuilt, saved in its intent. Public data only. */
export type PaymentDetails =
  | { kind: 'vanish'; commitData: string; amountWei: string; nonce: string; at: number }
  | { kind: 'summon' | 'claim'; amountWei: string; feeWei: string; marker: string; at: number };

export function encodeDetails(details: PaymentDetails): ArrayBuffer {
  const bytes = new TextEncoder().encode(JSON.stringify(details));
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export function decodeDetails(bytes: ArrayBuffer): PaymentDetails | null {
  try {
    const raw = JSON.parse(new TextDecoder().decode(new Uint8Array(bytes))) as PaymentDetails;
    return raw && (raw.kind === 'vanish' || raw.kind === 'summon' || raw.kind === 'claim') ? raw : null;
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

function coreReceipt(receipt: NodeReceipt): CoreReceipt {
  return {
    status: receipt.success ? RECEIPT_SUCCESS : RECEIPT_FAILED,
    blockHash: buffer(receipt.blockHash),
    blockHeight: BigInt(receipt.blockHeight),
  };
}

/**
 * What the chain says about `record` now, as the core's `ChainView`. A
 * reveal's marker is looked up in the coin tree this phone rebuilt: the
 * transaction that spent it, and whether it is spent at all.
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
    effectApplied(intent) {
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

export type Advance = {
  status: PaymentStatus;
  step: number | string;
  /** The payment needs a new attempt, and only the key (typed again) can make it. */
  needsKey: boolean;
  /** `recover` asked for a backup this screen can no longer give. */
  needsBackup: boolean;
};

function recoveryTag(tag: string): RecoveryTag {
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
  const view = await chainSnapshot(node, sequence.record(), tree);
  const recovery = sequence.recover(view);
  const tag = recoveryTag(recovery.tag);
  const result = (needsKey = false, needsBackup = false): Advance => {
    const step = sequence.step();
    return { status: needsKey || needsBackup ? statusOfRecovery(tag, step) : statusOfStep(step), step, needsKey, needsBackup };
  };
  switch (tag) {
    case 'BackUp':
      return result(false, true);
    case 'Sign':
    case 'Rebuild': {
      if (!rebuild) {
        return result(true);
      }
      const { signed, validUntil } = await rebuild(Number(view.tipHeight()));
      sequence.addAttempt(signed, validUntil);
      await node.sendRaw(bytesToHex(sequence.markSent()));
      return result();
    }
    case 'Send':
      await node.sendRaw(bytesToHex(sequence.markSent()));
      return result();
    case 'Wait':
    case 'Done':
      return result();
  }
}

/** Payment ids are the kind and the time: letters, digits and hyphens. */
export function newPaymentId(kind: RevealKind, now: number = Date.now()): string {
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
