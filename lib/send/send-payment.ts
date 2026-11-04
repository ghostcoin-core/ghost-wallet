// A plain send through the native core's step sequence (core/src/step_sequence.rs),
// like a Vanish: the intent is saved before anything is signed, the signed
// bytes before they are broadcast, and the chain is read back on every move,
// so a send survives the app being killed and lands exactly once. Its
// identity is the account's nonce: the chain lets one transaction use it.
//
// A send can be saved with the node out of reach, from the nonce Home last
// saw: it is queued, and the first move that reaches the node signs it in the
// native core (ML-DSA-44, account 0 of the saved account; the words never
// leave native code) and sends it. If another payment from this account took
// that nonce in the meantime, the send is conflicted and never goes out.
import {
  sendCore,
  type CoreChainView,
  type CorePaymentIntent,
  type CorePaymentRecord,
  type CorePaymentSequence,
  type SendBindings,
  type VanishBindings,
} from '../../modules/ghost-core';
import { bytesToHex } from '../../modules/ghost-core/account-lookup';
import { buildNetwork } from '../network/build-network';
import { checkedChainId } from '../vanish/actions';
import { readAccountTx, vanishNode } from '../vanish/node';
import { documentPaymentFiles, paymentStore } from '../vanish/payment-store';
import {
  PAYMENT_KIND,
  buffer,
  chainSnapshot,
  coreReceipt,
  decodeDetails,
  encodeDetails,
  newPaymentId,
  noteMove,
  onOtherChain,
  recoveryTag,
  resendNewest,
  savedChainId,
  sendAttempt,
  type SendDetails,
} from '../vanish/payments';
import { isStuck, markCancel, openShared, paymentsChanged, shared, unmarkCancel } from '../vanish/pending';
import { stepName } from '../vanish/status-mapping';
import type { PaymentKit } from '../vanish/use-payment';
import { nonceUsedBy } from './node';
import { sendStatusOf, type SendStatus } from './payment-status';
import { hasReached, markReached } from './reached';

export type SendKit = Omit<PaymentKit, 'core'> & { core: VanishBindings & SendBindings };

/** The core, the store and the node; null in a build without the native send. */
export function sendKit(nodeUrl: string): SendKit | null {
  try {
    const core = sendCore();
    const files = documentPaymentFiles();
    if (!files) {
      return null;
    }
    return { core, store: paymentStore(core, files), node: vanishNode(nodeUrl), nodeUrl };
  } catch {
    return null;
  }
}

/** The same kit, if its core can sign sends. */
export function asSendKit(kit: PaymentKit): SendKit | null {
  return typeof (kit.core as unknown as Partial<SendBindings>).signSend === 'function' ? (kit as SendKit) : null;
}

export function sendIntent(account: string, nonce: bigint, details: SendDetails): CorePaymentIntent {
  return {
    kind: PAYMENT_KIND.send,
    identity: { tag: 'AccountNonce', inner: { account: buffer(account), nonce } },
    details: encodeDetails(details),
  };
}

/** What the saved send pays, or null when its details do not read as a send. */
export function sendDetailsOf(record: CorePaymentRecord): SendDetails | null {
  const details = decodeDetails(record.intent.details);
  return details && details.kind === 'send' ? details : null;
}

export type FeeQuote = {
  /** The most each unit of gas may cost: twice the tip block's base fee and the priority fee. */
  maxFeePerGas: bigint;
  /** The most the send can pay in fee. */
  feeWei: bigint;
};

/** The most a send pays in fee now. */
export async function quoteFee(kit: SendKit): Promise<FeeQuote> {
  const tip = await kit.node.tipHeight();
  const [block, priority] = await Promise.all([kit.node.block(tip), kit.node.maxPriorityFeePerGas()]);
  const maxFeePerGas = 2n * block.baseFeePerGas + priority;
  return { maxFeePerGas, feeWei: maxFeePerGas * kit.core.testSendGasLimit() };
}

/**
 * One past the highest nonce of `account` this phone's saved sends and
 * Vanishes hold. A payment still waiting to be signed holds its nonce, so a
 * new send never takes it. A Vanish whose new key is not written down yet
 * holds none: it may still be dropped.
 */
export function reservedNonce(kit: Pick<PaymentKit, 'core' | 'store'>, account: string): bigint {
  let next = 0n;
  let ids: string[];
  try {
    ids = kit.store.list();
  } catch {
    return next;
  }
  const own = account.toLowerCase();
  for (const id of ids) {
    if (!id.startsWith('send-') && !id.startsWith('vanish-')) {
      continue;
    }
    const sequence = openShared(kit, id);
    if (!sequence) {
      continue;
    }
    const record = sequence.record();
    if (onOtherChain(record)) {
      // Its nonce is another chain's.
      continue;
    }
    const { identity } = record.intent;
    if (
      identity.tag === 'AccountNonce' &&
      bytesToHex(identity.inner.account) === own &&
      stepName(sequence.step()) !== 'Prepared' &&
      identity.inner.nonce + 1n > next
    ) {
      next = identity.inner.nonce + 1n;
    }
  }
  return next;
}

export const NOTHING_KNOWN =
  'This phone has not seen the account on the test node yet, so the send cannot be queued. Try again once the node can be reached';

/**
 * The nonce of the next send: the node's count of the account's transactions
 * (pending ones too), or with the node out of reach the count Home last saw,
 * and never one a saved payment holds.
 */
export async function nextNonce(kit: SendKit, account: string, cachedNonce: number | null): Promise<bigint> {
  let known: bigint | null = null;
  try {
    known = await kit.node.nonce(account);
  } catch {
    known = cachedNonce === null ? null : BigInt(cachedNonce);
  }
  if (known === null) {
    throw new Error(NOTHING_KNOWN);
  }
  const reserved = reservedNonce(kit, account);
  return known > reserved ? known : reserved;
}

export type NewSend = {
  /** This phone's account 0. */
  account: string;
  /** `0x` and 40 lowercase hex digits. */
  to: string;
  amountWei: bigint;
  /** The fee rate the person reviewed; null when the node was out of reach. */
  maxFeePerGas: bigint | null;
  /** What Home last saw: the account's nonce and the tip, or null. */
  cached: { nonce: number; tipHeight: number } | null;
};

/**
 * Saves a new send, ready to be signed: after this it is the step sequence's
 * to finish, from the payment screen or from Home. Nothing is signed or sent
 * here, so this works with the node out of reach.
 */
export async function startSend(kit: SendKit, send: NewSend, now: number = Date.now()): Promise<CorePaymentSequence> {
  const nonce = await nextNonce(kit, send.account, send.cached?.nonce ?? null);
  let fromHeight = send.cached?.tipHeight ?? 0;
  try {
    fromHeight = await kit.node.tipHeight();
  } catch {
    // Out of reach: the cached tip will do as where to look from.
  }
  const details: SendDetails = {
    kind: 'send',
    to: send.to,
    amountWei: send.amountWei.toString(),
    nonce: nonce.toString(),
    maxFeePerGas: send.maxFeePerGas === null ? null : send.maxFeePerGas.toString(),
    fromHeight,
    at: now,
    // Saved with the node out of reach too: it is signed only once a node of this chain is reached.
    chainId: buildNetwork.chainId.toString(),
  };
  const sequence = shared(
    kit.core.PaymentSequence.start(kit.store, newPaymentId('send', now), sendIntent(send.account, nonce, details)),
  );
  // The account's words are its backup: nothing more to save before signing.
  sequence.markBackedUp();
  paymentsChanged();
  return sequence;
}

/**
 * Signs the send in the native core with the fees of the tip, never above the
 * fee rate the person reviewed.
 */
export async function signSend(kit: SendKit, details: SendDetails): Promise<ArrayBuffer> {
  if (savedChainId(details) !== buildNetwork.chainId) {
    throw new Error('this send was saved on another network');
  }
  const chainId = await checkedChainId(kit);
  const tip = await kit.node.tipHeight();
  const [genesis, block, priority] = await Promise.all([
    kit.node.block(0),
    kit.node.block(tip),
    kit.node.maxPriorityFeePerGas(),
  ]);
  let maxFeePerGas = 2n * block.baseFeePerGas + priority;
  if (details.maxFeePerGas !== null && maxFeePerGas > BigInt(details.maxFeePerGas)) {
    maxFeePerGas = BigInt(details.maxFeePerGas);
  }
  const signed = kit.core.signSend({
    chainId,
    genesisHash: buffer(genesis.hash),
    nonce: BigInt(details.nonce),
    recipient: buffer(details.to),
    amountWei: details.amountWei,
    maxPriorityFeePerGas: priority > maxFeePerGas ? maxFeePerGas : priority,
    maxFeePerGas,
    gasLimit: kit.core.testSendGasLimit(),
  });
  return signed.envelope;
}

/**
 * What the chain says about a send: the attempts' receipts as for any
 * payment, and, while none of them landed, the transaction that took the
 * send's nonce if one did.
 */
export async function sendChainView(kit: SendKit, record: CorePaymentRecord): Promise<CoreChainView> {
  const base = await chainSnapshot(kit.node, record, null);
  const { identity } = record.intent;
  const step = stepName(record.step);
  if (identity.tag !== 'AccountNonce' || (step !== 'Signed' && step !== 'Sent')) {
    return base;
  }
  if (record.attempts.some((attempt) => base.receipt(attempt.transactionHash) !== undefined)) {
    return base;
  }
  const usedBy = await nonceUsedBy(
    kit.nodeUrl,
    bytesToHex(identity.inner.account),
    identity.inner.nonce,
    sendDetailsOf(record)?.fromHeight ?? 0,
    Number(base.tipHeight()),
  );
  if (!usedBy || record.attempts.some((attempt) => bytesToHex(attempt.transactionHash) === usedBy)) {
    return base;
  }
  const [receipt] = await kit.node.receipts([usedBy]);
  return {
    ...base,
    receipt(transactionHash) {
      if (bytesToHex(transactionHash) === usedBy) {
        return receipt ? coreReceipt(receipt) : undefined;
      }
      return base.receipt(transactionHash);
    },
    identityUsedBy() {
      return buffer(usedBy);
    },
  };
}

export type SendAdvance = {
  status: SendStatus;
  step: number | string;
  /** The node took it, and `STUCK_BLOCKS` blocks on it is in none: it can be cancelled. */
  cancellable?: boolean;
};

/**
 * Broadcasts the send's newest saved attempt, checked by the node first; the
 * node took it.
 */
async function broadcast(kit: SendKit, sequence: CorePaymentSequence) {
  await resendNewest(kit.node, sequence);
  markReached(sequence.record().id);
}

/**
 * One move of the send: read the chain, let the core save what it says, then
 * do what it asks (sign, send, or wait). Throws when the node is out of reach;
 * the send stays saved where it was, and the next move tries again.
 */
export async function advanceSend(kit: SendKit, sequence: CorePaymentSequence): Promise<SendAdvance> {
  const record = sequence.record();
  if (onOtherChain(record)) {
    // Saved for another chain: kept, never signed or sent from here.
    const step = sequence.step();
    return { step, status: sendStatusOf(step, hasReached(record.id)) };
  }
  const view = await sendChainView(kit, record);
  const tag = recoveryTag(sequence.recover(view).tag);
  switch (tag) {
    case 'BackUp':
    case 'Sign':
    case 'Rebuild': {
      if (tag === 'BackUp') {
        sequence.markBackedUp();
      }
      const details = sendDetailsOf(record);
      if (!details) {
        throw new Error('the saved send cannot be read');
      }
      // Checked by the node before it is saved: a refusal stays queued, never sent.
      await sendAttempt(kit.node, sequence, await signSend(kit, details));
      markReached(record.id);
      break;
    }
    case 'Send':
      await broadcast(kit, sequence);
      break;
    case 'Wait':
      // The node lists it, or it is in a block not deep enough yet.
      markReached(record.id);
      break;
    case 'Done':
      break;
  }
  const step = sequence.step();
  const reached = hasReached(record.id);
  // Only a send the node took counts its blocks: a queued one is not late.
  const { stuck, cancellable } = reached ? noteMove(sequence, Number(view.tipHeight())) : { stuck: false, cancellable: false };
  return { step, status: sendStatusOf(step, reached, stuck), cancellable };
}

/** Whole wei a cancel sends to the account itself: the core signs no send of nothing. */
export const CANCEL_WEI = 1n;

/** How much more a cancel pays than the attempt it replaces, in percent, at the least. */
export const CANCEL_FEE_BUMP_PERCENT = 15n;

function bumped(fee: bigint): bigint {
  // Rounded up, so it is never less than the bump.
  return (fee * (100n + CANCEL_FEE_BUMP_PERCENT) + 99n) / 100n;
}

/**
 * Cancels a payment the node took and has not mined in `STUCK_BLOCKS` blocks
 * (a send or a Vanish): signs a send of `CANCEL_WEI` from its account to the
 * same account with the same nonce, at a fee at least 15% above the stuck
 * attempt's (both the fee cap and the priority fee), and sends it the way
 * every attempt goes: checked by the node first. Only when the person taps
 * Cancel. Whichever of the two is mined first counts; a cancel that lands
 * shows the payment as not done.
 */
export async function cancelStuck(kit: SendKit, sequence: CorePaymentSequence): Promise<void> {
  const record = sequence.record();
  if (onOtherChain(record)) {
    throw new Error('this payment was saved on another network');
  }
  const { identity } = record.intent;
  if (identity.tag !== 'AccountNonce') {
    throw new Error('a Summon or Claim has no place in an account to cancel');
  }
  if (stepName(record.step) !== 'Sent' || !isStuck(record.id)) {
    throw new Error('only a payment the node has not mined yet can be cancelled');
  }
  const newest = record.attempts[record.attempts.length - 1];
  const stuckBytes = newest ? kit.store.loadPayload(record.id, newest.transactionHash) : undefined;
  if (!stuckBytes) {
    throw new Error('the payment to cancel is not saved on this phone');
  }
  const account = bytesToHex(identity.inner.account);
  const stuck = readAccountTx(bytesToHex(stuckBytes));
  const chainId = await checkedChainId(kit);
  if (stuck.chainId !== chainId || stuck.nonce !== identity.inner.nonce) {
    throw new Error('the payment to cancel does not read as this payment');
  }
  const tip = await kit.node.tipHeight();
  const [genesis, block, priority] = await Promise.all([
    kit.node.block(0),
    kit.node.block(tip),
    kit.node.maxPriorityFeePerGas(),
  ]);
  const maxPriorityFeePerGas = priority > bumped(stuck.maxPriorityFeePerGas) ? priority : bumped(stuck.maxPriorityFeePerGas);
  const now = 2n * block.baseFeePerGas + maxPriorityFeePerGas;
  const maxFeePerGas = now > bumped(stuck.maxFeePerGas) ? now : bumped(stuck.maxFeePerGas);
  const signed = kit.core.signSend({
    chainId,
    genesisHash: buffer(genesis.hash),
    nonce: identity.inner.nonce,
    recipient: buffer(account),
    amountWei: CANCEL_WEI.toString(),
    maxPriorityFeePerGas,
    maxFeePerGas,
    gasLimit: kit.core.testSendGasLimit(),
  });
  if (bytesToHex(signed.sender) !== account) {
    throw new Error("this phone's account is not the one that made this payment");
  }
  // Marked before it is saved, so a cancel that lands is never read as the payment.
  const hash = bytesToHex(signed.transactionHash);
  markCancel(hash);
  try {
    await sendAttempt(kit.node, sequence, signed.envelope);
  } catch (error) {
    if (!sequence.record().attempts.some((attempt) => bytesToHex(attempt.transactionHash) === hash)) {
      // Refused by the check, or not signed into the payment: no such attempt.
      unmarkCancel(hash);
    }
    throw error;
  }
  paymentsChanged();
}

export type RecentRecipient = { address: string; amountWei: string; at: number };

/** The addresses this phone sent to last, newest first, each once. */
export function recentRecipients(kit: Pick<PaymentKit, 'core' | 'store'>, limit = 3): RecentRecipient[] {
  let ids: string[];
  try {
    ids = kit.store.list().filter((id) => id.startsWith('send-'));
  } catch {
    return [];
  }
  const sends: RecentRecipient[] = [];
  for (const id of ids) {
    const sequence = openShared(kit, id);
    const details = sequence ? sendDetailsOf(sequence.record()) : null;
    if (details) {
      sends.push({ address: details.to, amountWei: details.amountWei, at: details.at });
    }
  }
  const recent: RecentRecipient[] = [];
  for (const send of sends.sort((a, b) => b.at - a.at)) {
    if (recent.length < limit && !recent.some((known) => known.address === send.address)) {
      recent.push(send);
    }
  }
  return recent;
}

/** The status of a saved send as it stands, without asking the node. */
export function savedSendStatus(sequence: CorePaymentSequence): SendStatus {
  const { id } = sequence.record();
  return sendStatusOf(sequence.step(), hasReached(id), isStuck(id));
}
