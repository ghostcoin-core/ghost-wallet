// The steps of a Vanish and of a Summon or Claim that talk to both the native
// core and the node: preparing a Vanish, signing it (again), finding a key's
// coins and proving a reveal (again, when its fee window passed).
import type { CorePaymentSequence } from '../../modules/ghost-core';
import { bytesToHex } from '../../modules/ghost-core/account-lookup';
import { spentBuffers, type CoinTree } from './coin-tree';
import { buffer, decodeDetails, newPaymentId, revealIntent, vanishIntent, type PaymentDetails, type Rebuild } from './payments';
import type { PaymentKit } from './use-payment';
import { treeAtTip } from './use-payment';

/** The node must be the test chain the core signs and proves for. */
export async function checkedChainId(kit: PaymentKit): Promise<bigint> {
  const chainId = await kit.node.chainId();
  if (chainId !== kit.core.testChainId()) {
    throw new Error('the node is not the Ghost test network');
  }
  return chainId;
}

/** The smallest Vanish at the node's tip: four Summon fees. */
export async function minimumVanish(kit: PaymentKit): Promise<bigint> {
  const tip = await kit.node.tipHeight();
  const window = kit.core.feeWindow(BigInt(tip));
  const reference = await kit.node.block(Number(window.referenceHeight));
  return BigInt(kit.core.minVanishWei(reference.baseFeePerGas.toString()));
}

/**
 * Makes a fresh Phantom Key in the core and saves the Vanish as prepared,
 * with the account nonce as its identity. Nothing is signed until the key is
 * written down and checked.
 */
export async function startVanish(
  kit: PaymentKit,
  account: string,
  amountWei: bigint,
): Promise<{ sequence: CorePaymentSequence; words: string[] }> {
  const chainId = await checkedChainId(kit);
  const nonce = await kit.node.nonce(account);
  const commit = kit.core.prepareVanish(chainId, amountWei.toString());
  const details: PaymentDetails = {
    kind: 'vanish',
    commitData: bytesToHex(commit.commitData),
    amountWei: commit.amountWei,
    nonce: nonce.toString(),
    at: Date.now(),
  };
  try {
    const sequence = kit.core.PaymentSequence.start(kit.store, newPaymentId('vanish'), vanishIntent(account, nonce, details));
    return { sequence, words: kit.core.takePhantomKeyWords() };
  } catch (error) {
    kit.core.forgetPhantomKey();
    throw error;
  }
}

/** Signs the Vanish of `sequence` (again) with the fees of the tip. Needs no key. */
export function signVanishAgain(kit: PaymentKit, sequence: CorePaymentSequence): Rebuild {
  return async (tip) => {
    const details = decodeDetails(sequence.record().intent.details);
    if (!details || details.kind !== 'vanish') {
      throw new Error('the saved Vanish cannot be read');
    }
    const [chainId, genesis, block, priority] = await Promise.all([
      checkedChainId(kit),
      kit.node.block(0),
      kit.node.block(tip),
      kit.node.maxPriorityFeePerGas(),
    ]);
    const signed = kit.core.signVanish({
      chainId,
      genesisHash: buffer(genesis.hash),
      nonce: BigInt(details.nonce),
      commitData: buffer(details.commitData),
      amountWei: details.amountWei,
      maxPriorityFeePerGas: priority,
      maxFeePerGas: 2n * block.baseFeePerGas + priority,
      gasLimit: kit.core.vanishGasLimit(),
    });
    return { signed: signed.envelope };
  };
}

export type KeyLookup = {
  status: string;
  amountWei: string;
  feeWei: string;
  tree: CoinTree;
  tip: number;
};

/** The key a tapped card handed to the native core; JavaScript never holds it. */
export const CARD_KEY = { card: true } as const;

/** The key of a Summon or Claim: the typed text, or the card key the core holds. */
export type KeySource = string | typeof CARD_KEY;

/** Looks the key up in the coin tree at the tip, with the fee a reveal pays now. */
export async function lookUpKey(kit: PaymentKit, key: KeySource): Promise<KeyLookup> {
  const chainId = await checkedChainId(kit);
  const { tree, tip } = await treeAtTip(kit);
  const coins =
    typeof key === 'string'
      ? kit.core.findKeyCoins(key, chainId, tree.leaves, spentBuffers(tree))
      : kit.core.findCardKeyCoins(chainId, tree.leaves, spentBuffers(tree));
  const window = kit.core.feeWindow(BigInt(tip));
  const reference = await kit.node.block(Number(window.referenceHeight));
  return { ...coins, feeWei: kit.core.revealFeeWei(reference.baseFeePerGas.toString()), tree, tip };
}

/**
 * Proves a reveal of the key's coin to `account` for the fee window of the
 * tip: the whole coin (Summon, `outWei` null) or part of it (Claim).
 */
export async function proveReveal(
  kit: PaymentKit,
  key: KeySource,
  account: string,
  outWei: bigint | null,
): Promise<{ envelope: ArrayBuffer; validUntil: bigint; marker: string; feeWei: string; outWei: string }> {
  const chainId = await checkedChainId(kit);
  const { tree, tip } = await treeAtTip(kit);
  const window = kit.core.feeWindow(BigInt(tip));
  const [genesis, reference] = await Promise.all([kit.node.block(0), kit.node.block(Number(window.referenceHeight))]);
  const request = {
    chainId,
    genesisHash: buffer(genesis.hash),
    recipient: buffer(account),
    baseFeeRefWei: reference.baseFeePerGas.toString(),
    outWei: outWei === null ? undefined : outWei.toString(),
  };
  const proved =
    typeof key === 'string'
      ? kit.core.proveKeyReveal(key, request, tree.leaves, spentBuffers(tree))
      : kit.core.proveCardKeyReveal(request, tree.leaves, spentBuffers(tree));
  return {
    envelope: proved.envelope,
    validUntil: window.validUntil,
    marker: bytesToHex(proved.marker),
    feeWei: proved.feeWei,
    outWei: proved.outWei,
  };
}

/** Proves the reveal, saves it with its marker as identity, and sends it. */
export async function startReveal(
  kit: PaymentKit,
  key: KeySource,
  account: string,
  outWei: bigint | null,
): Promise<CorePaymentSequence> {
  const kind = outWei === null ? 'summon' : 'claim';
  const proved = await proveReveal(kit, key, account, outWei);
  const details: PaymentDetails = {
    kind,
    amountWei: proved.outWei,
    feeWei: proved.feeWei,
    marker: proved.marker,
    at: Date.now(),
  };
  const sequence = kit.core.PaymentSequence.start(kit.store, newPaymentId(kind), revealIntent(kind, proved.marker, details));
  // The key (typed, or on its card) is the backup: nothing more to save before sending.
  sequence.markBackedUp();
  sequence.addAttempt(proved.envelope, proved.validUntil);
  await kit.node.sendRaw(bytesToHex(sequence.markSent()));
  return sequence;
}

/** A new proof of the same coin, for a fee window that moved. Needs the key typed (or its card tapped) again after a restart. */
export function proveRevealAgain(kit: PaymentKit, sequence: CorePaymentSequence, key: KeySource, account: string): Rebuild {
  return async () => {
    const details = decodeDetails(sequence.record().intent.details);
    if (!details || details.kind === 'vanish') {
      throw new Error('the saved Summon cannot be read');
    }
    const proved = await proveReveal(kit, key, account, details.kind === 'claim' ? BigInt(details.amountWei) : null);
    if (proved.marker !== details.marker) {
      throw new Error('this key does not hold the coin of this Summon');
    }
    return { signed: proved.envelope, validUntil: proved.validUntil };
  };
}
