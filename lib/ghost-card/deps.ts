// The app's Ghost card flows' parts: the native core, the native card flows,
// this build's chain and the chain check through the payment kit's nodes.
import { javaCardCore, type JavaCardBindings } from '../../modules/ghost-core';
import { ghostCardNative } from '../../modules/ghost-nfc/java-card';
import { buildNetwork } from '../network/build-network';
import type { PaymentKit } from '../vanish/use-payment';
import { coinOnChain } from './chain';
import type { GhostCardDeps } from './flows';

function optionalCore(): JavaCardBindings | null {
  try {
    return javaCardCore();
  } catch {
    return null;
  }
}

/** The app's parts; the chain check fails when there is no node (`kit` null). */
export function ghostCardDeps(kit: PaymentKit | null): GhostCardDeps {
  const chainId = buildNetwork.chainId;
  return {
    core: optionalCore(),
    nfc: ghostCardNative(),
    chainId,
    coinOnChain: (commitment, marker) =>
      kit ? coinOnChain(kit, chainId, commitment, marker) : Promise.reject(new Error('no node in this build')),
  };
}
