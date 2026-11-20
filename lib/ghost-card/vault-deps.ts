// The app's parts for a card as a vault (./vault.ts): the card flows, the
// Keychain's opened-card keys, the saved changes, and the wallet's Summon and
// Vanish through the payment kit, for account zero.
import { cardKeyStore } from '../../modules/ghost-nfc/java-card';
import {
  CARD_KEY,
  lookUpKey,
  proveRevealAgain,
  startReveal,
  startSealedCardVanish,
} from '../vanish/actions';
import { advance, decodeDetails } from '../vanish/payments';
import { moveAlone, openShared, paymentsChanged, shared, stoppedVanish } from '../vanish/pending';
import { statusOfStep } from '../vanish/status-mapping';
import type { PaymentKit } from '../vanish/use-payment';
import { ghostCardDeps } from './deps';
import { fileChanges, type PaymentState, type VaultDeps, type VaultPayments } from './vault';

function vaultPayments(kit: PaymentKit, account: string): VaultPayments {
  const state = (id: string): PaymentState => {
    const sequence = openShared(kit, id);
    if (!sequence) {
      return 'missing';
    }
    if (stoppedVanish(id, kit.store) !== null) {
      return 'failed';
    }
    const status = statusOfStep(sequence.step());
    return status === 'settled' || status === 'in-block' || status === 'failed' ? status : 'moving';
  };
  return {
    async lookUpHeldKey() {
      const found = await lookUpKey(kit, CARD_KEY);
      return found.status === 'found' || found.status === 'spent' ? found.status : 'not-found';
    },
    async summonHeldKey() {
      const sequence = shared(await startReveal(kit, CARD_KEY, account, null));
      paymentsChanged();
      return sequence.record().id;
    },
    async moveSummon(id) {
      const sequence = openShared(kit, id);
      if (!sequence) {
        return;
      }
      await moveAlone(id, () => advance(kit.node, sequence, proveRevealAgain(kit, sequence, CARD_KEY, account), null));
      paymentsChanged();
    },
    paymentState: state,
    async startVanish(amountWei, commitData) {
      const started = await startSealedCardVanish(kit, account, amountWei, commitData);
      const sequence = shared(started.sequence);
      paymentsChanged();
      return sequence.record().id;
    },
    vanishSavedInto(commitDataHex) {
      for (const id of kit.store.list()) {
        const saved = kit.store.load(id);
        const details = saved ? decodeDetails(saved.intent.details) : null;
        if (details?.kind === 'vanish' && details.commitData === commitDataHex) {
          const now = state(id);
          return now !== 'failed' && now !== 'missing';
        }
      }
      return false;
    },
    forgetHeldKey() {
      try {
        kit.core.forgetCardKey();
      } catch {
        // A core without the card calls holds no card key.
      }
    },
  };
}

/** The app's parts; no payments without a node (`kit` null) or an account. */
export function vaultDeps(kit: PaymentKit | null, account: string | null): VaultDeps {
  return {
    card: ghostCardDeps(kit),
    keys: cardKeyStore(),
    payments: kit && account ? vaultPayments(kit, account) : null,
    changes: fileChanges(),
  };
}
