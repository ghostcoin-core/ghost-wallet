// Phantom Keys on NTAG 424 DNA cards, as the app sees them.
//
// The native module (ios/) reads and writes the card through Core NFC and
// holds every secret: the card's keys in the Keychain (this device only), the
// session keys of each tap, and the Phantom Key, which goes from the native
// core to the card and from the card back to the native core without passing
// through JavaScript. The command framing is in this folder (apdu.ts,
// secure-messaging.ts, card.ts) so it is tested without a card.
import { requireOptionalNativeModule } from 'expo';

import { CardError, readCard, wipeCard, writeCard, type CardIdentity, type CardKeyVault } from './card';
import type { KeySet, Tag, VaultPlaintext } from './secure-messaging';

export { CARD_PROBLEMS, CardError, type CardProblem } from './card';

/** The Swift module's functions (ios/GhostNfcModule.swift). */
export type GhostNfcNative = {
  isSupported(): boolean;
  /** Opens a reader session and resolves once an ISO 7816 tag is connected. */
  beginSession(alert: string): Promise<void>;
  transceive(apdu: Uint8Array): Promise<Uint8Array>;
  /** Closes the reader session, with a success message or an error message. */
  endSession(alert: string | null, error: string | null): void;
  authPart2(uid: string, set: KeySet, keyNo: number, encryptedRndB: Uint8Array): Uint8Array;
  authFinish(encryptedResponse: Uint8Array): Uint8Array;
  cmac(input: Uint8Array): Uint8Array;
  encryptPadded(ivInput: Uint8Array, padded: Uint8Array): Uint8Array;
  encryptChangeKey(ivInput: Uint8Array, keyNo: number, to: KeySet, from: KeySet, version: number): Uint8Array;
  decrypt(ivInput: Uint8Array, ciphertext: Uint8Array): Uint8Array;
  endVaultSession(): void;
  hasKeys(uid: string): boolean;
  makeKeys(uid: string): void;
  forgetKeys(uid: string): void;
  sealPhantomKey(uid: string): Uint8Array;
  openPhantomKey(uid: string, sealed: Uint8Array): void;
};

/** Thrown when the person closes the card sheet. */
export class CardCancelled extends Error {
  constructor() {
    super('The card was not tapped.');
    this.name = 'CardCancelled';
  }
}

function native(): GhostNfcNative | null {
  return requireOptionalNativeModule<GhostNfcNative>('GhostNfc');
}

/** Whether this iPhone can read cards; false in a build without the module and in the simulator. */
export function cardsSupported(): boolean {
  try {
    return native()?.isSupported() ?? false;
  } catch {
    return false;
  }
}

/** The native module as the card code's tag and vault. */
export function vaultOf(nfc: GhostNfcNative): CardKeyVault {
  return {
    authPart2: (uid, key, encryptedRndB) => nfc.authPart2(uid, key.set, key.keyNo, encryptedRndB),
    authFinish: (response) => nfc.authFinish(response),
    cmac: (input) => nfc.cmac(input),
    encrypt: (ivInput, plaintext: VaultPlaintext) =>
      'padded' in plaintext
        ? nfc.encryptPadded(ivInput, plaintext.padded)
        : nfc.encryptChangeKey(
            ivInput,
            plaintext.changeKey.keyNo,
            plaintext.changeKey.to,
            plaintext.changeKey.from,
            plaintext.changeKey.version,
          ),
    decrypt: (ivInput, ciphertext) => nfc.decrypt(ivInput, ciphertext),
    endSession: () => nfc.endVaultSession(),
    hasKeys: (uid) => nfc.hasKeys(uid),
    makeKeys: (uid) => nfc.makeKeys(uid),
    forgetKeys: (uid) => nfc.forgetKeys(uid),
    sealPhantomKey: (uid) => nfc.sealPhantomKey(uid),
    openPhantomKey: (uid, sealed) => nfc.openPhantomKey(uid, sealed),
  };
}

type CardAction = (tag: Tag, vault: CardKeyVault) => Promise<CardIdentity>;

/** Runs `action` on the next card tapped, inside one reader session. */
export async function withCard(
  nfc: GhostNfcNative | null,
  messages: { hold: string; done: string },
  action: CardAction,
): Promise<CardIdentity> {
  if (!nfc || !nfc.isSupported()) {
    throw new Error('This iPhone cannot read cards.');
  }
  try {
    await nfc.beginSession(messages.hold);
  } catch (error) {
    if ((error as { code?: string } | null)?.code === 'ERR_NFC_CANCELLED') {
      throw new CardCancelled();
    }
    throw error;
  }
  const tag: Tag = { transceive: (apdu) => nfc.transceive(apdu) };
  const vault = vaultOf(nfc);
  try {
    const card = await action(tag, vault);
    nfc.endSession(messages.done, null);
    return card;
  } catch (error) {
    vault.endSession();
    const message = error instanceof CardError ? error.message : 'The card could not be read. Hold it still and try again.';
    nfc.endSession(null, message);
    throw error instanceof CardError ? error : new Error(message);
  }
}

/** Writes the Phantom Key the native core holds (after Vanish) to a blank card. */
export function putPhantomKeyOnCard(): Promise<CardIdentity> {
  return withCard(native(), { hold: 'Hold a blank NTAG 424 card near the top of the iPhone.', done: 'The Phantom Key is on the card.' }, writeCard);
}

/** Reads a card's Phantom Key into the native core, ready to Summon or Claim. */
export function readPhantomKeyFromCard(): Promise<CardIdentity> {
  return withCard(native(), { hold: 'Hold your Phantom Key card near the top of the iPhone.', done: 'Card read.' }, readCard);
}

/** Wipes a card this phone wrote back to a blank card. */
export function wipePhantomKeyCard(): Promise<CardIdentity> {
  return withCard(native(), { hold: 'Hold the card to wipe near the top of the iPhone.', done: 'The card is blank again.' }, wipeCard);
}
