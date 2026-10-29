// The card's keys, with a simulated NTAG 424 DNA: each card gets its own
// random keys, saved before the card changes; secrets never reach
// JavaScript; a card is read and wiped only on the phone that wrote it.
import { equalBytes, fromHex } from '../../modules/ghost-nfc/apdu';
import { CardError, KEY_FILE_SETTINGS, readCard, wipeCard, writeCard } from '../../modules/ghost-nfc/card';
import { CardCancelled, withCard, type GhostNfcNative } from '../../modules/ghost-nfc';
import { FakeNtag424, FakeVault, ZERO_KEY, contains } from './fake-card';

const UID = '04518DFAA96180';

function problemOf(promise: Promise<unknown>): Promise<string> {
  return promise.then(
    () => 'none',
    (error) => (error instanceof CardError ? error.problem : `other: ${String(error)}`),
  );
}

describe('writing a Phantom Key to a blank card', () => {
  it('gives the card its own random keys, saved in the Keychain, and the file only key 2 can read', async () => {
    const card = new FakeNtag424();
    const vault = new FakeVault();
    await writeCard(card, vault);

    const saved = vault.keychain.get(UID)!;
    expect(saved).toBeDefined();
    expect(equalBytes(card.keys[0], saved.master)).toBe(true);
    expect(equalBytes(card.keys[2], saved.file)).toBe(true);
    expect(equalBytes(saved.master, ZERO_KEY)).toBe(false);
    expect(equalBytes(saved.master, saved.file)).toBe(false);
    expect(card.keyVersions[0]).toBe(1);
    expect(card.keyVersions[2]).toBe(1);
    // Keys 1, 3 and 4 are untouched.
    expect(card.keys.filter((_, i) => i % 2 === 1 || i === 4).every((k) => equalBytes(k, ZERO_KEY))).toBe(true);
    expect(card.fileSettings).toEqual(KEY_FILE_SETTINGS);
    // The card holds the sealed key, never the words.
    expect(contains(card.file, new Uint8Array(Buffer.from(vault.held!, 'utf8')))).toBe(false);
    expect(contains(card.file, new Uint8Array(Buffer.from('abandon', 'utf8')))).toBe(false);
  });

  it('makes new keys for every write: no secret is shared between cards', async () => {
    const vault = new FakeVault();
    const card = new FakeNtag424();
    await writeCard(card, vault);
    const firstKeys = vault.keychain.get(UID)!;
    await wipeCard(card, vault);
    await writeCard(card, vault);
    const secondKeys = vault.keychain.get(UID)!;
    expect(equalBytes(firstKeys.master, secondKeys.master)).toBe(false);
    expect(equalBytes(firstKeys.file, secondKeys.file)).toBe(false);
    expect(equalBytes(firstKeys.seal, secondKeys.seal)).toBe(false);
  });

  it('saves the keys before the card changes, so a card moved away can be wiped', async () => {
    const card = new FakeNtag424();
    const vault = new FakeVault();
    let savedBeforeFirstChange: boolean | null = null;
    card.before = (apdu) => {
      if (apdu[0] === 0x90 && apdu[1] === 0x5f && savedBeforeFirstChange === null) {
        savedBeforeFirstChange = vault.hasKeys(UID);
      }
      // The card is pulled away when key 0 is about to change.
      if (apdu[0] === 0x90 && apdu[1] === 0xc4 && apdu[5] === 0x00) {
        throw new Error('Tag connection lost');
      }
    };
    expect(await problemOf(writeCard(card, vault))).toBe('write-failed');
    expect(savedBeforeFirstChange).toBe(true);
    expect(vault.hasKeys(UID)).toBe(true);
    // Key 2 changed, key 0 did not.
    expect(equalBytes(card.keys[2], ZERO_KEY)).toBe(false);
    expect(equalBytes(card.keys[0], ZERO_KEY)).toBe(true);

    card.before = () => {};
    await wipeCard(card, vault);
    expect(card.keys.every((k) => equalBytes(k, ZERO_KEY))).toBe(true);
    expect(card.fileSettings).toEqual(fromHex('00E0EE'));
    expect(vault.hasKeys(UID)).toBe(false);
  });

  it('refuses a card that fails the NXP genuineness check before changing or saving anything', async () => {
    const card = new FakeNtag424();
    card.signature = card.signature.slice();
    card.signature[10] ^= 0x40;
    const vault = new FakeVault();
    expect(await problemOf(writeCard(card, vault))).toBe('not-genuine');
    expect(vault.keychain.size).toBe(0);
    expect(card.sent.some((apdu) => apdu[1] === 0x71)).toBe(false);
  });

  it('refuses a card whose master key is not the factory key, saving no keys', async () => {
    const card = new FakeNtag424();
    card.keys[0] = fromHex('00112233445566778899AABBCCDDEEFF');
    const vault = new FakeVault();
    expect(await problemOf(writeCard(card, vault))).toBe('not-blank');
    expect(vault.keychain.size).toBe(0);
  });

  it('forgets the new keys and leaves the card blank when no Phantom Key is held', async () => {
    const card = new FakeNtag424();
    const vault = new FakeVault();
    vault.held = null;
    await expect(writeCard(card, vault)).rejects.toThrow('no Phantom Key is held');
    expect(vault.keychain.size).toBe(0);
    expect(card.keys.every((k) => equalBytes(k, ZERO_KEY))).toBe(true);
    expect(card.fileSettings).toEqual(fromHex('00E0EE'));
  });

  it('will not write over a card this phone already wrote', async () => {
    const card = new FakeNtag424();
    const vault = new FakeVault();
    await writeCard(card, vault);
    const keys = vault.keychain.get(UID);
    expect(await problemOf(writeCard(card, vault))).toBe('written-already');
    expect(vault.keychain.get(UID)).toBe(keys);
  });
});

describe('tapping a card to Summon or Claim', () => {
  it('hands the Phantom Key to the native side, not to JavaScript', async () => {
    const card = new FakeNtag424();
    const writer = new FakeVault();
    await writeCard(card, writer);
    writer.opened = null;
    const result = await readCard(card, writer);
    expect(writer.opened).toBe(writer.held);
    expect(Object.keys(result).sort()).toEqual(['uid', 'uidHex']);
  });

  it('says a card written on another phone cannot be read, without trying a key', async () => {
    const card = new FakeNtag424();
    await writeCard(card, new FakeVault());
    const otherPhone = new FakeVault();
    const sentBefore = card.sent.length;
    expect(await problemOf(readCard(card, otherPhone))).toBe('other-phone');
    expect(card.sent.slice(sentBefore).some((apdu) => apdu[1] === 0x71)).toBe(false);
    expect(otherPhone.opened).toBeNull();
    expect(await problemOf(wipeCard(card, otherPhone))).toBe('other-phone');
  });

  it('says so when the card\'s keys no longer match the saved ones', async () => {
    const card = new FakeNtag424();
    const vault = new FakeVault();
    await writeCard(card, vault);
    vault.keychain.get(UID)!.file = fromHex('0F0E0D0C0B0A09080706050403020100');
    expect(await problemOf(readCard(card, vault))).toBe('keys-changed');
  });
});

describe('wiping a card', () => {
  it('puts the card back to factory state and forgets its keys, so it can be written again', async () => {
    const card = new FakeNtag424();
    const vault = new FakeVault();
    await writeCard(card, vault);
    await wipeCard(card, vault);
    expect(card.keys.every((k) => equalBytes(k, ZERO_KEY))).toBe(true);
    expect(card.keyVersions).toEqual([0, 0, 0, 0, 0]);
    expect(card.fileSettings).toEqual(fromHex('00E0EE'));
    expect(card.file.every((byte) => byte === 0)).toBe(true);
    expect(vault.hasKeys(UID)).toBe(false);
    expect(await problemOf(readCard(card, vault))).toBe('other-phone');

    await writeCard(card, vault);
    vault.opened = null;
    await readCard(card, vault);
    expect(vault.opened).toBe(vault.held);
  });
});

describe('secrets never reach JavaScript', () => {
  it('no key, session key or key word is in a command or in anything the vault returns', async () => {
    const card = new FakeNtag424();
    const vault = new FakeVault();
    await writeCard(card, vault);
    await readCard(card, vault);
    const writtenKeys = { ...vault.keychain.get(UID)! };
    await wipeCard(card, vault);

    const secrets = [
      writtenKeys.master,
      writtenKeys.file,
      writtenKeys.seal,
      ...vault.sessionKeysSeen,
      new Uint8Array(Buffer.from(vault.held!, 'utf8')),
    ];
    expect(vault.sessionKeysSeen.length).toBeGreaterThanOrEqual(6);
    const seenByJavaScript = [...card.sent, ...vault.returned];
    for (const secret of secrets) {
      for (const bytes of seenByJavaScript) {
        expect(contains(bytes, secret)).toBe(false);
      }
    }
  });
});

describe('the reader session', () => {
  function nativeDouble(overrides: Partial<GhostNfcNative> = {}) {
    const vault = new FakeVault();
    const card = new FakeNtag424();
    const calls: string[] = [];
    const nfc: GhostNfcNative = {
      isSupported: () => true,
      beginSession: async () => {
        calls.push('begin');
      },
      transceive: (apdu) => card.transceive(apdu),
      endSession: (alert, error) => {
        calls.push(`end ${alert ?? ''}|${error ?? ''}`);
      },
      authPart2: (uid, set, keyNo, data) => vault.authPart2(uid, { set, keyNo }, data),
      authFinish: (data) => vault.authFinish(data),
      cmac: (input) => vault.cmac(input),
      encryptPadded: (iv, padded) => vault.encrypt(iv, { padded }),
      encryptChangeKey: (iv, keyNo, to, from, version) => vault.encrypt(iv, { changeKey: { keyNo, to, from, version } }),
      decrypt: (iv, data) => vault.decrypt(iv, data),
      endVaultSession: () => {
        calls.push('end vault');
        vault.endSession();
      },
      hasKeys: (uid) => vault.hasKeys(uid),
      makeKeys: (uid) => vault.makeKeys(uid),
      forgetKeys: (uid) => vault.forgetKeys(uid),
      sealPhantomKey: (uid) => vault.sealPhantomKey(uid),
      openPhantomKey: (uid, sealed) => vault.openPhantomKey(uid, sealed),
      ...overrides,
    };
    return { nfc, vault, card, calls };
  }

  const messages = { hold: 'Hold', done: 'Done' };

  it('runs a write and a read through the native module and closes the sheet with a message', async () => {
    const { nfc, vault, calls } = nativeDouble();
    await withCard(nfc, messages, writeCard);
    vault.opened = null;
    await withCard(nfc, messages, readCard);
    expect(vault.opened).toBe(vault.held);
    expect(calls.filter((call) => call.startsWith('end Done'))).toHaveLength(2);
  });

  it('shows the card problem on the sheet and wipes the session keys on failure', async () => {
    const { nfc, calls } = nativeDouble();
    await expect(withCard(nfc, messages, readCard)).rejects.toThrow(CardError);
    expect(calls).toContain('end vault');
    expect(calls.some((call) => call.includes('not written on this phone'))).toBe(true);
  });

  it('reports a closed sheet as cancelled', async () => {
    const { nfc } = nativeDouble({
      beginSession: async () => {
        throw Object.assign(new Error('cancelled'), { code: 'ERR_NFC_CANCELLED' });
      },
    });
    await expect(withCard(nfc, messages, readCard)).rejects.toThrow(CardCancelled);
  });

  it('refuses without the native module or NFC', async () => {
    await expect(withCard(null, messages, readCard)).rejects.toThrow('cannot read cards');
    const { nfc } = nativeDouble({ isSupported: () => false });
    await expect(withCard(nfc, messages, readCard)).rejects.toThrow('cannot read cards');
  });
});
