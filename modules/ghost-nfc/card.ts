// A Phantom Key on an NTAG 424 DNA card: write it to a blank card, read it
// back to Summon or Claim, and wipe the card.
//
// Every card gets its own keys, drawn from the phone's random source by the
// native vault and saved in this phone's Keychain (this device only) before
// the card changes: key 0 (the card's master key), key 2 (the key that reads
// and writes the Phantom Key's file) and a sealing key that never goes on the
// card. The Phantom Key is sealed under the sealing key (AES-GCM, in native
// code) and written to the card's file 2 over the chip's encrypted channel;
// the file then needs key 2 to be read or written and key 0 to be changed. A
// card is read only on the phone that wrote it. There is no PIN-only card: a
// key made from a short PIN and the card's public data could be guessed
// offline from one recorded tap.
//
// JavaScript sees the card's UID (public), its originality signature
// (public), encrypted command data and the sealed record, never a key or the
// Phantom Key itself.
import {
  COMMAND,
  COMM_MODE,
  ChipError,
  STATUS,
  accessRights,
  concat,
  equalBytes,
  expectIso,
  expectNative,
  fileRangeHeader,
  pad,
  selectNdefApplication,
  splitResponse,
  toHex,
  wrapNative,
} from './apdu';
import { readSignature, verifyOriginality } from './originality';
import { SecureSession, type CardVault, type KeyRef, type KeySet, type Tag } from './secure-messaging';

/** The card's master key and the key of the Phantom Key's file. */
export const MASTER_KEY = 0;
export const FILE_KEY = 2;
/** The NDEF file, 256 bytes, where the sealed Phantom Key goes. */
export const KEY_FILE = 0x02;
export const KEY_FILE_BYTES = 256;
/** The key version of a card's own keys; factory keys are version 0. */
export const CARD_KEY_VERSION = 0x01;
/** Bytes per ReadData or WriteData, so a Full command fits a short APDU. */
export const CHUNK_BYTES = 128;

/** File 2 as it leaves the factory: plain, free read and write, key 0 changes it. */
export const FACTORY_FILE_SETTINGS = concat(
  [COMM_MODE.plain],
  accessRights({ readWrite: 0xe, change: MASTER_KEY, read: 0xe, write: 0xe }),
);
/** File 2 holding a Phantom Key: encrypted channel, key 2 reads and writes, key 0 changes it. */
export const KEY_FILE_SETTINGS = concat(
  [COMM_MODE.full],
  accessRights({ readWrite: FILE_KEY, change: MASTER_KEY, read: FILE_KEY, write: FILE_KEY }),
);

/** "GK", the record's layout version, then the sealed key's length (2 bytes, big endian). */
const RECORD_MAGIC = [0x47, 0x4b] as const;
const RECORD_VERSION = 0x01;
const RECORD_HEADER_BYTES = 5;

/** The vault's card-key calls, on top of the session calls. */
export type CardKeyVault = CardVault & {
  /** Whether this phone saved keys for card `uid`. */
  hasKeys(uid: string): boolean;
  /** Draws card `uid`'s keys from the random source and saves them to the Keychain, this device only. */
  makeKeys(uid: string): void;
  /** Deletes card `uid`'s keys from the Keychain. */
  forgetKeys(uid: string): void;
  /**
   * Seals the Phantom Key the native core holds (made by Vanish, its words
   * already checked) under card `uid`'s sealing key; returns the sealed bytes.
   */
  sealPhantomKey(uid: string): Uint8Array;
  /** Opens a sealed Phantom Key read from card `uid` and hands it to the native core. */
  openPhantomKey(uid: string, sealed: Uint8Array): void;
};

export type CardProblem =
  | 'not-ntag424'
  | 'not-genuine'
  | 'not-blank'
  | 'written-already'
  | 'other-phone'
  | 'keys-changed'
  | 'empty'
  | 'too-long'
  | 'write-failed';

/** Why a card could not be written, read or wiped. Never holds a key. */
export class CardError extends Error {
  readonly problem: CardProblem;

  constructor(problem: CardProblem) {
    super(CARD_PROBLEMS[problem]);
    this.name = 'CardError';
    this.problem = problem;
  }
}

export const CARD_PROBLEMS: Record<CardProblem, string> = {
  'not-ntag424': 'This is not an NTAG 424 DNA card.',
  'not-genuine': 'This card did not pass the NXP genuineness check. Nothing was written.',
  'not-blank': 'This card is not blank. Use a new NTAG 424 DNA card.',
  'written-already': 'This card already holds a Phantom Key from this phone. Wipe it first.',
  'other-phone':
    'This card was not written on this phone. A card can only be read or wiped on the phone that wrote it.',
  'keys-changed': 'This card no longer matches the keys this phone saved for it.',
  empty: 'This card holds no Phantom Key.',
  'too-long': 'This Phantom Key does not fit on the card.',
  'write-failed':
    'The card was moved away before the Phantom Key was written. Wipe the card, then try again. Your key words still work.',
};

/** The card's UID, upper-case hex, as the vault keys it. */
export type CardIdentity = { uid: Uint8Array; uidHex: string };

/** Selects the NDEF application and reads GetVersion: an NXP NTAG and its 7-byte UID. */
export async function identifyCard(tag: Tag): Promise<CardIdentity> {
  expectIso('ISOSelectFile', splitResponse(await tag.transceive(selectNdefApplication())));
  const hardware = expectNative(
    'GetVersion',
    splitResponse(await tag.transceive(wrapNative(COMMAND.getVersion))),
    [STATUS.more],
  );
  expectNative('GetVersion', splitResponse(await tag.transceive(wrapNative(COMMAND.additionalFrame))), [STATUS.more]);
  const production = expectNative('GetVersion', splitResponse(await tag.transceive(wrapNative(COMMAND.additionalFrame))));
  // Vendor 0x04 is NXP, hardware type 0x04 an NTAG.
  if (hardware.length < 7 || hardware[0] !== 0x04 || hardware[1] !== 0x04 || production.length < 14) {
    throw new CardError('not-ntag424');
  }
  const uid = production.slice(0, 7);
  if (uid.every((byte) => byte === 0)) {
    // A random-ID card hides its UID until authenticated; this app's cards never use one.
    throw new CardError('not-ntag424');
  }
  return { uid, uidHex: toHex(uid) };
}

/** The bytes written to the card: header, then the sealed Phantom Key. */
export function cardRecord(sealed: Uint8Array): Uint8Array {
  if (sealed.length === 0) {
    throw new CardError('empty');
  }
  const record = concat(RECORD_MAGIC, [RECORD_VERSION, sealed.length >> 8, sealed.length & 0xff], sealed);
  if (record.length > KEY_FILE_BYTES) {
    throw new CardError('too-long');
  }
  return record;
}

/** The record's full length from its header, or null when the file holds no record. */
export function recordLength(header: Uint8Array): number | null {
  if (
    header.length < RECORD_HEADER_BYTES ||
    header[0] !== RECORD_MAGIC[0] ||
    header[1] !== RECORD_MAGIC[1] ||
    header[2] !== RECORD_VERSION
  ) {
    return null;
  }
  const length = RECORD_HEADER_BYTES + ((header[3] << 8) | header[4]);
  return length > RECORD_HEADER_BYTES && length <= KEY_FILE_BYTES ? length : null;
}

/** The sealed Phantom Key in a record, or null. */
export function sealedOf(record: Uint8Array): Uint8Array | null {
  const length = recordLength(record);
  return length !== null && record.length >= length ? record.slice(RECORD_HEADER_BYTES, length) : null;
}

function key(set: KeySet, keyNo: number): KeyRef {
  return { set, keyNo };
}

async function authenticate(tag: Tag, vault: CardVault, card: CardIdentity, ref: KeyRef): Promise<SecureSession> {
  return SecureSession.authenticate(tag, vault, card.uidHex, ref);
}

/** Authenticates with `ref`, or returns null when the chip refuses that key. */
async function tryAuthenticate(tag: Tag, vault: CardVault, card: CardIdentity, ref: KeyRef): Promise<SecureSession | null> {
  try {
    return await authenticate(tag, vault, card, ref);
  } catch (error) {
    if (error instanceof ChipError && error.authentication) {
      return null;
    }
    throw error;
  }
}

function changeKey(session: SecureSession, keyNo: number, to: KeySet, from: KeySet): Promise<Uint8Array> {
  return session.full({
    command: COMMAND.changeKey,
    header: Uint8Array.of(keyNo),
    plaintext: { changeKey: { keyNo, to, from, version: to === 'factory' ? 0x00 : CARD_KEY_VERSION } },
    // Changing the key the session runs on ends the session: no MAC comes back.
    responseMac: keyNo !== MASTER_KEY,
  });
}

function changeFileSettings(session: SecureSession, settings: Uint8Array): Promise<Uint8Array> {
  return session.full({
    command: COMMAND.changeFileSettings,
    header: Uint8Array.of(KEY_FILE),
    plaintext: { padded: pad(settings) },
  });
}

async function writeFile(session: SecureSession, data: Uint8Array): Promise<void> {
  for (let offset = 0; offset < data.length; offset += CHUNK_BYTES) {
    const chunk = data.slice(offset, offset + CHUNK_BYTES);
    await session.full({
      command: COMMAND.writeData,
      header: fileRangeHeader(KEY_FILE, offset, chunk.length),
      plaintext: { padded: pad(chunk) },
    });
  }
}

async function readRange(session: SecureSession, offset: number, length: number): Promise<Uint8Array> {
  return session.full({ command: COMMAND.readData, header: fileRangeHeader(KEY_FILE, offset, length), decrypt: true });
}

/** Reads the record from file 2 over the encrypted channel; null when it holds none. */
async function readRecord(session: SecureSession): Promise<Uint8Array | null> {
  const head = await readRange(session, 0, CHUNK_BYTES);
  const length = recordLength(head);
  if (length === null) {
    return null;
  }
  const parts = [head];
  for (let offset = CHUNK_BYTES; offset < length; offset += CHUNK_BYTES) {
    parts.push(await readRange(session, offset, Math.min(CHUNK_BYTES, length - offset)));
  }
  return concat(...parts).slice(0, length);
}

/**
 * Writes the Phantom Key the native core holds to a blank, genuine NTAG 424
 * DNA card. The card's keys are made and saved before the card changes, so a
 * card moved away halfway can still be wiped.
 */
export async function writeCard(tag: Tag, vault: CardKeyVault): Promise<CardIdentity> {
  const card = await identifyCard(tag);
  if (!verifyOriginality(card.uid, await readSignature(tag))) {
    throw new CardError('not-genuine');
  }
  if (vault.hasKeys(card.uidHex)) {
    throw new CardError('written-already');
  }
  const factory = await tryAuthenticate(tag, vault, card, key('factory', MASTER_KEY));
  if (!factory) {
    throw new CardError('not-blank');
  }
  vault.makeKeys(card.uidHex);
  let record: Uint8Array;
  try {
    record = cardRecord(vault.sealPhantomKey(card.uidHex));
  } catch (error) {
    // The card has not changed: its keys are not needed.
    factory.close();
    vault.forgetKeys(card.uidHex);
    throw error;
  }
  try {
    await changeFileSettings(factory, KEY_FILE_SETTINGS);
    await changeKey(factory, FILE_KEY, 'saved', 'factory');
    await changeKey(factory, MASTER_KEY, 'saved', 'factory');
    const session = await authenticate(tag, vault, card, key('saved', FILE_KEY));
    try {
      await writeFile(session, record);
      const written = await readRecord(session);
      if (!written || !equalBytes(written, record)) {
        throw new CardError('write-failed');
      }
    } finally {
      session.close();
    }
  } catch (error) {
    factory.close();
    throw error instanceof CardError ? error : new CardError('write-failed');
  }
  return card;
}

/**
 * Reads the Phantom Key from a card this phone wrote and hands it to the
 * native core, ready to Summon or Claim. JavaScript never sees it.
 */
export async function readCard(tag: Tag, vault: CardKeyVault): Promise<CardIdentity> {
  const card = await identifyCard(tag);
  if (!vault.hasKeys(card.uidHex)) {
    throw new CardError('other-phone');
  }
  const session = await tryAuthenticate(tag, vault, card, key('saved', FILE_KEY));
  if (!session) {
    throw new CardError('keys-changed');
  }
  let record: Uint8Array | null;
  try {
    record = await readRecord(session);
  } finally {
    session.close();
  }
  const sealed = record ? sealedOf(record) : null;
  if (!sealed) {
    throw new CardError('empty');
  }
  vault.openPhantomKey(card.uidHex, sealed);
  return card;
}

/**
 * Puts a card this phone wrote back to its factory state: file 2 plain and
 * free, keys 0 and 2 back to the factory key, the file zeroed, and the card's
 * keys deleted from the Keychain. Also finishes a card left halfway by a
 * write: a key that was never changed is still the factory key.
 */
export async function wipeCard(tag: Tag, vault: CardKeyVault): Promise<CardIdentity> {
  const card = await identifyCard(tag);
  if (!vault.hasKeys(card.uidHex)) {
    throw new CardError('other-phone');
  }
  let masterSet: KeySet = 'saved';
  let session = await tryAuthenticate(tag, vault, card, key('saved', MASTER_KEY));
  if (!session) {
    masterSet = 'factory';
    session = await tryAuthenticate(tag, vault, card, key('factory', MASTER_KEY));
  }
  if (!session) {
    throw new CardError('keys-changed');
  }
  await changeFileSettings(session, FACTORY_FILE_SETTINGS);
  try {
    await changeKey(session, FILE_KEY, 'factory', 'saved');
  } catch (error) {
    if (!(error instanceof ChipError)) {
      throw error;
    }
    // Key 2 is still the factory key (the write stopped before changing it);
    // the refusal ended the session.
    session = await authenticate(tag, vault, card, key(masterSet, MASTER_KEY));
  }
  if (masterSet === 'saved') {
    await changeKey(session, MASTER_KEY, 'factory', 'saved');
  } else {
    session.close();
  }
  // Selecting again drops any authentication; the file is plain and free now.
  expectIso('ISOSelectFile', splitResponse(await tag.transceive(selectNdefApplication())));
  const zeros = new Uint8Array(KEY_FILE_BYTES);
  for (let offset = 0; offset < zeros.length; offset += CHUNK_BYTES) {
    const chunk = zeros.slice(offset, offset + CHUNK_BYTES);
    expectNative(
      'WriteData',
      splitResponse(await tag.transceive(wrapNative(COMMAND.writeData, concat(fileRangeHeader(KEY_FILE, offset, chunk.length), chunk)))),
    );
  }
  vault.forgetKeys(card.uidHex);
  return card;
}
