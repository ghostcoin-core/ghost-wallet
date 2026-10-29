// Test doubles for the card code: a vault that does in Node what
// modules/ghost-nfc/ios/CardVault.swift does on the phone, and an NTAG 424
// DNA simulated from the datasheet (select, GetVersion, Read_Sig,
// AuthenticateEV2First, ChangeFileSettings, ChangeKey, WriteData, ReadData),
// which checks every MAC and enforces the file's access rights.
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

import { concat, equalBytes, fromHex, le16, pad, truncateMac, unpad } from '../../modules/ghost-nfc/apdu';
import type { CardKeyVault } from '../../modules/ghost-nfc/card';
import type { KeyRef, KeySet, VaultPlaintext } from '../../modules/ghost-nfc/secure-messaging';

export const ZERO_KEY = new Uint8Array(16);

/** AN12196 table 30: a genuine UID and NXP's signature over it. */
export const GENUINE_UID = fromHex('04518DFAA96180');
export const GENUINE_SIGNATURE = fromHex(
  'D1940D17CFEDA4BFF80359AB975F9F6514313E8F90C1D3CAAF5941AD744A1CDF9A83F883CAFE0FE95D1939B1B7E47113993324473B785D21',
);

export function ecb(key: Uint8Array, block: Uint8Array): Uint8Array {
  const cipher = createCipheriv('aes-128-ecb', key, null).setAutoPadding(false);
  return new Uint8Array(Buffer.concat([cipher.update(block), cipher.final()]));
}

export function cbcEncrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  const cipher = createCipheriv('aes-128-cbc', key, iv).setAutoPadding(false);
  return new Uint8Array(Buffer.concat([cipher.update(data), cipher.final()]));
}

export function cbcDecrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  const decipher = createDecipheriv('aes-128-cbc', key, iv).setAutoPadding(false);
  return new Uint8Array(Buffer.concat([decipher.update(data), decipher.final()]));
}

function shiftLeft(block: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) {
    out[i] = ((block[i] << 1) | (i < 15 ? block[i + 1] >> 7 : 0)) & 0xff;
  }
  if (block[0] & 0x80) {
    out[15] ^= 0x87;
  }
  return out;
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  return Uint8Array.from(a, (byte, i) => byte ^ b[i]);
}

/** AES-CMAC (RFC 4493). */
export function cmac(key: Uint8Array, message: Uint8Array): Uint8Array {
  const k1 = shiftLeft(ecb(key, new Uint8Array(16)));
  const k2 = shiftLeft(k1);
  const blocks = Math.max(1, Math.ceil(message.length / 16));
  const complete = message.length > 0 && message.length % 16 === 0;
  const lastStart = (blocks - 1) * 16;
  let last: Uint8Array;
  if (complete) {
    last = xor(message.slice(lastStart, lastStart + 16), k1);
  } else {
    const padded = new Uint8Array(16);
    const tail = message.slice(lastStart);
    padded.set(tail);
    padded[tail.length] = 0x80;
    last = xor(padded, k2);
  }
  let state = new Uint8Array(16);
  for (let i = 0; i < blocks - 1; i += 1) {
    state = ecb(key, xor(state, message.slice(i * 16, i * 16 + 16)));
  }
  return ecb(key, xor(state, last));
}

/** CRC32 without the final inversion (JAMCRC), little endian: the chip's CRC32 of a new key. */
export function crc32NewKey(data: Uint8Array): Uint8Array {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
  }
  crc >>>= 0;
  return Uint8Array.of(crc & 0xff, (crc >>> 8) & 0xff, (crc >>> 16) & 0xff, (crc >>> 24) & 0xff);
}

function rotateLeft(block: Uint8Array): Uint8Array {
  return concat(block.slice(1), [block[0]]);
}

export function sessionVector(label: [number, number], rndA: Uint8Array, rndB: Uint8Array): Uint8Array {
  return concat(label, [0x00, 0x01, 0x00, 0x80], rndA.slice(0, 2), xor(rndA.slice(2, 8), rndB.slice(0, 6)), rndB.slice(6), rndA.slice(8));
}

export function sessionKeys(key: Uint8Array, rndA: Uint8Array, rndB: Uint8Array) {
  return {
    enc: cmac(key, sessionVector([0xa5, 0x5a], rndA, rndB)),
    mac: cmac(key, sessionVector([0x5a, 0xa5], rndA, rndB)),
  };
}

type SavedKeys = { master: Uint8Array; file: Uint8Array; seal: Uint8Array };

/**
 * The vault, in Node. `keychain` stands for this phone's Keychain; `held` for
 * the Phantom Key the native core holds after Vanish; `opened` for the one a
 * card handed back to it.
 */
export class FakeVault implements CardKeyVault {
  keychain = new Map<string, SavedKeys>();
  held: string | null = 'abandon ability able about above absent absorb abstract absurd abuse access accident';
  opened: string | null = null;
  /** Everything handed back to JavaScript. */
  returned: Uint8Array[] = [];
  /** Session keys of every session, to check none leaves. */
  sessionKeysSeen: Uint8Array[] = [];
  random: (length: number) => Uint8Array = (length) => new Uint8Array(randomBytes(length));

  private pending: { key: Uint8Array; keyNo: number; rndA: Uint8Array; rndB: Uint8Array } | null = null;
  private session: { enc: Uint8Array; mac: Uint8Array; keyNo: number; uid: string } | null = null;
  private uid = '';

  /** `preset` skips the key exchange: the session gets these keys and TI (for AN12196's secure messaging vectors). */
  constructor(private readonly preset: { enc: Uint8Array; mac: Uint8Array; ti: Uint8Array } | null = null) {}

  private give<T extends Uint8Array>(value: T): T {
    this.returned.push(value);
    return value;
  }

  private keyFor(uid: string, ref: { set: KeySet; keyNo: number }): Uint8Array {
    if (ref.set === 'factory') {
      return ZERO_KEY;
    }
    const saved = this.keychain.get(uid);
    if (!saved) {
      throw new Error('no keys saved for this card');
    }
    if (ref.keyNo === 0) return saved.master;
    if (ref.keyNo === 2) return saved.file;
    throw new Error('the app uses keys 0 and 2 only');
  }

  authPart2(uid: string, key: KeyRef, encryptedRndB: Uint8Array): Uint8Array {
    const k = this.keyFor(uid, key);
    const rndB = cbcDecrypt(k, ZERO_KEY, encryptedRndB);
    const rndA = this.random(16);
    this.pending = { key: k, keyNo: key.keyNo, rndA, rndB };
    this.uid = uid;
    return this.give(cbcEncrypt(k, ZERO_KEY, concat(rndA, rotateLeft(rndB))));
  }

  authFinish(encryptedResponse: Uint8Array): Uint8Array {
    if (this.preset) {
      this.session = { enc: this.preset.enc, mac: this.preset.mac, keyNo: 0, uid: this.uid };
      return this.give(this.preset.ti);
    }
    const pending = this.pending;
    this.pending = null;
    if (!pending) {
      throw new Error('no authentication under way');
    }
    const plain = cbcDecrypt(pending.key, ZERO_KEY, encryptedResponse);
    if (!equalBytes(plain.slice(4, 20), rotateLeft(pending.rndA))) {
      throw new Error('the card did not prove it holds the key');
    }
    const keys = sessionKeys(pending.key, pending.rndA, pending.rndB);
    this.sessionKeysSeen.push(keys.enc, keys.mac);
    this.session = { ...keys, keyNo: pending.keyNo, uid: this.uid };
    return this.give(plain.slice(0, 4));
  }

  private open() {
    if (!this.session) {
      throw new Error('no card session');
    }
    return this.session;
  }

  cmac(input: Uint8Array): Uint8Array {
    return this.give(cmac(this.open().mac, input));
  }

  encrypt(ivInput: Uint8Array, plaintext: VaultPlaintext): Uint8Array {
    const session = this.open();
    let data: Uint8Array;
    if ('padded' in plaintext) {
      data = plaintext.padded;
    } else {
      const { keyNo, to, from, version } = plaintext.changeKey;
      const newKey = this.keyFor(session.uid, { set: to, keyNo });
      if (keyNo === session.keyNo) {
        data = pad(concat(newKey, [version]));
      } else {
        const oldKey = this.keyFor(session.uid, { set: from, keyNo });
        data = pad(concat(xor(newKey, oldKey), [version], crc32NewKey(newKey)));
      }
    }
    return this.give(cbcEncrypt(session.enc, ecb(session.enc, ivInput), data));
  }

  decrypt(ivInput: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    const session = this.open();
    return this.give(cbcDecrypt(session.enc, ecb(session.enc, ivInput), ciphertext));
  }

  endSession(): void {
    this.session = null;
    this.pending = null;
  }

  hasKeys(uid: string): boolean {
    return this.keychain.has(uid);
  }

  makeKeys(uid: string): void {
    this.keychain.set(uid, { master: this.random(16), file: this.random(16), seal: this.random(32) });
  }

  forgetKeys(uid: string): void {
    this.keychain.delete(uid);
  }

  sealPhantomKey(uid: string): Uint8Array {
    const saved = this.keychain.get(uid);
    if (!saved || !this.held) {
      throw new Error('no Phantom Key is held');
    }
    const nonce = this.random(12);
    const cipher = createCipheriv('aes-256-gcm', saved.seal, nonce);
    cipher.setAAD(Buffer.from(uid));
    const body = Buffer.concat([cipher.update(Buffer.from(this.held, 'utf8')), cipher.final()]);
    return this.give(concat(nonce, body, cipher.getAuthTag()));
  }

  openPhantomKey(uid: string, sealed: Uint8Array): void {
    const saved = this.keychain.get(uid);
    if (!saved) {
      throw new Error('no keys saved for this card');
    }
    const decipher = createDecipheriv('aes-256-gcm', saved.seal, sealed.slice(0, 12));
    decipher.setAAD(Buffer.from(uid));
    decipher.setAuthTag(sealed.slice(sealed.length - 16));
    this.opened = Buffer.concat([decipher.update(sealed.slice(12, sealed.length - 16)), decipher.final()]).toString('utf8');
  }

  /** Every secret this vault knows. */
  secrets(): Uint8Array[] {
    const saved = [...this.keychain.values()].flatMap((keys) => [keys.master, keys.file, keys.seal]);
    const words = this.held ? [new Uint8Array(Buffer.from(this.held, 'utf8'))] : [];
    return [...saved, ...this.sessionKeysSeen, ...words];
  }
}

/** Whether `needle` appears anywhere in `haystack`. */
export function contains(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i + needle.length <= haystack.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

const OK = [0x91, 0x00];
const MORE = [0x91, 0xaf];

function status(code: number): Uint8Array {
  return Uint8Array.of(0x91, code);
}

/** An NTAG 424 DNA, from its datasheet. */
export class FakeNtag424 {
  uid = GENUINE_UID;
  signature = GENUINE_SIGNATURE;
  keys: Uint8Array[] = Array.from({ length: 5 }, () => new Uint8Array(16));
  keyVersions = [0, 0, 0, 0, 0];
  fileSettings = fromHex('00E0EE');
  file = new Uint8Array(256);
  /** Every command the phone sent. */
  sent: Uint8Array[] = [];
  /** Called before each command; throw to stand for the card moving away. */
  before: (apdu: Uint8Array) => void = () => {};
  random: (length: number) => Uint8Array = (length) => new Uint8Array(randomBytes(length));

  private frame: 'none' | 'version2' | 'version3' | 'auth2' = 'none';
  private challenge: { keyNo: number; rndB: Uint8Array } | null = null;
  private auth: { keyNo: number; enc: Uint8Array; mac: Uint8Array; ti: Uint8Array; counter: number } | null = null;

  async transceive(apdu: Uint8Array): Promise<Uint8Array> {
    this.before(apdu);
    this.sent.push(apdu);
    return this.answer(apdu);
  }

  get authenticated(): boolean {
    return this.auth !== null;
  }

  private answer(apdu: Uint8Array): Uint8Array {
    if (apdu[0] === 0x00 && apdu[1] === 0xa4) {
      this.auth = null;
      this.frame = 'none';
      return equalBytes(apdu.slice(5, 5 + apdu[4]), fromHex('D2760000850101')) ? Uint8Array.of(0x90, 0x00) : Uint8Array.of(0x6a, 0x82);
    }
    if (apdu[0] !== 0x90 || apdu[2] !== 0 || apdu[3] !== 0 || apdu[apdu.length - 1] !== 0) {
      return Uint8Array.of(0x6e, 0x00);
    }
    const command = apdu[1];
    const data = apdu.length > 5 ? apdu.slice(5, 5 + apdu[4]) : new Uint8Array(0);
    if (apdu.length > 5 && apdu.length !== 6 + apdu[4]) {
      return status(0x7e);
    }
    const frame = this.frame;
    this.frame = 'none';
    switch (command) {
      case 0x60:
        this.frame = 'version2';
        return concat(fromHex('04040230001105'), MORE);
      case 0xaf:
        if (frame === 'version2') {
          this.frame = 'version3';
          return concat(fromHex('04040201021105'), MORE);
        }
        if (frame === 'version3') {
          return concat(this.uid, fromHex('CF39A14940'), [0x04, 0x22], OK);
        }
        if (frame === 'auth2') {
          return this.authPart2(data);
        }
        return status(0xca);
      case 0x3c:
        return this.auth ? status(0x9d) : concat(this.signature, OK);
      case 0x71: {
        this.auth = null;
        const keyNo = data[0];
        if (keyNo > 4) return status(0x40);
        const rndB = this.random(16);
        this.challenge = { keyNo, rndB };
        this.frame = 'auth2';
        return concat(cbcEncrypt(this.keys[keyNo], ZERO_KEY, rndB), MORE);
      }
      case 0x5f:
      case 0xc4:
        return this.secured(command, data, 1);
      case 0x8d:
      case 0xad:
        return this.fileCommand(command, data);
      default:
        return status(0x1c);
    }
  }

  private authPart2(data: Uint8Array): Uint8Array {
    const challenge = this.challenge;
    this.challenge = null;
    if (!challenge || data.length !== 32) return status(0x7e);
    const key = this.keys[challenge.keyNo];
    const plain = cbcDecrypt(key, ZERO_KEY, data);
    const rndA = plain.slice(0, 16);
    if (!equalBytes(plain.slice(16), rotateLeft(challenge.rndB))) {
      return status(0xae);
    }
    const ti = this.random(4);
    this.auth = { keyNo: challenge.keyNo, ...sessionKeys(key, rndA, challenge.rndB), ti, counter: 0 };
    return concat(cbcEncrypt(key, ZERO_KEY, concat(ti, rotateLeft(rndA), new Uint8Array(12))), OK);
  }

  /** Checks the MAC of a Full command and returns its header and decrypted data. */
  private open(command: number, data: Uint8Array, headerBytes: number): { header: Uint8Array; plain: Uint8Array } | Uint8Array {
    const auth = this.auth;
    if (!auth) return status(0xae);
    const header = data.slice(0, headerBytes);
    const encrypted = data.slice(headerBytes, data.length - 8);
    const mac = data.slice(data.length - 8);
    const input = concat([command], le16(auth.counter), auth.ti, header, encrypted);
    if (!equalBytes(truncateMac(cmac(auth.mac, input)), mac)) {
      this.auth = null;
      return status(0x1e);
    }
    if (encrypted.length === 0) {
      return { header, plain: new Uint8Array(0) };
    }
    const iv = ecb(auth.enc, concat([0xa5, 0x5a], auth.ti, le16(auth.counter), new Uint8Array(8)));
    try {
      return { header, plain: unpad(cbcDecrypt(auth.enc, iv, encrypted)) };
    } catch {
      this.auth = null;
      return status(0x1e);
    }
  }

  private macAnswer(body: Uint8Array = new Uint8Array(0)): Uint8Array {
    const auth = this.auth!;
    auth.counter += 1;
    let out = body;
    if (body.length > 0) {
      const iv = ecb(auth.enc, concat([0x5a, 0xa5], auth.ti, le16(auth.counter), new Uint8Array(8)));
      out = cbcEncrypt(auth.enc, iv, pad(body));
    }
    const mac = truncateMac(cmac(auth.mac, concat([0x00], le16(auth.counter), auth.ti, out)));
    return concat(out, mac, OK);
  }

  private secured(command: number, data: Uint8Array, headerBytes: number): Uint8Array {
    const opened = this.open(command, data, headerBytes);
    if (opened instanceof Uint8Array) return opened;
    const auth = this.auth!;
    const { header, plain } = opened;
    if (command === 0x5f) {
      if (header[0] !== 0x02 || plain.length !== 3) return status(0x9e);
      if (auth.keyNo !== (this.fileSettings[1] & 0x0f)) return status(0x9d);
      this.fileSettings = plain;
      return this.macAnswer();
    }
    // ChangeKey: only the application master key (0) changes keys.
    const keyNo = header[0];
    if (auth.keyNo !== 0) return status(0x9d);
    if (keyNo === auth.keyNo) {
      if (plain.length !== 17) return status(0x7e);
      this.keys[keyNo] = plain.slice(0, 16);
      this.keyVersions[keyNo] = plain[16];
      this.auth = null;
      return Uint8Array.from(OK);
    }
    if (plain.length !== 21) return status(0x7e);
    const newKey = xor(plain.slice(0, 16), this.keys[keyNo]);
    if (!equalBytes(crc32NewKey(newKey), plain.slice(17, 21))) {
      this.auth = null;
      return status(0x1e);
    }
    this.keys[keyNo] = newKey;
    this.keyVersions[keyNo] = plain[16];
    return this.macAnswer();
  }

  private fileCommand(command: number, data: Uint8Array): Uint8Array {
    const settings = this.fileSettings;
    const mode = settings[0] & 0x03;
    const readWrite = settings[1] >> 4;
    const read = settings[2] >> 4;
    const write = settings[2] & 0x0f;
    const right = command === 0xad ? read : write;
    const range = (header: Uint8Array) => ({
      fileNo: header[0],
      offset: header[1] | (header[2] << 8) | (header[3] << 16),
      length: header[4] | (header[5] << 8) | (header[6] << 16),
    });
    if (mode === 0x00) {
      // Plain, free access only, and only unauthenticated in this double.
      if (this.auth || (right !== 0xe && readWrite !== 0xe)) return status(0x9d);
      const { fileNo, offset, length } = range(data);
      if (fileNo !== 0x02 || offset + length > this.file.length) return status(0xbe);
      if (command === 0x8d) {
        if (data.length !== 7 + length) return status(0x7e);
        this.file.set(data.slice(7), offset);
        return Uint8Array.from(OK);
      }
      return concat(this.file.slice(offset, offset + length), OK);
    }
    const auth = this.auth;
    if (!auth || (auth.keyNo !== right && auth.keyNo !== readWrite)) return status(0x9d);
    const opened = this.open(command, data, 7);
    if (opened instanceof Uint8Array) return opened;
    const { fileNo, offset, length } = range(opened.header);
    if (fileNo !== 0x02 || offset + length > this.file.length) return status(0xbe);
    if (command === 0x8d) {
      if (opened.plain.length !== length) return status(0x7e);
      this.file.set(opened.plain, offset);
      return this.macAnswer();
    }
    return this.macAnswer(this.file.slice(offset, offset + length));
  }
}
