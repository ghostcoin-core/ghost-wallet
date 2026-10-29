// NTAG 424 DNA command framing, from NXP's public NTAG 424 DNA datasheet
// (NT4H2421Gx) and application note AN12196.
//
// Native commands go in an ISO/IEC 7816-4 wrapper: CLA 0x90, the command
// code as INS, P1 = P2 = 0, Lc and the data when there is data, Le = 0. The
// chip answers with the data, then SW1 = 0x91 and SW2 = its status. Nothing
// here holds a key: the bytes framed here are public, or already encrypted by
// the native vault.

/** The NDEF application's DF name (ISO SelectFile by name). */
export const NDEF_APPLICATION = fromHex('D2760000850101');

export const COMMAND = {
  getVersion: 0x60,
  readSig: 0x3c,
  authenticateEV2First: 0x71,
  additionalFrame: 0xaf,
  changeKey: 0xc4,
  changeFileSettings: 0x5f,
  writeData: 0x8d,
  readData: 0xad,
} as const;

export const STATUS = {
  ok: 0x00,
  more: 0xaf,
  /** Read_Sig answers 0x90 on some chip revisions. */
  okAlternative: 0x90,
  integrityError: 0x1e,
  lengthError: 0x7e,
  permissionDenied: 0x9d,
  parameterError: 0x9e,
  authenticationError: 0xae,
  boundaryError: 0xbe,
  noSuchKey: 0x40,
  commandAborted: 0xca,
  fileNotFound: 0xf0,
  memoryError: 0xee,
} as const;

/** Largest Lc of a short APDU. */
export const MAX_COMMAND_DATA = 255;

/** A chip status other than the one the command expects. */
export class ChipError extends Error {
  readonly sw1: number;
  readonly sw2: number;

  constructor(command: string, sw1: number, sw2: number) {
    super(`${command} answered ${hexByte(sw1)}${hexByte(sw2)}`);
    this.name = 'ChipError';
    this.sw1 = sw1;
    this.sw2 = sw2;
  }

  /** Whether the chip refused the key it was asked to authenticate with. */
  get authentication(): boolean {
    return this.sw1 === 0x91 && this.sw2 === STATUS.authenticationError;
  }
}

/** A response whose MAC or length is not what the chip must send. */
export class IntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IntegrityError';
  }
}

export type Response = { data: Uint8Array; sw1: number; sw2: number };

/** ISOSelectFile of the NDEF application by its DF name, as in AN12196. Selecting drops any authentication. */
export function selectNdefApplication(): Uint8Array {
  return concat([0x00, 0xa4, 0x04, 0x00, NDEF_APPLICATION.length], NDEF_APPLICATION, [0x00]);
}

/** A native command in its ISO/IEC 7816-4 wrapper. */
export function wrapNative(command: number, data: Uint8Array = new Uint8Array(0)): Uint8Array {
  if (data.length > MAX_COMMAND_DATA) {
    throw new RangeError(`command ${hexByte(command)} carries ${data.length} bytes; at most ${MAX_COMMAND_DATA} fit`);
  }
  if (data.length === 0) {
    return Uint8Array.of(0x90, command, 0x00, 0x00, 0x00);
  }
  return concat([0x90, command, 0x00, 0x00, data.length], data, [0x00]);
}

/** The data and status words of a raw response. */
export function splitResponse(raw: Uint8Array): Response {
  if (raw.length < 2) {
    throw new IntegrityError('the card answered without a status');
  }
  return { data: raw.slice(0, raw.length - 2), sw1: raw[raw.length - 2], sw2: raw[raw.length - 1] };
}

/** The data of a native response whose status is one of `allowed`. */
export function expectNative(name: string, response: Response, allowed: readonly number[] = [STATUS.ok]): Uint8Array {
  if (response.sw1 !== 0x91 || !allowed.includes(response.sw2)) {
    throw new ChipError(name, response.sw1, response.sw2);
  }
  return response.data;
}

/** The data of an ISO response that must end in 90 00. */
export function expectIso(name: string, response: Response): Uint8Array {
  if (response.sw1 !== 0x90 || response.sw2 !== 0x00) {
    throw new ChipError(name, response.sw1, response.sw2);
  }
  return response.data;
}

/** The FileNo, Offset and Length header of ReadData and WriteData (both little endian, 3 bytes). */
export function fileRangeHeader(fileNo: number, offset: number, length: number): Uint8Array {
  return concat([fileNo], le24(offset), le24(length));
}

/**
 * The access rights of a file: AR1 = Read&Write << 4 | Change, AR2 = Read << 4 | Write.
 * A key number 0 to 4, 0xE for free access, 0xF for none.
 */
export function accessRights(rights: { readWrite: number; change: number; read: number; write: number }): Uint8Array {
  for (const value of Object.values(rights)) {
    if (!Number.isInteger(value) || value < 0 || value > 0xf) {
      throw new RangeError('an access right is one nibble');
    }
  }
  return Uint8Array.of((rights.readWrite << 4) | rights.change, (rights.read << 4) | rights.write);
}

/** The communication mode bits of a file's FileOption. */
export const COMM_MODE = { plain: 0x00, mac: 0x01, full: 0x03 } as const;

/** ISO/IEC 9797-1 padding method 2: 0x80, then zeros up to a 16-byte block. Always adds at least one byte. */
export function pad(data: Uint8Array): Uint8Array {
  const length = (Math.floor(data.length / 16) + 1) * 16;
  const out = new Uint8Array(length);
  out.set(data);
  out[data.length] = 0x80;
  return out;
}

/** Removes ISO/IEC 9797-1 method 2 padding. */
export function unpad(data: Uint8Array): Uint8Array {
  let end = data.length - 1;
  while (end >= 0 && data[end] === 0x00) {
    end -= 1;
  }
  if (end < 0 || data[end] !== 0x80 || data.length - end > 16) {
    throw new IntegrityError('the decrypted response is not padded');
  }
  return data.slice(0, end);
}

/** The 8-byte MAC the chip uses: bytes 1, 3, 5, ... 15 of the 16-byte CMAC. */
export function truncateMac(full: Uint8Array): Uint8Array {
  if (full.length !== 16) {
    throw new RangeError('a CMAC is 16 bytes');
  }
  return Uint8Array.from({ length: 8 }, (_, i) => full[2 * i + 1]);
}

export function le16(value: number): Uint8Array {
  return Uint8Array.of(value & 0xff, (value >> 8) & 0xff);
}

export function le24(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffff) {
    throw new RangeError('not a 3-byte length or offset');
  }
  return Uint8Array.of(value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff);
}

export function concat(...parts: (Uint8Array | readonly number[])[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let difference = 0;
  for (let i = 0; i < a.length; i += 1) {
    difference |= a[i] ^ b[i];
  }
  return difference === 0;
}

export function fromHex(text: string): Uint8Array {
  const clean = text.replace(/\s+/g, '');
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
    throw new RangeError('not hex');
  }
  return Uint8Array.from({ length: clean.length / 2 }, (_, i) => parseInt(clean.slice(2 * i, 2 * i + 2), 16));
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, hexByte).join('');
}

function hexByte(value: number): string {
  return value.toString(16).toUpperCase().padStart(2, '0');
}
