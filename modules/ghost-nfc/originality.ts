// The NXP originality signature of an NTAG 424 DNA: ECDSA over secp224r1,
// signed by NXP at the factory over the chip's 7-byte UID. The UID is not
// hashed: it is the ECDSA integer z directly. Read_Sig returns r || s, 28
// bytes each, big endian. NXP's public key and the test vector are those of
// AN12196 (table 30). Everything here is public; no key of the app or of the
// card is involved.
import { COMMAND, STATUS, expectNative, splitResponse, wrapNative } from './apdu';
import type { Tag } from './secure-messaging';

/** NXP's NTAG 424 DNA originality public key, SEC1 uncompressed. */
export const NXP_ORIGINALITY_PUBLIC_KEY =
  '048A9B380AF2EE1B98DC417FECC263F8449C7625CECE82D9B916C992DA209D68422B81EC20B65A66B5102A61596AF3379200599316A00A1410';

export const SIGNATURE_BYTES = 56;

// secp224r1 (SEC 2, NIST P-224).
const P = 0xffffffffffffffffffffffffffffffff000000000000000000000001n;
const A = P - 3n;
const N = 0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3dn;
const G: Point = {
  x: 0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21n,
  y: 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34n,
};
const B = 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4n;

type Point = { x: bigint; y: bigint } | null;

function mod(value: bigint, modulus: bigint): bigint {
  const result = value % modulus;
  return result >= 0n ? result : result + modulus;
}

function inverse(value: bigint, modulus: bigint): bigint {
  let [low, high] = [mod(value, modulus), modulus];
  let [lowCoefficient, highCoefficient] = [1n, 0n];
  while (low > 1n) {
    const ratio = high / low;
    [low, high] = [high - ratio * low, low];
    [lowCoefficient, highCoefficient] = [highCoefficient - ratio * lowCoefficient, lowCoefficient];
  }
  if (low !== 1n) {
    throw new RangeError('no inverse');
  }
  return mod(lowCoefficient, modulus);
}

function add(p: Point, q: Point): Point {
  if (p === null) return q;
  if (q === null) return p;
  if (p.x === q.x) {
    if (mod(p.y + q.y, P) === 0n) {
      return null;
    }
    const slope = mod(3n * p.x * p.x + A, P) * inverse(2n * p.y, P);
    return line(p, p, mod(slope, P));
  }
  const slope = mod(q.y - p.y, P) * inverse(q.x - p.x, P);
  return line(p, q, mod(slope, P));
}

function line(p: { x: bigint; y: bigint }, q: { x: bigint; y: bigint }, slope: bigint): Point {
  const x = mod(slope * slope - p.x - q.x, P);
  return { x, y: mod(slope * (p.x - x) - p.y, P) };
}

function multiply(scalar: bigint, point: Point): Point {
  let result: Point = null;
  let addend = point;
  let k = scalar;
  while (k > 0n) {
    if (k & 1n) {
      result = add(result, addend);
    }
    addend = add(addend, addend);
    k >>= 1n;
  }
  return result;
}

function toBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

function fromHexString(text: string): Uint8Array {
  return Uint8Array.from({ length: text.length / 2 }, (_, i) => parseInt(text.slice(2 * i, 2 * i + 2), 16));
}

function publicPoint(sec1: string): { x: bigint; y: bigint } {
  const bytes = fromHexString(sec1);
  if (bytes.length !== 57 || bytes[0] !== 0x04) {
    throw new RangeError('not an uncompressed P-224 point');
  }
  const point = { x: toBigInt(bytes.slice(1, 29)), y: toBigInt(bytes.slice(29)) };
  if (mod(point.y * point.y - (point.x * point.x * point.x + A * point.x + B), P) !== 0n) {
    throw new RangeError('the point is not on secp224r1');
  }
  return point;
}

/** Whether `signature` (r || s) is NXP's (or `publicKey`'s) originality signature over `uid`. */
export function verifyOriginality(uid: Uint8Array, signature: Uint8Array, publicKey = NXP_ORIGINALITY_PUBLIC_KEY): boolean {
  if (signature.length !== SIGNATURE_BYTES || uid.length === 0 || uid.length > 28) {
    return false;
  }
  const r = toBigInt(signature.slice(0, 28));
  const s = toBigInt(signature.slice(28));
  if (r <= 0n || r >= N || s <= 0n || s >= N) {
    return false;
  }
  const z = toBigInt(uid);
  const w = inverse(s, N);
  const point = add(multiply(mod(z * w, N), G), multiply(mod(r * w, N), publicPoint(publicKey)));
  return point !== null && mod(point.x, N) === r;
}

/** Read_Sig, unauthenticated: the 56-byte signature in plain. */
export async function readSignature(tag: Tag): Promise<Uint8Array> {
  const response = splitResponse(await tag.transceive(wrapNative(COMMAND.readSig, Uint8Array.of(0x00))));
  const signature = expectNative('Read_Sig', response, [STATUS.ok, STATUS.okAlternative]);
  if (signature.length !== SIGNATURE_BYTES) {
    throw new RangeError('Read_Sig returned a wrong-sized signature');
  }
  return signature;
}
