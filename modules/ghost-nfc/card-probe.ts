// Speed test of a Java Card over Core NFC, against the probe applet in
// tools/card-probe (a throwaway measurement applet, never a product applet).
// It times the card-side work that loading GHOST onto a bearer card needs
// (docs/bearer-card-spec.md), checks every answer against known values, and
// checks whether answers longer than 256 bytes get through. Nothing secret
// crosses: the probe holds no key and every input is a fixed test value.
//
// The APDU framing and the run are here, apart from the reader, so they are
// tested without a card (__tests__/card-probe.test.ts).
import { requireOptionalNativeModule } from 'expo';

import type { GhostNfcNative } from './index';
import type { Tag } from './secure-messaging';

/** The probe applet's AID; it must also be in the app's ISO 7816 select identifiers. */
export const PROBE_AID = 'A00000084750524F4201';

/** Spec budgets, card on the phone (docs/bearer-card-spec.md). */
export const BUDGET_MS = { make: 10_000, check: 3_000, open: 3_000 } as const;

/** Make's Keccak-f[1600] permutations: as specified, and with the commit-data digest on native SHA-256. */
export const MAKE_PERMUTATIONS = { asSpecified: 14, recommended: 10 } as const;
/** Open's permutations as specified: the open-code hash and the open key. */
export const OPEN_PERMUTATIONS = 2;
/** Atomic write, digest and I/O at Make, estimated over contact. */
export const MAKE_OVERHEAD_MS = 200;
/** Bytes a Check sends back: the statement, the LMS signature and the certificate, about. */
export const CHECK_ANSWER_BYTES = 2_600;

// Known answers, computed off the card with standard implementations.
const SHA3_INPUT = 'ghost-card-probe';
const SHA3_EXPECTED = '44095cad84b63d5b6d63521087c0db05c3f6007d31843085f9511715f0582727';
/** ChaCha20-Poly1305, key 00..1f, nonce 00..0b, 352-byte body (byte i = i), 40-byte AAD (0xA0 + i). */
const SEAL_TAG_EXPECTED = 'aa10fb34fd934a6d3c37926b1fbc6679';
const SEAL_CT_EXPECTED = '89fa0a032d12a347bf8a35f89410006c';
/** SHA-256 of the 1,000-byte extended command's data (byte i = 7i mod 256). */
const EXT_IN_EXPECTED = '89f4ff56a25dd1db06a4ce6033603775d705fb96f30f8693733fef602a1ca532';
/** SHA-256 of the 16 bytes 0xCD sent with each long-answer request. */
const EXT_SMALL_EXPECTED = 'c0a265d5eaedd3be7ff118927bfcc5d53723bca9443650383a2a47223843ed87';

const INS = {
  nop: 0x00,
  info: 0x01,
  sha256Loop: 0x10,
  keccakPlainLoop: 0x20,
  keccakFastLoop: 0x24,
  sha3Fast: 0x25,
  sealFast: 0x32,
  lmsSign: 0x40,
  extended: 0x50,
} as const;

const INFO_NAMES = [
  'SHA-256',
  'SHA-512',
  'SHA3-256',
  'SHA3-512',
  'AES-CBC',
  'AES-CTR',
  'AES-GCM',
  'AES-CCM',
  'AES-256 key',
  'AES-CMAC',
  'HMAC-SHA256',
  'SecureRandom',
  'TRNG',
  'KeyGen RNG',
  'RAM int arrays',
] as const;

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * One command APDU, CLA 0x80 unless given. Short form when the data fits in
 * 255 bytes and the expected answer in 256; otherwise extended form (Lc and
 * Le as two bytes after a 0x00 marker). `le` 0 means no answer expected.
 */
export function command(ins: number, p1p2: number, data: Uint8Array = new Uint8Array(0), le = 0, cla = 0x80): Uint8Array {
  const header = [cla, ins, (p1p2 >> 8) & 0xff, p1p2 & 0xff];
  const extended = data.length > 255 || le > 256;
  const parts: number[] = [...header];
  if (extended) {
    parts.push(0x00);
    if (data.length > 0) {
      parts.push((data.length >> 8) & 0xff, data.length & 0xff);
    }
  } else if (data.length > 0) {
    parts.push(data.length);
  }
  const head = Uint8Array.from(parts);
  let tail: number[] = [];
  if (le > 0) {
    tail = extended ? [(le >> 8) & 0xff, le & 0xff] : [le === 256 ? 0x00 : le];
  }
  const out = new Uint8Array(head.length + data.length + tail.length);
  out.set(head, 0);
  out.set(data, head.length);
  out.set(tail, head.length + data.length);
  return out;
}

export function selectProbe(): Uint8Array {
  return command(0xa4, 0x0400, fromHex(PROBE_AID), 256, 0x00);
}

/** The status word of a raw answer (data then SW1 SW2). */
function sw(answer: Uint8Array): number {
  return answer.length < 2 ? -1 : (answer[answer.length - 2] << 8) | answer[answer.length - 1];
}

function data(answer: Uint8Array): Uint8Array {
  return answer.slice(0, Math.max(0, answer.length - 2));
}

function hexSw(value: number): string {
  return value < 0 ? 'none' : value.toString(16).toUpperCase().padStart(4, '0');
}

function u32(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] << 24) >>> 0) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3];
}

export type LongAnswer = { asked: number; ok: boolean; got: number; ms: number | null; note: string };

export type ProbeReport = {
  /** Lines of algorithm support and free memory, as the card reports them. */
  info: string[];
  noopMs: number;
  sha256Ms: number;
  keccakPlainMs: number;
  keccakFastMs: number;
  sha3Matches: boolean;
  sealMs: number;
  sealMatches: boolean;
  lmsSignMs: number;
  lmsHashes: number;
  extendedIn: { ok: boolean; ms: number | null; note: string };
  longAnswers: LongAnswer[];
  /** The steps that failed, in order; empty when every step ran. */
  problems: string[];
};

export type Estimates = {
  makeAsSpecifiedMs: number;
  makeRecommendedMs: number;
  makePrecomputedMs: number;
  checkMs: number;
  openMs: number;
};

/** Make, Check and Open from the measured parts, as docs/j3r180-measurements.md adds them up. */
export function estimate(report: ProbeReport): Estimates {
  const k = report.keccakFastMs;
  const perByte = longAnswerMsPerByte(report);
  return {
    makeAsSpecifiedMs: MAKE_PERMUTATIONS.asSpecified * k + report.sealMs + report.lmsSignMs + MAKE_OVERHEAD_MS,
    makeRecommendedMs: MAKE_PERMUTATIONS.recommended * k + report.sealMs + MAKE_OVERHEAD_MS,
    makePrecomputedMs: k + report.sealMs + report.lmsSignMs + MAKE_OVERHEAD_MS,
    checkMs: report.lmsSignMs + CHECK_ANSWER_BYTES * perByte,
    openMs: OPEN_PERMUTATIONS * k + 100,
  };
}

/** Time per byte of answer, from the longest answer that came back; 0.1 ms per byte if none did. */
function longAnswerMsPerByte(report: ProbeReport): number {
  const best = report.longAnswers.filter((a) => a.ok && a.ms !== null).sort((a, b) => b.got - a.got)[0];
  if (!best || best.ms === null || best.got === 0) {
    return 0.1;
  }
  return Math.max(0, best.ms - report.noopMs) / best.got;
}

type Clock = () => number;

function defaultClock(): number {
  const perf = (globalThis as { performance?: { now?: () => number } }).performance;
  return perf?.now ? perf.now() : Date.now();
}

class StepFailed extends Error {}

/**
 * Runs the whole test on a connected card: select, report, then each timed
 * step. Long answers come last, since an answer the phone cannot take may end
 * the tap. `progress` is told each step's name as it starts.
 */
export async function runProbe(tag: Tag, now: Clock = defaultClock, progress: (step: string) => void = () => {}): Promise<ProbeReport> {
  const problems: string[] = [];

  async function send(apdu: Uint8Array, step: string): Promise<{ answer: Uint8Array; ms: number }> {
    const start = now();
    let answer: Uint8Array;
    try {
      answer = await tag.transceive(apdu);
    } catch {
      throw new StepFailed(`${step}: the card stopped answering`);
    }
    const ms = now() - start;
    if (sw(answer) !== 0x9000) {
      throw new StepFailed(`${step}: card answered ${hexSw(sw(answer))}`);
    }
    return { answer: data(answer), ms };
  }

  async function timed(ins: number, count: number, step: string): Promise<number> {
    return (await send(command(ins, count), step)).ms;
  }

  const report: ProbeReport = {
    info: [],
    noopMs: NaN,
    sha256Ms: NaN,
    keccakPlainMs: NaN,
    keccakFastMs: NaN,
    sha3Matches: false,
    sealMs: NaN,
    sealMatches: false,
    lmsSignMs: NaN,
    lmsHashes: NaN,
    extendedIn: { ok: false, ms: null, note: 'not run' },
    longAnswers: [],
    problems,
  };

  try {
    progress('Selecting the probe');
    await send(selectProbe(), 'select the probe');

    progress('Reading what the card offers');
    const info = (await send(command(INS.info, 0, undefined, 256), 'info')).answer;
    report.info = INFO_NAMES.map((name, i) => `${name}: ${info[i] === 1 ? 'yes' : info[i] === 0 ? 'no' : 'error'}`);
    if (info.length >= INFO_NAMES.length + 12) {
      const o = INFO_NAMES.length;
      report.info.push(`free persistent: ${u32(info, o)} bytes`, `free RAM: ${u32(info, o + 4)} bytes (reset), ${u32(info, o + 8)} bytes (deselect)`);
    }

    progress('Round trip');
    const nops: number[] = [];
    for (let i = 0; i < 10; i++) {
      nops.push(await timed(INS.nop, 0, 'no-op'));
    }
    nops.sort((a, b) => a - b);
    const nop = nops[5];
    report.noopMs = nop;

    progress('SHA-256 ×100');
    report.sha256Ms = Math.max(0, (await timed(INS.sha256Loop, 100, 'SHA-256')) - nop) / 100;

    progress('SHA3-256 answer');
    const sha3 = (await send(command(INS.sha3Fast, 0, Uint8Array.from(SHA3_INPUT, (c) => c.charCodeAt(0)), 32), 'SHA3-256')).answer;
    report.sha3Matches = toHex(sha3) === SHA3_EXPECTED;
    if (!report.sha3Matches) {
      problems.push('SHA3-256: the card\'s answer is wrong');
    }

    progress('Keccak, fast');
    const k1 = await timed(INS.keccakFastLoop, 1, 'Keccak (fast)');
    const k5 = await timed(INS.keccakFastLoop, 5, 'Keccak (fast)');
    report.keccakFastMs = Math.max(0, k5 - k1) / 4;

    progress('Keccak, plain loop');
    report.keccakPlainMs = Math.max(0, (await timed(INS.keccakPlainLoop, 1, 'Keccak (plain)')) - nop);

    progress('Note seal');
    const seal = await send(command(INS.sealFast, 1, undefined, 32), 'seal');
    report.sealMatches = toHex(seal.answer.slice(0, 16)) === SEAL_TAG_EXPECTED && toHex(seal.answer.slice(16, 32)) === SEAL_CT_EXPECTED;
    if (!report.sealMatches) {
      problems.push('seal: the card\'s ciphertext or tag is wrong');
    }
    const s3 = await timed(INS.sealFast, 3, 'seal');
    report.sealMs = Math.max(0, s3 - seal.ms) / 2;

    progress('LMS signatures');
    const signs: number[] = [];
    let hashes = 0;
    for (let i = 0; i < 3; i++) {
      const sign = await send(command(INS.lmsSign, 1, undefined, 4), 'LMS sign');
      signs.push(Math.max(0, sign.ms - nop));
      hashes += u32(sign.answer, 0);
    }
    report.lmsSignMs = signs.reduce((a, b) => a + b, 0) / signs.length;
    report.lmsHashes = Math.round(hashes / signs.length);
  } catch (error) {
    problems.push(error instanceof StepFailed ? error.message : String(error));
    return report;
  }

  progress('Extended command, 1,000 bytes');
  const big = new Uint8Array(1000);
  for (let i = 0; i < big.length; i++) {
    big[i] = (i * 7) & 0xff;
  }
  try {
    const ext = await send(command(INS.extended, 34, big, 34), 'extended command');
    const ok = toHex(ext.answer.slice(0, 32)) === EXT_IN_EXPECTED && ((ext.answer[32] << 8) | ext.answer[33]) === 1000;
    report.extendedIn = { ok, ms: ext.ms, note: ok ? 'card hashed all 1,000 bytes right' : 'the card\'s hash of the data is wrong' };
  } catch (error) {
    report.extendedIn = { ok: false, ms: null, note: error instanceof Error ? error.message : String(error) };
  }

  const small = new Uint8Array(16).fill(0xcd);
  for (const asked of [256, 257, 1000]) {
    progress(`Answer of ${asked} bytes`);
    try {
      const long = await send(command(INS.extended, asked, small, asked), `answer of ${asked} bytes`);
      const a = long.answer;
      const ok =
        a.length === asked &&
        toHex(a.slice(0, 32)) === EXT_SMALL_EXPECTED &&
        a.slice(34).every((b) => b === 0x5a);
      report.longAnswers.push({ asked, ok, got: a.length, ms: long.ms, note: ok ? 'all bytes right' : `got ${a.length} bytes, not as sent` });
    } catch (error) {
      report.longAnswers.push({ asked, ok: false, got: 0, ms: null, note: error instanceof Error ? error.message : String(error) });
    }
  }
  return report;
}

function ms(value: number): string {
  if (!Number.isFinite(value)) {
    return 'not measured';
  }
  return value >= 1000 ? `${(value / 1000).toFixed(2)} s` : `${value.toFixed(value < 10 ? 2 : 0)} ms`;
}

function verdict(value: number, budget: number): string {
  if (!Number.isFinite(value)) {
    return '';
  }
  return value <= budget ? ' (pass)' : ' (over budget)';
}

/** The report as plain text lines, for the screen and for copying into the doc. */
export function describeProbe(report: ProbeReport): string {
  const e = estimate(report);
  const complete = [report.keccakFastMs, report.sealMs, report.lmsSignMs].every(Number.isFinite);
  const lines = [
    `round trip (no-op): ${ms(report.noopMs)}`,
    `SHA-256, native: ${ms(report.sha256Ms)} per call`,
    `Keccak-f[1600], fast: ${ms(report.keccakFastMs)} per permutation${report.sha3Matches ? ' (SHA3-256 right)' : ''}`,
    `Keccak-f[1600], plain loop: ${ms(report.keccakPlainMs)}`,
    `note seal: ${ms(report.sealMs)}${report.sealMatches ? ' (tag right)' : ''}`,
    `LMS sign: ${ms(report.lmsSignMs)} (${Number.isFinite(report.lmsHashes) ? report.lmsHashes : '?'} SHA-256 calls)`,
    `extended command, 1,000 bytes: ${report.extendedIn.ok ? 'yes' : 'no'}${report.extendedIn.ms === null ? '' : `, ${ms(report.extendedIn.ms)}`} (${report.extendedIn.note})`,
    ...report.longAnswers.map(
      (a) => `answer of ${a.asked} bytes: ${a.ok ? 'yes' : 'no'}${a.ms === null ? '' : `, ${ms(a.ms)}`} (${a.note})`,
    ),
  ];
  if (complete) {
    lines.push(
      '',
      'estimates over NFC',
      `Make, as specified: ${ms(e.makeAsSpecifiedMs)}${verdict(e.makeAsSpecifiedMs, BUDGET_MS.make)}`,
      `Make, recommended: ${ms(e.makeRecommendedMs)}${verdict(e.makeRecommendedMs, BUDGET_MS.make)}`,
      `Make, precomputed: ${ms(e.makePrecomputedMs)}${verdict(e.makePrecomputedMs, BUDGET_MS.make)}`,
      `Check: ${ms(e.checkMs)}${verdict(e.checkMs, BUDGET_MS.check)}`,
      `Open: ${ms(e.openMs)}${verdict(e.openMs, BUDGET_MS.open)}`,
    );
  }
  if (report.problems.length > 0) {
    lines.push('', 'problems', ...report.problems);
  }
  if (report.info.length > 0) {
    lines.push('', 'card', ...report.info);
  }
  return lines.join('\n');
}

export class ProbeCancelled extends Error {
  constructor() {
    super('The card was not tapped.');
    this.name = 'ProbeCancelled';
  }
}

/** Opens a reader session, runs the probe on the card tapped, and closes it. */
export async function probeCardOverNfc(progress: (step: string) => void = () => {}): Promise<ProbeReport> {
  const nfc = requireOptionalNativeModule<GhostNfcNative>('GhostNfc');
  if (!nfc || !nfc.isSupported()) {
    throw new Error('This iPhone cannot read cards.');
  }
  try {
    await nfc.beginSession('Hold the test card flat on the top of the iPhone, and keep it still for about 20 seconds.');
  } catch (error) {
    if ((error as { code?: string } | null)?.code === 'ERR_NFC_CANCELLED') {
      throw new ProbeCancelled();
    }
    throw error;
  }
  try {
    const report = await runProbe({ transceive: (apdu) => nfc.transceive(apdu) }, defaultClock, progress);
    if (report.problems.length > 0 && !Number.isFinite(report.lmsSignMs)) {
      nfc.endSession(null, 'The test stopped. Check the screen.');
    } else {
      nfc.endSession('Done. The timings are on the screen.', null);
    }
    return report;
  } catch (error) {
    nfc.endSession(null, 'The card could not be read. Hold it still and try again.');
    throw error;
  }
}
