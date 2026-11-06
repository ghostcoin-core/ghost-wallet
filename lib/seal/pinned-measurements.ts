// The Seal builds the app trusts: the list of allowed Nitro enclave
// measurements, pinned in the app. Same format and rules as the published
// list `enclave/measurements.json` (and the Seal's own reader in
// `seal/src/measurements.rs`; both read `seal/tests/fixtures/measurements.json`
// in their tests):
//
//   {"version": 1, "builds": [{"name": ..., "released": "YYYY-MM-DD",
//     "pcr0": 96 hex, "pcr1": 96 hex, "pcr2": 96 hex, "status": "allowed" | "revoked"}]}
//
// A Seal is accepted only when its PCR0, PCR1 and PCR2 all equal one allowed
// build's. A revoked build is never accepted. The list is empty until the
// first build is published, and an empty list refuses every Seal.

/** The format version this reader accepts. */
export const MEASUREMENTS_VERSION = 1;
/** The most builds a list may hold. */
export const MAX_BUILDS = 256;
/** The longest build name. */
export const MAX_NAME_LENGTH = 64;

export type BuildStatus = 'allowed' | 'revoked';

export interface PublishedBuild {
  readonly name: string;
  readonly released: string;
  /** 96 lowercase hex digits (SHA-384). */
  readonly pcr0: string;
  readonly pcr1: string;
  readonly pcr2: string;
  readonly status: BuildStatus;
}

export interface MeasurementList {
  readonly version: 1;
  readonly builds: readonly PublishedBuild[];
}

export interface Measurements {
  readonly pcr0: string;
  readonly pcr1: string;
  readonly pcr2: string;
}

export type MeasurementCheck =
  | { ok: true; build: PublishedBuild }
  | { ok: false; reason: 'not-listed' | 'revoked' | 'debug-mode' | 'malformed' };

export class MeasurementListError extends Error {
  constructor(message: string) {
    super(`measurements list: ${message}`);
    this.name = 'MeasurementListError';
  }
}

const PCR = /^[0-9a-f]{96}$/;
const ZERO_PCR = /^0+$/;
const NAME = /^[A-Za-z0-9._-]+$/;

type Json = null | boolean | { number: string } | string | Json[] | Map<string, Json>;

/** A strict JSON reader: no duplicate keys, no trailing data, nesting at most 16 deep. */
function readJson(text: string): Json {
  let at = 0;
  const fail = (what: string): never => {
    throw new MeasurementListError(`not JSON: ${what}`);
  };
  const space = () => {
    while (at < text.length && ' \t\n\r'.includes(text[at])) {
      at += 1;
    }
  };
  const expect = (c: string) => {
    if (text[at] !== c) {
      fail(`expected ${c}`);
    }
    at += 1;
  };
  const string = (): string => {
    expect('"');
    let out = '';
    for (;;) {
      if (at >= text.length) {
        return fail('unterminated string');
      }
      const c = text[at];
      if (c === '"') {
        at += 1;
        return out;
      }
      if (c < ' ') {
        return fail('a control character in a string');
      }
      if (c !== '\\') {
        out += c;
        at += 1;
        continue;
      }
      const escape = text[at + 1];
      at += 2;
      const simple: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
      if (escape !== undefined && escape in simple) {
        out += simple[escape];
      } else if (escape === 'u') {
        const hex = text.slice(at, at + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
          return fail('bad escape');
        }
        out += String.fromCharCode(parseInt(hex, 16));
        at += 4;
      } else {
        return fail('bad escape');
      }
    }
  };
  const value = (depth: number): Json => {
    if (depth > 16) {
      return fail('nested too deep');
    }
    space();
    const c = text[at];
    if (c === '{') {
      at += 1;
      const fields = new Map<string, Json>();
      space();
      if (text[at] === '}') {
        at += 1;
        return fields;
      }
      for (;;) {
        space();
        const key = string();
        if (fields.has(key)) {
          return fail('a key appears twice in one object');
        }
        space();
        expect(':');
        fields.set(key, value(depth + 1));
        space();
        if (text[at] === ',') {
          at += 1;
        } else if (text[at] === '}') {
          at += 1;
          return fields;
        } else {
          return fail('expected , or }');
        }
      }
    }
    if (c === '[') {
      at += 1;
      const items: Json[] = [];
      space();
      if (text[at] === ']') {
        at += 1;
        return items;
      }
      for (;;) {
        items.push(value(depth + 1));
        space();
        if (text[at] === ',') {
          at += 1;
        } else if (text[at] === ']') {
          at += 1;
          return items;
        } else {
          return fail('expected , or ]');
        }
      }
    }
    if (c === '"') {
      return string();
    }
    for (const [word, result] of [
      ['true', true],
      ['false', false],
      ['null', null],
    ] as const) {
      if (text.startsWith(word, at)) {
        at += word.length;
        return result;
      }
    }
    const number = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(text.slice(at));
    if (number) {
      at += number[0].length;
      return { number: number[0] };
    }
    return fail('expected a value');
  };
  const result = value(0);
  space();
  if (at !== text.length) {
    fail('data after the end');
  }
  return result;
}

function object(value: Json, what: string): Map<string, Json> {
  if (!(value instanceof Map)) {
    throw new MeasurementListError(`${what} is not an object`);
  }
  return value;
}

function onlyKeys(fields: Map<string, Json>, keys: readonly string[], what: string) {
  for (const key of fields.keys()) {
    if (!keys.includes(key)) {
      throw new MeasurementListError(`${what} has an unknown field ${JSON.stringify(key)}`);
    }
  }
  for (const key of keys) {
    if (!fields.has(key)) {
      throw new MeasurementListError(`${what} has no ${key}`);
    }
  }
}

function text(value: Json | undefined, what: string): string {
  if (typeof value !== 'string') {
    throw new MeasurementListError(`${what} is not a string`);
  }
  return value;
}

function isDate(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) {
    return false;
  }
  const [year, month, day] = [Number(match[1]), Number(match[2]), Number(match[3])];
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  return year >= 2000 && days !== undefined && day >= 1 && day <= days;
}

function readBuild(entry: Json, index: number): PublishedBuild {
  const what = `build ${index}`;
  const fields = object(entry, what);
  onlyKeys(fields, ['name', 'released', 'pcr0', 'pcr1', 'pcr2', 'status'], what);
  const name = text(fields.get('name'), 'name');
  if (name.length === 0 || name.length > MAX_NAME_LENGTH || !NAME.test(name)) {
    throw new MeasurementListError(`${what}: a name is 1 to ${MAX_NAME_LENGTH} of a-z, A-Z, 0-9, '-', '.', '_'`);
  }
  const released = text(fields.get('released'), 'released');
  if (!isDate(released)) {
    throw new MeasurementListError(`${what}: released is not a YYYY-MM-DD date`);
  }
  const pcr = (key: 'pcr0' | 'pcr1' | 'pcr2') => {
    const value = text(fields.get(key), key);
    if (!PCR.test(value)) {
      throw new MeasurementListError(`${what}: ${key} is not 96 lowercase hex digits`);
    }
    if (ZERO_PCR.test(value)) {
      throw new MeasurementListError(`${what}: ${key} is all zeros (a debug-mode enclave)`);
    }
    return value;
  };
  const status = text(fields.get('status'), 'status');
  if (status !== 'allowed' && status !== 'revoked') {
    throw new MeasurementListError(`${what}: status ${JSON.stringify(status)} is not allowed or revoked`);
  }
  return { name, released, pcr0: pcr('pcr0'), pcr1: pcr('pcr1'), pcr2: pcr('pcr2'), status };
}

/** Reads a list in the published format; throws `MeasurementListError` on anything else. */
export function parseMeasurementList(json: string): MeasurementList {
  const top = object(readJson(json), 'the list');
  onlyKeys(top, ['version', 'builds'], 'the list');
  const version = top.get('version');
  if (version === null || typeof version !== 'object' || !('number' in version) || version.number !== '1') {
    throw new MeasurementListError(`version is not ${MEASUREMENTS_VERSION}`);
  }
  const entries = top.get('builds');
  if (!Array.isArray(entries)) {
    throw new MeasurementListError('builds is not an array');
  }
  if (entries.length > MAX_BUILDS) {
    throw new MeasurementListError(`more than ${MAX_BUILDS} builds`);
  }
  const builds: PublishedBuild[] = [];
  entries.forEach((entry, index) => {
    const build = readBuild(entry, index);
    if (builds.some((b) => b.name === build.name)) {
      throw new MeasurementListError(`build name ${build.name} is listed twice`);
    }
    if (builds.some((b) => b.pcr0 === build.pcr0)) {
      throw new MeasurementListError(`build ${build.name} repeats a listed PCR0`);
    }
    builds.push(build);
  });
  return { version: 1, builds };
}

/** Accepts `measured` only when PCR0, PCR1 and PCR2 all equal one allowed build's. */
export function checkMeasurements(list: MeasurementList, measured: Measurements): MeasurementCheck {
  const values = [measured.pcr0, measured.pcr1, measured.pcr2].map((v) => v.toLowerCase());
  if (!values.every((v) => PCR.test(v))) {
    return { ok: false, reason: 'malformed' };
  }
  if (values.some((v) => ZERO_PCR.test(v))) {
    return { ok: false, reason: 'debug-mode' };
  }
  const [pcr0, pcr1, pcr2] = values;
  const build = list.builds.find((b) => b.pcr0 === pcr0 && b.pcr1 === pcr1 && b.pcr2 === pcr2);
  if (!build) {
    return { ok: false, reason: 'not-listed' };
  }
  if (build.status !== 'allowed') {
    return { ok: false, reason: 'revoked' };
  }
  return { ok: true, build };
}

/**
 * The builds this app accepts. Empty until the first Seal build is published
 * (its PCRs come from a Nitro-capable builder): until then every Seal is
 * refused. Each entry must also be in `enclave/measurements.json`.
 */
export const PINNED_MEASUREMENTS: MeasurementList = parseMeasurementList(`{
  "version": 1,
  "builds": []
}`);
