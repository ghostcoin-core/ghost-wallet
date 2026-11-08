// Why a Seal region's attestation fetch failed, as the card screen says it:
// the native fetch (modules/ghost-nfc/ios/SealAttestation.swift) rejects with
// one code per cause, the relay (modules/ghost-nfc/relay.ts) turns it into a
// short reason, and the loader (lib/seal/seal-attestation.ts) tries a failed
// fetch once more, with a fresh challenge, before it drops the region and
// keeps the second failure's reason for "<region>: <reason>". The reasons are
// codes and numbers only: never a key, a hash, a challenge or the answer.
import * as fs from 'fs';
import * as path from 'path';

import type { CoreSealAttestationCheck, CoreSealAttestationVerdict, SealAttestationBindings } from '../../modules/ghost-core';
import type { GhostNfcSealPinNative, GhostNfcSealRegionsNative } from '../../modules/ghost-nfc';
import {
  checkWithSeal,
  confirmFillWithSeal,
  fetchSealAttestation,
  fillWithSeal,
  HOME_REGION,
  openWithSeal,
  SealRelayError,
} from '../../modules/ghost-nfc/relay';
import { statusDetail, statusText, type CardStatus } from '../../lib/seal/card-status';
import { checkCard, type SealDeps } from '../../lib/seal/flows';
import { parseMeasurementList } from '../../lib/seal/pinned-measurements';
import { ATTESTATION_FETCH_TRIES, attestSeal, type SealAttestationDeps } from '../../lib/seal/seal-attestation';
import { forgetTrustedSeals, noSealReason, refreshTrustedSeals, type TrustedSealsDeps } from '../../lib/seal/trusted-seal';
import { hexOf, PINNED_JSON, regionUrl, resetWorld, THREE_REGIONS, type World } from '../sealed-card/fake-seal';

jest.mock('expo', () => ({ requireOptionalNativeModule: () => null }));
const mockFiles = new Map<string, unknown>();
jest.mock('../../lib/storage', () => ({
  jsonFile: (name: string) => ({
    read: () => mockFiles.get(name) ?? null,
    write: async (value: unknown) => {
      mockFiles.set(name, JSON.parse(JSON.stringify(value)));
    },
  }),
}));

const PINNED = parseMeasurementList(PINNED_JSON);
const URL_ = 'https://seal.example:8443';
const REGION = 'us-east-1';
const CERT_HEX = '7e'.repeat(32);
const ATTESTATION_HEX = '4750413201020304';
/** A run of hex longer than 16 digits: a key, hash or challenge. */
const LONG_HEX = /[0-9a-fA-F]{17,}/;

/** Each native code of the fetch, and the reason the screen shows for it. */
const CODES: [string, string][] = [
  ['ERR_SEAL_ATTEST_NETWORK:-1200', 'attest-network(-1200)'],
  ['ERR_SEAL_ATTEST_NETWORK:-1001', 'attest-network(-1001)'],
  ['ERR_SEAL_ATTEST_STATUS:503', 'attest-status(503)'],
  ['ERR_SEAL_ATTEST_STATUS:404', 'attest-status(404)'],
  ['ERR_SEAL_ATTEST_NO_LEAF', 'attest-no-leaf'],
  ['ERR_SEAL_ATTEST_TOO_LONG', 'attest-too-long'],
  ['ERR_SEAL_ATTEST_PARSE', 'attest-parse'],
  ['ERR_SEAL_ATTEST_BAD_CHALLENGE', 'attest-bad-challenge'],
];

/** Every reason the tests saw, for the check that none holds a secret. */
const seen: string[] = [];

/** A native rejection, as Expo hands it over: a code and a message that is never shown. */
function nativeError(code: string): Error {
  return Object.assign(new Error(`synthetic message ${'ab'.repeat(32)}`), { code });
}

type Answer = Error | { attestation: string; certSha256: string } | 'hang';

const GOOD_ANSWER = { attestation: ATTESTATION_HEX, certSha256: CERT_HEX };

/** The fake native fetch: answers each fetch with the next of `answers` (the last one again once they run out). */
class FakeNative implements GhostNfcSealPinNative, GhostNfcSealRegionsNative {
  challenges: string[] = [];
  pins: string[] = [];

  constructor(private readonly answers: Answer[]) {}

  async fetchSealAttestation(_sealUrl: string, challenge: string) {
    this.challenges.push(challenge);
    const answer = this.answers[Math.min(this.challenges.length - 1, this.answers.length - 1)];
    if (answer === 'hang') {
      return new Promise<never>(() => {});
    }
    if (answer instanceof Error) {
      throw answer;
    }
    return answer;
  }

  setSealPin(_sealUrl: string, certSha256: string) {
    this.pins.push(certSha256);
  }

  setSealRegions(): boolean {
    return true;
  }
}

function buffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

const ACCEPTED: CoreSealAttestationVerdict = {
  refusal: '',
  seal: {
    verifyingKey: buffer(new Uint8Array(1952).fill(0xa1)),
    kemKey: buffer(new Uint8Array(1184).fill(0xb2)),
    measurement: buffer(new Uint8Array(48).fill(0x5e)),
    buildName: 'fake-seal-test',
  },
};

/** The fake attestation core: a fresh challenge each time (1, 2, ...), and every attestation accepted. */
class FakeCore implements SealAttestationBindings {
  checks: CoreSealAttestationCheck[] = [];
  made = 0;

  verifySealAttestation(check: CoreSealAttestationCheck): CoreSealAttestationVerdict {
    this.checks.push(check);
    return ACCEPTED;
  }

  sealAttestationChallenge(): ArrayBuffer {
    this.made += 1;
    return buffer(new Uint8Array(32).fill(this.made));
  }
}

let core: FakeCore;
let world: World;

beforeEach(() => {
  forgetTrustedSeals();
  core = new FakeCore();
  world = resetWorld();
  mockFiles.clear();
});

function deps(native: FakeNative, overrides: Partial<SealAttestationDeps> = {}): SealAttestationDeps {
  return { region: REGION, url: URL_, native, core: () => core, now: () => Date.now(), list: PINNED, ...overrides };
}

async function reasonOfFetch(native: FakeNative): Promise<string> {
  try {
    await fetchSealAttestation(URL_, new Uint8Array(32).fill(7), native);
  } catch (error) {
    expect(error).toBeInstanceOf(SealRelayError);
    return (error as SealRelayError).reason;
  }
  return 'none';
}

/** The reason line the card screen shows under "Can't verify this card". */
function reasonOf(status: CardStatus | null): string {
  expect(status).toMatchObject({ kind: 'cant-verify' });
  expect(statusText(status!)).toBe("Can't verify this card");
  const lines = statusDetail(status!)!.split('\n');
  expect(lines[1]).toMatch(/^Reason: /);
  const reason = lines[1].slice('Reason: '.length);
  seen.push(reason);
  return reason;
}

/** A Check whose refresh runs the real loader of every live region against `native`. */
function checkDeps(native: FakeNative): SealDeps {
  const refresh: TrustedSealsDeps = {
    regions: THREE_REGIONS.map((id) => ({ id, url: regionUrl(id) })),
    native,
    core: () => core,
    now: () => Date.now(),
    list: PINNED,
  };
  return {
    seals: new Map(),
    refresh: () => refreshTrustedSeals(refresh),
    core: world.core,
    check: () => checkWithSeal(HOME_REGION, world.native),
    fill: (amountWei, pin) => fillWithSeal(HOME_REGION, amountWei, pin, world.native),
    confirm: () => confirmFillWithSeal(HOME_REGION, world.native),
    open: (phoneKey, pin) => openWithSeal(HOME_REGION, phoneKey, pin, world.native),
    keeper: world.native,
    list: PINNED,
  };
}

describe('the relay', () => {
  it.each(CODES)('maps %s to %s', async (code, reason) => {
    const fetched = await reasonOfFetch(new FakeNative([nativeError(code)]));
    expect(fetched).toBe(reason);
    seen.push(fetched);
  });

  it('keeps the relay problems of a network or status failure, and of a bad answer', async () => {
    const problemOf = async (code: string) => {
      try {
        await fetchSealAttestation(URL_, new Uint8Array(32), new FakeNative([nativeError(code)]));
      } catch (error) {
        return (error as SealRelayError).problem;
      }
      return 'none';
    };
    expect(await problemOf('ERR_SEAL_ATTEST_NETWORK:-1200')).toBe('seal-unreachable');
    expect(await problemOf('ERR_SEAL_ATTEST_STATUS:503')).toBe('seal-unreachable');
    expect(await problemOf('ERR_SEAL_ATTEST_PARSE')).toBe('bad-answer');
    expect(await problemOf('ERR_SEAL_ADDRESS')).toBe('bad-address');
  });

  it('gives failed for a code it does not know, a number that is not one, or one too long', async () => {
    for (const code of [
      'ERR_SEAL_ATTESTATION',
      'ERR_SEAL_ATTEST_NETWORK',
      'ERR_SEAL_ATTEST_NETWORK:',
      'ERR_SEAL_ATTEST_NETWORK:abc',
      `ERR_SEAL_ATTEST_STATUS:${'1'.repeat(20)}`,
      `ERR_SEAL_ATTEST_NETWORK:${'ab'.repeat(32)}`,
      'ERR_SEAL_ATTEST_NO_LEAF:extra',
    ]) {
      const reason = await reasonOfFetch(new FakeNative([nativeError(code)]));
      expect([code, reason]).toEqual([code, 'failed']);
      seen.push(reason);
    }
    expect(await reasonOfFetch(new FakeNative([new Error('no code')]))).toBe('failed');
  });

  it('every code the Swift fetch can reject with is one the relay maps', () => {
    const root = path.join(__dirname, '..', '..');
    const swift = fs.readFileSync(path.join(root, 'modules', 'ghost-nfc', 'ios', 'SealAttestation.swift'), 'utf8');
    const emitted = [...swift.matchAll(/"(ERR_SEAL_ATTEST_[A-Z_]+)(:\\\(number\))?"/g)].map((m) => m[1]).sort();
    expect(emitted).toEqual(
      [
        'ERR_SEAL_ATTEST_BAD_CHALLENGE',
        'ERR_SEAL_ATTEST_NETWORK',
        'ERR_SEAL_ATTEST_NO_LEAF',
        'ERR_SEAL_ATTEST_PARSE',
        'ERR_SEAL_ATTEST_STATUS',
        'ERR_SEAL_ATTEST_TOO_LONG',
      ].sort(),
    );
    // No bare rejection is left: every one names its cause.
    expect(swift).not.toMatch(/SealAttestationException\(\)/);
  });
});

describe('the card screen', () => {
  it.each(CODES)('shows %s after its region as <region>: %s', async (code, reason) => {
    const native = new FakeNative([nativeError(code)]);
    expect(reasonOf(await checkCard(checkDeps(native)))).toBe(THREE_REGIONS.map((id) => `${id}: ${reason}`).join('; '));
    // Each region was fetched twice, and no card sheet opened.
    expect(native.challenges).toHaveLength(THREE_REGIONS.length * ATTESTATION_FETCH_TRIES);
    expect(world.calls).toEqual([]);
  });
});

describe('a fetch that fails', () => {
  it('is tried once more right away, with a fresh challenge, and that Seal is kept', async () => {
    expect(ATTESTATION_FETCH_TRIES).toBe(2);
    const native = new FakeNative([nativeError('ERR_SEAL_ATTEST_NETWORK:-1200'), GOOD_ANSWER]);
    const attested = await attestSeal(deps(native));
    expect(attested.reason).toBe('');
    expect(attested.seal).toMatchObject({ region: REGION, url: URL_ });
    expect(native.challenges).toEqual(['01'.repeat(32), '02'.repeat(32)]);
    // The core checks the answer against the challenge it was fetched with, exactly once.
    expect(core.checks).toHaveLength(1);
    expect(hexOf(new Uint8Array(core.checks[0].challenge))).toBe('02'.repeat(32));
    expect(hexOf(new Uint8Array(core.checks[0].tlsCertSha256))).toBe(CERT_HEX);
    expect(native.pins).toEqual([CERT_HEX]);
  });

  it('is tried once more after its deadline', async () => {
    const native = new FakeNative(['hang', GOOD_ANSWER]);
    const attested = await attestSeal(deps(native, { deadlineMs: 5 }));
    expect(attested.seal).not.toBeNull();
    expect(native.challenges).toHaveLength(2);
  });

  it('twice gives no Seal, the second reason and no pin, and is not tried a third time', async () => {
    const native = new FakeNative([
      nativeError('ERR_SEAL_ATTEST_NETWORK:-1200'),
      nativeError('ERR_SEAL_ATTEST_STATUS:503'),
      GOOD_ANSWER,
    ]);
    expect(await attestSeal(deps(native))).toEqual({ seal: null, reason: 'attest-status(503)' });
    expect(native.challenges).toEqual(['01'.repeat(32), '02'.repeat(32)]);
    expect(core.checks).toHaveLength(0);
    expect(native.pins).toEqual(['']);
  });

  it('twice says the second reason on the card screen', async () => {
    const native = new FakeNative([
      nativeError('ERR_SEAL_ATTEST_NETWORK:-1200'),
      nativeError('ERR_SEAL_ATTEST_NETWORK:-1200'),
      nativeError('ERR_SEAL_ATTEST_NETWORK:-1200'),
      nativeError('ERR_SEAL_ATTEST_NO_LEAF'),
    ]);
    const seals = await refreshTrustedSeals({
      regions: THREE_REGIONS.map((id) => ({ id, url: regionUrl(id) })),
      native,
      core: () => core,
      now: () => Date.now(),
      list: PINNED,
    });
    expect(seals.size).toBe(0);
    // The three first fetches fail with -1200; the three retries give no leaf.
    expect(noSealReason(seals)).toBe(THREE_REGIONS.map((id) => `${id}: attest-no-leaf`).join('; '));
  });

  it('a second fetch past its deadline is seal-unreachable', async () => {
    const native = new FakeNative([nativeError('ERR_SEAL_ATTEST_PARSE'), 'hang']);
    expect(await attestSeal(deps(native, { deadlineMs: 5 }))).toEqual({ seal: null, reason: 'seal-unreachable' });
  });

  it('a first fetch that succeeds is not fetched again', async () => {
    const native = new FakeNative([GOOD_ANSWER]);
    expect((await attestSeal(deps(native))).seal).not.toBeNull();
    expect(native.challenges).toHaveLength(1);
  });

  it('an answer the core refuses is not fetched again', async () => {
    const native = new FakeNative([GOOD_ANSWER]);
    core.verifySealAttestation = () => ({ refusal: 'not-pinned' });
    expect(await attestSeal(deps(native))).toEqual({ seal: null, reason: 'not-pinned' });
    expect(native.challenges).toHaveLength(1);
  });
});

describe('every reason', () => {
  it('holds no hex longer than 16 digits', () => {
    expect(seen.length).toBeGreaterThan(CODES.length * 2);
    for (const reason of seen) {
      expect([reason, LONG_HEX.test(reason)]).toEqual([reason, false]);
      expect(reason).toMatch(/^[a-z0-9 :;,()-]+$/);
    }
  });
});
