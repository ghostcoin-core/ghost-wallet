// The seam the card screens read the Seal from (lib/seal/trusted-seal.ts)
// and its loader (lib/seal/seal-attestation.ts), with a fake native fetch and
// a fake native core: only a verified attestation gives a Seal and pins the
// relay; everything else gives no Seal, drops the pin and never throws. The
// real checks of the attestation are core/tests/seal_attestation.rs.
import type { CoreSealAttestationCheck, CoreSealAttestationVerdict, SealAttestationBindings } from '../../modules/ghost-core';
import type { GhostNfcSealPinNative } from '../../modules/ghost-nfc';
import { parseMeasurementList } from '../../lib/seal/pinned-measurements';
import { attestationDeps, loadTrustedSeal, pinnedBuilds, type SealAttestationDeps } from '../../lib/seal/seal-attestation';
import { SEAL_URL } from '../../lib/seal/seal-config';
import {
  FAILED_SEAL_MS,
  forgetTrustedSeal,
  refreshTrustedSeal,
  trustedSeal,
  VERIFIED_SEAL_MS,
} from '../../lib/seal/trusted-seal';

const mockApp: { native: GhostNfcSealPinNative | null; core: Record<string, unknown> | null; url: string } = {
  native: null,
  core: null,
  url: '',
};

jest.mock('expo', () => ({
  requireOptionalNativeModule: (name: string) => (name === 'GhostNfc' ? mockApp.native : null),
}));
jest.mock(
  '../../modules/ghost-core/src/index',
  () =>
    new Proxy(
      {},
      {
        get(_target, name: string) {
          const core = mockApp.core;
          const value = core?.[name];
          return typeof value === 'function' ? value.bind(core) : value;
        },
      },
    ),
  { virtual: true },
);
jest.mock('../../lib/seal/seal-config', () => ({
  get SEAL_URL() {
    return mockApp.url;
  },
}));

const URL_ = 'https://seal.example:8443';
const NOW_MS = 1_800_000_000_000;
const CERT_HEX = '7e'.repeat(32);
const ATTESTATION = Uint8Array.from([0x47, 0x50, 0x41, 0x32, 1, 2, 3, 4, 5, 6, 7, 8]);

const LIST = parseMeasurementList(
  JSON.stringify({
    version: 1,
    builds: [
      { name: 'seal-test-old', released: '2026-10-01', pcr0: '77'.repeat(48), pcr1: '11'.repeat(48), pcr2: '22'.repeat(48), status: 'revoked' },
      { name: 'seal-test-new', released: '2026-11-01', pcr0: '5e'.repeat(48), pcr1: '33'.repeat(48), pcr2: '44'.repeat(48), status: 'allowed' },
    ],
  }),
);

function hexOf(data: ArrayBuffer | Uint8Array): string {
  return Array.from(data instanceof Uint8Array ? data : new Uint8Array(data), (b) => b.toString(16).padStart(2, '0')).join('');
}

function buffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

const GOOD: CoreSealAttestationVerdict = {
  refusal: '',
  seal: {
    verifyingKey: buffer(new Uint8Array(1952).fill(0xa1)),
    kemKey: buffer(new Uint8Array(1184).fill(0xb2)),
    measurement: buffer(new Uint8Array(48).fill(0x5e)),
    buildName: 'seal-test-new',
  },
};

/** The fake native core: verifies nothing, answers with `verdict`, and keeps what it was asked. */
class FakeCore implements SealAttestationBindings {
  verdict: CoreSealAttestationVerdict = GOOD;
  checks: CoreSealAttestationCheck[] = [];
  challenges = 0;
  throws = false;
  challengeBytes = 32;

  verifySealAttestation(check: CoreSealAttestationCheck): CoreSealAttestationVerdict {
    this.checks.push(check);
    if (this.throws) {
      throw new Error('core failed');
    }
    return this.verdict;
  }

  sealAttestationChallenge(): ArrayBuffer {
    this.challenges += 1;
    return buffer(new Uint8Array(this.challengeBytes).fill(this.challenges));
  }
}

/** The fake native fetch and pin. */
class FakeNative implements GhostNfcSealPinNative {
  fetches: { url: string; challenge: string }[] = [];
  pins: { url: string; hash: string }[] = [];
  fail: Error | null = null;
  pinThrows = false;
  gate: Promise<void> | null = null;

  async fetchSealAttestation(sealUrl: string, challenge: string) {
    this.fetches.push({ url: sealUrl, challenge });
    if (this.gate) {
      await this.gate;
    }
    if (this.fail) {
      throw this.fail;
    }
    return { attestation: hexOf(ATTESTATION), certSha256: CERT_HEX };
  }

  setSealPin(sealUrl: string, certSha256: string) {
    if (this.pinThrows) {
      throw new Error('no pin');
    }
    this.pins.push({ url: sealUrl, hash: certSha256 });
  }

  /** The pin the relay holds now. */
  get pin(): string | null {
    const last = this.pins[this.pins.length - 1];
    return last && last.hash !== '' ? last.hash : null;
  }
}

let core: FakeCore;
let native: FakeNative;
let clock: number;
let logged: jest.SpyInstance[];

function deps(overrides: Partial<SealAttestationDeps> = {}): SealAttestationDeps {
  return {
    url: URL_,
    native,
    core: () => core,
    now: () => clock,
    list: LIST,
    ...overrides,
  };
}

beforeEach(() => {
  forgetTrustedSeal();
  core = new FakeCore();
  native = new FakeNative();
  clock = NOW_MS;
  mockApp.native = null;
  mockApp.core = null;
  mockApp.url = '';
  logged = (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
    jest.spyOn(console, method).mockImplementation(() => {}),
  );
});

afterEach(() => {
  // Nothing the loader does ever logs: no challenge, key or hash reaches a log.
  for (const spy of logged) {
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  }
});

describe('a verified attestation', () => {
  it('gives the Seal its keys, measurement and certificate hash, and pins the relay to it', async () => {
    const seal = await refreshTrustedSeal(deps());
    expect(seal).not.toBeNull();
    expect(seal!.url).toBe(URL_);
    expect(hexOf(seal!.verifyingKey)).toBe('a1'.repeat(1952));
    expect(hexOf(seal!.kemKey)).toBe('b2'.repeat(1184));
    expect(hexOf(seal!.measurement)).toBe('5e'.repeat(48));
    expect(hexOf(seal!.tlsCertSha256)).toBe(CERT_HEX);
    expect(trustedSeal(clock)).toBe(seal);
    expect(native.pins).toEqual([{ url: URL_, hash: CERT_HEX }]);
  });

  it('is checked by the core against the challenge sent, the certificate measured, every pinned build and now', async () => {
    await refreshTrustedSeal(deps());
    expect(native.fetches).toHaveLength(1);
    expect(core.checks).toHaveLength(1);
    const check = core.checks[0];
    expect(hexOf(check.challenge)).toBe('01'.repeat(32));
    expect(native.fetches[0]).toEqual({ url: URL_, challenge: '01'.repeat(32) });
    expect(hexOf(check.attestation)).toBe(hexOf(ATTESTATION));
    expect(hexOf(check.tlsCertSha256)).toBe(CERT_HEX);
    expect(check.now).toBe(1_800_000_000n);
    expect(check.pinnedBuilds.map((b) => [b.name, hexOf(b.pcr0), hexOf(b.pcr1), hexOf(b.pcr2), b.allowed])).toEqual([
      ['seal-test-old', '77'.repeat(48), '11'.repeat(48), '22'.repeat(48), false],
      ['seal-test-new', '5e'.repeat(48), '33'.repeat(48), '44'.repeat(48), true],
    ]);
  });

  it('is fetched with a fresh challenge each time', async () => {
    await loadTrustedSeal(deps());
    await loadTrustedSeal(deps());
    expect(native.fetches.map((f) => f.challenge)).toEqual(['01'.repeat(32), '02'.repeat(32)]);
  });

  it('is not trusted when the relay could not be pinned to it', async () => {
    native.pinThrows = true;
    expect(await refreshTrustedSeal(deps())).toBeNull();
    expect(trustedSeal(clock)).toBeNull();
  });
});

describe('anything but a verified attestation', () => {
  it.each([
    'malformed',
    'bad-chain',
    'bad-signature',
    'expired',
    'not-yet-valid',
    'not-pinned',
    'revoked',
    'debug-mode',
    'keys-not-bound',
    'tls-mismatch',
  ])('a %s refusal gives no Seal and drops the pin', async (refusal) => {
    // A Seal verified earlier, then refused.
    await refreshTrustedSeal(deps());
    expect(native.pin).toBe(CERT_HEX);
    forgetTrustedSeal();
    core.verdict = { refusal, seal: GOOD.seal };
    expect(await refreshTrustedSeal(deps())).toBeNull();
    expect(trustedSeal(clock)).toBeNull();
    expect(native.pin).toBeNull();
  });

  it('a verdict with no Seal or a key of the wrong length gives no Seal', async () => {
    for (const verdict of [
      { refusal: '' },
      { refusal: '', seal: { ...GOOD.seal!, verifyingKey: buffer(new Uint8Array(1951)) } },
      { refusal: '', seal: { ...GOOD.seal!, kemKey: buffer(new Uint8Array(32)) } },
      { refusal: '', seal: { ...GOOD.seal!, measurement: buffer(new Uint8Array(32)) } },
    ]) {
      core.verdict = verdict as CoreSealAttestationVerdict;
      expect(await loadTrustedSeal(deps())).toBeNull();
      expect(native.pin).toBeNull();
    }
  });

  it('a fetch that throws gives no Seal and no pin', async () => {
    native.fail = Object.assign(new Error('offline'), { code: 'ERR_SEAL_UNREACHABLE' });
    expect(await refreshTrustedSeal(deps())).toBeNull();
    expect(core.checks).toHaveLength(0);
    expect(native.pin).toBeNull();
  });

  it('a build with no native module gives no Seal', async () => {
    expect(await refreshTrustedSeal(deps({ native: null }))).toBeNull();
    expect(core.checks).toHaveLength(0);
  });

  it('a build with no attestation check in its core gives no Seal and fetches nothing', async () => {
    expect(await refreshTrustedSeal(deps({ core: () => null }))).toBeNull();
    expect(native.fetches).toHaveLength(0);
    expect(native.pin).toBeNull();
  });

  it('an empty SEAL_URL fetches nothing and gives no Seal', async () => {
    expect(SEAL_URL).toBe('');
    expect(attestationDeps().url).toBe('');
    expect(await refreshTrustedSeal(deps({ url: '' }))).toBeNull();
    expect(native.fetches).toHaveLength(0);
    expect(core.checks).toHaveLength(0);
    expect(native.pins).toHaveLength(0);
  });

  it('a challenge that is not 32 bytes fetches nothing', async () => {
    core.challengeBytes = 0;
    expect(await loadTrustedSeal(deps())).toBeNull();
    expect(native.fetches).toHaveLength(0);
  });

  it('never throws, whatever fails', async () => {
    core.throws = true;
    await expect(refreshTrustedSeal(deps())).resolves.toBeNull();
    forgetTrustedSeal();
    await expect(
      refreshTrustedSeal(
        deps({
          core: () => {
            throw new Error('no core');
          },
        }),
      ),
    ).resolves.toBeNull();
    forgetTrustedSeal();
    native.pinThrows = true;
    native.fail = new Error('offline');
    await expect(refreshTrustedSeal(deps())).resolves.toBeNull();
    forgetTrustedSeal();
    await expect(
      refreshTrustedSeal(
        deps({
          random: () => {
            throw new Error('no randomness');
          },
        }),
      ),
    ).resolves.toBeNull();
  });
});

describe('the cache', () => {
  it('holds a verified Seal for 5 minutes, then checks the attestation again', async () => {
    expect(VERIFIED_SEAL_MS).toBe(300_000);
    const seal = await refreshTrustedSeal(deps());
    clock += VERIFIED_SEAL_MS - 1;
    expect(await refreshTrustedSeal(deps())).toBe(seal);
    expect(trustedSeal(clock)).toBe(seal);
    expect(native.fetches).toHaveLength(1);
    clock += 1;
    expect(trustedSeal(clock)).toBeNull();
    core.verdict = { refusal: 'expired' };
    expect(await refreshTrustedSeal(deps())).toBeNull();
    expect(native.fetches).toHaveLength(2);
    expect(native.pin).toBeNull();
  });

  it('holds a failure for 30 seconds, then tries again', async () => {
    expect(FAILED_SEAL_MS).toBe(30_000);
    native.fail = new Error('offline');
    expect(await refreshTrustedSeal(deps())).toBeNull();
    native.fail = null;
    clock += FAILED_SEAL_MS - 1;
    expect(await refreshTrustedSeal(deps())).toBeNull();
    expect(native.fetches).toHaveLength(1);
    clock += 1;
    expect(await refreshTrustedSeal(deps())).not.toBeNull();
    expect(native.fetches).toHaveLength(2);
  });

  it('is shared by card flows that ask at the same time', async () => {
    let release: () => void = () => {};
    native.gate = new Promise<void>((resolve) => (release = resolve));
    const first = refreshTrustedSeal(deps());
    const second = refreshTrustedSeal(deps());
    release();
    const [a, b] = await Promise.all([first, second]);
    expect(a).not.toBeNull();
    expect(a).toBe(b);
    expect(native.fetches).toHaveLength(1);
  });

  it('is empty until a card flow asks: the seam fetches nothing by itself', () => {
    expect(trustedSeal()).toBeNull();
    expect(native.fetches).toHaveLength(0);
  });
});

describe('the app wiring', () => {
  it('uses the module, the core, its challenge and the pinned list when SEAL_URL is set', async () => {
    mockApp.url = URL_;
    mockApp.native = native;
    mockApp.core = core as unknown as Record<string, unknown>;
    const seal = await refreshTrustedSeal();
    expect(seal?.url).toBe(URL_);
    expect(core.challenges).toBe(1);
    expect(native.pin).toBe(CERT_HEX);
    expect(core.checks[0].pinnedBuilds).toEqual(pinnedBuilds());
  });

  it('gives no Seal with no native module, without throwing', async () => {
    mockApp.url = URL_;
    mockApp.core = core as unknown as Record<string, unknown>;
    expect(await refreshTrustedSeal()).toBeNull();
    expect(core.checks).toHaveLength(0);
  });

  it('gives no Seal when the address is not https://', async () => {
    expect(await refreshTrustedSeal(deps({ url: 'http://seal.example' }))).toBeNull();
    expect(native.fetches).toHaveLength(0);
  });
});
