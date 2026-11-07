// The seam the card screens read the Seal regions from
// (lib/seal/trusted-seal.ts) and its loader of one region
// (lib/seal/seal-attestation.ts), with a fake native fetch, pin and region
// list and a fake native core: only a verified attestation gives a region's
// Seal and pins the relay to it; everything else gives that region no Seal,
// drops its pin and never throws, and never touches another region. The real
// checks of the attestation are core/tests/seal_attestation.rs.
import type { CoreSealAttestationCheck, CoreSealAttestationVerdict, SealAttestationBindings } from '../../modules/ghost-core';
import type { GhostNfcSealPinNative, GhostNfcSealRegionsNative } from '../../modules/ghost-nfc';
import { parseMeasurementList } from '../../lib/seal/pinned-measurements';
import {
  ATTESTATION_DEADLINE_MS,
  appAttestationParts,
  attestationDeps,
  loadTrustedSeal,
  pinnedBuilds,
  type SealAttestationDeps,
} from '../../lib/seal/seal-attestation';
import { SEAL_REGIONS, type SealRegion } from '../../lib/seal/seal-config';
import {
  FAILED_SEAL_MS,
  forgetTrustedSeals,
  refreshTrustedSeals,
  trustedSeal,
  trustedSealsDeps,
  VERIFIED_SEAL_MS,
  type TrustedSealsDeps,
} from '../../lib/seal/trusted-seal';

const mockApp: {
  native: (GhostNfcSealPinNative & GhostNfcSealRegionsNative) | null;
  core: Record<string, unknown> | null;
  regions: SealRegion[];
} = {
  native: null,
  core: null,
  regions: [],
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
  get SEAL_REGIONS() {
    return mockApp.regions;
  },
}));

const URL_ = 'https://seal.example:8443';
const REGION = 'us-east-1';
const ONE: SealRegion[] = [{ id: REGION, url: URL_ }];
const THREE: SealRegion[] = [
  { id: 'us-east-1', url: 'https://us-east-1.seal.example' },
  { id: 'eu-central-1', url: 'https://eu-central-1.seal.example' },
  { id: 'ap-southeast-1', url: 'https://ap-southeast-1.seal.example' },
];
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

/** The fake native fetch, pin and region list. */
class FakeNative implements GhostNfcSealPinNative, GhostNfcSealRegionsNative {
  fetches: { url: string; challenge: string }[] = [];
  pins: { url: string; hash: string }[] = [];
  lists: string[] = [];
  /** Every native call, in order. */
  events: string[] = [];
  /** Fetches of these addresses fail. */
  failing = new Set<string>();
  fail: Error | null = null;
  pinThrows = false;
  listRefused = false;
  /** Every fetch waits on this. */
  gate: Promise<void> | null = null;
  /** Fetches still waiting on the gate. */
  waiting = 0;

  async fetchSealAttestation(sealUrl: string, challenge: string) {
    this.events.push(`fetch ${sealUrl}`);
    this.fetches.push({ url: sealUrl, challenge });
    if (this.gate) {
      this.waiting += 1;
      await this.gate;
      this.waiting -= 1;
    }
    if (this.fail) {
      throw this.fail;
    }
    if (this.failing.has(sealUrl)) {
      throw Object.assign(new Error('offline'), { code: 'ERR_SEAL_UNREACHABLE' });
    }
    return { attestation: hexOf(ATTESTATION), certSha256: CERT_HEX };
  }

  setSealPin(sealUrl: string, certSha256: string) {
    if (this.pinThrows) {
      throw new Error('no pin');
    }
    this.events.push(`pin ${sealUrl}`);
    this.pins.push({ url: sealUrl, hash: certSha256 });
  }

  setSealRegions(regionsJson: string): boolean {
    this.events.push('regions');
    this.lists.push(regionsJson);
    return !this.listRefused;
  }

  /** The pin the relay holds now for `url`. */
  pinOf(url: string = URL_): string | null {
    const last = this.pins.filter((p) => p.url === url).pop();
    return last && last.hash !== '' ? last.hash : null;
  }
}

let core: FakeCore;
let native: FakeNative;
let clock: number;
let logged: jest.SpyInstance[];

/** One region's loader. */
function deps(overrides: Partial<SealAttestationDeps> = {}): SealAttestationDeps {
  return {
    region: REGION,
    url: URL_,
    native,
    core: () => core,
    now: () => clock,
    list: LIST,
    ...overrides,
  };
}

/** Every region's refresh. */
function sealsDeps(overrides: Partial<TrustedSealsDeps> = {}): TrustedSealsDeps {
  return {
    regions: ONE,
    native,
    core: () => core,
    now: () => clock,
    list: LIST,
    ...overrides,
  };
}

/** The one region's Seal after a refresh. */
async function refreshOne(overrides: Partial<TrustedSealsDeps> = {}) {
  return (await refreshTrustedSeals(sealsDeps(overrides))).get(REGION) ?? null;
}

beforeEach(() => {
  forgetTrustedSeals();
  core = new FakeCore();
  native = new FakeNative();
  clock = NOW_MS;
  mockApp.native = null;
  mockApp.core = null;
  mockApp.regions = [];
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
  it("gives the region's Seal its id, keys, measurement and certificate hash, and pins the relay to it", async () => {
    const seal = await refreshOne();
    expect(seal).not.toBeNull();
    expect(seal!.region).toBe(REGION);
    expect(seal!.url).toBe(URL_);
    expect(hexOf(seal!.verifyingKey)).toBe('a1'.repeat(1952));
    expect(hexOf(seal!.kemKey)).toBe('b2'.repeat(1184));
    expect(hexOf(seal!.measurement)).toBe('5e'.repeat(48));
    expect(hexOf(seal!.tlsCertSha256)).toBe(CERT_HEX);
    expect(trustedSeal(REGION, clock)).toBe(seal);
    expect(trustedSeal('eu-central-1', clock)).toBeNull();
    expect(native.pins).toEqual([{ url: URL_, hash: CERT_HEX }]);
  });

  it('is checked by the core against the challenge sent, the certificate measured, every pinned build and now', async () => {
    await refreshOne();
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
    expect(await refreshOne()).toBeNull();
    expect(trustedSeal(REGION, clock)).toBeNull();
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
    await refreshOne();
    expect(native.pinOf()).toBe(CERT_HEX);
    forgetTrustedSeals();
    core.verdict = { refusal, seal: GOOD.seal };
    expect(await refreshOne()).toBeNull();
    expect(trustedSeal(REGION, clock)).toBeNull();
    expect(native.pinOf()).toBeNull();
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
      expect(native.pinOf()).toBeNull();
    }
  });

  it('a fetch that throws gives no Seal and no pin', async () => {
    native.fail = Object.assign(new Error('offline'), { code: 'ERR_SEAL_UNREACHABLE' });
    expect(await refreshOne()).toBeNull();
    expect(core.checks).toHaveLength(0);
    expect(native.pinOf()).toBeNull();
  });

  it('a fetch past its 10 second deadline gives no Seal and no pin', async () => {
    expect(ATTESTATION_DEADLINE_MS).toBe(10_000);
    native.gate = new Promise<void>(() => {});
    expect(await loadTrustedSeal(deps({ deadlineMs: 5 }))).toBeNull();
    expect(core.checks).toHaveLength(0);
    expect(native.pinOf()).toBeNull();
  });

  it('a build with no native module gives no Seal', async () => {
    expect(await refreshOne({ native: null })).toBeNull();
    expect(core.checks).toHaveLength(0);
    expect(await loadTrustedSeal(deps({ native: null }))).toBeNull();
  });

  it('a build with no attestation check in its core gives no Seal and fetches nothing', async () => {
    expect(await refreshOne({ core: () => null })).toBeNull();
    expect(native.fetches).toHaveLength(0);
    expect(native.pinOf()).toBeNull();
  });

  it('a region with no address or no id fetches nothing and gives no Seal', async () => {
    expect(await loadTrustedSeal(deps({ url: '' }))).toBeNull();
    expect(await loadTrustedSeal(deps({ region: '' }))).toBeNull();
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
    await expect(refreshTrustedSeals(sealsDeps())).resolves.toEqual(new Map());
    forgetTrustedSeals();
    await expect(
      refreshTrustedSeals(
        sealsDeps({
          core: () => {
            throw new Error('no core');
          },
        }),
      ),
    ).resolves.toEqual(new Map());
    forgetTrustedSeals();
    native.pinThrows = true;
    native.fail = new Error('offline');
    await expect(refreshTrustedSeals(sealsDeps())).resolves.toEqual(new Map());
    forgetTrustedSeals();
    await expect(
      refreshTrustedSeals(
        sealsDeps({
          random: () => {
            throw new Error('no randomness');
          },
        }),
      ),
    ).resolves.toEqual(new Map());
    forgetTrustedSeals();
    native.setSealRegions = () => {
      throw new Error('no list');
    };
    await expect(refreshTrustedSeals(sealsDeps())).resolves.toEqual(new Map());
  });
});

describe('every region', () => {
  it('has its list handed to the native relay, in order, before any fetch', async () => {
    await refreshTrustedSeals(sealsDeps({ regions: THREE }));
    expect(native.lists).toEqual([JSON.stringify(THREE)]);
    expect(native.events[0]).toBe('regions');
    expect(native.events.filter((e) => e === 'regions')).toHaveLength(1);
    expect(native.events.slice(1).every((e) => e !== 'regions')).toBe(true);
  });

  it('is attested in parallel, each with its own fetch, check and pin', async () => {
    let release: () => void = () => {};
    native.gate = new Promise<void>((resolve) => (release = resolve));
    const pending = refreshTrustedSeals(sealsDeps({ regions: THREE }));
    // Let every fetch start before any of them answers.
    for (let i = 0; i < 10 && native.waiting < 3; i += 1) {
      await Promise.resolve();
    }
    expect(native.waiting).toBe(3);
    expect(native.fetches.map((f) => f.url)).toEqual(THREE.map((r) => r.url));
    release();
    const seals = await pending;
    expect([...seals.keys()]).toEqual(THREE.map((r) => r.id));
    for (const region of THREE) {
      expect(seals.get(region.id)!.region).toBe(region.id);
      expect(seals.get(region.id)!.url).toBe(region.url);
      expect(trustedSeal(region.id, clock)).toBe(seals.get(region.id));
      expect(native.pinOf(region.url)).toBe(CERT_HEX);
    }
    expect(core.checks).toHaveLength(3);
  });

  it('is cached on its own: one region failing leaves the others verified and pinned', async () => {
    native.failing.add(THREE[1].url);
    const seals = await refreshTrustedSeals(sealsDeps({ regions: THREE }));
    expect([...seals.keys()]).toEqual(['us-east-1', 'ap-southeast-1']);
    expect(trustedSeal('eu-central-1', clock)).toBeNull();
    expect(native.pinOf(THREE[1].url)).toBeNull();
    expect(native.pinOf(THREE[0].url)).toBe(CERT_HEX);
    expect(native.pinOf(THREE[2].url)).toBe(CERT_HEX);

    // The failure is kept 30 seconds, the verified ones 5 minutes, each apart.
    native.failing.clear();
    clock += FAILED_SEAL_MS;
    const again = await refreshTrustedSeals(sealsDeps({ regions: THREE }));
    expect([...again.keys()]).toEqual(THREE.map((r) => r.id));
    expect(native.fetches.map((f) => f.url)).toEqual([...THREE.map((r) => r.url), THREE[1].url]);
    expect(again.get('us-east-1')).toBe(seals.get('us-east-1'));
  });

  it('gives only listed regions', async () => {
    await refreshTrustedSeals(sealsDeps({ regions: THREE }));
    const seals = await refreshTrustedSeals(sealsDeps({ regions: ONE }));
    expect([...seals.keys()]).toEqual([REGION]);
    // A region listed with another address is attested again, at that address.
    const moved = [{ id: REGION, url: 'https://moved.seal.example' }];
    const after = await refreshTrustedSeals(sealsDeps({ regions: moved }));
    expect(after.get(REGION)!.url).toBe('https://moved.seal.example');
  });

  it('fetches nothing when the list could not be handed to the relay', async () => {
    native.listRefused = true;
    expect(await refreshTrustedSeals(sealsDeps({ regions: THREE }))).toEqual(new Map());
    expect(native.fetches).toHaveLength(0);
  });

  it('fetches nothing for a list the relay would refuse, and clears the native list', async () => {
    for (const regions of [
      [{ id: 'us-east-1', url: 'http://seal.example' }],
      [{ id: 'US East', url: URL_ }],
      [
        { id: 'us-east-1', url: URL_ },
        { id: 'us-east-1', url: 'https://other.seal.example' },
      ],
    ]) {
      native.lists = [];
      expect(await refreshTrustedSeals(sealsDeps({ regions }))).toEqual(new Map());
      expect(native.lists).toEqual(['[]']);
    }
    expect(native.fetches).toHaveLength(0);
  });

  it('with an empty list fetches nothing, checks nothing, pins nothing and gives no Seal', async () => {
    expect(SEAL_REGIONS).toEqual([]);
    expect(trustedSealsDeps().regions).toEqual([]);
    expect(await refreshTrustedSeals(sealsDeps({ regions: [] }))).toEqual(new Map());
    expect(native.fetches).toHaveLength(0);
    expect(core.checks).toHaveLength(0);
    expect(native.pins).toHaveLength(0);
  });
});

describe('the cache', () => {
  it('holds a verified Seal for 5 minutes, then checks the attestation again', async () => {
    expect(VERIFIED_SEAL_MS).toBe(300_000);
    const seal = await refreshOne();
    clock += VERIFIED_SEAL_MS - 1;
    expect(await refreshOne()).toBe(seal);
    expect(trustedSeal(REGION, clock)).toBe(seal);
    expect(native.fetches).toHaveLength(1);
    clock += 1;
    expect(trustedSeal(REGION, clock)).toBeNull();
    core.verdict = { refusal: 'expired' };
    expect(await refreshOne()).toBeNull();
    expect(native.fetches).toHaveLength(2);
    expect(native.pinOf()).toBeNull();
  });

  it('holds a failure for 30 seconds, then tries again', async () => {
    expect(FAILED_SEAL_MS).toBe(30_000);
    native.fail = new Error('offline');
    expect(await refreshOne()).toBeNull();
    native.fail = null;
    clock += FAILED_SEAL_MS - 1;
    expect(await refreshOne()).toBeNull();
    expect(native.fetches).toHaveLength(1);
    clock += 1;
    expect(await refreshOne()).not.toBeNull();
    expect(native.fetches).toHaveLength(2);
  });

  it('is shared by card flows that ask at the same time', async () => {
    let release: () => void = () => {};
    native.gate = new Promise<void>((resolve) => (release = resolve));
    const first = refreshOne();
    const second = refreshOne();
    release();
    const [a, b] = await Promise.all([first, second]);
    expect(a).not.toBeNull();
    expect(a).toBe(b);
    expect(native.fetches).toHaveLength(1);
  });

  it('is empty until a card flow asks: the seam fetches nothing by itself', () => {
    expect(trustedSeal(REGION)).toBeNull();
    expect(native.fetches).toHaveLength(0);
    expect(native.lists).toHaveLength(0);
  });
});

describe('the app wiring', () => {
  it('uses the module, the core, its challenge, the pinned list and SEAL_REGIONS when it is set', async () => {
    mockApp.regions = THREE;
    mockApp.native = native;
    mockApp.core = core as unknown as Record<string, unknown>;
    const seals = await refreshTrustedSeals();
    expect([...seals.keys()]).toEqual(THREE.map((r) => r.id));
    expect(native.lists).toEqual([JSON.stringify(THREE)]);
    expect(core.challenges).toBe(3);
    expect(native.pinOf(THREE[0].url)).toBe(CERT_HEX);
    expect(core.checks[0].pinnedBuilds).toEqual(pinnedBuilds());
    expect(attestationDeps(THREE[1])).toMatchObject({ region: 'eu-central-1', url: THREE[1].url });
    expect(Object.keys(appAttestationParts()).sort()).toEqual(['core', 'list', 'now']);
  });

  it('gives no Seal with no native module, without throwing', async () => {
    mockApp.regions = ONE;
    mockApp.core = core as unknown as Record<string, unknown>;
    expect(await refreshTrustedSeals()).toEqual(new Map());
    expect(core.checks).toHaveLength(0);
  });

  it('gives no Seal when the address is not https://', async () => {
    expect(await loadTrustedSeal(deps({ url: 'http://seal.example' }))).toBeNull();
    expect(native.fetches).toHaveLength(0);
  });
});
