// Each Sealed card is served by one home region (docs/sealed-card.md, "Home
// region"), and the app reaches it: the list of live regions is in
// lib/seal/seal-config.ts (the live Seal's regions), the native
// relay chooses the card's home region with the native core's rule once the
// UID is read (core/src/seal_home_region.rs, tested against the Seal's
// vectors in core/tests/seal_home_region.rs), and JavaScript never chooses a
// region and has no hash code of its own.
//
// Here: the committed list is the live Seal's three regions in its release
// order; with no region no card flow fetches, opens a card sheet or relays
// anything, and with the live list but no attestation that checks no card
// flow opens a card sheet or relays anything either; and the Swift relay and
// the bridge, read as text (they cannot run here), call the home rule over
// the whole list, send one start request per tap, never try another region
// after a refusal, and never log.
import * as fs from 'fs';
import * as path from 'path';

import { checkCard, confirmFill, fillCard, openCard, sealDeps } from '../../lib/seal/flows';
import type { SealRegion } from '../../lib/seal/seal-config';
import { forgetTrustedSeals, refreshTrustedSeals } from '../../lib/seal/trusted-seal';

// The region list the card flows see: the committed one unless a test sets another.
const mockRegions: { list: readonly SealRegion[] | null } = { list: null };
jest.mock('../../lib/seal/seal-config', () => {
  const actual = jest.requireActual('../../lib/seal/seal-config');
  return {
    get SEAL_REGIONS() {
      return mockRegions.list ?? actual.SEAL_REGIONS;
    },
  };
});
const COMMITTED: readonly SealRegion[] = jest.requireActual('../../lib/seal/seal-config').SEAL_REGIONS;

const mockCalls: { native: string[]; core: string[] } = { native: [], core: [] };

/** A recorder standing in for a module: every function called is noted, and answers harmlessly. */
function mockRecorder(calls: string[], answers: Record<string, unknown>) {
  return new Proxy(
    {},
    {
      get(_target, name: string) {
        if (name === 'then') {
          return undefined;
        }
        return (...args: unknown[]) => {
          calls.push(name);
          const answer = answers[name];
          return typeof answer === 'function' ? (answer as (...a: unknown[]) => unknown)(...args) : answer;
        };
      },
    },
  );
}

jest.mock('expo', () => ({
  requireOptionalNativeModule: (name: string) =>
    name === 'GhostNfc'
      ? mockRecorder(mockCalls.native, {
          isSupported: true,
          setSealRegions: true,
          restoreOpenKey: false,
          fetchSealAttestation: () => Promise.reject(new Error('no fetch expected')),
          relayCheck: () => Promise.reject(new Error('no relay expected')),
          relayFill: () => Promise.reject(new Error('no relay expected')),
          relayFillConfirm: () => Promise.reject(new Error('no relay expected')),
          relayOpen: () => Promise.reject(new Error('no relay expected')),
          beginSession: () => Promise.reject(new Error('no card sheet expected')),
        })
      : null,
}));
jest.mock(
  '../../modules/ghost-core/src/index',
  () =>
    mockRecorder(mockCalls.core, {
      hasSealOpenKey: false,
      sealAttestationChallenge: () => new ArrayBuffer(32),
      sealOpenPhoneKey: () => new ArrayBuffer(1184),
      verifySealAttestation: () => ({ refusal: 'not-pinned' }),
      verifySealAnswer: () => ({ refusal: 'not-pinned' }),
      verifySealFillAnswer: () => ({ refusal: 'not-pinned' }),
      finishSealOpen: () => ({ refusal: 'not-pinned' }),
    }),
  { virtual: true },
);
const mockFiles = new Map<string, unknown>();
jest.mock('../../lib/storage', () => ({
  jsonFile: (name: string) => ({
    read: () => mockFiles.get(name) ?? null,
    write: async (value: unknown) => {
      mockFiles.set(name, JSON.parse(JSON.stringify(value)));
    },
  }),
}));

const root = path.join(__dirname, '..', '..');
const read = (...parts: string[]) => fs.readFileSync(path.join(root, ...parts), 'utf8');

// Any logging call (Swift or the system logger).
const LOGGING = /\bprint\s*\(|\bNSLog\b|\bos_log\b|\bLogger\s*\(|\bdebugPrint\s*\(|\bdump\s*\(/;

beforeEach(() => {
  forgetTrustedSeals();
  mockRegions.list = null;
  mockCalls.native.length = 0;
  mockCalls.core.length = 0;
  mockFiles.clear();
});

describe('the committed region list', () => {
  it("is the live Seal's three regions, in its release order, each at its https address", () => {
    expect(COMMITTED.map((r) => r.id)).toEqual(['us-east-1', 'eu-central-1', 'ap-southeast-1']);
    for (const region of COMMITTED) {
      expect(new URL(region.url).protocol).toBe('https:');
    }
    const source = read('lib', 'seal', 'seal-config.ts');
    expect(source).not.toMatch(/http:\/\//i);
    // The one address there was is gone, and nothing reads it.
    expect(source).not.toMatch(/SEAL_URL/);
    for (const file of ['flows.ts', 'seal-attestation.ts', 'trusted-seal.ts']) {
      expect(read('lib', 'seal', file)).not.toMatch(/\bSEAL_URL\b/);
    }
  });
});

const RELAY = /^(relayCheck|relayFill|relayFillConfirm|relayOpen|beginSession|transceive)$/;

describe('with the live regions but no attestation that checks', () => {
  it('every card flow gives "Can\'t verify this card" and relays nothing, opening no card sheet', async () => {
    expect(await checkCard(sealDeps())).toEqual({ kind: 'cant-verify' });
    expect(await fillCard(sealDeps(), 10n ** 18n, null)).toEqual({ ok: false, status: { kind: 'cant-verify' } });
    expect(await confirmFill(sealDeps())).toEqual({ kind: 'cant-verify' });
    expect(await openCard(sealDeps(), null)).toEqual({ ok: false, status: { kind: 'cant-verify' } });
    // The flows asked each live region for its attestation, and nothing else.
    expect(mockCalls.native).toContain('fetchSealAttestation');
    expect(mockCalls.native.filter((name) => RELAY.test(name))).toEqual([]);
    expect(mockFiles.size).toBe(0);
  });
});

describe('with no region', () => {
  const RELAY_OR_FETCH = /^(fetchSealAttestation|setSealPin|relayCheck|relayFill|relayFillConfirm|relayOpen|beginSession|transceive)$/;

  beforeEach(() => {
    mockRegions.list = [];
  });

  it('every card flow gives "Can\'t verify this card", fetching nothing and opening no card sheet', async () => {
    expect(await checkCard(sealDeps())).toEqual({ kind: 'cant-verify' });
    expect(await fillCard(sealDeps(), 10n ** 18n, null)).toEqual({ ok: false, status: { kind: 'cant-verify' } });
    expect(await confirmFill(sealDeps())).toEqual({ kind: 'cant-verify' });
    expect(await openCard(sealDeps(), null)).toEqual({ ok: false, status: { kind: 'cant-verify' } });
    expect(mockCalls.native.filter((name) => RELAY_OR_FETCH.test(name))).toEqual([]);
    // No attestation was asked for or checked, no phone key made, no answer checked.
    expect(mockCalls.core).toEqual([]);
    expect(mockFiles.size).toBe(0);
  });

  it('the refresh gives no Seal and fetches nothing', async () => {
    expect(await refreshTrustedSeals()).toEqual(new Map());
    expect(mockCalls.native.filter((name) => RELAY_OR_FETCH.test(name))).toEqual([]);
    expect(mockCalls.core).toEqual([]);
  });
});

describe('GhostCardBridge.h', () => {
  const header = read('modules', 'ghost-nfc', 'ios', 'GhostCardBridge.h');

  it('declares the home rule of the native core, with its UID and its ids as one buffer', () => {
    expect(header).toContain(
      'intptr_t ghost_wallet_seal_home_region(const uint8_t *uid, uintptr_t uid_len, const uint8_t *ids, uintptr_t ids_len);',
    );
    expect(header).toMatch(/one id per line/);
    expect(header).toMatch(/-1 for none/);
    expect(header).toMatch(/-3 for a\s+(\/\/\/\s+)?null pointer/);
  });

  it('matches the Rust bridge', () => {
    const rust = read('core', 'src', 'seal_home_region.rs');
    expect(rust).toMatch(
      /pub unsafe extern "C" fn ghost_wallet_seal_home_region\(\s*uid: \*const u8,\s*uid_len: usize,\s*ids: \*const u8,\s*ids_len: usize,\s*\) -> isize/,
    );
    expect(rust).toContain('pub fn home_region_index(uid: &[u8], region_ids: &[String]) -> Option<usize>');
    expect(rust).toContain('b"ghost-seal/v1/home-region"');
    expect(read('core', 'src', 'lib.rs')).toContain('pub mod seal_home_region;');
  });
});

describe('SealRelay.swift', () => {
  const source = read('modules', 'ghost-nfc', 'ios', 'SealRelay.swift');

  it('chooses the home region with the native core, over the whole listed list', () => {
    const home = source.match(/private static func homeRegion\([\s\S]*?\n {2}\}\n/);
    expect(home).not.toBeNull();
    expect(home![0]).toContain('regions.map(\\.id).joined(separator: "\\n")');
    expect(home![0]).toContain('ghost_wallet_seal_home_region(');
    expect(home![0]).toMatch(/guard index >= 0, index < regions\.count else \{ return nil \}/);
    // The list is taken as it is, never cut down to the regions that verified or are pinned.
    expect(source).toMatch(/let regions = SealRegions\.shared\.list\s/);
    expect(source).toContain('target = .home(regions)');
    expect(source).toContain('guard let home = homeRegion(uid: uid, regions: regions) else { return nil }');
    expect(source).not.toMatch(/regions\.filter|\.filter\s*\{[^}]*pinned/);
    expect(source.match(/ghost_wallet_seal_home_region\(/g)).toHaveLength(1);
  });

  it('sends nothing with no list, or with no pin for the home region', () => {
    expect(source).toMatch(/guard !regions\.isEmpty else \{\s*promise\.reject\(SealUnreachableException\(\)\)\s*return\s*\}/);
    expect(source).toMatch(
      /guard let destination = Self\.destination\(target, uid: uid\),\s*SealPins\.shared\.allows\(destination\.base\)\s*else \{\s*self\.end\(promise, error: SealUnreachableException\(\)\)\s*return\s*\}/,
    );
  });

  it('chooses one Seal per tap and sends exactly one start request to it', () => {
    expect(source.match(/Self\.destination\(/g)).toHaveLength(1);
    expect(source.match(/path: flow\.path/g)).toHaveLength(1);
    // Every other request continues the one session or tells it the card left.
    const posts = [...source.matchAll(/self\.post\(run, path: ([^,]+),/g)].map((m) => m[1]);
    expect(posts).toEqual(['flow.path', '"v1/relay/step"']);
    // A run keeps the one address it was given.
    expect(source).toMatch(/let base: URL\n/);
    expect(source).not.toMatch(/var base: URL/);
  });

  it('ends the tap on a refusal, never following the region it names or trying another', () => {
    expect(source).toMatch(/guard status == 200 else \{\s*self\.finish\(run, error: Self\.refusal\(fields\)\)\s*return\s*\}/);
    expect(source).toContain('case "wrong-region": return SealWrongRegionException()');
    expect(source).toContain(
      '"This card is served by another Seal region than the one this iPhone chose. Update Ghost Wallet, then try again."',
    );
    // The region the Seal names is never read.
    expect(source).not.toMatch(/fields\["homeRegion"\]/);
    const end = source.match(/private func end\([\s\S]*?\n {2}\}\n/);
    expect(end).not.toBeNull();
    expect(end![0]).not.toMatch(/post\(|run\(|dataTask/);
    expect(source).not.toMatch(/retry|again\(|nextRegion|otherRegion/i);
  });

  it('names the region in the result: the id it chose, or none for a typed address', () => {
    expect(source).toContain('"region": run.region,');
    expect(source).toContain('return (base, "")');
    expect(source).toContain('return (home.url, home.id)');
  });

  it('keeps the region list in memory only and never logs', () => {
    expect(source).not.toMatch(/UserDefaults|SecItemAdd|FileManager/);
    expect(source).not.toMatch(LOGGING);
  });
});

describe('GhostNfcModule.swift', () => {
  const source = read('modules', 'ghost-nfc', 'ios', 'GhostNfcModule.swift');

  it('registers the region list beside the pin', () => {
    expect(source).toContain('Function("setSealRegions") { (regionsJson: String) -> Bool in');
    expect(source).toContain('SealRegions.shared.set(json: regionsJson)');
    expect(source).not.toMatch(LOGGING);
  });
});

describe('JavaScript', () => {
  const tsFiles = (dir: string): string[] =>
    fs.readdirSync(path.join(root, dir), { withFileTypes: true }).flatMap((entry) => {
      const rel = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        return tsFiles(rel);
      }
      return /\.(ts|tsx|js|jsx)$/.test(entry.name) ? [rel] : [];
    });

  it('picks no region: no home rule, label or hash of it anywhere in lib/ or the card module', () => {
    const files = [...tsFiles('lib'), ...tsFiles(path.join('modules', 'ghost-nfc'))];
    expect(files.length).toBeGreaterThan(10);
    for (const file of files) {
      const source = read(file);
      expect([file, /ghost_wallet_seal_home_region|ghost-seal\/v1\/home-region|homeRegion|home_region/.test(source)]).toEqual([file, false]);
    }
    // Every card flow goes to the home region the native relay chooses.
    const flows = read('lib', 'seal', 'flows.ts');
    expect(flows).toContain('check: () => checkWithSeal(HOME_REGION)');
    expect(flows).toContain('fill: (amountWei, pin) => fillWithSeal(HOME_REGION, amountWei, pin)');
    expect(flows).toContain('confirm: () => confirmFillWithSeal(HOME_REGION)');
    expect(flows).toContain('open: (phoneKey, pin) => openWithSeal(HOME_REGION, phoneKey, pin)');
    // Each flow makes one relay call, and none is made again after a failure.
    expect(flows.match(/await deps\.(check|fill|confirm|open)\(/g)).toEqual([
      'await deps.check(',
      'await deps.fill(',
      'await deps.confirm(',
      'await deps.open(',
    ]);
  });

  it('imports no hash or crypto library under lib/', () => {
    const banned = [
      'js-' + 'sha3',
      '@noble/' + 'hashes',
      'crypto-js',
      'expo-crypto',
      'react-native-quick-crypto',
      'tweetnacl',
      'hash.js',
      'sha3',
      'sha.js',
      'crypto',
      'node:crypto',
    ];
    const createHash = new RegExp('create' + 'Hash\\(');
    const subtle = new RegExp('crypto' + '\\.subtle');
    for (const file of tsFiles('lib')) {
      const source = read(file);
      const imported = [...source.matchAll(/(?:from\s+|require\(\s*|import\(\s*)['"]([^'"]+)['"]/g)].map((m) => m[1]);
      for (const name of imported) {
        expect([file, banned.some((b) => name === b || name.startsWith(`${b}/`))]).toEqual([file, false]);
      }
      expect([file, createHash.test(source) || subtle.test(source)]).toEqual([file, false]);
    }
  });

  it('logs nothing in the region code', () => {
    const consoleCall = /\bconsole\.(log|info|warn|error|debug)\s*\(/;
    for (const file of [
      ['lib', 'seal', 'flows.ts'],
      ['lib', 'seal', 'trusted-seal.ts'],
      ['lib', 'seal', 'seal-attestation.ts'],
      ['lib', 'seal', 'seal-config.ts'],
      ['modules', 'ghost-nfc', 'relay.ts'],
    ]) {
      expect(read(...file)).not.toMatch(consoleCall);
    }
  });
});
