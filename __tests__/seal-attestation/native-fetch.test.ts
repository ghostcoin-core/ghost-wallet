// The native fetch of the Seal's attestation and the relay's pinned
// certificate, as JavaScript sees them (modules/ghost-nfc/relay.ts), and the
// Swift that does the work, read as text: the Swift files cannot run here, so
// the device check is after merge.
import * as fs from 'fs';
import * as path from 'path';

import type { GhostNfcSealPinNative } from '../../modules/ghost-nfc';
import { fetchSealAttestation, SealRelayError, setSealPin } from '../../modules/ghost-nfc/relay';

jest.mock('expo', () => ({ requireOptionalNativeModule: () => null }));

const URL_ = 'https://seal.example:8443';
const CERT_HEX = '7e'.repeat(32);

function hexOf(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

type Answer = Record<string, unknown>;

function fakeNative(answer: Answer | Error = { attestation: '47504132aabb', certSha256: CERT_HEX }) {
  const fetches: { url: string; challenge: string }[] = [];
  const pins: { url: string; hash: string }[] = [];
  const nfc: GhostNfcSealPinNative = {
    fetchSealAttestation: async (sealUrl, challenge) => {
      fetches.push({ url: sealUrl, challenge });
      if (answer instanceof Error) {
        throw answer;
      }
      return answer as { attestation: string; certSha256: string };
    },
    setSealPin: (sealUrl, certSha256) => {
      pins.push({ url: sealUrl, hash: certSha256 });
    },
  };
  return { nfc, fetches, pins };
}

async function problemOf(run: Promise<unknown>): Promise<string> {
  try {
    await run;
  } catch (error) {
    return error instanceof SealRelayError ? error.problem : 'other';
  }
  return 'none';
}

const challenge = Uint8Array.from({ length: 32 }, (_, i) => i * 7);

describe('fetchSealAttestation', () => {
  it('returns only the attestation and the certificate hash', async () => {
    const { nfc, fetches } = fakeNative({
      attestation: '47504132AABB',
      certSha256: CERT_HEX.toUpperCase(),
      uid: '04518dfaa96180',
      apdu: '9000',
      extra: 'anything',
    });
    const fetched = await fetchSealAttestation(URL_, challenge, nfc);
    expect(Object.keys(fetched).sort()).toEqual(['attestation', 'certSha256']);
    expect(hexOf(fetched.attestation)).toBe('47504132aabb');
    expect(hexOf(fetched.certSha256)).toBe(CERT_HEX);
    expect(fetches).toEqual([{ url: URL_, challenge: hexOf(challenge) }]);
  });

  it('asks only an https:// Seal, with a 32-byte challenge, and only a build with the fetch', async () => {
    const { nfc, fetches } = fakeNative();
    expect(await problemOf(fetchSealAttestation('http://seal.example', challenge, nfc))).toBe('bad-address');
    expect(await problemOf(fetchSealAttestation('', challenge, nfc))).toBe('bad-address');
    expect(await problemOf(fetchSealAttestation(URL_, challenge.slice(1), nfc))).toBe('failed');
    expect(fetches).toEqual([]);
    expect(await problemOf(fetchSealAttestation(URL_, challenge, null))).toBe('seal-unreachable');
    expect(await problemOf(fetchSealAttestation(URL_, challenge))).toBe('seal-unreachable');
  });

  it('refuses an answer with no attestation, a hash that is not 32 bytes, or more than 32 KiB', async () => {
    const answers: Answer[] = [
      { certSha256: CERT_HEX },
      { attestation: '', certSha256: CERT_HEX },
      { attestation: 'zz', certSha256: CERT_HEX },
      { attestation: '4750', certSha256: '7e'.repeat(31) },
      { attestation: '4750' },
      { attestation: 'ab'.repeat(32 * 1024 + 1), certSha256: CERT_HEX },
    ];
    for (const answer of answers) {
      const { nfc } = fakeNative(answer);
      expect(await problemOf(fetchSealAttestation(URL_, challenge, nfc))).toBe('bad-answer');
    }
    const { nfc } = fakeNative({ attestation: 'ab'.repeat(32 * 1024), certSha256: CERT_HEX });
    expect((await fetchSealAttestation(URL_, challenge, nfc)).attestation).toHaveLength(32 * 1024);
  });

  it('turns a native failure into a relay problem', async () => {
    const { nfc } = fakeNative(Object.assign(new Error('offline'), { code: 'ERR_SEAL_UNREACHABLE' }));
    expect(await problemOf(fetchSealAttestation(URL_, challenge, nfc))).toBe('seal-unreachable');
    const other = fakeNative(new Error('anything'));
    expect(await problemOf(fetchSealAttestation(URL_, challenge, other.nfc))).toBe('failed');
  });
});

describe('setSealPin', () => {
  it('pins the Seal to a 32-byte certificate hash, as lowercase hex, and drops it with null', () => {
    const { nfc, pins } = fakeNative();
    const hash = new Uint8Array(32).fill(0xab);
    expect(setSealPin(URL_, hash, nfc)).toBe(true);
    expect(setSealPin(URL_, null, nfc)).toBe(true);
    expect(pins).toEqual([
      { url: URL_, hash: 'ab'.repeat(32) },
      { url: URL_, hash: '' },
    ]);
  });

  it('sets nothing for a bad address or hash, or with no module', () => {
    const { nfc, pins } = fakeNative();
    expect(setSealPin('not an address', new Uint8Array(32), nfc)).toBe(false);
    expect(setSealPin(URL_, new Uint8Array(31), nfc)).toBe(false);
    expect(pins).toEqual([]);
    expect(setSealPin(URL_, new Uint8Array(32), null)).toBe(false);
    expect(setSealPin(URL_, new Uint8Array(32))).toBe(false);
  });

  it('returns no card traffic and nothing but whether the pin was set', () => {
    const { nfc } = fakeNative();
    nfc.setSealPin = () => {
      throw new Error('refused');
    };
    expect(setSealPin(URL_, new Uint8Array(32), nfc)).toBe(false);
  });
});

const root = path.join(__dirname, '..', '..');
const read = (...parts: string[]) => fs.readFileSync(path.join(root, ...parts), 'utf8');

// Any logging call (Swift or the system logger).
const LOGGING = /\bprint\s*\(|\bNSLog\b|\bos_log\b|\bLogger\s*\(|\bdebugPrint\s*\(|\bdump\s*\(/;
// An App Transport Security exception, of any kind.
const ATS_EXCEPTION = new RegExp(['NSApp' + 'TransportSecurity', 'NSAllows' + 'Arbitrary', 'NSException' + 'Domains', 'NSAllows' + 'Local'].join('|'));

describe('the native module type', () => {
  const index = read('modules', 'ghost-nfc', 'index.ts');

  it('keeps the fetch and the pin in their own type, apart from the card and relay types', () => {
    const type = index.match(/export type GhostNfcSealPinNative = \{([\s\S]*?)\n\};/);
    expect(type).not.toBeNull();
    const members = [...type![1].matchAll(/^\s+(\w+)\(/gm)].map((m) => m[1]).sort();
    expect(members).toEqual(['fetchSealAttestation', 'setSealPin']);
    const card = index.match(/export type GhostNfcNative = \{([\s\S]*?)\n\};/);
    expect(card![1]).not.toMatch(/fetchSealAttestation|setSealPin/);
    expect(read('modules', 'ghost-nfc', 'relay.ts').match(/export type GhostNfcSealNative = [\s\S]*?\n\};/)![0]).not.toMatch(
      /fetchSealAttestation|setSealPin/,
    );
  });
});

describe('SealAttestation.swift', () => {
  const source = read('modules', 'ghost-nfc', 'ios', 'SealAttestation.swift');

  it('makes one POST to /v1/attestation with the challenge, a 10 second timeout and a 32 KiB cap', () => {
    expect(source).toContain('appendingPathComponent("v1/attestation")');
    expect(source).toContain('request.httpMethod = "POST"');
    expect(source).toContain('["challenge": challenge.lowercased()]');
    expect(source).toContain('config.timeoutIntervalForRequest = 10');
    expect(source).toContain('config.timeoutIntervalForResource = 10');
    expect(source).toContain('static let maxBytes = 32 * 1024');
    expect(source).toMatch(/body\.count > SealAttestation\.maxBytes/);
    expect(source).toMatch(/base\.scheme\?\.lowercased\(\) == "https"/);
  });

  it('hashes the DER of the leaf certificate the connection presented, for this request only', () => {
    expect(source).toMatch(/SecTrustCopyCertificateChain\(trust\)[\s\S]*chain\.first/);
    expect(source).toContain('SecCertificateCopyData(leaf)');
    expect(source).toContain('SHA256.hash(data: der)');
    expect(source).toMatch(/NSURLAuthenticationMethodServerTrust/);
    // Its own session and delegate for each request, let go once it is over.
    expect(source).toMatch(/URLSession\(configuration: config, delegate: capture, delegateQueue: nil\)/);
    expect(source).toContain('session.finishTasksAndInvalidate()');
    // A connection with no leaf certificate to hash is cancelled.
    expect(source).toContain('completionHandler(.cancelAuthenticationChallenge, nil)');
  });

  it('hands JavaScript only the attestation and the certificate hash', () => {
    const resolves = [...source.matchAll(/promise\.resolve\((.*)\)\s*$/gm)].map((m) => m[1]);
    expect(resolves).toEqual(['["attestation": Self.hex(attestation), "certSha256": Self.hex(hash)]']);
  });

  it('sets no ATS exception and never logs', () => {
    expect(source).not.toMatch(ATS_EXCEPTION);
    expect(source).not.toMatch(LOGGING);
  });
});

describe('SealRelay.swift', () => {
  const source = read('modules', 'ghost-nfc', 'ios', 'SealRelay.swift');

  it('connects only to a pinned Seal whose leaf certificate hashes to the pin', () => {
    expect(source).toContain('URLSession(configuration: config, delegate: PinnedSealTrust(), delegateQueue: nil)');
    const check = source.match(/private func check\([\s\S]*?\n {2}\}\n/);
    expect(check).not.toBeNull();
    expect(check![0]).toContain('SealPins.shared.pinned(host: space.host, port: space.port)');
    expect(check![0]).toContain('SealCertificates.leafSha256(trust)');
    expect(check![0]).toContain('presented == pinned');
    expect(check![0]).toMatch(/else \{\s*completionHandler\(\.cancelAuthenticationChallenge, nil\)\s*return\s*\}/);
  });

  it('refuses to start a flow, or send a request, with no pin as seal-unreachable', () => {
    expect(source).toMatch(/guard SealPins\.shared\.allows\(base\) else \{\s*promise\.reject\(SealUnreachableException\(\)\)/);
    expect(source).toMatch(/guard SealPins\.shared\.allows\(run\.base\) else \{\s*finish\(run, error: SealUnreachableException\(\)\)/);
    expect(source).toMatch(/func allows\(_ url: URL\) -> Bool \{\s*guard url\.scheme\?\.lowercased\(\) == "https"/);
  });

  it('drops a pin for anything but a 64-digit hash, and keeps pins in memory only', () => {
    expect(source).toContain('let hash = certSha256.count == 64 ? Self.bytes(certSha256) : nil');
    expect(source).toContain('pins[key] = hash');
    expect(source).not.toMatch(/UserDefaults|SecItemAdd|FileManager/);
  });

  it('sets no ATS exception and never logs', () => {
    expect(source).not.toMatch(ATS_EXCEPTION);
    expect(source).not.toMatch(LOGGING);
  });
});

describe('GhostNfcModule.swift', () => {
  const source = read('modules', 'ghost-nfc', 'ios', 'GhostNfcModule.swift');

  it('registers the fetch and the pin', () => {
    expect(source).toContain('AsyncFunction("fetchSealAttestation") { (sealUrl: String, challenge: String, promise: Promise) in');
    expect(source).toContain('self.attestation.fetch(sealUrl: sealUrl, challenge: challenge, promise: promise)');
    expect(source).toContain('Function("setSealPin") { (sealUrl: String, certSha256: String) in');
    expect(source).toContain('SealPins.shared.set(sealUrl: sealUrl, certSha256: certSha256)');
    expect(source).not.toMatch(LOGGING);
  });
});
