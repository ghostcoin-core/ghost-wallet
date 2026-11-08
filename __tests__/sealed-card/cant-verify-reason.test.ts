// "Can't verify this card" says which check failed: every way a card flow
// gets there carries a short, non-secret reason, and the card screen shows it
// on a second line, "Reason: ...". The reasons are codes and region ids only:
// never a key, a hash, a challenge, card data or a PIN.
//
// Here: no region verifies (each region's own first failure, through the real
// refresh and loader, with a fake native fetch and pin and a fake attestation
// core), a refusal of the native core (`wrong-challenge`, faked as
// core/src/seal_answer.rs checks it), an answer from a region with no
// verified Seal (`seal-of-answer`), and the relay's own `bad-answer`.
import type { CoreSealAttestationCheck, CoreSealAttestationVerdict, SealAttestationBindings } from '../../modules/ghost-core';
import type { GhostNfcSealPinNative, GhostNfcSealRegionsNative } from '../../modules/ghost-nfc';
import { checkWithSeal, confirmFillWithSeal, fillWithSeal, HOME_REGION, openWithSeal, SealRelayError } from '../../modules/ghost-nfc/relay';
import { cantVerify, reasonText, statusDetail, statusOfFailure, statusText, type CardStatus } from '../../lib/seal/card-status';
import { checkCard, confirmFill, fillCard, openCard, type SealDeps } from '../../lib/seal/flows';
import { parseMeasurementList } from '../../lib/seal/pinned-measurements';
import { forgetTrustedSeals, refreshTrustedSeals, type TrustedSealsDeps } from '../../lib/seal/trusted-seal';
import { GHOST, hexOf, PINNED_JSON, resetWorld, THREE_REGIONS, regionUrl, type World } from './fake-seal';

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
const SENTENCE = 'The Seal’s answer did not pass this iPhone’s checks. Do not accept this card.';
/** A run of hex longer than 16 digits: a key, hash or challenge. */
const LONG_HEX = /[0-9a-fA-F]{17,}/;

/** Every reason the tests saw, for the check that none holds a secret. */
const seen: string[] = [];

/** The reason line the card screen shows under "Can't verify this card", after checking the rest of it. */
function reasonOf(status: CardStatus | null): string {
  expect(status).toMatchObject({ kind: 'cant-verify' });
  expect(statusText(status!)).toBe("Can't verify this card");
  const lines = statusDetail(status!)!.split('\n');
  expect(lines).toHaveLength(2);
  expect(lines[0]).toBe(SENTENCE);
  expect(lines[1]).toMatch(/^Reason: /);
  const reason = lines[1].slice('Reason: '.length);
  seen.push(reason);
  return reason;
}

function depsOf(world: World): SealDeps {
  return {
    seals: new Map(),
    refresh: async () => world.refreshed(),
    core: world.core,
    check: () => checkWithSeal(HOME_REGION, world.native),
    fill: (amountWei, pin) => fillWithSeal(HOME_REGION, amountWei, pin, world.native),
    confirm: () => confirmFillWithSeal(HOME_REGION, world.native),
    open: (phoneKey, pin) => openWithSeal(HOME_REGION, phoneKey, pin, world.native),
    keeper: world.native,
    list: PINNED,
  };
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

/** The fake attestation core: answers each region's attestation (its first byte names the region) with `verdicts`. */
class FakeAttestationCore implements SealAttestationBindings {
  verdicts = new Map<number, CoreSealAttestationVerdict>();
  challenges: string[] = [];

  verifySealAttestation(check: CoreSealAttestationCheck): CoreSealAttestationVerdict {
    this.challenges.push(hexOf(new Uint8Array(check.challenge)));
    return this.verdicts.get(new Uint8Array(check.attestation)[0]) ?? ACCEPTED;
  }

  sealAttestationChallenge(): ArrayBuffer {
    return buffer(Uint8Array.from({ length: 32 }, (_, i) => 0xc0 + i));
  }
}

/**
 * The fake native attestation fetch and pin, with the world's region list:
 * the relay sees the same list the refresh hands it.
 */
function attestationNative(world: World, options: { unreachable: Set<string>; pinRefused: Set<string> }) {
  const native: GhostNfcSealPinNative & GhostNfcSealRegionsNative = {
    async fetchSealAttestation(sealUrl) {
      if (options.unreachable.has(sealUrl)) {
        throw Object.assign(new Error('offline'), { code: 'ERR_SEAL_UNREACHABLE' });
      }
      const index = THREE_REGIONS.findIndex((id) => regionUrl(id) === sealUrl);
      return { attestation: hexOf(Uint8Array.from([index, 0x47, 0x50, 0x41, 0x32])), certSha256: '7e'.repeat(32) };
    },
    setSealPin(sealUrl, certSha256) {
      if (certSha256 !== '' && options.pinRefused.has(sealUrl)) {
        throw new Error('pin refused');
      }
    },
    setSealRegions: (regionsJson) => world.native.setSealRegions(regionsJson),
  };
  return native;
}

let world: World;

beforeEach(() => {
  forgetTrustedSeals();
  world = resetWorld();
  mockFiles.clear();
});

describe('no region verifies', () => {
  function refreshDeps(core: FakeAttestationCore, native: ReturnType<typeof attestationNative>): TrustedSealsDeps {
    return {
      regions: THREE_REGIONS.map((id) => ({ id, url: regionUrl(id) })),
      native,
      core: () => core,
      now: () => Date.now(),
      list: PINNED,
    };
  }

  it("names each region's first failure: the fetch's error code, the core's refusal, or pin-failed", async () => {
    world.useRegions(THREE_REGIONS);
    world.sealedCard(5n * GHOST);
    const core = new FakeAttestationCore();
    core.verdicts.set(1, { refusal: 'not-pinned' });
    const native = attestationNative(world, {
      unreachable: new Set([regionUrl('us-east-1')]),
      pinRefused: new Set([regionUrl('ap-southeast-1')]),
    });
    const deps: SealDeps = { ...depsOf(world), refresh: () => refreshTrustedSeals(refreshDeps(core, native)) };
    const expected = 'us-east-1: seal-unreachable; eu-central-1: not-pinned; ap-southeast-1: pin-failed';

    expect(reasonOf(await checkCard(deps))).toBe(expected);
    // The failures are kept 30 seconds, and every flow says the same.
    const fill = await fillCard(deps, GHOST, null);
    expect(fill.ok).toBe(false);
    expect(reasonOf(fill.ok ? null : fill.status)).toBe(expected);
    expect(reasonOf(await confirmFill(deps))).toBe(expected);
    const open = await openCard(deps, null);
    expect(reasonOf(open.ok ? null : open.status)).toBe(expected);
    // No card sheet opened, and no challenge reached the reason.
    expect(world.calls).toEqual([]);
    for (const challenge of core.challenges) {
      expect(expected).not.toContain(challenge);
    }
  });

  it('says so when no region is listed, or the list could not be handed to the relay', async () => {
    const core = new FakeAttestationCore();
    const native = attestationNative(world, { unreachable: new Set(), pinRefused: new Set() });
    const none = { ...refreshDeps(core, native), regions: [] };
    expect(reasonOf(await checkCard({ ...depsOf(world), refresh: () => refreshTrustedSeals(none) }))).toBe('no-regions');
    const refused = { ...refreshDeps(core, { ...native, setSealRegions: () => false }) };
    expect(reasonOf(await checkCard({ ...depsOf(world), refresh: () => refreshTrustedSeals(refused) }))).toBe('regions-not-listed');
  });

  it('names a refresh that failed, and a missing core', async () => {
    const failing = async () => {
      throw new Error('no attestation');
    };
    expect(reasonOf(await checkCard({ ...depsOf(world), refresh: failing }))).toBe('refresh-failed');
    expect(reasonOf(await checkCard({ ...depsOf(world), core: null }))).toBe('no-answer-core');
  });
});

describe('a refusal of the native core', () => {
  it('is the reason of a Check: a replayed answer is wrong-challenge', async () => {
    world.sealedCard(5n * GHOST);
    world.refreshed();
    const old = await checkWithSeal(HOME_REGION, world.native);
    const fresh = await checkWithSeal(HOME_REGION, world.native);
    const deps: SealDeps = { ...depsOf(world), check: async () => ({ ...fresh, answer: old.answer, signature: old.signature }) };
    expect(reasonOf(await checkCard(deps))).toBe('wrong-challenge');
  });

  it("is the reason of a Fill and of a Fill's confirmation", async () => {
    world.newCard();
    world.refreshed();
    const old = await fillWithSeal(HOME_REGION, GHOST, null, world.native);
    const fresh = await fillWithSeal(HOME_REGION, GHOST, null, world.native);
    const replayed = { ...fresh, answer: old.answer, signature: old.signature };
    const filled = await fillCard({ ...depsOf(world), fill: async () => replayed }, GHOST, null);
    expect(reasonOf(filled.ok ? null : filled.status)).toBe('wrong-challenge');

    world.seal.paid = true;
    const confirmed = await confirmFillWithSeal(HOME_REGION, world.native);
    const again = await confirmFillWithSeal(HOME_REGION, world.native);
    const stale = { ...again, answer: confirmed.answer, signature: confirmed.signature };
    expect(reasonOf(await confirmFill({ ...depsOf(world), confirm: async () => stale }))).toBe('wrong-challenge');
  });

  it('is the reason the core gave for each tampered answer', async () => {
    world.sealedCard(5n * GHOST);
    world.seal.tamper = 'bad-signature';
    expect(reasonOf(await checkCard(depsOf(world)))).toBe('bad-signature');
    world.seal.tamper = 'expired';
    expect(reasonOf(await checkCard(depsOf(world)))).toBe('expired');
  });

  it('never shows a long run of hex, whatever the core says', () => {
    const odd = cantVerify(`bad-${'ab'.repeat(32)}`);
    expect(reasonOf(odd)).not.toMatch(LONG_HEX);
    expect(reasonOf(odd)).toMatch(/^bad-/);
    expect(reasonText('')).toBe('unknown');
    expect(reasonText('pin\n1234\u0000')).not.toMatch(/\n|\u0000/);
  });
});

describe('an answer from a region with no verified Seal', () => {
  it('is seal-of-answer, naming the region', async () => {
    world.useRegions(THREE_REGIONS);
    // This card's home is ap-southeast-1, whose attestation fails now.
    world.sealedCard(5n * GHOST, null, '0412345678ABCD');
    world.unverified.add('ap-southeast-1');
    expect(reasonOf(await checkCard(depsOf(world)))).toBe('seal-of-answer (ap-southeast-1)');
    expect(world.calls).toEqual(['check']);
  });

  it("names that region's own failure when the refresh knows it", async () => {
    world.useRegions(THREE_REGIONS);
    world.sealedCard(5n * GHOST, null, '0412345678ABCD');
    const core = new FakeAttestationCore();
    core.verdicts.set(2, { refusal: 'revoked' });
    const native = attestationNative(world, { unreachable: new Set(), pinRefused: new Set() });
    const refresh = () =>
      refreshTrustedSeals({
        regions: THREE_REGIONS.map((id) => ({ id, url: regionUrl(id) })),
        native,
        core: () => core,
        now: () => Date.now(),
        list: PINNED,
      });
    const deps: SealDeps = { ...depsOf(world), refresh };
    expect(reasonOf(await checkCard(deps))).toBe('seal-of-answer (ap-southeast-1: revoked)');
    const open = await openCard(deps, null);
    expect(reasonOf(open.ok ? null : open.status)).toBe('seal-of-answer (ap-southeast-1: revoked)');
  });

  it('is seal-of-answer when the answer names no region', async () => {
    world.sealedCard(5n * GHOST);
    world.refreshed();
    const relayed = await checkWithSeal(HOME_REGION, world.native);
    expect(reasonOf(await checkCard({ ...depsOf(world), check: async () => ({ ...relayed, region: '' }) }))).toBe(
      'seal-of-answer (no region)',
    );
  });
});

describe("the relay's own bad-answer", () => {
  it('is the reason when the relay refuses an answer of another challenge or card', async () => {
    world.sealedCard(5n * GHOST);
    world.refreshed();
    await checkWithSeal(HOME_REGION, world.native);
    world.seal.tamper = 'replay';
    expect(reasonOf(await checkCard(depsOf(world)))).toBe('bad-answer');
    world.seal.tamper = 'other-card';
    expect(reasonOf(await checkCard(depsOf(world)))).toBe('bad-answer');
    expect(reasonOf(statusOfFailure(new SealRelayError('bad-answer')))).toBe('bad-answer');
  });
});

describe('every reason', () => {
  it('is short codes and region ids: no hex longer than 16 digits', () => {
    expect(seen.length).toBeGreaterThan(10);
    for (const reason of seen) {
      expect([reason, LONG_HEX.test(reason)]).toEqual([reason, false]);
      // `?` stands for anything else the core said.
      expect(reason).toMatch(/^[a-z0-9 :;,()?-]+$/);
    }
  });
});
