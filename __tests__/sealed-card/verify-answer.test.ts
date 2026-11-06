// The phone's check of the Seal's signed answers, from the relay's result to
// the card's status. The native core's checks run in Rust
// (core/tests/seal_answer.rs); here the core is the fake world's, which
// checks in the same order, and the Seal and card are fakes too.
import { STATUS_TEXT, statusOfFailure, statusText, type CardStatus } from '../../lib/seal/card-status';
import { checkCard, fillCard, type SealDeps } from '../../lib/seal/flows';
import { parseMeasurementList, PINNED_MEASUREMENTS } from '../../lib/seal/pinned-measurements';
import { trustedSeal } from '../../lib/seal/trusted-seal';
import { answerCheck, pinnedAnswerMeasurements, verifyCheckAnswer } from '../../lib/seal/verify-answer';
import { CardCancelled } from '../../modules/ghost-nfc';
import { checkWithSeal, confirmFillWithSeal, fillWithSeal, openWithSeal, SealRelayError } from '../../modules/ghost-nfc/relay';
import { FAKE_MEASUREMENT_HEX, GHOST, hexOf, PINNED_JSON, resetWorld, UID_HEX, type World } from './fake-seal';

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

function depsOf(world: World, list = PINNED): SealDeps {
  return {
    seal: world.trusted(),
    core: world.core,
    check: (url) => checkWithSeal(url, world.native),
    fill: (url, amountWei, pin) => fillWithSeal(url, amountWei, pin, world.native),
    confirm: (url) => confirmFillWithSeal(url, world.native),
    open: (url, phoneKey, pin) => openWithSeal(url, phoneKey, pin, world.native),
    keeper: world.native,
    list,
  };
}

let world: World;

beforeEach(() => {
  world = resetWorld();
  mockFiles.clear();
});

describe('the pinned measurements', () => {
  it('pins no Seal today, so every Seal is refused', () => {
    expect(PINNED_MEASUREMENTS.builds).toEqual([]);
    expect(pinnedAnswerMeasurements()).toEqual([]);
  });

  it('pins the PCR0 of each allowed build, and never a revoked one', () => {
    const list = parseMeasurementList(
      JSON.stringify({
        version: 1,
        builds: [
          { name: 'old', released: '2026-10-01', pcr0: '77'.repeat(48), pcr1: '11'.repeat(48), pcr2: '22'.repeat(48), status: 'revoked' },
          { name: 'new', released: '2026-11-01', pcr0: FAKE_MEASUREMENT_HEX, pcr1: '33'.repeat(48), pcr2: '44'.repeat(48), status: 'allowed' },
        ],
      }),
    );
    expect(pinnedAnswerMeasurements(list).map(hexOf)).toEqual([FAKE_MEASUREMENT_HEX]);
  });

  it('has no Seal to vouch for outside the tests: the seam returns nothing', () => {
    expect(trustedSeal()).toBeNull();
  });
});

describe('what the core checks an answer against', () => {
  it('is the challenge the relay sent, the card tapped, now, the Seal key and the pinned list', async () => {
    world.sealedCard(5n * GHOST);
    const relayed = await checkWithSeal('https://seal.example', world.native);
    const check = answerCheck(world.trusted()!, relayed, 'check', { now: () => 1_800_000_000_500, list: PINNED });
    expect(hexOf(new Uint8Array(check.challenge))).toBe(hexOf(world.challenges[0]));
    expect(hexOf(new Uint8Array(check.uid)).toUpperCase()).toBe(UID_HEX);
    expect(check.now).toBe(1_800_000_000n);
    expect(check.kind).toBe('check');
    expect(hexOf(new Uint8Array(check.verifyingKey))).toBe(hexOf(world.seal.key));
    expect(check.pinnedMeasurements.map((m) => hexOf(new Uint8Array(m)))).toEqual([FAKE_MEASUREMENT_HEX]);
  });
});

describe('a Check answer', () => {
  it('is accepted when the Seal signed it fresh over this challenge about this card', async () => {
    world.sealedCard(5n * GHOST);
    const relayed = await checkWithSeal('https://seal.example', world.native);
    const verdict = verifyCheckAnswer(world.core, world.trusted()!, relayed, { list: PINNED });
    expect(verdict).toEqual({
      ok: true,
      answer: expect.objectContaining({ state: 'sealed', amountWei: 5n * GHOST, uid: UID_HEX, pinRequired: false }),
    });
  });

  it('with a bad signature is refused and gives no amount', async () => {
    world.sealedCard(5n * GHOST);
    world.seal.tamper = 'bad-signature';
    const relayed = await checkWithSeal('https://seal.example', world.native);
    const verdict = verifyCheckAnswer(world.core, world.trusted()!, relayed, { list: PINNED });
    expect(verdict).toEqual({ ok: false, refusal: 'bad-signature' });
    expect(JSON.stringify(verdict, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v))).not.toMatch(/5000000000000000000/);
  });

  it('signed by another key is refused', async () => {
    world.sealedCard(5n * GHOST);
    world.seal.tamper = 'other-key';
    const relayed = await checkWithSeal('https://seal.example', world.native);
    expect(verifyCheckAnswer(world.core, world.trusted()!, relayed, { list: PINNED })).toEqual({ ok: false, refusal: 'bad-signature' });
  });

  it('replayed (an old Sealed answer over an earlier challenge) is refused', async () => {
    world.sealedCard(5n * GHOST);
    const old = await checkWithSeal('https://seal.example', world.native);
    // The card is opened since; the old answer is sent with a fresh challenge.
    world.card.state = 'opened';
    const fresh = await checkWithSeal('https://seal.example', world.native);
    const replayed = { ...fresh, answer: old.answer, signature: old.signature };
    expect(verifyCheckAnswer(world.core, world.trusted()!, replayed, { list: PINNED })).toEqual({
      ok: false,
      refusal: 'wrong-challenge',
    });
    // And the relay itself refuses an answer over another challenge.
    world.seal.tamper = 'replay';
    await expect(checkWithSeal('https://seal.example', world.native)).rejects.toMatchObject({ problem: 'bad-answer' });
  });

  it('expired is refused', async () => {
    world.sealedCard(5n * GHOST);
    world.seal.tamper = 'expired';
    const relayed = await checkWithSeal('https://seal.example', world.native);
    expect(verifyCheckAnswer(world.core, world.trusted()!, relayed, { list: PINNED })).toEqual({ ok: false, refusal: 'expired' });

    world.seal.tamper = null;
    const fresh = await checkWithSeal('https://seal.example', world.native);
    const later = { list: PINNED, now: () => Date.now() + 121_000 };
    expect(verifyCheckAnswer(world.core, world.trusted()!, fresh, later)).toEqual({ ok: false, refusal: 'expired' });
  });

  it('from Seal code that is not pinned is refused', async () => {
    world.sealedCard(5n * GHOST);
    const relayed = await checkWithSeal('https://seal.example', world.native);
    expect(verifyCheckAnswer(world.core, world.trusted()!, relayed, { list: PINNED_MEASUREMENTS })).toEqual({
      ok: false,
      refusal: 'not-pinned',
    });
    world.seal.tamper = 'other-measurement';
    const other = await checkWithSeal('https://seal.example', world.native);
    expect(verifyCheckAnswer(world.core, world.trusted()!, other, { list: PINNED })).toEqual({ ok: false, refusal: 'wrong-measurement' });
  });

  it('is refused when the core cannot check it', async () => {
    world.sealedCard(5n * GHOST);
    const relayed = await checkWithSeal('https://seal.example', world.native);
    const broken = { ...world.core, verifySealAnswer: () => { throw new Error('core gone'); } } as unknown as typeof world.core;
    expect(verifyCheckAnswer(broken, world.trusted()!, relayed, { list: PINNED })).toEqual({ ok: false, refusal: 'core-failed' });
  });
});

describe('the card status of a Check', () => {
  async function checked(set: (world: World) => void, list = PINNED): Promise<CardStatus | null> {
    set(world);
    return checkCard(depsOf(world, list));
  }

  async function textOf(set: (world: World) => void): Promise<string> {
    world = resetWorld();
    const status = await checked(set);
    return status ? statusText(status) : 'nothing';
  }

  it('reads the five outcomes the screen shows', async () => {
    expect(await textOf((w) => w.sealedCard(5n * GHOST))).toBe('Secured, 5 GHOST, never opened');
    expect(
      await textOf((w) => {
        w.sealedCard(5n * GHOST);
        w.seal.paid = false;
      }),
    ).toBe('Filling, waiting to settle');
    expect(
      await textOf((w) => {
        w.sealedCard(5n * GHOST).state = 'opened';
      }),
    ).toBe('Opened, empty');
    expect(
      await textOf((w) => {
        w.newCard().ghost = false;
      }),
    ).toBe('Not a Ghost card');
    expect(
      await textOf((w) => {
        w.seal.offline = true;
      }),
    ).toBe("Can't check right now (no connection)");
  });

  it('says a card being opened is opened, and a set-up card is empty', async () => {
    expect(
      await checked((w) => {
        w.sealedCard(GHOST).state = 'opening';
      }),
    ).toEqual({ kind: 'opened', finishing: true });
    world = resetWorld();
    expect(await checked((w) => void w.newCard())).toEqual({ kind: 'empty', uid: UID_HEX });
  });

  it('says a card this phone filled, which the Seal still answers empty, is filling', async () => {
    world.newCard();
    const deps = depsOf(world);
    const filled = await fillCard(deps, 2n * GHOST, null);
    expect(filled.ok).toBe(true);
    expect(await checkCard(deps)).toEqual({ kind: 'filling' });
    // Another phone, which did not fill it, sees it empty.
    mockFiles.clear();
    expect(await checkCard(deps)).toEqual({ kind: 'empty', uid: UID_HEX });
  });

  it('says the chain cannot be checked right now, and that a spent card is empty', async () => {
    expect(
      await checked((w) => {
        w.sealedCard(GHOST);
        w.seal.chainDown = true;
      }),
    ).toEqual({ kind: 'no-connection' });
    world = resetWorld();
    expect(
      await checked((w) => {
        w.sealedCard(GHOST);
        w.seal.spent = true;
      }),
    ).toEqual({ kind: 'spent' });
  });

  it('is "Can\'t verify this card", never an amount, for every answer that fails its check', async () => {
    for (const tamper of ['bad-signature', 'other-key', 'replay', 'expired', 'other-measurement', 'other-card'] as const) {
      world = resetWorld();
      world.sealedCard(5n * GHOST);
      // A first answer, so a replay has an old one to send.
      world.seal.sign(new Uint8Array(203));
      await checkWithSeal('https://seal.example', world.native);
      world.seal.tamper = tamper;
      const status = await checkCard(depsOf(world));
      expect([tamper, status]).toEqual([tamper, { kind: 'cant-verify' }]);
      expect(statusText(status!)).toBe("Can't verify this card");
    }
  });

  it('is "Can\'t verify this card" for a perfectly signed answer while the pinned list is empty', async () => {
    expect(await checked((w) => void w.sealedCard(5n * GHOST), PINNED_MEASUREMENTS)).toEqual({ kind: 'cant-verify' });
  });

  it('is "Can\'t verify this card" without tapping when there is no Seal or no core', async () => {
    world.noSeal = true;
    expect(await checkCard(depsOf(world))).toEqual({ kind: 'cant-verify' });
    world.noSeal = false;
    expect(await checkCard({ ...depsOf(world), core: null })).toEqual({ kind: 'cant-verify' });
    expect(world.calls).toEqual([]);
  });

  it('is nothing when the card sheet was closed', async () => {
    world.cancel = true;
    expect(await checkCard(depsOf(world))).toBeNull();
    expect(statusOfFailure(new CardCancelled())).toBeNull();
  });

  it('asks to tap again when the card moved away', () => {
    expect(statusOfFailure(new SealRelayError('card-lost'))).toEqual({
      kind: 'retry',
      message: 'The card moved away. Hold it still and try again.',
    });
  });

  it('has the exact words of the ticket', () => {
    expect(STATUS_TEXT).toMatchObject({
      filling: 'Filling, waiting to settle',
      opened: 'Opened, empty',
      'not-ghost': 'Not a Ghost card',
      'no-connection': "Can't check right now (no connection)",
      'cant-verify': "Can't verify this card",
    });
    expect(statusText({ kind: 'secured', uid: UID_HEX, amountWei: 1_500_000_000_000_000_000n, pinRequired: false, pinTriesLeft: 0 })).toBe(
      'Secured, 1.5 GHOST, never opened',
    );
  });
});
