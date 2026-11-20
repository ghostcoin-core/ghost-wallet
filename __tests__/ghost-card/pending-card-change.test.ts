// The wallet as it will be once the card changes finish
// (lib/ghost-card/vault.ts, pendingCardChange): Home never shows the balance
// jump up and back while a card change goes through.
import { pendingCardChange, type CardChange, type PaymentAtReading } from '../../lib/ghost-card/vault';

jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));

const GHOST = 10n ** 18n;

function change(over: Partial<CardChange>): CardChange {
  return {
    id: 'c',
    cardId: '0x11',
    cardNumber: 'CARD',
    oldFill: 1,
    oldMarker: '0xaa',
    oldCommitData: null,
    oldCounted: true,
    beforeWei: (3n * GHOST).toString(),
    afterWei: (5n * GHOST).toString(),
    commitData: '0xbb',
    newFill: 2,
    summonId: null,
    vanishId: null,
    at: 1,
    ...over,
  };
}

const states = (map: Record<string, PaymentAtReading>) => (id: string) => map[id] ?? 'not-yet';

it('adding 2 to a card holding 3 shows the wallet down 2 at every step, never up 3', () => {
  const wallet = 10n * GHOST;
  // Held: nothing has moved yet.
  expect(wallet + pendingCardChange([change({})], states({}))).toBe(8n * GHOST);
  // The old 3 came home; the 5 has not gone yet.
  expect(wallet + 3n * GHOST + pendingCardChange([change({ summonId: 's' })], states({ s: 'in-reading' }))).toBe(8n * GHOST);
  // Both landed.
  expect(
    wallet + 3n * GHOST - 5n * GHOST + pendingCardChange([change({ summonId: 's', vanishId: 'v' })], states({ s: 'in-reading', v: 'in-reading' })),
  ).toBe(8n * GHOST);
});

it('taking all off shows it in the wallet at once, and a failed Vanish or a cut-off hold moves nothing', () => {
  expect(pendingCardChange([change({ afterWei: '0', commitData: null })], states({}))).toBe(3n * GHOST);
  expect(pendingCardChange([change({ summonId: 's', vanishId: 'v' })], states({ s: 'in-reading', v: 'failed' }))).toBe(0n);
  expect(pendingCardChange([change({ commitData: null })], states({}))).toBe(0n);
  // An uncounted old coin (nobody had paid it) is not counted as coming in.
  expect(pendingCardChange([change({ oldCounted: false, beforeWei: '0' })], states({}))).toBe(-5n * GHOST);
});
