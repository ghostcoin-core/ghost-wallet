/* eslint-disable @typescript-eslint/no-require-imports -- the jest.mock factories reach the shared fake world lazily */
// A card served by one home region (docs/sealed-card.md, "Home region"), on
// the iPhone, the iPhone Duo folded and the iPhone Duo open, against the
// fake Seals and card (fake-seal.ts).
//
// A `wrong-region` refusal of a Check, a Fill, a Fill's confirmation or an
// Open shows one plain message, with exactly one relay call for the tap and
// nothing sent again, to that region or another; it releases no card key,
// notes no Fill and never shows Secured or an amount. With three regions the
// native relay's choice of home region (the fixed vectors) is where each card
// goes, and each answer is checked with that region's Seal only: a region
// with no verified Seal is "Can't verify this card", and it changes nothing
// for cards homed elsewhere.
import { act, fireEvent, screen } from '@testing-library/react-native';

import CheckCardScreen from '../../app/check-card';
import FillCardScreen from '../../app/fill-card';
import OpenCardScreen from '../../app/open-card';
import { RELAY_PROBLEMS } from '../../modules/ghost-nfc/relay';
import { GHOST, HOME_VECTORS, hexOf, resetWorld, THREE_REGIONS, UID_HEX, type World } from './fake-seal';
import { DEVICE_NAMES, fakeKit, isRed, renderOn } from './screen-kit';

jest.mock('expo', () => ({
  requireOptionalNativeModule: (name: string) => (name === 'GhostNfc' ? require('./fake-seal').world.current.native : null),
}));
jest.mock(
  '../../modules/ghost-core/src/index',
  () =>
    new Proxy(
      {},
      {
        get(_target, name: string) {
          const core = require('./fake-seal').world.current.core;
          const value = core[name];
          return typeof value === 'function' ? value.bind(core) : value;
        },
      },
    ),
  { virtual: true },
);
jest.mock('../../lib/seal/trusted-seal', () => ({
  trustedSeal: (region: string) => require('./fake-seal').world.current.trustedSeal(region),
  refreshTrustedSeals: async () => require('./fake-seal').world.current.refreshed(),
}));
jest.mock('../../lib/seal/pinned-measurements', () => {
  const actual = jest.requireActual('../../lib/seal/pinned-measurements');
  return { ...actual, PINNED_MEASUREMENTS: actual.parseMeasurementList(require('./fake-seal').PINNED_JSON) };
});
const mockFiles = new Map<string, unknown>();
jest.mock('../../lib/storage', () => ({
  jsonFile: (name: string) => ({
    read: () => mockFiles.get(name) ?? null,
    write: async (value: unknown) => {
      mockFiles.set(name, JSON.parse(JSON.stringify(value)));
    },
  }),
}));
jest.mock('../../lib/account', () => ({ accountZeroAddress: () => require('./screen-kit').ACCOUNT }));
const mockKit: { current: ReturnType<typeof fakeKit> | null } = { current: null };
jest.mock('../../lib/vanish/use-payment', () => ({
  paymentKit: () => mockKit.current?.kit ?? null,
  usePayment: (_kit: unknown, sequence: unknown) => (sequence ? { status: 'sent', step: 3, needsKey: false, error: null } : null),
}));
const mockStartReveal = jest.fn(async (..._args: unknown[]) => ({
  record: () => ({ id: 'summon-1' }),
  step: () => 3,
}));
jest.mock('../../lib/vanish/actions', () => ({
  ...jest.requireActual('../../lib/vanish/actions'),
  minimumVanish: async () => 10n ** 15n,
  signVanishAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
  startReveal: (...args: unknown[]) => mockStartReveal(...args),
  proveRevealAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
}));
jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: jest.fn() }) }));
jest.mock('react-native/Libraries/Utilities/useWindowDimensions', () => ({
  __esModule: true,
  default: () => require('./screen-kit').windowSize,
}));

const MESSAGE = 'This card is served by another Seal region than the one this iPhone chose. Update Ghost Wallet, then try again.';

let world: World;

beforeEach(() => {
  world = resetWorld();
  mockFiles.clear();
  mockKit.current = fakeKit();
  mockStartReveal.mockClear();
});

async function press(testID: string) {
  await act(async () => {
    fireEvent.press(screen.getByTestId(testID));
  });
}

function text(testID: string): string {
  return String(screen.getByTestId(testID).props.children);
}

/** How many start requests reached each region's Seal. */
function starts(): Record<string, number> {
  return Object.fromEntries([...world.regionSeals].map(([id, seal]) => [id, seal.starts]));
}

/** Nothing was released, kept or noted, and no payment began. */
function nothingHeld() {
  expect(world.core.cardKeyHeld).toBe(false);
  expect(world.core.release).toBeNull();
  expect(mockStartReveal).not.toHaveBeenCalled();
  expect(mockKit.current!.started).toEqual([]);
  expect([...mockFiles.values()].map((value) => JSON.stringify(value)).join()).not.toMatch(/04518DFAA96180|04518dfaa96180/);
}

describe.each(DEVICE_NAMES)('A card served by another region on the %s', (device) => {
  it('a Check refused wrong-region shows the plain message, once, and no amount', async () => {
    renderOn(device, CheckCardScreen);
    world.sealedCard(5n * GHOST);
    world.seal.wrongRegion = true;
    await press('check-card-run');
    expect(text('check-card-status-text')).toBe(MESSAGE);
    expect(MESSAGE).toBe(RELAY_PROBLEMS['wrong-region']);
    expect(isRed('check-card-status-text')).toBe(false);
    expect(world.calls).toEqual(['check']);
    expect(world.seal.starts).toBe(1);
    expect(screen.queryByText(/[0-9] GHOST/)).toBeNull();
    expect(screen.queryByText(/^Secured/)).toBeNull();
    nothingHeld();
  });

  it('a Fill refused wrong-region writes no key, notes no Fill and pays nothing', async () => {
    renderOn(device, FillCardScreen);
    world.newCard();
    world.seal.wrongRegion = true;
    await act(async () => {});
    fireEvent.changeText(screen.getByTestId('fill-amount'), '5');
    await press('fill-tap');
    expect(text('fill-status-text')).toBe(MESSAGE);
    expect(world.calls).toEqual(['fill']);
    expect(world.seal.starts).toBe(1);
    expect(world.seal.fills.size).toBe(0);
    expect(world.card.keyPresent).toBe(false);
    expect(mockFiles.size).toBe(0);
    expect(screen.queryByTestId('fill-summary')).toBeNull();
    expect(screen.queryByTestId('payment-progress')).toBeNull();
    expect(screen.queryByText(/^Secured/)).toBeNull();
    nothingHeld();
  });

  it('a Fill confirmation refused wrong-region stays where it was, with the plain message', async () => {
    renderOn(device, CheckCardScreen);
    world.sealedCard(5n * GHOST);
    world.seal.paid = false;
    await press('check-card-run');
    expect(text('check-card-status-text')).toBe('Filling, waiting to settle');
    world.seal.paid = true;
    world.seal.wrongRegion = true;
    await press('check-card-confirm');
    expect(text('check-card-status-text')).toBe(MESSAGE);
    expect(world.calls).toEqual(['check', 'confirm']);
    expect(world.seal.starts).toBe(2);
    expect(screen.queryByText(/[0-9] GHOST/)).toBeNull();
    expect(screen.queryByText(/^Secured/)).toBeNull();
    nothingHeld();
  });

  it('an Open refused wrong-region releases no card key and claims nothing', async () => {
    renderOn(device, OpenCardScreen);
    world.sealedCard(5n * GHOST);
    await press('open-check');
    expect(text('open-status-text')).toBe('Secured, 5 GHOST, never opened');
    world.seal.wrongRegion = true;
    await press('open-run');
    expect(text('open-status-text')).toBe(MESSAGE);
    expect(world.calls).toEqual(['check', 'open']);
    expect(world.seal.starts).toBe(2);
    expect(world.seal.opens.size).toBe(0);
    expect(world.card.state).toBe('sealed');
    expect(screen.queryByTestId('payment-progress')).toBeNull();
    nothingHeld();
  });

  it('is never followed to another region: one start request, at the home region only', async () => {
    world.useRegions(THREE_REGIONS);
    renderOn(device, CheckCardScreen);
    world.sealedCard(5n * GHOST, null, UID_HEX);
    world.sealOf('eu-central-1').wrongRegion = true;
    await press('check-card-run');
    expect(text('check-card-status-text')).toBe(MESSAGE);
    expect(world.regionsUsed).toEqual(['eu-central-1']);
    expect(starts()).toEqual({ 'us-east-1': 0, 'eu-central-1': 1, 'ap-southeast-1': 0 });
    // Tapping again is the person's choice, and goes to the same home region.
    await press('check-card-run');
    expect(world.calls).toEqual(['check', 'check']);
    expect(starts()).toEqual({ 'us-east-1': 0, 'eu-central-1': 2, 'ap-southeast-1': 0 });
    nothingHeld();
  });
});

describe.each(DEVICE_NAMES)('Three regions on the %s', (device) => {
  beforeEach(() => {
    world.useRegions(THREE_REGIONS);
  });

  it.each(HOME_VECTORS)('sends card $uid to $home and checks its answer with that Seal only', async ({ uid, home }) => {
    renderOn(device, CheckCardScreen);
    world.sealedCard(5n * GHOST, null, uid);
    await press('check-card-run');
    expect(world.regionsUsed).toEqual([home]);
    expect(starts()).toEqual(Object.fromEntries(THREE_REGIONS.map((id) => [id, id === home ? 1 : 0])));
    expect(text('check-card-status-text')).toBe('Secured, 5 GHOST, never opened');
    const checked = world.core.checks.map((check) => hexOf(new Uint8Array(check.verifyingKey)));
    expect(checked).toEqual([hexOf(world.sealOf(home).key)]);
    for (const other of THREE_REGIONS.filter((id) => id !== home)) {
      expect(checked).not.toContain(hexOf(world.sealOf(other).key));
    }
  });

  it("says \"Can't verify this card\" for an answer from a region with no verified Seal, and not for a card homed elsewhere", async () => {
    renderOn(device, CheckCardScreen);
    world.unverified.add('eu-central-1');
    world.sealedCard(5n * GHOST, null, '04518DFAA96180');
    await press('check-card-run');
    expect(world.regionsUsed).toEqual(['eu-central-1']);
    expect(text('check-card-status-text')).toBe("Can't verify this card");
    expect(isRed('check-card-status-text')).toBe(true);
    expect(screen.queryByText(/[0-9] GHOST/)).toBeNull();
    // Its answer was never checked with another region's Seal.
    expect(world.core.checks).toEqual([]);

    world.sealedCard(5n * GHOST, null, '04A1B2C3D4E5F6');
    await press('check-card-run');
    expect(world.regionsUsed).toEqual(['eu-central-1', 'us-east-1']);
    expect(text('check-card-status-text')).toBe('Secured, 5 GHOST, never opened');
  });

  it('opens a card in its home region, released to the core with that Seal checking the answer', async () => {
    renderOn(device, OpenCardScreen);
    world.sealedCard(5n * GHOST, null, '04A1B2C3D4E5F6');
    await press('open-check');
    await press('open-run');
    expect(world.regionsUsed).toEqual(['us-east-1', 'us-east-1']);
    expect(world.sealOf('us-east-1').opens.size).toBe(1);
    expect(world.sealOf('eu-central-1').opens.size).toBe(0);
    expect(world.core.cardKeyHeld).toBe(true);
  });

  it('holds no card key when the Open answer comes from a region with no verified Seal', async () => {
    renderOn(device, OpenCardScreen);
    world.sealedCard(5n * GHOST, null, '0412345678ABCD');
    await press('open-check');
    world.unverified.add('ap-southeast-1');
    await press('open-run');
    expect(world.regionsUsed).toEqual(['ap-southeast-1', 'ap-southeast-1']);
    expect(text('open-status-text')).toBe("Can't verify this card");
    expect(world.core.cardKeyHeld).toBe(false);
    expect(mockStartReveal).not.toHaveBeenCalled();
  });

  it('opens no card sheet when no region verified', async () => {
    renderOn(device, CheckCardScreen);
    for (const id of THREE_REGIONS) {
      world.unverified.add(id);
    }
    world.sealedCard(5n * GHOST);
    await press('check-card-run');
    expect(world.calls).toEqual([]);
    expect(text('check-card-status-text')).toBe("Can't verify this card");
  });
});
