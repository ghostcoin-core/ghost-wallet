/* eslint-disable @typescript-eslint/no-require-imports -- the jest.mock factories reach the shared fake world lazily */
// The Open into my wallet screen on the three devices, against the fake Seal
// and card (fake-seal.ts): the core's phone key goes to the Seal, the release
// goes to the core (never to JavaScript), the core checks the Open answer and
// holds the card's key, the existing Claim takes the coin into the account at
// once, and the phone key is wiped only once that Claim settles.
import { act, fireEvent, screen } from '@testing-library/react-native';

import CheckCardScreen from '../../app/check-card';
import OpenCardScreen from '../../app/open-card';
import { GHOST, hexOf, resetWorld, type World } from './fake-seal';
import { ACCOUNT, DEVICE_NAMES, fakeKit, isRed, renderOn, sideBySide } from './screen-kit';

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
jest.mock('../../lib/seal/trusted-seal', () => ({ trustedSeal: () => require('./fake-seal').world.current.trusted() }));
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
const mockPayment = { status: 'sent' };
jest.mock('../../lib/vanish/use-payment', () => ({
  paymentKit: () => mockKit.current?.kit ?? null,
  usePayment: (_kit: unknown, sequence: unknown) =>
    sequence ? { status: mockPayment.status, step: 3, needsKey: false, error: null } : null,
}));
const mockClaimed = { id: 'summon-1', step: 3 };
const mockStartReveal = jest.fn(async (..._args: unknown[]) => ({
  record: () => ({ id: mockClaimed.id }),
  step: () => mockClaimed.step,
}));
jest.mock('../../lib/vanish/actions', () => ({
  ...jest.requireActual('../../lib/vanish/actions'),
  startReveal: (...args: unknown[]) => mockStartReveal(...args),
  proveRevealAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
}));
jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: jest.fn() }) }));
jest.mock('react-native/Libraries/Utilities/useWindowDimensions', () => ({
  __esModule: true,
  default: () => require('./screen-kit').windowSize,
}));

let world: World;

beforeEach(() => {
  world = resetWorld();
  mockFiles.clear();
  mockKit.current = fakeKit();
  mockPayment.status = 'sent';
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

describe.each(DEVICE_NAMES)('Open into my wallet on the %s', (device) => {
  const open = device === 'iPhone Duo open';

  it('opens a Secured card into the core and Claims its coin into the account at once', async () => {
    renderOn(device, OpenCardScreen);
    expect(sideBySide('open-card-screen-content')).toBe(open);
    world.sealedCard(5n * GHOST);
    await press('open-check');
    expect(text('open-status-text')).toBe('Secured, 5 GHOST, never opened');
    expect(screen.getByTestId('open-run')).toHaveTextContent('Open 5 GHOST into my wallet');

    await press('open-run');
    expect(world.calls).toEqual(['check', 'open']);
    // The core's public phone key went to the Seal, kept in the Keychain before it went.
    const phoneKey = world.core.phoneKey!;
    expect(world.seal.lastRequest.phoneKey).toBe(hexOf(phoneKey));
    expect(hexOf(world.keychain!)).toBe(hexOf(phoneKey));
    // The release went to the core, which holds the card's key for the Claim.
    expect(world.core.cardKeyHeld).toBe(true);
    expect(mockStartReveal).toHaveBeenCalledTimes(1);
    expect(mockStartReveal.mock.calls[0].slice(1)).toEqual([{ card: true }, ACCOUNT, null]);
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
    expect(world.card.state).toBe('opened');
  });

  it('keeps the phone key until the Claim settles, then wipes it, and a Check says Opened', async () => {
    const view = renderOn(device, OpenCardScreen);
    world.sealedCard(5n * GHOST);
    await press('open-check');
    await press('open-run');
    expect(world.core.hasSealOpenKey()).toBe(true);
    expect(world.keychain).not.toBeNull();

    mockPayment.status = 'settled';
    await act(async () => view.again());
    expect(world.core.hasSealOpenKey()).toBe(false);
    expect(world.keychain).toBeNull();
    expect(world.core.cardKeyHeld).toBe(false);
    expect(screen.getByTestId('open-done')).toBeOnTheScreen();

    view.unmount();
    renderOn(device, CheckCardScreen);
    await press('check-card-run');
    expect(text('check-card-status-text')).toBe('Opened, empty');
  });

  it('shows an Open answer that fails its check as "Can\'t verify this card" and claims nothing', async () => {
    renderOn(device, OpenCardScreen);
    world.sealedCard(5n * GHOST);
    await press('open-check');
    world.seal.tamper = 'bad-signature';
    await press('open-run');
    expect(text('open-status-text')).toBe("Can't verify this card");
    expect(isRed('open-status-text')).toBe(true);
    expect(world.core.cardKeyHeld).toBe(false);
    expect(mockStartReveal).not.toHaveBeenCalled();
    expect(screen.queryByText(/[0-9] GHOST/)).toBeNull();
    // The phone key stays, so the Open can be asked again.
    expect(world.keychain).not.toBeNull();
  });

  it('asks again with the same phone key after an Open cut off, even after a restart', async () => {
    const first = renderOn(device, OpenCardScreen);
    world.sealedCard(5n * GHOST);
    await press('open-check');
    world.dropAfterFlow = true;
    await press('open-run');
    expect(text('open-status-text')).toBe('The card moved away. Hold it still and try again.');
    expect(mockStartReveal).not.toHaveBeenCalled();
    const kept = hexOf(world.keychain!);
    first.unmount();

    // The app restarts: the core's memory is gone, the Keychain is not.
    world.core.phoneKey = null;
    renderOn(device, OpenCardScreen);
    await press('open-check');
    expect(text('open-status-text')).toBe('Opened, empty');
    expect(screen.getByTestId('open-run')).toHaveTextContent('Finish opening into my wallet');
    await press('open-run');
    expect(world.seal.lastRequest.phoneKey).toBe(kept);
    expect(world.core.cardKeyHeld).toBe(true);
    expect(mockStartReveal).toHaveBeenCalledTimes(1);
  });

  it('offers no Open for a card that is not Secured', async () => {
    renderOn(device, OpenCardScreen);
    world.newCard();
    await press('open-check');
    expect(text('open-status-text')).toBe('Empty, ready to fill');
    expect(screen.queryByTestId('open-run')).toBeNull();
    expect(world.calls).toEqual(['check']);
  });

  it('shows a spinner while the Seal opens the card', async () => {
    renderOn(device, OpenCardScreen);
    world.sealedCard(5n * GHOST);
    await press('open-check');
    let release: () => void = () => {};
    world.gate = new Promise<void>((resolve) => (release = resolve));
    await press('open-run');
    expect(screen.getByTestId('open-spinner')).toBeOnTheScreen();
    await act(async () => release());
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
  });
});

it('never hands JavaScript the release or the card key', async () => {
  renderOn('iPhone', OpenCardScreen);
  world.sealedCard(5n * GHOST);
  await press('open-check');
  const results: unknown[] = [];
  const relayOpen = world.native.relayOpen;
  world.native.relayOpen = async (...args) => {
    const result = await relayOpen(...args);
    results.push(result);
    return result;
  };
  await press('open-run');
  expect(results).toHaveLength(1);
  expect(Object.keys(results[0] as object).sort()).toEqual(['answer', 'challenge', 'rounds', 'signature', 'totalMs', 'uid']);
});
