/* eslint-disable @typescript-eslint/no-require-imports -- the jest.mock factories reach the shared fake world lazily */
// The Check NFC Chip screen on the iPhone, the iPhone Duo folded and the
// iPhone Duo open, against the fake Seal and card (fake-seal.ts): every
// state it shows, and every answer that fails its check, which is always
// "Can't verify this card" in red with no amount.
import { act, fireEvent, screen } from '@testing-library/react-native';

import CheckCardScreen from '../../app/check-card';
import { GHOST, resetWorld, type World } from './fake-seal';
import { DEVICE_NAMES, isRed, renderOn, sideBySide } from './screen-kit';

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
jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: jest.fn() }) }));
jest.mock('react-native/Libraries/Utilities/useWindowDimensions', () => ({
  __esModule: true,
  default: () => require('./screen-kit').windowSize,
}));

let world: World;

beforeEach(() => {
  world = resetWorld();
  mockFiles.clear();
});

async function tapCheck() {
  await act(async () => {
    fireEvent.press(screen.getByTestId('check-card-run'));
  });
}

function shown(): string {
  return String(screen.getByTestId('check-card-status-text').props.children);
}

describe.each(DEVICE_NAMES)('Check NFC Chip on the %s', (device) => {
  const open = device === 'iPhone Duo open';

  it('shows a Sealed card as Secured with its amount, from a fresh verified answer', async () => {
    renderOn(device, CheckCardScreen);
    expect(sideBySide('check-card-screen-content')).toBe(open);
    world.sealedCard(5n * GHOST);
    await tapCheck();
    expect(world.calls).toEqual(['check']);
    expect(shown()).toBe('Secured, 5 GHOST, never opened');
    expect(isRed('check-card-status-text')).toBe(false);
    expect(screen.getByTestId('check-card-status-detail')).toHaveTextContent(/No PIN is set/);
  });

  it('shows a spinner while the Check runs, and only then the answer', async () => {
    renderOn(device, CheckCardScreen);
    world.sealedCard(5n * GHOST);
    let release: () => void = () => {};
    world.gate = new Promise<void>((resolve) => (release = resolve));
    await tapCheck();
    expect(screen.getByTestId('check-card-spinner')).toBeOnTheScreen();
    expect(screen.getByTestId('check-card-run')).toBeDisabled();
    expect(screen.queryByTestId('check-card-status')).toBeNull();
    await act(async () => release());
    expect(screen.queryByTestId('check-card-spinner')).toBeNull();
    expect(shown()).toBe('Secured, 5 GHOST, never opened');
  });

  it('shows a card waiting for its payment to settle as Filling, and confirms it once settled', async () => {
    renderOn(device, CheckCardScreen);
    world.sealedCard(5n * GHOST);
    world.seal.paid = false;
    await tapCheck();
    expect(shown()).toBe('Filling, waiting to settle');
    world.seal.paid = true;
    await act(async () => {
      fireEvent.press(screen.getByTestId('check-card-confirm'));
    });
    expect(world.calls).toEqual(['check', 'confirm']);
    expect(shown()).toBe('Secured, 5 GHOST, never opened');
  });

  it('shows an opened card as Opened, empty', async () => {
    renderOn(device, CheckCardScreen);
    world.sealedCard(5n * GHOST).state = 'opened';
    await tapCheck();
    expect(shown()).toBe('Opened, empty');
  });

  it('shows a card the Seal does not know as Not a Ghost card', async () => {
    renderOn(device, CheckCardScreen);
    world.newCard().ghost = false;
    await tapCheck();
    expect(shown()).toBe('Not a Ghost card');
  });

  it('says it cannot check right now with no connection, and never an amount', async () => {
    renderOn(device, CheckCardScreen);
    world.sealedCard(5n * GHOST);
    world.seal.offline = true;
    await tapCheck();
    expect(shown()).toBe("Can't check right now (no connection)");
    expect(screen.queryByText(/[0-9] GHOST/)).toBeNull();
  });

  it.each(['bad-signature', 'replay', 'expired'] as const)(
    'shows a %s answer as "Can\'t verify this card" in red, never an amount',
    async (tamper) => {
      renderOn(device, CheckCardScreen);
      world.sealedCard(5n * GHOST);
      // An earlier genuine answer, for the replay to send again.
      await tapCheck();
      expect(shown()).toBe('Secured, 5 GHOST, never opened');
      world.card.state = 'opened';
      world.seal.tamper = tamper;
      await tapCheck();
      expect(shown()).toBe("Can't verify this card");
      expect(isRed('check-card-status-text')).toBe(true);
      expect(screen.queryByText(/[0-9] GHOST/)).toBeNull();
      expect(screen.queryByText(/^Secured/)).toBeNull();
    },
  );

  it('says "Can\'t verify this card" without tapping while there is no Seal to vouch for', async () => {
    // The seam is asked when the screen opens.
    world.noSeal = true;
    renderOn(device, CheckCardScreen);
    world.sealedCard(5n * GHOST);
    await tapCheck();
    expect(world.calls).toEqual([]);
    expect(shown()).toBe("Can't verify this card");
    expect(isRed('check-card-status-text')).toBe(true);
  });

  it('checks the Seal again at the start of the Check, and says "Can\'t verify" when it no longer verifies', async () => {
    renderOn(device, CheckCardScreen);
    world.sealedCard(5n * GHOST);
    expect(world.refreshes).toBe(0);
    // The Seal vouched for when the screen opened, but its attestation fails now.
    world.noSeal = true;
    await tapCheck();
    expect(world.refreshes).toBe(1);
    expect(world.calls).toEqual([]);
    expect(shown()).toBe("Can't verify this card");
    expect(screen.queryByText(/[0-9] GHOST/)).toBeNull();
  });

  it('shows nothing new when the card sheet is closed', async () => {
    renderOn(device, CheckCardScreen);
    world.cancel = true;
    await tapCheck();
    expect(screen.queryByTestId('check-card-status')).toBeNull();
    expect(screen.getByTestId('check-card-run')).not.toBeDisabled();
  });
});
