/* eslint-disable @typescript-eslint/no-require-imports -- the jest.mock factories reach the shared fake world lazily */
// A Sealed card's optional Open PIN on the three devices, against the fake
// Seal and card (fake-seal.ts): set at Fill (4 to 8 digits, typed twice),
// asked for before an Open, the tries left shown only from a signed answer,
// a wrong PIN costing a try, and a card with no tries left shown as locked.
// The PIN goes to the Seal only: never stored and cleared from the screen
// once it is sent.
import { act, fireEvent, screen } from '@testing-library/react-native';

import FillCardScreen from '../../app/fill-card';
import OpenCardScreen from '../../app/open-card';
import { pinRule, triesText } from '../../lib/seal/pin';
import { GHOST, resetWorld, type World } from './fake-seal';
import { DEVICE_NAMES, fakeKit, renderOn } from './screen-kit';

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
jest.mock('../../lib/vanish/use-payment', () => ({
  paymentKit: () => mockKit.current?.kit ?? null,
  usePayment: (_kit: unknown, sequence: unknown) => (sequence ? { status: 'sent', step: 3, needsKey: false, error: null } : null),
}));
const mockStartReveal = jest.fn(async (..._args: unknown[]) => ({ record: () => ({ id: 'summon-1' }), step: () => 3 }));
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

const PIN = '4821';

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

/** Nothing this phone saved holds the PIN. */
function pinNotStored() {
  expect(JSON.stringify([...mockFiles.entries()])).not.toContain(PIN);
}

describe('the PIN rule', () => {
  it('takes 4 to 8 digits, typed the same twice, or nothing at Fill', () => {
    expect(pinRule('', '', true)).toEqual({ ok: true, pin: null });
    expect(pinRule('', null, false)).toEqual({ ok: false, message: 'Enter the card’s PIN.' });
    expect(pinRule('123', '123', true)).toEqual({ ok: false, message: 'A PIN is 4 to 8 digits.' });
    expect(pinRule('123456789', '123456789', true).ok).toBe(false);
    expect(pinRule('12a4', '12a4', true).ok).toBe(false);
    expect(pinRule('1234', '1243', true)).toEqual({ ok: false, message: 'The two PINs are not the same.' });
    expect(pinRule('12345678', '12345678', true)).toEqual({ ok: true, pin: '12345678' });
    expect(triesText(1)).toBe('1 try left');
    expect(triesText(4)).toBe('4 tries left');
  });
});

describe.each(DEVICE_NAMES)('the card PIN on the %s', (device) => {
  it('is set at Fill: sent to the Seal only, then cleared from the screen', async () => {
    renderOn(device, FillCardScreen);
    world.newCard();
    await act(async () => {});
    fireEvent.changeText(screen.getByTestId('fill-amount'), '5');
    fireEvent.changeText(screen.getByTestId('fill-pin'), PIN);
    expect(screen.getByTestId('fill-tap')).toBeDisabled();
    fireEvent.changeText(screen.getByTestId('fill-pin-again'), '4812');
    expect(screen.getByTestId('fill-pin-error')).toHaveTextContent('The two PINs are not the same.');
    expect(screen.getByTestId('fill-tap')).toBeDisabled();
    fireEvent.changeText(screen.getByTestId('fill-pin-again'), PIN);
    expect(screen.queryByTestId('fill-pin-error')).toBeNull();
    await press('fill-tap');

    expect(world.seal.lastRequest.pin).toBe(PIN);
    expect(world.card.pin).toBe(PIN);
    expect(world.card.tries).toBe(5);
    expect(mockKit.current!.started).toHaveLength(1);
    pinNotStored();
    expect(JSON.stringify(mockKit.current!.started, (_k, v: unknown) => (typeof v === 'bigint' ? String(v) : v))).not.toContain(PIN);
  });

  it('is never sent when it is not 4 to 8 digits', async () => {
    renderOn(device, FillCardScreen);
    world.newCard();
    await act(async () => {});
    fireEvent.changeText(screen.getByTestId('fill-amount'), '5');
    fireEvent.changeText(screen.getByTestId('fill-pin'), '123');
    fireEvent.changeText(screen.getByTestId('fill-pin-again'), '123');
    expect(screen.getByTestId('fill-pin-error')).toHaveTextContent('A PIN is 4 to 8 digits.');
    fireEvent.press(screen.getByTestId('fill-tap'));
    expect(world.calls).toEqual([]);
  });

  it('is asked for before an Open, with the tries left from the signed answer', async () => {
    renderOn(device, OpenCardScreen);
    world.sealedCard(5n * GHOST, PIN);
    await press('open-check');
    expect(text('open-status-text')).toBe('Secured, 5 GHOST, never opened');
    expect(screen.getByTestId('open-status-detail')).toHaveTextContent(/^Opening it needs its PIN: 5 tries left\./);
    expect(screen.getByTestId('open-pin-tries')).toHaveTextContent('5 tries left');
    expect(screen.getByTestId('open-run')).toBeDisabled();

    fireEvent.changeText(screen.getByTestId('open-pin'), PIN);
    await press('open-run');
    expect(world.seal.lastRequest.pin).toBe(PIN);
    expect(world.core.cardKeyHeld).toBe(true);
    expect(mockStartReveal).toHaveBeenCalledTimes(1);
    pinNotStored();
  });

  it('costs a try when wrong, and shows the tries left only after a new Check', async () => {
    renderOn(device, OpenCardScreen);
    world.sealedCard(5n * GHOST, PIN);
    await press('open-check');
    fireEvent.changeText(screen.getByTestId('open-pin'), '1111');
    await press('open-run');
    expect(screen.getByTestId('open-error')).toHaveTextContent('Wrong PIN. Check the card again to see how many tries are left.');
    expect(world.seal.pinTries).toBe(1);
    expect(world.core.cardKeyHeld).toBe(false);
    expect(mockStartReveal).not.toHaveBeenCalled();
    // The tries shown before are gone with the answer they came from.
    expect(screen.queryByTestId('open-pin-tries')).toBeNull();
    expect(screen.queryByTestId('open-run')).toBeNull();

    await press('open-check');
    expect(screen.getByTestId('open-pin-tries')).toHaveTextContent('4 tries left');
    // The PIN typed before was cleared when it was sent.
    expect(screen.getByTestId('open-pin').props.value).toBe('');
  });

  it('locks the card once no tries are left, and shows it as locked', async () => {
    renderOn(device, OpenCardScreen);
    world.sealedCard(5n * GHOST, PIN);
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await press('open-check');
      fireEvent.changeText(screen.getByTestId('open-pin'), '0000');
      await press('open-run');
    }
    expect(world.card.tries).toBe(0);
    await press('open-check');
    expect(text('open-status-text')).toBe('Locked: its PIN has no tries left');
    expect(screen.queryByTestId('open-run')).toBeNull();
    expect(world.seal.pinTries).toBe(5);
    expect(world.core.cardKeyHeld).toBe(false);
  });

  it('shows a card whose tries were used up elsewhere as locked, and offers no PIN field', async () => {
    renderOn(device, OpenCardScreen);
    world.sealedCard(5n * GHOST, PIN);
    await press('open-check');
    expect(screen.getByTestId('open-pin')).toBeOnTheScreen();
    // Another phone used up the tries; the Seal never certifies a locked card.
    world.card.tries = 0;
    await press('open-check');
    expect(text('open-status-text')).toBe('Locked: its PIN has no tries left');
    expect(screen.queryByTestId('open-pin')).toBeNull();
  });
});
