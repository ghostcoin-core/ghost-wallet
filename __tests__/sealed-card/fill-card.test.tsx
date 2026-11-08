/* eslint-disable @typescript-eslint/no-require-imports -- the jest.mock factories reach the shared fake world lazily */
// The Fill a card screen on the three devices, against the fake Seal and card
// (fake-seal.ts): the Seal writes a fresh key and hands back the commit data,
// the app Vanishes exactly that amount to exactly that commit data with the
// usual Vanish payment, shows Filling until the Seal answers Sealed, and never
// shows words or a key.
import { act, fireEvent, screen } from '@testing-library/react-native';

import FillCardScreen from '../../app/fill-card';
import { decodeDetails } from '../../lib/vanish/payments';
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
jest.mock('../../lib/seal/trusted-seal', () => ({
  ...jest.requireActual('../../lib/seal/trusted-seal'),
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
const mockPayment = { status: 'sent' };
jest.mock('../../lib/vanish/use-payment', () => ({
  paymentKit: () => mockKit.current?.kit ?? null,
  usePayment: (_kit: unknown, sequence: unknown) =>
    sequence ? { status: mockPayment.status, step: 3, needsKey: false, error: null } : null,
}));
jest.mock('../../lib/vanish/actions', () => ({
  ...jest.requireActual('../../lib/vanish/actions'),
  minimumVanish: async () => 10n ** 15n,
  signVanishAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
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
});

async function settle() {
  // The minimum arrives first, so the button is enabled.
  await act(async () => {});
}

async function fill(amount: string) {
  await settle();
  fireEvent.changeText(screen.getByTestId('fill-amount'), amount);
  await act(async () => {
    fireEvent.press(screen.getByTestId('fill-tap'));
  });
}

function shown(): string {
  return String(screen.getByTestId('fill-status-text').props.children);
}

describe.each(DEVICE_NAMES)('Fill a card on the %s', (device) => {
  const open = device === 'iPhone Duo open';

  it('fills an empty card and Vanishes exactly the amount to exactly the Seal’s commit data', async () => {
    renderOn(device, FillCardScreen);
    expect(sideBySide('fill-card-screen-content')).toBe(open);
    world.newCard();
    await fill('5');

    expect(world.calls).toEqual(['fill']);
    expect(world.seal.lastRequest).toMatchObject({ amountWei: (5n * GHOST).toString(), pin: '' });
    const { started } = mockKit.current!;
    expect(started).toHaveLength(1);
    const details = decodeDetails(started[0].intent.details);
    const sealCommit = world.seal.fills.get(hexOf(world.card.uid))!.commitData;
    expect(details).toMatchObject({ kind: 'vanish', commitData: `0x${hexOf(sealCommit)}`, amountWei: (5n * GHOST).toString() });
    expect(started[0].intent.identity).toMatchObject({ tag: 'AccountNonce', inner: { nonce: 7n } });
    // The card holds the key already: the Vanish is backed up and may go.
    expect(mockKit.current!.records.get(started[0].id)!.step).toBe(1);

    expect(shown()).toBe('Filling, waiting to settle');
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
    expect(screen.getByTestId('fill-summary')).toHaveTextContent('5 GHOST to card 04518DFAA96180.');
  });

  it('never shows words or a key', async () => {
    renderOn(device, FillCardScreen);
    world.newCard();
    await fill('5');
    expect(screen.queryAllByTestId(/word/)).toEqual([]);
    expect(screen.queryByText(/words?:/i)).toBeNull();
    expect(screen.queryByText(/[0-9a-f]{32}/i)).toBeNull();
  });

  it('shows Filling until the Seal answers Sealed once the payment settled', async () => {
    renderOn(device, FillCardScreen);
    world.newCard();
    world.seal.paid = false;
    await fill('5');
    await act(async () => {
      fireEvent.press(screen.getByTestId('fill-confirm'));
    });
    expect(world.calls).toEqual(['fill', 'confirm']);
    expect(shown()).toBe('Filling, waiting to settle');

    mockPayment.status = 'settled';
    world.seal.paid = true;
    await act(async () => {
      fireEvent.press(screen.getByTestId('fill-confirm'));
    });
    expect(shown()).toBe('Secured, 5 GHOST, never opened');
    expect(screen.queryByTestId('fill-confirm')).toBeNull();
    expect(screen.getByTestId('fill-done')).toBeOnTheScreen();
  });

  it('pays a Fill asked again (its answer lost) once: the same coin, never a second Vanish', async () => {
    const first = renderOn(device, FillCardScreen);
    world.newCard();
    await fill('5');
    first.unmount();
    renderOn(device, FillCardScreen);
    await fill('5');
    expect(world.calls).toEqual(['fill', 'fill']);
    expect(mockKit.current!.started).toHaveLength(1);
    expect(shown()).toBe('Filling, waiting to settle');
  });

  it('shows a Fill answer that fails its check as "Can\'t verify this card" and pays nothing', async () => {
    renderOn(device, FillCardScreen);
    world.newCard();
    world.seal.tamper = 'bad-signature';
    await fill('5');
    expect(shown()).toBe("Can't verify this card");
    expect(isRed('fill-status-text')).toBe(true);
    expect(mockKit.current!.started).toEqual([]);
    expect(screen.queryByTestId('payment-progress')).toBeNull();
  });

  it('pays nothing for a card that is not empty', async () => {
    renderOn(device, FillCardScreen);
    world.sealedCard(2n * GHOST);
    await fill('5');
    expect(shown()).toBe('This card cannot do that now.');
    expect(mockKit.current!.started).toEqual([]);
  });

  it('refuses an amount below the smallest Vanish before any tap', async () => {
    renderOn(device, FillCardScreen);
    await settle();
    fireEvent.changeText(screen.getByTestId('fill-amount'), '0.0001');
    expect(screen.getByTestId('fill-amount-error')).toHaveTextContent('The smallest card is 0.001 GHOST.');
    expect(screen.getByTestId('fill-tap')).toBeDisabled();
    fireEvent.press(screen.getByTestId('fill-tap'));
    expect(world.calls).toEqual([]);
  });

  it('shows a spinner while the Seal fills the card', async () => {
    renderOn(device, FillCardScreen);
    world.newCard();
    let release: () => void = () => {};
    world.gate = new Promise<void>((resolve) => (release = resolve));
    await fill('5');
    expect(screen.getByTestId('fill-spinner')).toBeOnTheScreen();
    expect(screen.getByTestId('fill-tap')).toBeDisabled();
    await act(async () => release());
    expect(screen.queryByTestId('fill-spinner')).toBeNull();
    expect(shown()).toBe('Filling, waiting to settle');
  });
});

it('fills from the account the wallet holds', async () => {
  renderOn('iPhone', FillCardScreen);
  world.newCard();
  await fill('1.5');
  const identity = mockKit.current!.started[0].intent.identity;
  expect(identity.tag).toBe('AccountNonce');
  const account = identity.tag === 'AccountNonce' ? identity.inner.account : new ArrayBuffer(0);
  expect(`0x${hexOf(new Uint8Array(account))}`).toBe(ACCOUNT);
});
