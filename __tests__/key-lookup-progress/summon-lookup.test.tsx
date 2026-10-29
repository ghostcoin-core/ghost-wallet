import { act, fireEvent, render, screen } from '@testing-library/react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import SummonScreen from '../../app/summon';

const mockKeyWords = Array.from({ length: 24 }, (_, i) => ['abandon', 'ability', 'able', 'about'][i % 4]);

const mockCore = {
  checkKeyWords: jest.fn(() => ({ verdict: 'phantom-key', position: 0 })),
  forgetCardKey: jest.fn(),
  savedAccountZeroAddress: () => '0x00000000000000000000000000000000000000aa',
  hasAccount: () => true,
};
jest.mock('../../modules/ghost-core/src/index', () => mockCore, { virtual: true });

jest.mock('../../lib/vanish/use-payment', () => ({
  paymentKit: () => ({ core: mockCore, store: { list: () => [], remove: jest.fn() }, node: {}, nodeUrl: 'http://127.0.0.1:8547' }),
  usePayment: () => null,
}));

const FOUND = { status: 'found', amountWei: '5000000000000000000', feeWei: '1000', tree: {}, tip: 9 };
const mockLookUp = jest.fn();
jest.mock('../../lib/vanish/actions', () => ({
  CARD_KEY: { card: true },
  lookUpKey: (...args: unknown[]) => mockLookUp(...args),
  proveRevealAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
  startReveal: jest.fn(),
}));

const mockRead = jest.fn();
jest.mock('../../modules/ghost-nfc', () => ({
  ...jest.requireActual('../../modules/ghost-nfc'),
  cardsSupported: () => true,
  readPhantomKeyFromCard: () => mockRead(),
}));

jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));
jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: jest.fn() }) }));

/** A lookup that stays open until the test settles it. */
function pendingLookup() {
  let resolve: (value: unknown) => void = () => {};
  let reject: (reason: unknown) => void = () => {};
  mockLookUp.mockImplementationOnce(
    () =>
      new Promise((yes, no) => {
        resolve = yes;
        reject = no;
      }),
  );
  return { resolve: (value: unknown) => resolve(value), reject: (reason: unknown) => reject(reason) };
}

function renderSummon() {
  return render(
    <SafeAreaProvider
      initialMetrics={{ frame: { x: 0, y: 0, width: 393, height: 852 }, insets: { top: 47, left: 0, right: 0, bottom: 34 } }}
    >
      <SummonScreen />
    </SafeAreaProvider>,
  );
}

async function tapCard() {
  await act(async () => {
    fireEvent.press(screen.getByTestId('summon-tap-card'));
  });
}

async function typeAndFind() {
  fireEvent.changeText(screen.getByTestId('summon-key'), mockKeyWords.join(' '));
  await act(async () => {
    fireEvent.press(screen.getByTestId('summon-find'));
  });
}

beforeEach(() => {
  jest.useFakeTimers();
  mockLookUp.mockReset();
  mockRead.mockReset();
  mockRead.mockResolvedValue({ uidHex: '04518DFAA96180' });
});

afterEach(() => {
  jest.useRealTimers();
});

describe.each([
  ['a tapped card', tapCard],
  ['a typed key', typeAndFind],
] as const)('looking up %s', (_name, start) => {
  it('shows the lookup with a spinner until the coins are found', async () => {
    const lookup = pendingLookup();
    renderSummon();
    await start();

    expect(screen.getByTestId('key-lookup-status')).toHaveTextContent("Looking up this key's coins…");
    expect(screen.getByTestId('key-lookup-spinner')).toBeOnTheScreen();
    expect(screen.queryByTestId('key-lookup-slow')).toBeNull();
    expect(screen.queryByTestId('summon-amount')).toBeNull();

    await act(async () => lookup.resolve(FOUND));
    expect(screen.queryByTestId('key-lookup-progress')).toBeNull();
    expect(screen.getByTestId('summon-amount')).toHaveTextContent('5.00 GHOST');
  });

  it('adds a note once the lookup has taken over 15 seconds', async () => {
    const lookup = pendingLookup();
    renderSummon();
    await start();

    act(() => jest.advanceTimersByTime(14_900));
    expect(screen.queryByTestId('key-lookup-slow')).toBeNull();
    act(() => jest.advanceTimersByTime(200));
    expect(screen.getByTestId('key-lookup-slow')).toHaveTextContent('This can take a minute on a long chain.');
    expect(screen.getByTestId('key-lookup-status')).toHaveTextContent("Looking up this key's coins…");

    await act(async () => lookup.resolve(FOUND));
    expect(screen.queryByTestId('key-lookup-slow')).toBeNull();
    expect(screen.getByTestId('summon-amount')).toBeOnTheScreen();
  });

  it('says why a failed lookup failed and tries again', async () => {
    const lookup = pendingLookup();
    renderSummon();
    await start();
    act(() => jest.advanceTimersByTime(20_000));

    await act(async () => lookup.reject(new TypeError('Network request failed')));
    expect(screen.queryByTestId('key-lookup-progress')).toBeNull();
    expect(screen.queryByTestId('key-lookup-slow')).toBeNull();
    expect(screen.getByTestId('summon-error')).toHaveTextContent(
      "The coins could not be looked up. Can't reach the test node at http://127.0.0.1:8547. Check that it is running and that this phone is on the same network.",
    );
    expect(screen.getByTestId('key-lookup-retry')).toBeOnTheScreen();

    const again = pendingLookup();
    await act(async () => {
      fireEvent.press(screen.getByTestId('key-lookup-retry'));
    });
    expect(mockLookUp).toHaveBeenCalledTimes(2);
    expect(mockLookUp.mock.calls[1][1]).toEqual(mockLookUp.mock.calls[0][1]);
    expect(screen.queryByTestId('summon-error')).toBeNull();
    expect(screen.getByTestId('key-lookup-status')).toHaveTextContent("Looking up this key's coins…");
    // The slow note waits a fresh 15 seconds on the new try.
    expect(screen.queryByTestId('key-lookup-slow')).toBeNull();

    await act(async () => again.resolve(FOUND));
    expect(screen.getByTestId('summon-amount')).toHaveTextContent('5.00 GHOST');
  });
});

it('looks up the card key after the card is read, not the typed one', async () => {
  pendingLookup();
  renderSummon();
  await tapCard();
  expect(mockLookUp).toHaveBeenCalledWith(expect.anything(), { card: true });
  expect(screen.getByTestId('summon-card-key')).toBeOnTheScreen();
  expect(screen.getByTestId('key-lookup-progress')).toBeOnTheScreen();
});

it('drops a lookup still on its way when the key is changed', async () => {
  const lookup = pendingLookup();
  renderSummon();
  await typeAndFind();
  fireEvent.changeText(screen.getByTestId('summon-key'), 'abandon');
  expect(screen.queryByTestId('key-lookup-progress')).toBeNull();
  await act(async () => lookup.resolve(FOUND));
  expect(screen.queryByTestId('summon-amount')).toBeNull();
});
