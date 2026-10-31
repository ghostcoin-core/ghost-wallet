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

const mockLookUp = jest.fn();
const mockStartReveal = jest.fn();
jest.mock('../../lib/vanish/actions', () => ({
  CARD_KEY: { card: true },
  lookUpKey: (...args: unknown[]) => mockLookUp(...args),
  proveRevealAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
  startReveal: (...args: unknown[]) => mockStartReveal(...args),
}));

jest.mock('../../modules/ghost-nfc', () => ({
  ...jest.requireActual('../../modules/ghost-nfc'),
  cardsSupported: () => false,
}));

jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));
jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: jest.fn() }) }));

const HINT_TEXT = 'Not checked: these coins may have been summoned already.';

type Hint = { checked: false; spent: boolean | null };

/** A spent hint that stays open until the test settles it. */
function pendingHint() {
  let resolve: (value: Hint) => void = () => {};
  let reject: (reason: unknown) => void = () => {};
  const promise = new Promise<Hint>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve: (value: Hint) => resolve(value), reject: (reason: unknown) => reject(reason) };
}

function found(spentHint?: Promise<Hint>) {
  return { status: 'found', amountWei: '5000000000000000000', feeWei: '1000', tree: {}, tip: 9, spentHint };
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

async function typeAndFind(words = mockKeyWords.join(' ')) {
  fireEvent.changeText(screen.getByTestId('summon-key'), words);
  await act(async () => {
    fireEvent.press(screen.getByTestId('summon-find'));
  });
}

beforeEach(() => {
  mockLookUp.mockReset();
  mockStartReveal.mockReset();
  mockStartReveal.mockReturnValue(new Promise(() => {}));
});

it('shows the coins at once, then the quiet hint when the markers say spent', async () => {
  const hint = pendingHint();
  mockLookUp.mockResolvedValueOnce(found(hint.promise));
  renderSummon();
  await typeAndFind();

  // The lookup is shown without waiting on the hint.
  expect(screen.getByTestId('summon-amount')).toHaveTextContent('5.00 GHOST');
  expect(screen.queryByTestId('summon-spent-hint')).toBeNull();
  expect(screen.getByTestId('summon-reveal')).not.toBeDisabled();

  await act(async () => hint.resolve({ checked: false, spent: true }));
  expect(screen.getByTestId('summon-spent-hint')).toHaveTextContent(HINT_TEXT);
});

it('still offers Summon and Claim while the hint says spent', async () => {
  mockLookUp.mockResolvedValueOnce(found(Promise.resolve({ checked: false, spent: true })));
  renderSummon();
  await typeAndFind();

  expect(screen.getByTestId('summon-spent-hint')).toHaveTextContent(HINT_TEXT);
  expect(screen.getByTestId('summon-reveal')).not.toBeDisabled();

  fireEvent.press(screen.getByTestId('summon-part'));
  fireEvent.changeText(screen.getByTestId('summon-claim-amount'), '1');
  expect(screen.getByTestId('summon-reveal')).not.toBeDisabled();
  expect(screen.getByTestId('summon-spent-hint')).toBeOnTheScreen();

  jest.useFakeTimers();
  try {
    fireEvent.press(screen.getByTestId('summon-reveal'));
    act(() => jest.advanceTimersByTime(100));
  } finally {
    jest.useRealTimers();
  }
  expect(mockStartReveal).toHaveBeenCalledTimes(1);
});

it.each([
  ['the markers say unspent', () => Promise.resolve<Hint>({ checked: false, spent: false })],
  ['the markers could not be read', () => Promise.resolve<Hint>({ checked: false, spent: null })],
  ['the hint fails', () => Promise.reject<Hint>(new Error('markers unavailable'))],
  ['there is no hint', () => undefined],
])('shows no hint when %s', async (_name, makeHint) => {
  const spentHint = makeHint();
  mockLookUp.mockResolvedValueOnce(found(spentHint));
  renderSummon();
  await typeAndFind();
  await act(async () => {});

  expect(screen.getByTestId('summon-amount')).toBeOnTheScreen();
  expect(screen.queryByTestId('summon-spent-hint')).toBeNull();
  expect(screen.getByTestId('summon-reveal')).not.toBeDisabled();
});

it('clears the hint when the key changes, and ignores a hint from a dropped lookup', async () => {
  mockLookUp.mockResolvedValueOnce(found(Promise.resolve({ checked: false, spent: true })));
  renderSummon();
  await typeAndFind();
  expect(screen.getByTestId('summon-spent-hint')).toBeOnTheScreen();

  // A new key: its lookup's hint is still on its way, the old one's must not show.
  const late = pendingHint();
  mockLookUp.mockResolvedValueOnce(found(late.promise));
  await typeAndFind(`${mockKeyWords.join(' ')} `);
  expect(screen.getByTestId('summon-amount')).toBeOnTheScreen();
  expect(screen.queryByTestId('summon-spent-hint')).toBeNull();

  // A hint for a lookup the screen has dropped never shows.
  const dropped = pendingHint();
  mockLookUp.mockResolvedValueOnce(found(dropped.promise));
  await typeAndFind();
  fireEvent.changeText(screen.getByTestId('summon-key'), 'abandon');
  await act(async () => dropped.resolve({ checked: false, spent: true }));
  await act(async () => late.resolve({ checked: false, spent: true }));
  expect(screen.queryByTestId('summon-spent-hint')).toBeNull();
});

it('does not show the hint when the coins are not found', async () => {
  mockLookUp.mockResolvedValueOnce({
    ...found(Promise.resolve({ checked: false, spent: true })),
    status: 'not-found',
  });
  renderSummon();
  await typeAndFind();
  await act(async () => {});

  expect(screen.queryByTestId('summon-amount')).toBeNull();
  expect(screen.queryByTestId('summon-spent-hint')).toBeNull();
});
