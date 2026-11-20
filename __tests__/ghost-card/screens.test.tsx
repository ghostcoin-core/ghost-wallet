/* eslint-disable @typescript-eslint/no-require-imports -- the jest.mock factories reach the test's fakes lazily */
// The Ghost card screens on the iPhone, the iPhone Duo folded and the iPhone
// Duo open. A card works like a vault: Add to card takes an amount and one
// hold; Take off card shows what the card holds, asks how much (or all), and
// takes it in one hold; the card screen shows one balance. No screen asks for
// a code or shows a card state (sealed, opened, fill, reuse, not safe).
import { act, fireEvent, screen } from '@testing-library/react-native';

import CheckCardScreen from '../../app/(tabs)/(cards)/check-card';
import FillGhostCardScreen from '../../app/(tabs)/(cards)/fill-ghost-card';
import OpenGhostCardScreen from '../../app/(tabs)/(cards)/open-ghost-card';
import { DEVICE_NAMES, renderOn, sideBySide } from '../sealed-card/screen-kit';

const GHOST = 10n ** 18n;

const fake = {
  change: jest.fn(),
  move: jest.fn(),
  check: jest.fn(),
  sealCheck: jest.fn(),
};

jest.mock('../../lib/ghost-card/vault-deps', () => ({
  vaultDeps: () => ({
    card: { core: {}, nfc: {}, chainId: 1n, coinOnChain: async () => ({ status: 'buried', spent: false, leaf: null }) },
    keys: {},
    payments: { vanishSavedInto: () => false, paymentState: () => 'missing' },
    changes: { read: () => [], write: async () => {} },
  }),
}));
jest.mock('../../lib/ghost-card/deps', () => ({
  ghostCardDeps: () => ({ core: {}, nfc: {}, chainId: 1n, coinOnChain: async () => ({ status: 'buried', spent: false, leaf: null }) }),
}));
jest.mock('../../lib/ghost-card/vault', () => ({
  ...jest.requireActual('../../lib/ghost-card/vault'),
  changeCard: (...args: unknown[]) => require('./screens.test').fake.change(...args),
  moveChanges: (...args: unknown[]) => require('./screens.test').fake.move(...args),
}));
jest.mock('../../lib/ghost-card/flows', () => ({
  ...jest.requireActual('../../lib/ghost-card/flows'),
  checkGhostCard: (...args: unknown[]) => require('./screens.test').fake.check(...args),
}));
jest.mock('../../lib/seal/flows', () => ({
  sealDeps: () => ({}),
  checkCard: (...args: unknown[]) => require('./screens.test').fake.sealCheck(...args),
  confirmFill: async () => null,
}));
jest.mock('../../lib/vanish/use-payment', () => ({
  paymentKit: () => ({ core: {}, nodeUrl: 'http://node.example.com' }),
}));
jest.mock('../../lib/home/use-home', () => ({
  useHome: () => ({ view: { snapshot: { balanceWei: (100n * 10n ** 18n).toString() } } }),
}));
jest.mock('../../lib/vanish/actions', () => ({
  minimumVanish: async () => 10n ** 17n,
  summonFee: async () => 10n ** 15n,
  vanishFee: async () => 10n ** 15n,
}));
jest.mock('../../lib/account', () => ({ accountZeroAddress: () => '0x00000000000000000000000000000000000000aa' }));
jest.mock('../../modules/ghost-nfc', () => ({
  ...jest.requireActual('../../modules/ghost-nfc'),
  cardsSupported: () => true,
}));
const mockRouter = { push: jest.fn(), back: jest.fn(), replace: jest.fn() };
let mockParams: Record<string, string> = {};
jest.mock('expo-router', () => ({ useRouter: () => mockRouter, useLocalSearchParams: () => mockParams }));
jest.mock('react-native/Libraries/Utilities/useWindowDimensions', () => ({
  __esModule: true,
  default: () => require('../sealed-card/screen-kit').windowSize,
}));

export { fake };

/** Words a card screen never shows: the card has one balance, not states. */
const NO_STATE_WORDS = /sealed|opened|fill \d|reuse|not safe|reset|seal check|blank/i;

function shownText(): string {
  return JSON.stringify(screen.toJSON());
}

function heldCheck(amountWei: bigint) {
  return {
    status: { kind: 'sealed', fill: 2, amountWei, checksLeft: 900, cardNumber: 'AAAA BBBB' },
    statement: { cardId: new ArrayBuffer(16), fill: 2, cardNumber: 'AAAA BBBB', amountWei: amountWei.toString() },
    ms: 2000,
    commitData: null,
  };
}

beforeEach(() => {
  mockParams = {};
  for (const fn of [fake.change, fake.move, fake.check, fake.sealCheck, mockRouter.replace, mockRouter.push, mockRouter.back]) {
    fn.mockReset();
  }
});

async function press(testID: string) {
  await act(async () => {
    fireEvent.press(screen.getByTestId(testID));
  });
}

describe.each(DEVICE_NAMES)('on the %s', (device) => {
  const open = device === 'iPhone Duo open';

  it('Add: an amount, then one hold, and the card shows its new total', async () => {
    renderOn(device, FillGhostCardScreen);
    expect(sideBySide('fill-ghost-card-screen-content')).toBe(open);
    await act(async () => {});
    fireEvent.changeText(screen.getByTestId('ghost-fill-amount'), '10');
    fake.change.mockResolvedValue({ ok: true, cardNumber: 'AAAA BBBB', beforeWei: 5n * GHOST, afterWei: 15n * GHOST });
    await press('ghost-fill-tap');
    expect(fake.change).toHaveBeenCalledWith(expect.anything(), { kind: 'add', amountWei: 10n * GHOST }, 10n ** 17n);
    expect(fake.move).toHaveBeenCalledTimes(1);
    expect(String(screen.getByTestId('ghost-fill-balance-text').props.children)).toBe('15 GHOST');
    expect(screen.getByTestId('ghost-fill-done')).toHaveTextContent(/Added 10 GHOST/);
    expect(shownText()).not.toMatch(NO_STATE_WORDS);
  });

  it('Add from Vanish: the hold starts at once, with no second button', async () => {
    mockParams = { amount: '2', start: '1' };
    fake.change.mockResolvedValue({ ok: true, cardNumber: 'AAAA', beforeWei: 0n, afterWei: 2n * GHOST });
    renderOn(device, FillGhostCardScreen);
    await act(async () => {});
    expect(fake.change).toHaveBeenCalledTimes(1);
    expect(fake.change.mock.calls[0][1]).toEqual({ kind: 'add', amountWei: 2n * GHOST });
  });

  it('Add: opened without the go-ahead, it waits for the hold', async () => {
    mockParams = { amount: '2' };
    renderOn(device, FillGhostCardScreen);
    await act(async () => {});
    expect(fake.change).not.toHaveBeenCalled();
  });

  it('Add: more than the wallet holds is refused before any hold', async () => {
    renderOn(device, FillGhostCardScreen);
    await act(async () => {});
    fireEvent.changeText(screen.getByTestId('ghost-fill-amount'), '100');
    expect(screen.getByTestId('ghost-fill-not-enough')).toBeOnTheScreen();
    await press('ghost-fill-tap');
    expect(fake.change).not.toHaveBeenCalled();
  });

  it('Add: a card that was not changed says so in plain words', async () => {
    renderOn(device, FillGhostCardScreen);
    await act(async () => {});
    fireEvent.changeText(screen.getByTestId('ghost-fill-amount'), '1');
    fake.change.mockResolvedValue({ ok: false, message: "This isn't a Ghost card.", alarm: true });
    await press('ghost-fill-tap');
    expect(screen.getByTestId('ghost-fill-error')).toHaveTextContent("This isn't a Ghost card.");
    expect(screen.queryByTestId('ghost-fill-balance')).toBeNull();
  });

  it('Take off: shows what the card holds, asks how much, and takes it in one hold', async () => {
    renderOn(device, OpenGhostCardScreen);
    expect(sideBySide('open-ghost-card-screen-content')).toBe(open);
    await act(async () => {});
    fake.check.mockResolvedValue(heldCheck(35n * GHOST));
    await press('ghost-open-look');
    expect(String(screen.getByTestId('ghost-open-balance-text').props.children)).toBe('35 GHOST');
    fireEvent.changeText(screen.getByTestId('ghost-open-amount'), '3');
    fake.change.mockResolvedValue({ ok: true, cardNumber: 'AAAA BBBB', beforeWei: 35n * GHOST, afterWei: 32n * GHOST });
    await press('ghost-open-take');
    expect(fake.change).toHaveBeenCalledWith(expect.anything(), { kind: 'take', amountWei: 3n * GHOST }, 10n ** 17n);
    expect(String(screen.getByTestId('ghost-open-after-text').props.children)).toBe('32 GHOST');
    expect(screen.getByTestId('ghost-open-done')).toHaveTextContent(/Took off 3 GHOST/);
    expect(shownText()).not.toMatch(NO_STATE_WORDS);
  });

  it('Take off: All takes everything and leaves the card empty', async () => {
    renderOn(device, OpenGhostCardScreen);
    await act(async () => {});
    fake.check.mockResolvedValue(heldCheck(35n * GHOST));
    await press('ghost-open-look');
    await press('ghost-open-all');
    fake.change.mockResolvedValue({ ok: true, cardNumber: 'AAAA BBBB', beforeWei: 35n * GHOST, afterWei: 0n });
    await press('ghost-open-take');
    expect(fake.change.mock.calls[0][1]).toEqual({ kind: 'take', amountWei: null });
    expect(String(screen.getByTestId('ghost-open-after-text').props.children)).toBe('Empty');
  });

  it('Take off: more than the card holds is refused before the hold', async () => {
    renderOn(device, OpenGhostCardScreen);
    await act(async () => {});
    fake.check.mockResolvedValue(heldCheck(5n * GHOST));
    await press('ghost-open-look');
    fireEvent.changeText(screen.getByTestId('ghost-open-amount'), '6');
    expect(screen.getByTestId('ghost-open-amount-error')).toHaveTextContent('The card holds 5 GHOST.');
    await press('ghost-open-take');
    expect(fake.change).not.toHaveBeenCalled();
  });

  it('Take off from Summon: the card is read at once', async () => {
    mockParams = { start: '1' };
    fake.check.mockResolvedValue(heldCheck(5n * GHOST));
    renderOn(device, OpenGhostCardScreen);
    await act(async () => {});
    expect(fake.check).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('ghost-open-amount')).toBeOnTheScreen();
  });

  it('Card screen: one balance with Add and Take off, an empty card is Empty, an NTAG 424 card goes to its Seal', async () => {
    renderOn(device, CheckCardScreen);
    fake.check.mockResolvedValue(heldCheck(3n * GHOST));
    await press('check-card-run');
    expect(String(screen.getByTestId('check-card-status-text').props.children)).toBe('3 GHOST');
    expect(screen.getByTestId('check-card-fill')).toBeOnTheScreen();
    expect(screen.getByTestId('check-card-open')).toBeOnTheScreen();
    expect(shownText()).not.toMatch(NO_STATE_WORDS);

    // Opened before and its coin taken: just an empty card, ready to add to.
    fake.check.mockResolvedValue({
      status: { kind: 'opened', fill: 2, cardNumber: 'AAAA BBBB', spent: true },
      statement: { cardId: new ArrayBuffer(16), fill: 2, cardNumber: 'AAAA BBBB', amountWei: '0' },
      ms: 2000,
      commitData: null,
    });
    await press('check-card-run');
    expect(String(screen.getByTestId('check-card-status-text').props.children)).toBe('Empty');
    expect(screen.getByTestId('check-card-fill')).toBeOnTheScreen();
    expect(screen.queryByTestId('check-card-open')).toBeNull();
    expect(shownText()).not.toMatch(NO_STATE_WORDS);

    fake.check.mockResolvedValue({ status: { kind: 'carry-to-claim' }, statement: null, ms: null, commitData: null });
    fake.sealCheck.mockResolvedValue({ kind: 'spent' });
    await press('check-card-run');
    expect(fake.sealCheck).toHaveBeenCalledTimes(1);
    expect(String(screen.getByTestId('check-card-status-text').props.children)).toBe('Spent, empty');
  });
});
