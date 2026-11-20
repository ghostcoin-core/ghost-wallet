/* eslint-disable @typescript-eslint/no-require-imports -- the jest.mock factories reach the test's fakes lazily */
// The Ghost card screens on the iPhone, the iPhone Duo folded and the iPhone
// Duo open: Fill pays only after the card checked out; Open needs nothing but
// a tap, summons at once and offers Reuse once settled; Check shows a Ghost
// card's state and sends an NTAG 424 card on to its Seal. No screen asks for
// or shows a code: the card is a bearer object.
import { act, fireEvent, screen } from '@testing-library/react-native';

import CheckCardScreen from '../../app/(tabs)/(cards)/check-card';
import FillGhostCardScreen from '../../app/(tabs)/(cards)/fill-ghost-card';
import OpenGhostCardScreen from '../../app/(tabs)/(cards)/open-ghost-card';
import { DEVICE_NAMES, renderOn, sideBySide } from '../sealed-card/screen-kit';

const fake = {
  calls: [] as string[],
  fill: jest.fn(),
  open: jest.fn(),
  refill: jest.fn(),
  check: jest.fn(),
  paymentStatus: null as string | null,
  sealCheck: jest.fn(),
};

jest.mock('../../lib/ghost-card/deps', () => ({
  ghostCardDeps: () => ({
    core: {
      forgetJavaCardRelease: () => {},
    },
    nfc: {},
    chainId: 1n,
    coinOnChain: async () => ({ status: 'buried', spent: false, leaf: null }),
  }),
}));
jest.mock('../../lib/ghost-card/flows', () => ({
  ...jest.requireActual('../../lib/ghost-card/flows'),
  fillGhostCard: (...args: unknown[]) => require('./screens.test').fake.fill(...args),
  openGhostCard: (...args: unknown[]) => require('./screens.test').fake.open(...args),
  refillGhostCard: (...args: unknown[]) => require('./screens.test').fake.refill(...args),
  checkGhostCard: (...args: unknown[]) => require('./screens.test').fake.check(...args),
}));
jest.mock('../../lib/seal/flows', () => ({
  sealDeps: () => ({}),
  checkCard: (...args: unknown[]) => require('./screens.test').fake.sealCheck(...args),
  confirmFill: async () => null,
}));
jest.mock('../../lib/vanish/use-payment', () => ({
  paymentKit: () => ({ core: { forgetCardKey: () => {} }, nodeUrl: 'http://node.example.com' }),
  usePayment: (_kit: unknown, sequence: unknown) =>
    sequence ? { status: require('./screens.test').fake.paymentStatus ?? 'sending', step: 0, needsKey: false, error: null } : null,
}));
jest.mock('../../lib/vanish/actions', () => ({
  CARD_KEY: { card: true },
  minimumVanish: async () => 10n ** 17n,
  signVanishAgain: () => null,
  proveRevealAgain: () => null,
  startSealedCardVanish: async () => {
    require('./screens.test').fake.calls.push('vanish');
    return { sequence: {}, again: false };
  },
  startReveal: async () => {
    require('./screens.test').fake.calls.push('summon');
    return {};
  },
}));
jest.mock('../../lib/vanish/pending', () => ({ paymentsChanged: () => {}, shared: (s: unknown) => s }));
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

beforeEach(() => {
  mockParams = {};
  fake.calls = [];
  fake.paymentStatus = null;
  for (const fn of [fake.fill, fake.open, fake.refill, fake.check, fake.sealCheck, mockRouter.replace, mockRouter.push]) {
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

  it('Fill: an amount, then one tap, and pays only after the card checked out', async () => {
    renderOn(device, FillGhostCardScreen);
    expect(sideBySide('fill-ghost-card-screen-content')).toBe(open);
    await act(async () => {});
    fireEvent.changeText(screen.getByTestId('ghost-fill-amount'), '2');
    fake.fill.mockResolvedValue({
      ok: true,
      commitData: new Uint8Array(430),
      amountWei: 2n * 10n ** 18n,
      fill: 1,
      cardNumber: 'AAAA BBBB',
      checksLeft: 40,
      ms: 4200,
    });
    await press('ghost-fill-tap');
    expect(fake.fill.mock.calls[0][1]).toBe(2n * 10n ** 18n);
    expect(fake.fill.mock.calls[0].length).toBe(2);
    expect(fake.calls).toEqual(['vanish']);
    expect(screen.getByTestId('ghost-fill-low-checks')).toBeTruthy();
  });

  it('Fill from Vanish: the card read starts at once, with no second button', async () => {
    mockParams = { amount: '2', start: '1' };
    fake.fill.mockResolvedValue({
      ok: true,
      commitData: new Uint8Array(430),
      amountWei: 2n * 10n ** 18n,
      fill: 1,
      cardNumber: 'AAAA BBBB',
      checksLeft: 400,
      ms: 4200,
    });
    renderOn(device, FillGhostCardScreen);
    await act(async () => {});
    expect(fake.fill).toHaveBeenCalledTimes(1);
    expect(fake.fill.mock.calls[0][1]).toBe(2n * 10n ** 18n);
    expect(fake.calls).toEqual(['vanish']);
  });

  it('Fill: opened without the go-ahead, it waits for the tap', async () => {
    mockParams = { amount: '2' };
    renderOn(device, FillGhostCardScreen);
    await act(async () => {});
    expect(fake.fill).not.toHaveBeenCalled();
  });

  it('Open from Summon: the card read starts at once, with no second button', async () => {
    mockParams = { start: '1' };
    fake.open.mockResolvedValue({
      ok: true,
      amountWei: 2n * 10n ** 18n,
      cardId: new Uint8Array(16).fill(7),
      fill: 1,
      cardNumber: 'AAAA BBBB',
      ms: 2600,
    });
    renderOn(device, OpenGhostCardScreen);
    await act(async () => {});
    expect(fake.open).toHaveBeenCalledTimes(1);
    expect(fake.calls).toEqual(['summon']);
  });

  it('Fill: a card that does not check out pays nothing', async () => {
    renderOn(device, FillGhostCardScreen);
    await act(async () => {});
    fireEvent.changeText(screen.getByTestId('ghost-fill-amount'), '2');
    fake.fill.mockResolvedValue({ ok: false, status: { kind: 'not-genuine', reason: 'fill-other-amount' } });
    await press('ghost-fill-tap');
    expect(fake.calls).toEqual([]);
    expect(String(screen.getByTestId('ghost-fill-status-text').props.children)).toBe(
      'Not a genuine Ghost card: not safe to accept',
    );
  });

  it('Open: needs nothing but a tap, summons at once, and offers Reuse once the Summon settled', async () => {
    const view = renderOn(device, OpenGhostCardScreen);
    expect(sideBySide('open-ghost-card-screen-content')).toBe(open);
    expect(screen.queryByLabelText('Open code')).toBeNull();
    fake.open.mockResolvedValue({
      ok: true,
      amountWei: 2n * 10n ** 18n,
      cardId: new Uint8Array(16).fill(7),
      fill: 1,
      cardNumber: 'AAAA BBBB',
      ms: 2600,
    });
    await press('ghost-open-run');
    expect(fake.open.mock.calls[0].length).toBe(1);
    expect(fake.calls).toEqual(['summon']);
    expect(screen.queryByTestId('ghost-open-reuse')).toBeNull();
    fake.paymentStatus = 'settled';
    view.again();
    fake.refill.mockResolvedValue({ ok: true, fill: 1, ms: 300 });
    await press('ghost-open-refill');
    expect(fake.refill).toHaveBeenCalledTimes(1);
    // Only the card just opened, at its fill.
    expect(fake.refill.mock.calls[0][1]).toEqual({ cardId: new Uint8Array(16).fill(7), fill: 1 });
    await press('ghost-open-fill-next');
    expect(mockRouter.replace).toHaveBeenCalledWith('/fill-ghost-card');
  });

  it('Open: a card whose coin was already summoned is offered for reuse, not summoned again', async () => {
    renderOn(device, OpenGhostCardScreen);
    fake.open.mockResolvedValue({
      ok: false,
      status: { kind: 'opened', fill: 1, cardNumber: 'AAAA', spent: true },
      reuse: { cardId: new Uint8Array(16).fill(7), fill: 1 },
    });
    await press('ghost-open-run');
    expect(fake.calls).toEqual([]);
    fake.refill.mockResolvedValue({ ok: true, fill: 1, ms: 300 });
    await press('ghost-open-refill');
    expect(fake.refill.mock.calls[0][1]).toEqual({ cardId: new Uint8Array(16).fill(7), fill: 1 });
    expect(screen.getByTestId('ghost-open-refilled')).toBeTruthy();
  });

  it('Open: a card that does not check out summons nothing', async () => {
    renderOn(device, OpenGhostCardScreen);
    fake.open.mockResolvedValue({ ok: false, status: { kind: 'not-genuine', reason: 'open-not-the-coin' } });
    await press('ghost-open-run');
    expect(fake.calls).toEqual([]);
    expect(String(screen.getByTestId('ghost-open-status-text').props.children)).toBe(
      'Not a genuine Ghost card: not safe to accept',
    );
  });

  it('Check: shows a sealed Ghost card, and sends an NTAG 424 card on to its Seal', async () => {
    renderOn(device, CheckCardScreen);
    fake.check.mockResolvedValue({
      status: { kind: 'sealed', fill: 2, amountWei: 3n * 10n ** 18n, checksLeft: 900, cardNumber: 'AAAA' },
      statement: null,
      ms: 2000,
      commitData: null,
    });
    await press('check-card-run');
    expect(String(screen.getByTestId('check-card-status-text').props.children)).toBe('Sealed (fill 2): holds 3 GHOST');
    expect(fake.sealCheck).not.toHaveBeenCalled();

    fake.check.mockResolvedValue({ status: { kind: 'carry-to-claim' }, statement: null, ms: null, commitData: null });
    fake.sealCheck.mockResolvedValue({ kind: 'spent' });
    await press('check-card-run');
    expect(fake.sealCheck).toHaveBeenCalledTimes(1);
    expect(String(screen.getByTestId('check-card-status-text').props.children)).toBe('Spent, empty');
  });
});
