/* eslint-disable @typescript-eslint/no-require-imports -- the jest.mock factories reach the test's fakes lazily */
// The Ghost card screens on the iPhone, the iPhone Duo folded and the iPhone
// Duo open: Fill shows the open code before any tap and pays only after the
// card checked out; Open summons at once and offers Reuse once settled; Check
// shows a Ghost card's state and sends an NTAG 424 card on to its Seal.
import { act, fireEvent, screen } from '@testing-library/react-native';

import CheckCardScreen from '../../app/check-card';
import FillGhostCardScreen from '../../app/fill-ghost-card';
import OpenGhostCardScreen from '../../app/open-ghost-card';
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
      javaCardNewOpenCode: () => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
      javaCardOpenCode: (text: string) => {
        if (text.replace(/[\s-]/g, '').length !== 32) {
          throw new Error('not-an-open-code');
        }
        return new ArrayBuffer(20);
      },
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
jest.mock('expo-router', () => ({ useRouter: () => mockRouter }));
jest.mock('react-native/Libraries/Utilities/useWindowDimensions', () => ({
  __esModule: true,
  default: () => require('../sealed-card/screen-kit').windowSize,
}));

export { fake };

beforeEach(() => {
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

  it('Fill: shows the open code before the card is tapped, and pays only after the card checked out', async () => {
    renderOn(device, FillGhostCardScreen);
    expect(sideBySide('fill-ghost-card-screen-content')).toBe(open);
    await act(async () => {});
    fireEvent.changeText(screen.getByTestId('ghost-fill-amount'), '2');
    await press('ghost-fill-make-code');
    expect(String(screen.getByTestId('ghost-fill-code-text').props.children)).toBe('ABCDEFGH IJKLMNOP QRSTUVWX YZ234567');
    // No tap until the writer says the code is kept.
    expect(screen.queryByTestId('ghost-fill-tap')).toBeNull();
    await press('ghost-fill-kept');
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
    expect(fake.calls).toEqual(['vanish']);
    // The code is gone from the screen once the card holds its hash.
    expect(screen.queryByTestId('ghost-fill-code')).toBeNull();
    expect(screen.getByTestId('ghost-fill-low-checks')).toBeTruthy();
  });

  it('Fill: a card that does not check out pays nothing', async () => {
    renderOn(device, FillGhostCardScreen);
    await act(async () => {});
    fireEvent.changeText(screen.getByTestId('ghost-fill-amount'), '2');
    await press('ghost-fill-make-code');
    await press('ghost-fill-kept');
    fake.fill.mockResolvedValue({ ok: false, status: { kind: 'not-genuine', reason: 'fill-other-amount' } });
    await press('ghost-fill-tap');
    expect(fake.calls).toEqual([]);
    expect(String(screen.getByTestId('ghost-fill-status-text').props.children)).toBe(
      'Not a genuine Ghost card: not safe to accept',
    );
  });

  it('Open: needs a well-formed code, summons at once, and offers Reuse once the Summon settled', async () => {
    const view = renderOn(device, OpenGhostCardScreen);
    expect(sideBySide('open-ghost-card-screen-content')).toBe(open);
    fireEvent.changeText(screen.getByTestId('ghost-open-code'), 'ABCD');
    expect(screen.getByTestId('ghost-open-code-error')).toBeTruthy();
    fireEvent.changeText(screen.getByTestId('ghost-open-code'), 'ABCDEFGH IJKLMNOP QRSTUVWX YZ234567');
    fake.open.mockResolvedValue({ ok: true, amountWei: 2n * 10n ** 18n, fill: 1, cardNumber: 'AAAA BBBB', ms: 2600 });
    await press('ghost-open-run');
    expect(fake.calls).toEqual(['summon']);
    expect(screen.queryByTestId('ghost-open-reuse')).toBeNull();
    fake.paymentStatus = 'settled';
    view.again();
    fake.refill.mockResolvedValue({ ok: true, fill: 1, ms: 300 });
    await press('ghost-open-refill');
    expect(fake.refill).toHaveBeenCalledTimes(1);
    await press('ghost-open-fill-next');
    expect(mockRouter.replace).toHaveBeenCalledWith('/fill-ghost-card');
  });

  it('Open: a wrong code opens nothing and summons nothing', async () => {
    renderOn(device, OpenGhostCardScreen);
    fireEvent.changeText(screen.getByTestId('ghost-open-code'), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567');
    fake.open.mockResolvedValue({ ok: false, status: { kind: 'code-wrong', cardNumber: 'AAAA' } });
    await press('ghost-open-run');
    expect(fake.calls).toEqual([]);
    expect(String(screen.getByTestId('ghost-open-status-text').props.children)).toBe('Open code wrong: not safe to accept');
  });

  it('Check: shows a sealed Ghost card, and sends an NTAG 424 card on to its Seal', async () => {
    renderOn(device, CheckCardScreen);
    fake.check.mockResolvedValue({
      status: { kind: 'sealed', fill: 2, amountWei: 3n * 10n ** 18n, checksLeft: 900, cardNumber: 'AAAA', codeConfirmed: false },
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
