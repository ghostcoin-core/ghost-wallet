import { act, fireEvent, render, screen } from '@testing-library/react-native';
import type { ComponentType } from 'react';
import { StyleSheet } from 'react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import SummonScreen from '../../app/summon';
import VanishScreen from '../../app/vanish';
import WipeCardScreen from '../../app/wipe-card';
import { CardError } from '../../modules/ghost-nfc/card';

const mockKeyWords = Array.from({ length: 24 }, (_, i) => ['abandon', 'ability', 'able', 'about'][i % 4]);

const mockCore = {
  checkKeyWords: jest.fn(() => ({ verdict: 'word-check', position: 0 })),
  checkPhantomKeyWord: jest.fn((position: number, word: string) => mockKeyWords[position - 1] === word),
  confirmPhantomKeySaved: jest.fn(),
  forgetPhantomKey: jest.fn(),
  forgetCardKey: jest.fn(),
  savedAccountZeroAddress: () => '0x00000000000000000000000000000000000000aa',
  hasAccount: () => true,
};
jest.mock('../../modules/ghost-core/src/index', () => mockCore, { virtual: true });

const mockSequence = { step: jest.fn(() => 0), record: () => ({ id: 'vanish-1' }), markBackedUp: jest.fn() };
jest.mock('../../lib/vanish/use-payment', () => ({
  paymentKit: () => ({ core: mockCore, store: { list: () => [], remove: jest.fn() }, node: {}, nodeUrl: 'http://127.0.0.1:8547' }),
  usePayment: (_kit: unknown, sequence: unknown) => (sequence ? { status: 'sent', step: 3, needsKey: false, error: null } : null),
}));

const mockLookUp = jest.fn(async () => ({ status: 'found', amountWei: '2000000000000000000', feeWei: '1000', tree: {}, tip: 9 }));
jest.mock('../../lib/vanish/actions', () => ({
  CARD_KEY: { card: true },
  minimumVanish: async () => 10n ** 17n,
  vanishFee: async () => 1000n,
  startVanish: async () => ({ sequence: mockSequence, words: [...mockKeyWords] }),
  lookUpKey: (...args: unknown[]) => mockLookUp(...(args as [])),
  signVanishAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
  proveRevealAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
  startReveal: jest.fn(),
}));

const mockPut = jest.fn();
const mockRead = jest.fn();
const mockWipe = jest.fn();
jest.mock('../../modules/ghost-nfc', () => ({
  ...jest.requireActual('../../modules/ghost-nfc'),
  cardsSupported: () => true,
  putPhantomKeyOnCard: () => mockPut(),
  readPhantomKeyFromCard: () => mockRead(),
  wipePhantomKeyCard: () => mockWipe(),
}));

jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));
jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: jest.fn() }) }));

const mockWindow = { width: 393, height: 852, scale: 3, fontScale: 1 };
jest.mock('react-native/Libraries/Utilities/useWindowDimensions', () => ({ __esModule: true, default: () => mockWindow }));

const DEVICES = {
  iPhone: { width: 393, height: 852 },
  'iPhone Duo folded': { width: 466, height: 678 },
  'iPhone Duo open': { width: 626, height: 890 },
} as const;
type Device = keyof typeof DEVICES;

function renderOn(device: Device, Screen: ComponentType) {
  const { width, height } = DEVICES[device];
  mockWindow.width = width;
  mockWindow.height = height;
  return render(
    <SafeAreaProvider initialMetrics={{ frame: { x: 0, y: 0, width, height }, insets: { top: 47, left: 0, right: 0, bottom: 34 } }}>
      <Screen />
    </SafeAreaProvider>,
  );
}

function sideBySide(testID: string): boolean {
  return StyleSheet.flatten(screen.getByTestId(testID).props.contentContainerStyle).flexDirection === 'row';
}

async function reachCheck() {
  fireEvent.changeText(screen.getByTestId('vanish-amount'), '1.5');
  await act(async () => {
    fireEvent.press(screen.getByTestId('vanish-make-key'));
  });
  fireEvent.press(screen.getByTestId('vanish-saved'));
  for (const field of screen.getAllByTestId(/^vanish-check-\d+$/)) {
    const position = Number(field.props.testID.replace('vanish-check-', ''));
    fireEvent.changeText(field, mockKeyWords[position - 1]);
  }
}

beforeEach(() => {
  jest.clearAllMocks();
  mockPut.mockResolvedValue({ uidHex: '04518DFAA96180' });
  mockRead.mockResolvedValue({ uidHex: '04518DFAA96180' });
  mockWipe.mockResolvedValue({ uidHex: '04518DFAA96180' });
});

describe.each(Object.keys(DEVICES) as Device[])('on the %s', (device) => {
  const open = device === 'iPhone Duo open';

  it('puts the checked key on a card while the core still holds it, then sends', async () => {
    renderOn(device, VanishScreen);
    expect(sideBySide('vanish-screen-content')).toBe(open);
    await reachCheck();
    let finishWrite: () => void = () => {};
    mockPut.mockReturnValue(new Promise<void>((resolve) => (finishWrite = resolve)));
    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-card'));
    });
    expect(mockPut).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('vanish-card-hold')).toHaveTextContent(/Hold a blank NTAG 424 DNA card/);
    // The key is dropped only after the card holds it.
    expect(mockCore.confirmPhantomKeySaved).not.toHaveBeenCalled();
    await act(async () => finishWrite());
    expect(mockCore.confirmPhantomKeySaved).toHaveBeenCalledTimes(1);
    expect(mockSequence.markBackedUp).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
  });

  it('does not put a key on a card when the words typed for it are wrong', async () => {
    renderOn(device, VanishScreen);
    await reachCheck();
    for (const field of screen.getAllByTestId(/^vanish-check-\d+$/)) fireEvent.changeText(field, 'zoo');
    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-card'));
    });
    expect(mockPut).not.toHaveBeenCalled();
    expect(screen.getByTestId('vanish-error')).toHaveTextContent(/does not match/);
  });

  it('shows why a card was refused and lets the Vanish go on without it', async () => {
    renderOn(device, VanishScreen);
    await reachCheck();
    mockPut.mockRejectedValue(new CardError('not-genuine'));
    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-card'));
    });
    expect(screen.getByTestId('vanish-error')).toHaveTextContent(/NXP genuineness check/);
    expect(mockCore.confirmPhantomKeySaved).not.toHaveBeenCalled();
    expect(screen.getByTestId('vanish-card-retry')).toBeOnTheScreen();
    fireEvent.press(screen.getByTestId('vanish-without-card'));
    expect(mockCore.confirmPhantomKeySaved).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
  });

  it('summons from a tapped card without the key reaching the screen, and forgets it on leaving', async () => {
    const view = renderOn(device, SummonScreen);
    expect(sideBySide('summon-screen-content')).toBe(open);
    await act(async () => {
      fireEvent.press(screen.getByTestId('summon-tap-card'));
    });
    expect(mockRead).toHaveBeenCalledTimes(1);
    expect(mockLookUp).toHaveBeenCalledWith(expect.anything(), { card: true });
    expect(screen.getByTestId('summon-card-key')).toBeOnTheScreen();
    expect(screen.queryByTestId('summon-key')).toBeNull();
    expect(screen.getByTestId('summon-amount')).toHaveTextContent('2.00 GHOST');
    view.unmount();
    expect(mockCore.forgetCardKey).toHaveBeenCalled();
  });

  it('says a card from another phone cannot be read here', async () => {
    renderOn(device, SummonScreen);
    mockRead.mockRejectedValue(new CardError('other-phone'));
    await act(async () => {
      fireEvent.press(screen.getByTestId('summon-tap-card'));
    });
    expect(screen.getByTestId('summon-error')).toHaveTextContent(/only be read or wiped on the phone that wrote it/);
    expect(mockLookUp).not.toHaveBeenCalled();
    expect(screen.getByTestId('summon-key')).toBeOnTheScreen();
  });

  it('wipes a card', async () => {
    renderOn(device, WipeCardScreen);
    expect(sideBySide('wipe-card-screen-content')).toBe(open);
    await act(async () => {
      fireEvent.press(screen.getByTestId('wipe-card'));
    });
    expect(mockWipe).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('wipe-card-done')).toBeOnTheScreen();

    mockWipe.mockRejectedValue(new CardError('keys-changed'));
    await act(async () => {
      fireEvent.press(screen.getByTestId('wipe-card'));
    });
    expect(screen.getByTestId('wipe-card-error')).toHaveTextContent(/no longer matches/);
    expect(screen.queryByTestId('wipe-card-done')).toBeNull();
  });
});
