import { act, fireEvent, render, screen } from '@testing-library/react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import VanishScreen from '../../app/vanish';
import { SKIP_CHECK_LABEL } from '../../components/skip-check';
import { backupStatusStore } from '../../lib/onboarding/backup-status';
import { encodeDetails } from '../../lib/vanish/payments';
import { resetPending } from '../../lib/vanish/pending';
import { CardCancelled } from '../../modules/ghost-nfc';

// Plain list words stand in for a new Phantom Key.
const mockKeyWords = Array.from({ length: 24 }, (_, i) => ['abandon', 'ability', 'able', 'about'][i % 4]);

const VANISH = { kind: 'vanish', commitData: '0x00', amountWei: '1500000000000000000', nonce: '0', at: 2 };

type MockSequence = { stepNow: number; step: () => number; record: () => object; markBackedUp: jest.Mock };
let mockSaved: Record<string, MockSequence> = {};
function mockNewSequence(): MockSequence {
  const sequence: MockSequence = {
    stepNow: 0,
    step: () => sequence.stepNow,
    record: () => ({ id: 'vanish-new', intent: { details: encodeDetails(VANISH as never) } }),
    markBackedUp: jest.fn(() => {
      sequence.stepNow = 1;
    }),
  };
  return sequence;
}

const mockCore = {
  checkKeyWords: jest.fn(() => ({ verdict: 'word-check', position: 0 })),
  checkPhantomKeyWord: jest.fn((position: number, word: string) => mockKeyWords[position - 1] === word),
  confirmPhantomKeySaved: jest.fn(),
  confirmPhantomKeySavedUnchecked: jest.fn(),
  forgetPhantomKey: jest.fn(),
  forgetCardKey: jest.fn(),
  savedAccountZeroAddress: () => '0x00000000000000000000000000000000000000aa',
  hasAccount: () => true,
  PaymentSequence: {
    open: (_store: unknown, id: string) => {
      const found = mockSaved[id];
      if (!found) throw new Error('no such payment');
      return found;
    },
  },
};
jest.mock('../../modules/ghost-core/src/index', () => mockCore, { virtual: true });

const mockStore = {
  list: () => Object.keys(mockSaved),
  remove: jest.fn((id: string) => {
    delete mockSaved[id];
  }),
};
jest.mock('../../lib/vanish/use-payment', () => ({
  paymentKit: () => ({ core: mockCore, store: mockStore, node: {}, nodeUrl: 'http://127.0.0.1:8547' }),
  usePayment: (_kit: unknown, sequence: unknown) => (sequence ? { status: 'sent', step: 3, needsKey: false, error: null } : null),
}));

jest.mock('../../lib/vanish/actions', () => ({
  CARD_KEY: { card: true },
  minimumVanish: async () => 10n ** 17n,
  vanishFee: () => new Promise(() => {}),
  startVanish: async () => {
    const sequence = mockNewSequence();
    mockSaved['vanish-new'] = sequence;
    return { sequence, words: [...mockKeyWords] };
  },
  lookUpKey: jest.fn(),
  signVanishAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
  proveRevealAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
  startReveal: jest.fn(),
}));

const mockPut = jest.fn();
jest.mock('../../modules/ghost-nfc', () => ({
  ...jest.requireActual('../../modules/ghost-nfc'),
  cardsSupported: () => true,
  putPhantomKeyOnCard: () => mockPut(),
}));

jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));
// The Vanish screen's balance is not known here.
jest.mock('../../lib/home/read-account', () => ({ readAccountZero: () => new Promise(() => {}) }));
const mockBack = jest.fn();
jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: mockBack }) }));

const mockWindow = { width: 393, height: 852, scale: 3, fontScale: 1 };
jest.mock('react-native/Libraries/Utilities/useWindowDimensions', () => ({ __esModule: true, default: () => mockWindow }));

const DEVICES = {
  iPhone: { width: 393, height: 852 },
  'iPhone Duo folded': { width: 466, height: 678 },
  'iPhone Duo open': { width: 626, height: 890 },
} as const;
type Device = keyof typeof DEVICES;

function renderOn(device: Device) {
  const { width, height } = DEVICES[device];
  mockWindow.width = width;
  mockWindow.height = height;
  return render(
    <SafeAreaProvider initialMetrics={{ frame: { x: 0, y: 0, width, height }, insets: { top: 47, left: 0, right: 0, bottom: 34 } }}>
      <VanishScreen />
    </SafeAreaProvider>,
  );
}

async function reachCheck() {
  fireEvent.changeText(screen.getByTestId('vanish-amount'), '1.5');
  await act(async () => {
    fireEvent.press(screen.getByTestId('vanish-make-key'));
  });
  fireEvent.press(screen.getByTestId('vanish-saved'));
}

function checkPositions(): number[] {
  return screen.getAllByTestId(/^vanish-check-\d+$/).map((field) => Number(field.props.testID.replace('vanish-check-', '')));
}

function typeWords(word: (position: number) => string) {
  for (const position of checkPositions()) {
    fireEvent.changeText(screen.getByTestId(`vanish-check-${position}`), word(position));
  }
}

function disabled(testID: string): boolean {
  return screen.getByTestId(testID).props.accessibilityState?.disabled === true;
}

beforeEach(() => {
  jest.clearAllMocks();
  resetPending();
  mockSaved = {};
  mockPut.mockResolvedValue({ uidHex: '04518DFAA96180' });
});

describe.each(Object.keys(DEVICES) as Device[])('on the %s', (device) => {
  it('shows the skip box unticked on the Phantom Key check', async () => {
    renderOn(device);
    await reachCheck();
    const box = screen.getByTestId('vanish-skip-check');
    expect(box.props.accessibilityRole).toBe('checkbox');
    expect(box.props.accessibilityState).toEqual({ checked: false });
    expect(screen.getByText(SKIP_CHECK_LABEL)).toBeOnTheScreen();
    expect(screen.getByTestId('vanish-send')).toBeOnTheScreen();
  });

  it('keeps Vanish disabled until the words are typed, and sends only once they pass', async () => {
    renderOn(device);
    await reachCheck();
    expect(disabled('vanish-send')).toBe(true);
    fireEvent.press(screen.getByTestId('vanish-send'));
    expect(mockCore.confirmPhantomKeySaved).not.toHaveBeenCalled();

    typeWords(() => 'zoo');
    expect(disabled('vanish-send')).toBe(false);
    fireEvent.press(screen.getByTestId('vanish-send'));
    expect(screen.getByTestId('vanish-error')).toHaveTextContent(/does not match/);
    expect(mockCore.confirmPhantomKeySaved).not.toHaveBeenCalled();
    expect(mockCore.confirmPhantomKeySavedUnchecked).not.toHaveBeenCalled();
    expect(mockSaved['vanish-new'].markBackedUp).not.toHaveBeenCalled();

    typeWords((position) => mockKeyWords[position - 1]);
    fireEvent.press(screen.getByTestId('vanish-send'));
    expect(mockCore.confirmPhantomKeySaved).toHaveBeenCalledTimes(1);
    expect(mockCore.confirmPhantomKeySavedUnchecked).not.toHaveBeenCalled();
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
  });

  it('enables Vanish when the box is ticked, and has the core drop the key unchecked', async () => {
    renderOn(device);
    await reachCheck();
    fireEvent.press(screen.getByTestId('vanish-skip-check'));
    expect(screen.getByTestId('vanish-skip-check').props.accessibilityState).toEqual({ checked: true });
    expect(disabled('vanish-send')).toBe(false);
    fireEvent.press(screen.getByTestId('vanish-skip-check'));
    expect(disabled('vanish-send')).toBe(true);
    fireEvent.press(screen.getByTestId('vanish-skip-check'));

    fireEvent.press(screen.getByTestId('vanish-send'));
    expect(mockCore.confirmPhantomKeySavedUnchecked).toHaveBeenCalledTimes(1);
    expect(mockCore.confirmPhantomKeySaved).not.toHaveBeenCalled();
    expect(mockCore.checkPhantomKeyWord).not.toHaveBeenCalled();
    expect(mockSaved['vanish-new'].markBackedUp).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
    // A Phantom Key is never stored, so nothing marks it in Settings.
    expect(backupStatusStore.unchecked()).toBe(false);
  });

  it('never remembers the skip: the check opened again starts unticked', async () => {
    const first = renderOn(device);
    await reachCheck();
    fireEvent.press(screen.getByTestId('vanish-skip-check'));
    fireEvent.press(screen.getByTestId('back'));
    first.unmount();

    renderOn(device);
    expect(screen.getByTestId('vanish-skip-check').props.accessibilityState).toEqual({ checked: false });
    expect(disabled('vanish-send')).toBe(true);
    // And going back to the key and on to the check again unticks it too.
    fireEvent.press(screen.getByTestId('vanish-skip-check'));
    fireEvent.press(screen.getByTestId('vanish-show-again'));
    fireEvent.press(screen.getByTestId('vanish-saved'));
    expect(screen.getByTestId('vanish-skip-check').props.accessibilityState).toEqual({ checked: false });
  });

  it('puts the key on a card with no word check, then sends', async () => {
    renderOn(device);
    await reachCheck();
    expect(disabled('vanish-card')).toBe(false);
    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-card'));
    });
    expect(mockPut).toHaveBeenCalledTimes(1);
    expect(mockCore.checkPhantomKeyWord).not.toHaveBeenCalled();
    expect(mockCore.confirmPhantomKeySaved).toHaveBeenCalledTimes(1);
    expect(mockCore.confirmPhantomKeySavedUnchecked).not.toHaveBeenCalled();
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
  });

  it('goes back to the check when an unchecked key could not go on a card', async () => {
    renderOn(device);
    await reachCheck();
    const asked = checkPositions();
    mockPut.mockRejectedValueOnce(new CardCancelled());
    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-card'));
    });
    fireEvent.press(screen.getByTestId('vanish-without-card'));
    // Not sent: the words were never checked and no card holds the key.
    expect(mockCore.confirmPhantomKeySaved).not.toHaveBeenCalled();
    expect(checkPositions()).toEqual(asked);
    expect(screen.getByTestId('vanish-skip-check').props.accessibilityState).toEqual({ checked: false });
    expect(disabled('vanish-send')).toBe(true);
    typeWords((position) => mockKeyWords[position - 1]);
    fireEvent.press(screen.getByTestId('vanish-send'));
    expect(mockCore.confirmPhantomKeySaved).toHaveBeenCalledTimes(1);
  });
});
