import { act, fireEvent, render, screen } from '@testing-library/react-native';
import type { ComponentType } from 'react';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import SummonScreen from '../../app/summon';
import VanishScreen from '../../app/vanish';
import { encodeDetails } from '../../lib/vanish/payments';
import { reopenPayment, resetPending } from '../../lib/vanish/pending';
import { CardCancelled } from '../../modules/ghost-nfc';

const mockKeyWords = Array.from({ length: 24 }, (_, i) => ['abandon', 'ability', 'able', 'about'][i % 4]);

// The saved payments, as the store lists them; steps are the core's Step (0 Prepared, 1 BackedUp, 3 Sent).
type MockSequence = { id: string; stepNow: number; step: () => number; record: () => object; markBackedUp: jest.Mock };
let mockSaved: Record<string, MockSequence> = {};
function mockSequence(id: string, stepNow: number, details: object): MockSequence {
  const sequence: MockSequence = {
    id,
    stepNow,
    step: () => sequence.stepNow,
    record: () => ({ id, intent: { details: encodeDetails(details as never) } }),
    markBackedUp: jest.fn(() => {
      sequence.stepNow = 1;
    }),
  };
  return sequence;
}
const VANISH = { kind: 'vanish', commitData: '0x00', amountWei: '1500000000000000000', nonce: '0', at: 2 };

const mockCore = {
  checkKeyWords: jest.fn(() => ({ verdict: 'word-check', position: 0 })),
  checkPhantomKeyWord: jest.fn((position: number, word: string) => mockKeyWords[position - 1] === word),
  confirmPhantomKeySaved: jest.fn(),
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
  usePayment: (_kit: unknown, sequence: { step(): number } | null) =>
    sequence ? { status: 'sent', step: sequence.step(), needsKey: false, error: null } : null,
}));

const mockStartVanish = jest.fn(async () => {
  const sequence = mockSequence('vanish-new', 0, VANISH);
  mockSaved[sequence.id] = sequence;
  return { sequence, words: [...mockKeyWords] };
});
jest.mock('../../lib/vanish/actions', () => ({
  CARD_KEY: { card: true },
  minimumVanish: () => new Promise(() => {}),
  startVanish: () => mockStartVanish(),
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

function renderOn(device: Device, Screen: ComponentType = VanishScreen) {
  const { width, height } = DEVICES[device];
  mockWindow.width = width;
  mockWindow.height = height;
  return render(
    <SafeAreaProvider initialMetrics={{ frame: { x: 0, y: 0, width, height }, insets: { top: 47, left: 0, right: 0, bottom: 34 } }}>
      <Screen />
    </SafeAreaProvider>,
  );
}

async function makeKey() {
  // Opening the screen with no key held forgot any stale one; count from here.
  mockCore.forgetPhantomKey.mockClear();
  fireEvent.changeText(screen.getByTestId('vanish-amount'), '1.5');
  await act(async () => {
    fireEvent.press(screen.getByTestId('vanish-make-key'));
  });
}

function checkPositions(): number[] {
  return screen.getAllByTestId(/^vanish-check-\d+$/).map((field) => Number(field.props.testID.replace('vanish-check-', '')));
}

function typeCheckWords() {
  for (const position of checkPositions()) {
    fireEvent.changeText(screen.getByTestId(`vanish-check-${position}`), mockKeyWords[position - 1]);
  }
}

/** Leaves with Back, as the person would, and closes the screen. */
function leave(view: ReturnType<typeof render>) {
  fireEvent.press(screen.getByTestId('back'));
  expect(mockBack).toHaveBeenCalled();
  view.unmount();
}

beforeEach(() => {
  jest.clearAllMocks();
  resetPending();
  mockSaved = {};
  mockPut.mockResolvedValue({ uidHex: '04518DFAA96180' });
});

describe.each(Object.keys(DEVICES) as Device[])('on the %s', (device) => {
  it('returns to the shown key when the Vanish is left before the words are written down', async () => {
    const first = renderOn(device);
    await makeKey();
    expect(screen.getAllByTestId(/^phantom-key-word-\d+$/)).toHaveLength(24);
    leave(first);
    // The core keeps the key and the Vanish stays saved.
    expect(mockCore.forgetPhantomKey).not.toHaveBeenCalled();
    expect(mockStore.remove).not.toHaveBeenCalled();

    renderOn(device);
    expect(screen.queryByTestId('vanish-amount')).toBeNull();
    const words = screen.getAllByTestId(/^phantom-key-word-\d+$/).map((word) => word.props.children);
    expect(words).toEqual(mockKeyWords);
    expect(mockCore.forgetPhantomKey).not.toHaveBeenCalled();
  });

  it('returns to the same three-word check, then sends with the saved amount', async () => {
    const first = renderOn(device);
    await makeKey();
    fireEvent.press(screen.getByTestId('vanish-saved'));
    const asked = checkPositions();
    leave(first);

    renderOn(device);
    expect(checkPositions()).toEqual(asked);
    expect(screen.getByTestId('vanish-send')).toHaveTextContent('Vanish 1.50 GHOST');
    // The key can still be shown again from here.
    fireEvent.press(screen.getByTestId('vanish-show-again'));
    expect(screen.getAllByTestId(/^phantom-key-word-\d+$/)).toHaveLength(24);
    fireEvent.press(screen.getByTestId('vanish-saved'));
    typeCheckWords();
    fireEvent.press(screen.getByTestId('vanish-send'));
    expect(mockCore.confirmPhantomKeySaved).toHaveBeenCalledTimes(1);
    expect(mockSaved['vanish-new'].markBackedUp).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
    expect(screen.getByTestId('vanish-leave-note')).toBeOnTheScreen();
  });

  it('returns to the card step when left before the card was written', async () => {
    const first = renderOn(device);
    await makeKey();
    fireEvent.press(screen.getByTestId('vanish-saved'));
    typeCheckWords();
    mockPut.mockRejectedValueOnce(new CardCancelled());
    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-card'));
    });
    expect(screen.getByTestId('vanish-card-retry')).toBeOnTheScreen();
    leave(first);
    expect(mockCore.confirmPhantomKeySaved).not.toHaveBeenCalled();

    renderOn(device);
    expect(screen.getByTestId('vanish-card-hold')).toHaveTextContent('The card was not written. Nothing has been sent yet.');
    expect(screen.queryByTestId('phantom-key')).toBeNull();
    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-card-retry'));
    });
    expect(mockPut).toHaveBeenCalledTimes(2);
    // The key is dropped only after the card holds it.
    expect(mockCore.confirmPhantomKeySaved).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
  });

  it('returns to the progress when the Vanish is left after it was sent', async () => {
    const first = renderOn(device);
    await makeKey();
    fireEvent.press(screen.getByTestId('vanish-saved'));
    typeCheckWords();
    fireEvent.press(screen.getByTestId('vanish-send'));
    leave(first);

    renderOn(device);
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
    expect(screen.queryByTestId('phantom-key')).toBeNull();
    expect(screen.queryByTestId('vanish-done')).toBeNull();
  });

  it('drops a Vanish whose key was never written down once the app was closed', async () => {
    mockSaved['vanish-old'] = mockSequence('vanish-old', 0, VANISH);
    renderOn(device);
    expect(mockCore.forgetPhantomKey).toHaveBeenCalled();
    expect(mockStore.remove).toHaveBeenCalledWith('vanish-old');
    expect(screen.getByTestId('vanish-amount')).toBeOnTheScreen();
  });

  it('cancels a Vanish only when asked, with its key', async () => {
    const first = renderOn(device);
    await makeKey();
    fireEvent.press(screen.getByTestId('vanish-cancel'));
    expect(mockCore.forgetPhantomKey).toHaveBeenCalledTimes(1);
    expect(mockStore.remove).toHaveBeenCalledWith('vanish-new');
    first.unmount();
    renderOn(device);
    expect(screen.getByTestId('vanish-amount')).toBeOnTheScreen();
  });

  it('opens the payment tapped on Home, not only the newest', () => {
    mockSaved['vanish-1'] = mockSequence('vanish-1', 3, { ...VANISH, amountWei: '700000000000000000' });
    // The newest Vanish is settled: opened plainly, the screen would start a new one.
    mockSaved['vanish-2'] = mockSequence('vanish-2', 5, VANISH);
    reopenPayment('vanish-1');
    renderOn(device);
    expect(screen.queryByTestId('vanish-amount')).toBeNull();
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
    expect(screen.getByTestId('vanish-leave-note')).toBeOnTheScreen();
  });

  it('reopens a Summon left mid-way on its progress', () => {
    mockSaved['summon-1'] = mockSequence('summon-1', 3, { kind: 'summon', amountWei: '1', feeWei: '1', marker: '0x01', at: 1 });
    reopenPayment('summon-1');
    renderOn(device, SummonScreen);
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
    expect(screen.queryByTestId('summon-key')).toBeNull();
    expect(screen.getByTestId('summon-leave')).toBeOnTheScreen();
  });
});
