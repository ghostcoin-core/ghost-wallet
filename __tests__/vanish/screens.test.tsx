import { act, fireEvent, render, screen, within } from '@testing-library/react-native';
import type { ComponentType } from 'react';
import { StyleSheet } from 'react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import SummonScreen from '../../app/summon';
import VanishScreen from '../../app/vanish';
import { PHANTOM_KEY_LABEL } from '../../components/vanish-ui';
import { NOT_FOUND_MESSAGE } from '../../lib/vanish/status-mapping';
import { RECOVERY_WORDS_IN_KEY_FIELD } from '../../lib/vanish/word-validation';

// Plain list words stand in for a new Phantom Key and for recovery words.
const mockKeyWords = Array.from({ length: 24 }, (_, i) => ['abandon', 'ability', 'able', 'about'][i % 4]);
const mockRecovery = Array.from({ length: 24 }, (_, i) => ['zoo', 'zone', 'zero', 'youth'][i % 4]).join(' ');

const mockCore = {
  checkKeyWords: jest.fn((text: string) => {
    if (text === mockKeyWords.join(' ')) return { verdict: 'phantom-key', position: 0 };
    if (text === mockRecovery) return { verdict: 'account-words', position: 0 };
    return { verdict: 'word-check', position: 0 };
  }),
  checkPhantomKeyWord: jest.fn((position: number, word: string) => mockKeyWords[position - 1] === word),
  confirmPhantomKeySaved: jest.fn(),
  forgetPhantomKey: jest.fn(),
  savedAccountZeroAddress: () => '0x00000000000000000000000000000000000000aa',
  hasAccount: () => true,
};
jest.mock('../../modules/ghost-core/src/index', () => mockCore, { virtual: true });

const mockSequence = {
  step: jest.fn(() => 0),
  record: () => ({ id: 'vanish-1' }),
  markBackedUp: jest.fn(),
};
const mockStore = { list: () => [], remove: jest.fn() };
const SENT_VIEW = { status: 'sent', step: 3, needsKey: false, error: null };
let mockView: Record<string, unknown> = SENT_VIEW;
jest.mock('../../lib/vanish/use-payment', () => ({
  paymentKit: () => ({ core: mockCore, store: mockStore, node: {}, nodeUrl: 'http://127.0.0.1:8547' }),
  usePayment: (_kit: unknown, sequence: unknown) => (sequence ? mockView : null),
}));

const mockCancel = jest.fn(async (_kit: unknown, _sequence: unknown) => {});
jest.mock('../../lib/send/send-payment', () => ({
  asSendKit: (kit: unknown) => kit,
  cancelStuck: (kit: unknown, sequence: unknown) => mockCancel(kit, sequence),
}));

const mockStartVanish = jest.fn(async () => ({ sequence: mockSequence, words: [...mockKeyWords] }));
const mockLookUp = jest.fn(async () => ({ status: 'not-found', amountWei: '0', feeWei: '1000', tree: {}, tip: 9 }));
jest.mock('../../lib/vanish/actions', () => ({
  minimumVanish: async () => 10n ** 17n,
  vanishFee: async () => 1000n,
  startVanish: (...args: unknown[]) => mockStartVanish(...(args as [])),
  lookUpKey: (...args: unknown[]) => mockLookUp(...(args as [])),
  signVanishAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
  proveRevealAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
  startReveal: jest.fn(),
}));

jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));
jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: jest.fn() }) }));

const mockWindow = { width: 393, height: 852, scale: 3, fontScale: 1 };
jest.mock('react-native/Libraries/Utilities/useWindowDimensions', () => ({
  __esModule: true,
  default: () => mockWindow,
}));

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
    <SafeAreaProvider
      initialMetrics={{ frame: { x: 0, y: 0, width, height }, insets: { top: 47, left: 0, right: 0, bottom: 34 } }}
    >
      <Screen />
    </SafeAreaProvider>,
  );
}

function sideBySide(testID: string): boolean {
  const content = screen.getByTestId(testID);
  return StyleSheet.flatten(content.props.contentContainerStyle).flexDirection === 'row';
}

beforeEach(() => {
  jest.clearAllMocks();
  mockView = SENT_VIEW;
});

/** Makes a key, checks its three words and sends the Vanish: the screen shows its progress. */
async function vanishSent() {
  fireEvent.changeText(screen.getByTestId('vanish-amount'), '1.5');
  await act(async () => {
    fireEvent.press(screen.getByTestId('vanish-make-key'));
  });
  fireEvent.press(screen.getByTestId('vanish-saved'));
  for (const field of screen.getAllByTestId(/^vanish-check-\d+$/)) {
    const position = Number(field.props.testID.replace('vanish-check-', ''));
    fireEvent.changeText(field, mockKeyWords[position - 1]);
  }
  fireEvent.press(screen.getByTestId('vanish-send'));
}

describe('a Vanish the node took but has not mined in 10 blocks', () => {
  it('shows "Not mined yet", never Sent, says the Phantom Key holds nothing, and cancels only on a tap', async () => {
    mockView = { status: 'stuck', step: 3, needsKey: false, error: null, stuck: true, cancellable: true };
    renderOn('iPhone', VanishScreen);
    await vanishSent();

    expect(screen.getByTestId('progress-stuck')).toHaveTextContent('Not mined yet');
    expect(screen.queryByTestId('progress-sent')).toBeNull();
    expect(screen.getByTestId('payment-status')).toHaveTextContent(/Not mined yet: 10 blocks went by/);
    expect(screen.getByTestId('payment-status')).toHaveTextContent(/The Phantom Key holds nothing until it is/);
    expect(mockCancel).not.toHaveBeenCalled();

    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-not-mined-cancel'));
    });
    expect(mockCancel).toHaveBeenCalledTimes(1);
    expect(mockCancel.mock.calls[0][1]).toBe(mockSequence);
  });

  it('says why a cancel did not go out', async () => {
    mockView = { status: 'stuck', step: 3, needsKey: false, error: null, stuck: true, cancellable: true };
    mockCancel.mockRejectedValueOnce(
      Object.assign(new Error('the node refused a call: replacement transaction underpriced'), { notSent: true, refused: true }),
    );
    renderOn('iPhone', VanishScreen);
    await vanishSent();
    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-not-mined-cancel'));
    });
    expect(screen.getByTestId('vanish-cancel-error')).toHaveTextContent(
      /The Vanish could not be cancelled\. Not sent: the test node checked it first and would not take it\./,
    );
  });

  it('offers no Cancel while it is only Sent', async () => {
    renderOn('iPhone', VanishScreen);
    await vanishSent();
    expect(screen.getByTestId('progress-sent')).toBeOnTheScreen();
    expect(screen.queryByTestId('vanish-not-mined-cancel')).toBeNull();
  });
});

describe.each(Object.keys(DEVICES) as Device[])('on the %s', (device) => {
  const open = device === 'iPhone Duo open';

  it('vanishes: the key shows once, labelled, then three words are checked before anything is signed', async () => {
    renderOn(device, VanishScreen);
    expect(sideBySide('vanish-screen-content')).toBe(open);

    fireEvent.changeText(screen.getByTestId('vanish-amount'), '1.5');
    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-make-key'));
    });
    expect(mockStartVanish).toHaveBeenCalledWith(expect.anything(), '0x00000000000000000000000000000000000000aa', 1_500_000_000_000_000_000n);

    const key = screen.getByTestId('phantom-key');
    expect(within(key).getByTestId('phantom-key-label')).toHaveTextContent(PHANTOM_KEY_LABEL);
    expect(within(key).getAllByTestId(/^phantom-key-word-\d+$/)).toHaveLength(24);
    // Nothing offers to copy or save the key.
    expect(screen.queryByText(/copy|download|photo/i)).toBeNull();

    fireEvent.press(screen.getByTestId('vanish-saved'));
    expect(screen.queryByTestId('phantom-key')).toBeNull();
    const fields = screen.getAllByTestId(/^vanish-check-\d+$/);
    expect(fields).toHaveLength(3);

    // A wrong word sends nothing.
    for (const field of fields) fireEvent.changeText(field, 'zoo');
    fireEvent.press(screen.getByTestId('vanish-send'));
    expect(screen.getByTestId('vanish-error')).toHaveTextContent(/does not match your Phantom Key/);
    expect(mockCore.confirmPhantomKeySaved).not.toHaveBeenCalled();
    expect(mockSequence.markBackedUp).not.toHaveBeenCalled();

    for (const field of fields) {
      const position = Number(field.props.testID.replace('vanish-check-', ''));
      fireEvent.changeText(field, mockKeyWords[position - 1]);
    }
    fireEvent.press(screen.getByTestId('vanish-send'));
    expect(mockCore.confirmPhantomKeySaved).toHaveBeenCalledTimes(1);
    expect(mockSequence.markBackedUp).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
    expect(screen.getByTestId('payment-status')).toHaveTextContent('Safe to close the app. It never pays twice.');
    expect(screen.queryByTestId('phantom-key')).toBeNull();
  });

  it('summons: refuses recovery words, and shows a key it cannot find as not found, never zero', async () => {
    renderOn(device, SummonScreen);
    expect(sideBySide('summon-screen-content')).toBe(open);

    fireEvent.changeText(screen.getByTestId('summon-key'), mockRecovery);
    expect(screen.getByTestId('summon-key-error')).toHaveTextContent(RECOVERY_WORDS_IN_KEY_FIELD);
    expect(screen.getByTestId('summon-find')).toBeDisabled();

    fireEvent.changeText(screen.getByTestId('summon-key'), mockKeyWords.join(' ').toUpperCase());
    expect(screen.queryByTestId('summon-key-error')).toBeNull();
    await act(async () => {
      fireEvent.press(screen.getByTestId('summon-find'));
    });
    expect(mockLookUp).toHaveBeenCalledWith(expect.anything(), mockKeyWords.join(' '));
    expect(screen.getByTestId('summon-lookup-message')).toHaveTextContent(NOT_FOUND_MESSAGE, { exact: false });
    expect(screen.queryByTestId('summon-amount')).toBeNull();
  });
});
