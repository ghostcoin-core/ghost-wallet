import { act, fireEvent, render, screen } from '@testing-library/react-native';
import * as Clipboard from 'expo-clipboard';
import { Share } from 'react-native';

import HomeScreen from '../app/home';
import ReceiveScreen from '../app/receive';
import RecoveryWordsScreen from '../app/recovery-words';
import SettingsScreen from '../app/settings';
import { TEST_WORDS } from '../modules/ghost-core/test-words';

// Account 0 (rescue-key scheme 0x0003) of Ghost's counting-bytes test seed,
// the first vector of client/tests/rescue_accounts.rs in the ghost repository.
const EXPECTED_ADDRESS = '0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd';

const COUNTING_SEED_WORDS =
  'abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware';

// The generated native bindings run only on the phone. This stand-in answers
// like the Rust core: the expected address for the counting-seed words only.
const mockAccountZeroAddress = jest.fn((words: string): string => {
  if (words !== COUNTING_SEED_WORDS) {
    throw new Error('invalid account words');
  }
  return EXPECTED_ADDRESS;
});

jest.mock(
  '../modules/ghost-core/src/index',
  () => ({ accountZeroAddress: (words: string) => mockAccountZeroAddress(words) }),
  { virtual: true },
);

const mockPush = jest.fn();
jest.mock('expo-router', () => ({ useRouter: () => ({ push: mockPush, back: jest.fn() }) }));

jest.mock('expo-clipboard', () => ({ setStringAsync: jest.fn(async () => true) }));

jest.mock('react-native-qrcode-svg', () => {
  const { Text } = jest.requireActual('react-native');
  return function QRCode({ value }: { value: string }) {
    return <Text testID="qr-value">{value}</Text>;
  };
});

jest.mock('../lib/storage', () => ({
  jsonFile: () => ({ read: () => null, write: async () => {} }),
}));

jest.mock('../lib/home/read-account', () => ({
  readAccountZero: () => new Promise(() => {}),
}));

const mockAuthenticate = jest.fn();
jest.mock('../lib/device-auth', () => ({
  ...jest.requireActual('../lib/device-auth'),
  authenticate: (prompt: string) => mockAuthenticate(prompt),
}));

beforeEach(() => {
  mockAccountZeroAddress.mockClear();
  mockPush.mockClear();
  mockAuthenticate.mockReset();
});

describe('Account 0', () => {
  it('uses the words of the counting-bytes test seed', () => {
    expect(TEST_WORDS).toBe(COUNTING_SEED_WORDS);
    expect(TEST_WORDS.split(' ')).toHaveLength(24);
  });

  it('home never puts the words on the screen', () => {
    render(<HomeScreen />);

    expect(mockAccountZeroAddress).toHaveBeenCalledWith(COUNTING_SEED_WORDS);
    expect(screen.queryByText(TEST_WORDS, { exact: false })).toBeNull();
    expect(screen.queryByText('abandon', { exact: false })).toBeNull();
  });
});

describe('ReceiveScreen', () => {
  it('shows the address the native core derives as text and as a QR code', () => {
    render(<ReceiveScreen />);

    expect(screen.getByTestId('receive-address')).toHaveTextContent(EXPECTED_ADDRESS);
    expect(screen.getByTestId('qr-value')).toHaveTextContent(EXPECTED_ADDRESS);
  });

  it('copies and shares the address', async () => {
    const share = jest.spyOn(Share, 'share').mockResolvedValue({ action: Share.sharedAction, activityType: undefined });
    render(<ReceiveScreen />);

    await act(async () => {
      fireEvent.press(screen.getByTestId('copy-address'));
    });
    expect(Clipboard.setStringAsync).toHaveBeenCalledWith(EXPECTED_ADDRESS);
    expect(screen.getByText('Copied')).toBeOnTheScreen();

    await act(async () => {
      fireEvent.press(screen.getByTestId('share-address'));
    });
    expect(share).toHaveBeenCalledWith({ message: EXPECTED_ADDRESS });
  });

  it('says the address is unavailable when the native core fails', () => {
    mockAccountZeroAddress.mockImplementationOnce(() => {
      throw new Error('native core missing');
    });

    render(<ReceiveScreen />);

    expect(screen.getByTestId('receive-address')).toHaveTextContent('Address unavailable');
    expect(screen.queryByTestId('qr-value')).toBeNull();
  });
});

describe('RecoveryWordsScreen', () => {
  it('shows the words only after Face ID', async () => {
    mockAuthenticate.mockResolvedValue({ ok: true });
    render(<RecoveryWordsScreen />);
    expect(screen.queryByText('abandon')).toBeNull();

    await act(async () => {
      fireEvent.press(screen.getByTestId('show-recovery-words'));
    });

    expect(mockAuthenticate).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('recovery-words')).toBeOnTheScreen();
    expect(screen.getAllByText('amount')).toHaveLength(2);
    expect(screen.getByText('unaware')).toBeOnTheScreen();
  });

  it('keeps the words hidden when Face ID fails or is not in the build', async () => {
    mockAuthenticate.mockResolvedValue({ ok: false, reason: 'unavailable' });
    render(<RecoveryWordsScreen />);

    await act(async () => {
      fireEvent.press(screen.getByTestId('show-recovery-words'));
    });

    expect(screen.queryByTestId('recovery-words')).toBeNull();
    expect(screen.queryByText('abandon')).toBeNull();
    expect(screen.getByTestId('recovery-words-message')).toHaveTextContent('Face ID is not available in this build.');
  });
});

describe('SettingsScreen', () => {
  it('lists the account, recovery words, app lock, network, node and version', () => {
    render(<SettingsScreen />);

    expect(screen.getByText('0xe5fb…55fd')).toBeOnTheScreen();
    expect(screen.getByText('Recovery words')).toBeOnTheScreen();
    expect(screen.getByText('App lock')).toBeOnTheScreen();
    // The badge in the top bar and the network row.
    expect(screen.getAllByText('Test network')).toHaveLength(2);
    expect(screen.getByText('http://127.0.0.1:8547')).toBeOnTheScreen();
    expect(screen.getByTestId('settings-version-detail')).toHaveTextContent(/^Version .+, experimental$/);
  });

  it('opens the recovery words screen', () => {
    render(<SettingsScreen />);
    fireEvent.press(screen.getByTestId('settings-recovery-words'));
    expect(mockPush).toHaveBeenCalledWith('/recovery-words');
  });

  it('opens the bench on the seventh tap of the version, not before', () => {
    render(<SettingsScreen />);
    for (let i = 0; i < 6; i++) {
      fireEvent.press(screen.getByTestId('settings-version'));
    }
    expect(mockPush).not.toHaveBeenCalled();
    fireEvent.press(screen.getByTestId('settings-version'));
    expect(mockPush).toHaveBeenCalledWith('/bench');
  });

  it('changes app lock only after Face ID', async () => {
    mockAuthenticate.mockResolvedValueOnce({ ok: false, reason: 'cancelled' }).mockResolvedValueOnce({ ok: true });
    render(<SettingsScreen />);

    await act(async () => {
      fireEvent(screen.getByTestId('app-lock-switch'), 'valueChange', true);
    });
    expect(screen.getByTestId('app-lock-switch').props.value).toBe(false);
    expect(screen.getByTestId('app-lock-message')).toHaveTextContent('Cancelled.');

    await act(async () => {
      fireEvent(screen.getByTestId('app-lock-switch'), 'valueChange', true);
    });
    expect(screen.getByTestId('app-lock-switch').props.value).toBe(true);
  });

  it('saves a node address and refuses one that is not a URL', async () => {
    render(<SettingsScreen />);
    fireEvent.press(screen.getByTestId('settings-node'));

    fireEvent.changeText(screen.getByTestId('node-url-input'), 'not a node');
    await act(async () => {
      fireEvent.press(screen.getByTestId('node-url-save'));
    });
    expect(screen.getByTestId('node-url-error')).toBeOnTheScreen();

    fireEvent.changeText(screen.getByTestId('node-url-input'), ' http://192.168.1.20:8547/ ');
    await act(async () => {
      fireEvent.press(screen.getByTestId('node-url-save'));
    });
    expect(screen.getByText('http://192.168.1.20:8547')).toBeOnTheScreen();
  });
});
