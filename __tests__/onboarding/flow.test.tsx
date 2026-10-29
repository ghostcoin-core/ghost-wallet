import { act, fireEvent, renderRouter, screen, waitFor } from 'expo-router/testing-library';

import BackupScreen from '../../app/backup';
import BenchScreen from '../../app/bench';
import CheckScreen from '../../app/check';
import HomeScreen from '../../app/home';
import ImportScreen from '../../app/import';
import WelcomeScreen from '../../app/index';
import LockScreen from '../../app/lock';
import ReceiveScreen from '../../app/receive';
import RecoveryWordsScreen from '../../app/recovery-words';
import SettingsScreen from '../../app/settings';
import RootLayout from '../../app/_layout';
import { TEST_WORDS } from '../../modules/ghost-core/test-words';

// A stand-in for the Rust core, which runs only in a native build. It holds new
// words until saved, keeps "the Keychain" in a variable, and knows only these
// plain test words and Ghost's public test words.
const NEW_WORDS = Array.from({ length: 24 }, (_, index) => `test${index + 1}`);
const LIST = new Set([...NEW_WORDS, ...TEST_WORDS.split(' ')]);
const SAVED_ADDRESS = '0x00000000000000000000000000000000000000aa';

const mockCore = {
  held: null as string[] | null,
  saved: null as string | null,
};

const mockBindings = {
  accountZeroAddress: jest.fn(() => SAVED_ADDRESS),
  newAccountWords: jest.fn(() => {
    mockCore.held = [...NEW_WORDS];
    return [...NEW_WORDS];
  }),
  checkNewAccountWord: jest.fn((position: number, word: string) => mockCore.held?.[position - 1] === word),
  saveNewAccount: jest.fn(() => {
    if (!mockCore.held) throw new Error('nothing held');
    mockCore.saved = mockCore.held.join(' ');
    mockCore.held = null;
  }),
  discardNewAccount: jest.fn(() => {
    mockCore.held = null;
  }),
  isAccountWord: jest.fn((word: string) => LIST.has(word)),
  importAccountWords: jest.fn((words: string) => {
    if (words !== TEST_WORDS) throw new Error('invalid account words');
    mockCore.saved = words;
  }),
  hasAccount: jest.fn(() => mockCore.saved !== null),
  savedAccountZeroAddress: jest.fn(() => {
    if (mockCore.saved === null) throw new Error('no account');
    return SAVED_ADDRESS;
  }),
};

jest.mock('../../modules/ghost-core/src/index', () => mockBindings, { virtual: true });

jest.mock('expo-font', () => ({ useFonts: () => [true, null] }));

const mockAuthenticate = jest.fn();
jest.mock('expo-local-authentication', () => ({
  authenticateAsync: (options: unknown) => mockAuthenticate(options),
}));

jest.mock('../../modules/ghost-bench', () => ({
  listBenchmarks: () => ['dummy'],
  runBenchmark: jest.fn(),
}));

// Home's cache and settings files, and the node: nothing is stored, the node
// never answers.
jest.mock('../../lib/storage', () => ({
  jsonFile: () => ({ read: () => null, write: async () => {} }),
}));
jest.mock('../../lib/home/read-account', () => ({
  readAccountZero: () => new Promise(() => {}),
}));
jest.mock('../../lib/node/test-network', () => ({ useTestNetwork: () => false }));
jest.mock('expo-clipboard', () => ({ setStringAsync: jest.fn(async () => true) }));
jest.mock('react-native-qrcode-svg', () => {
  const { Text } = jest.requireActual('react-native');
  return function QRCode({ value }: { value: string }) {
    return <Text testID="qr-value">{value}</Text>;
  };
});

const APP = {
  _layout: RootLayout,
  index: WelcomeScreen,
  backup: BackupScreen,
  check: CheckScreen,
  import: ImportScreen,
  lock: LockScreen,
  home: HomeScreen,
  receive: ReceiveScreen,
  settings: SettingsScreen,
  'recovery-words': RecoveryWordsScreen,
  bench: BenchScreen,
};

const METRICS = {
  frame: { x: 0, y: 0, width: 393, height: 852 },
  insets: { top: 59, left: 0, right: 0, bottom: 34 },
};

async function openApp(initialUrl = '/') {
  const app = await renderRouter(APP, { initialUrl, initialMetrics: METRICS } as Parameters<typeof renderRouter>[1]);
  await act(async () => {});
  return app;
}

/** The positions the check screen asks for, read from its boxes. */
function askedPositions(): number[] {
  return screen
    .getAllByTestId(/^check-word-\d+$/)
    .map((box) => Number(String(box.props.testID).replace('check-word-', '')));
}

beforeEach(() => {
  mockCore.held = null;
  mockCore.saved = null;
  Object.values(mockBindings).forEach((mock) => mock.mockClear());
  mockAuthenticate.mockReset();
  mockAuthenticate.mockResolvedValue({ success: true });
});

describe('opening the app', () => {
  it('opens on Welcome when no account is saved', async () => {
    const app = await openApp();

    expect(screen.getByTestId('welcome-screen')).toBeOnTheScreen();
    expect(app.getPathname()).toBe('/');
    expect(screen.getByRole('header', { name: 'Your coins, one among many.' })).toBeOnTheScreen();
  });

  it('opens on the lock when an account is saved, and asks for Face ID', async () => {
    mockCore.saved = TEST_WORDS;
    mockAuthenticate.mockResolvedValue({ success: false, error: 'user_cancel' });

    const app = await openApp();

    expect(screen.getByTestId('lock-screen')).toBeOnTheScreen();
    expect(app.getPathname()).toBe('/lock');
    await waitFor(() => expect(mockAuthenticate).toHaveBeenCalledTimes(1));
    expect(screen.queryByTestId('home-screen')).toBeNull();
  });

  it('does not reach Home by link while locked', async () => {
    mockCore.saved = TEST_WORDS;
    mockAuthenticate.mockResolvedValue({ success: false, error: 'user_cancel' });

    await openApp('/home');

    expect(screen.getByTestId('lock-screen')).toBeOnTheScreen();
    expect(screen.queryByTestId('home-screen')).toBeNull();
  });

  it('does not reach Home by link without an account', async () => {
    await openApp('/home');

    expect(screen.getByTestId('welcome-screen')).toBeOnTheScreen();
    expect(mockBindings.savedAccountZeroAddress).not.toHaveBeenCalled();
  });

  it('opens Home after the unlock passes', async () => {
    mockCore.saved = TEST_WORDS;
    mockAuthenticate.mockResolvedValueOnce({ success: false, error: 'user_cancel' });
    await openApp();
    await waitFor(() => expect(mockAuthenticate).toHaveBeenCalledTimes(1));

    await act(async () => {
      fireEvent.press(screen.getByTestId('lock-passcode'));
    });

    expect(await screen.findByTestId('home-screen')).toBeOnTheScreen();
    expect(mockAuthenticate).toHaveBeenLastCalledWith(
      expect.objectContaining({ promptMessage: 'Unlock Ghost Wallet', disableDeviceFallback: false }),
    );
    expect(screen.getByTestId('balance')).toBeOnTheScreen();
  });

  it('does not reach Settings by link without an account', async () => {
    await openApp('/settings');

    expect(screen.getByTestId('welcome-screen')).toBeOnTheScreen();
    expect(screen.queryByTestId('settings-version')).toBeNull();
  });

  it('keeps the bench reachable by link for the device scripts', async () => {
    await openApp('/bench');

    expect(screen.getByTestId('bench-screen')).toBeOnTheScreen();
  });
});

describe('create, back up, check, home', () => {
  async function toCheck() {
    await openApp();
    fireEvent.press(screen.getByTestId('welcome-create'));
    expect(await screen.findByTestId('backup-screen')).toBeOnTheScreen();
    fireEvent.press(screen.getByTestId('backup-continue'));
    expect(await screen.findByTestId('check-screen')).toBeOnTheScreen();
  }

  it('shows the 24 new words in order on the backup screen', async () => {
    await openApp();
    fireEvent.press(screen.getByTestId('welcome-create'));

    await screen.findByTestId('backup-screen');
    expect(mockBindings.newAccountWords).toHaveBeenCalledTimes(1);
    NEW_WORDS.forEach((word, index) => {
      expect(screen.getByTestId(`backup-word-${index + 1}`)).toHaveTextContent(word);
    });
  });

  it('opens Home once the three asked words match, and saves the account', async () => {
    await toCheck();
    const positions = askedPositions();
    expect(positions).toHaveLength(3);
    expect(screen.getByTestId('check-confirm')).toBeDisabled();

    positions.forEach((position) => {
      fireEvent.changeText(screen.getByTestId(`check-word-${position}`), ` ${NEW_WORDS[position - 1].toUpperCase()}`);
    });
    fireEvent.press(screen.getByTestId('check-confirm'));

    expect(await screen.findByTestId('home-screen')).toBeOnTheScreen();
    expect(mockBindings.saveNewAccount).toHaveBeenCalledTimes(1);
    expect(mockCore.saved).toBe(NEW_WORDS.join(' '));
    // Back from Home does not return to the onboarding screens.
    expect(screen.queryByTestId('check-screen')).toBeNull();
    expect(screen.queryByTestId('backup-screen')).toBeNull();
  });

  it('stays on the check and saves nothing when a word is wrong', async () => {
    await toCheck();
    const [first, second, third] = askedPositions();

    fireEvent.changeText(screen.getByTestId(`check-word-${first}`), NEW_WORDS[first - 1]);
    fireEvent.changeText(screen.getByTestId(`check-word-${second}`), 'wrong');
    fireEvent.changeText(screen.getByTestId(`check-word-${third}`), NEW_WORDS[third - 1]);
    fireEvent.press(screen.getByTestId('check-confirm'));

    expect(screen.getByTestId('check-error')).toHaveTextContent(
      `Word ${second} does not match your backup. Look at your paper again.`,
    );
    expect(screen.queryByTestId('home-screen')).toBeNull();
    expect(mockBindings.saveNewAccount).not.toHaveBeenCalled();
    expect(mockCore.saved).toBeNull();
  });

  it('forgets the new words when the person goes back to Welcome', async () => {
    await openApp();
    fireEvent.press(screen.getByTestId('welcome-create'));
    await screen.findByTestId('backup-screen');
    expect(mockCore.held).not.toBeNull();

    fireEvent.press(screen.getByTestId('back-button'));

    expect(await screen.findByTestId('welcome-screen')).toBeOnTheScreen();
    await waitFor(() => expect(mockCore.held).toBeNull());
  });

  it('cannot continue when the core cannot create words', async () => {
    mockBindings.newAccountWords.mockImplementationOnce(() => {
      throw new Error('native core missing');
    });
    await openApp();
    fireEvent.press(screen.getByTestId('welcome-create'));

    await screen.findByText('Your words could not be created on this phone.');
    expect(screen.getByTestId('backup-continue')).toBeDisabled();
  });
});

describe('import, home', () => {
  async function toImport() {
    await openApp();
    fireEvent.press(screen.getByTestId('welcome-import'));
    expect(await screen.findByTestId('import-screen')).toBeOnTheScreen();
  }

  it('opens Home after the 24 words are pasted into the first box', async () => {
    await toImport();
    expect(screen.getByTestId('import-open')).toBeDisabled();

    fireEvent.changeText(screen.getByTestId('import-word-1'), TEST_WORDS);
    expect(screen.getByTestId('import-word-24').props.value).toBe('unaware');
    fireEvent.press(screen.getByTestId('import-open'));

    expect(await screen.findByTestId('home-screen')).toBeOnTheScreen();
    expect(mockBindings.importAccountWords).toHaveBeenCalledWith(TEST_WORDS);
    expect(mockCore.saved).toBe(TEST_WORDS);
  });

  it('marks a word that is not in the list and keeps the button off', async () => {
    await toImport();
    const words = TEST_WORDS.split(' ');
    words[6] = 'cagee';

    fireEvent.changeText(screen.getByTestId('import-word-1'), words.join(' '));

    expect(screen.getByTestId('import-error')).toHaveTextContent(
      'Word 7 is not one of the backup words. Check its spelling.',
    );
    expect(screen.getByTestId('import-open')).toBeDisabled();
  });

  it('stays on import when the core turns the 24 words down', async () => {
    await toImport();
    const words = TEST_WORDS.split(' ');
    [words[0], words[1]] = [words[1], words[0]];

    fireEvent.changeText(screen.getByTestId('import-word-1'), words.join(' '));
    fireEvent.press(screen.getByTestId('import-open'));

    expect(screen.getByTestId('import-error')).toHaveTextContent(
      'These 24 words are not a Ghost account. Check their order and spelling.',
    );
    expect(screen.queryByTestId('home-screen')).toBeNull();
    expect(mockCore.saved).toBeNull();
  });
});

describe('Home', () => {
  it('opens Settings, and the bench on seven taps of the version there', async () => {
    mockCore.saved = TEST_WORDS;
    await openApp();
    await screen.findByTestId('home-screen');

    fireEvent.press(screen.getByTestId('open-settings'));
    await screen.findByTestId('settings-version');
    await act(async () => {
      for (let tap = 0; tap < 7; tap++) {
        fireEvent.press(screen.getByTestId('settings-version'));
      }
    });

    expect(await screen.findByTestId('bench-screen')).toBeOnTheScreen();
  });
});
