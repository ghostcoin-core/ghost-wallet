import { act, fireEvent, renderRouter, screen } from 'expo-router/testing-library';

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
import { readAccountZero } from '../../lib/home/read-account';
import { TEST_WORDS, TEST_WORDS_ACCOUNT_ZERO } from '../../modules/ghost-core/test-words';

// A stand-in for the Rust core. Each set of words has its own address, so a
// screen that showed the public test account instead of the saved one would
// show TEST_WORDS_ACCOUNT_ZERO and fail.
const IMPORTED_WORDS = Array.from({ length: 24 }, (_, index) => `test${index + 1}`);
const NEW_WORDS = Array.from({ length: 24 }, (_, index) => `fake${index + 1}`);
const ADDRESSES: Record<string, string> = {
  [IMPORTED_WORDS.join(' ')]: '0x' + '11'.repeat(20),
  [NEW_WORDS.join(' ')]: '0x' + '22'.repeat(20),
  [TEST_WORDS]: TEST_WORDS_ACCOUNT_ZERO,
};
const LIST = new Set([...IMPORTED_WORDS, ...NEW_WORDS]);
const TIP_HASH = '0x' + 'ab'.repeat(32);

const mockCore = { held: null as string[] | null, saved: null as string | null };

function savedAddress(): string {
  if (mockCore.saved === null) throw new Error('no account');
  return ADDRESSES[mockCore.saved];
}

const mockBindings = {
  accountZeroAddress: jest.fn((words: string) => ADDRESSES[words]),
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
    if (!(words in ADDRESSES) || words === TEST_WORDS) throw new Error('invalid account words');
    mockCore.saved = words;
  }),
  hasAccount: jest.fn(() => mockCore.saved !== null),
  savedAccountZeroAddress: jest.fn(savedAddress),
  savedAccountWords: jest.fn(() => {
    if (mockCore.saved === null) throw new Error('no account');
    return mockCore.saved.split(' ');
  }),
  RestoreLookup: Object.assign(
    jest.fn(() => {
      throw new Error('the wallet must not look up words held in JavaScript');
    }),
    {
      savedAccount: jest.fn(
        (
          lookup: { accountState(address: ArrayBuffer, blockHash: ArrayBuffer): { balance: ArrayBuffer; nonce: bigint } },
          _tipHeight: bigint,
          tipHash: ArrayBuffer,
        ) => {
          const address = savedAddress();
          return {
            deriveAccount: (index: number) => ({ index, address }),
            lookUpAccount: (index: number) => {
              const bytes = Uint8Array.from(address.slice(2).match(/../g) ?? [], (pair) => parseInt(pair, 16));
              const state = lookup.accountState(bytes.buffer as ArrayBuffer, tipHash);
              const balance = new Uint8Array(state.balance).reduce((total, byte) => total * 256n + BigInt(byte), 0n);
              return { index, address, balance: balance.toString(), nonce: state.nonce, used: true, unverified: true };
            },
            uniffiDestroy: () => {},
          };
        },
      ),
    },
  ),
};

jest.mock('../../modules/ghost-core/src/index', () => mockBindings, { virtual: true });
jest.mock('expo-font', () => ({ useFonts: () => [true, null] }));
jest.mock('expo-local-authentication', () => ({ authenticateAsync: async () => ({ success: true }) }));
jest.mock('../../modules/ghost-bench', () => ({ listBenchmarks: () => ['dummy'], runBenchmark: jest.fn() }));
jest.mock('../../lib/storage', () => ({
  jsonFile: () => ({ read: () => null, write: async () => {} }),
}));
jest.mock('expo-clipboard', () => ({ setStringAsync: jest.fn(async () => true) }));
jest.mock('react-native-qrcode-svg', () => {
  const { Text } = jest.requireActual('react-native');
  return function QRCode({ value }: { value: string }) {
    return <Text testID="qr-value">{value}</Text>;
  };
});

// The node: its tip, and 7 wei for the saved account's address only.
const mockNode = {
  getTip: jest.fn(async () => ({ height: 120, hash: TIP_HASH })),
  getAccountState: jest.fn(async (_url: string, address: string) => ({
    balance: address === savedAddress() ? 7n : 0n,
    nonce: 0n,
  })),
};
jest.mock('../../lib/node/rpc', () => ({
  getTip: () => mockNode.getTip(),
  getAccountState: (url: string, address: string) => mockNode.getAccountState(url, address),
}));

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

const METRICS = { frame: { x: 0, y: 0, width: 393, height: 852 }, insets: { top: 59, left: 0, right: 0, bottom: 34 } };

async function openApp() {
  await renderRouter(APP, { initialUrl: '/', initialMetrics: METRICS } as Parameters<typeof renderRouter>[1]);
  await act(async () => {});
}

async function openReceive() {
  fireEvent.press(screen.getByTestId('open-receive'));
  await screen.findByTestId('receive-address');
}

beforeEach(() => {
  mockCore.held = null;
  mockCore.saved = null;
  jest.clearAllMocks();
  mockBindings.savedAccountZeroAddress.mockImplementation(savedAddress);
});

describe('the deposit address after onboarding', () => {
  it('is the imported account, as text and as a QR code, never the public test account', async () => {
    await openApp();
    fireEvent.press(screen.getByTestId('welcome-import'));
    await screen.findByTestId('import-screen');
    fireEvent.changeText(screen.getByTestId('import-word-1'), IMPORTED_WORDS.join(' '));
    fireEvent.press(screen.getByTestId('import-open'));
    await screen.findByTestId('home-screen');

    await openReceive();

    const imported = ADDRESSES[IMPORTED_WORDS.join(' ')];
    expect(screen.getByTestId('receive-address')).toHaveTextContent(imported);
    expect(screen.getByTestId('qr-value')).toHaveTextContent(imported);
    expect(screen.queryByText(TEST_WORDS_ACCOUNT_ZERO)).toBeNull();
    expect(mockBindings.accountZeroAddress).not.toHaveBeenCalled();
  });

  it('is the created account after back up and check', async () => {
    await openApp();
    fireEvent.press(screen.getByTestId('welcome-create'));
    await screen.findByTestId('backup-screen');
    fireEvent.press(screen.getByTestId('backup-continue'));
    await screen.findByTestId('check-screen');
    for (const box of screen.getAllByTestId(/^check-word-\d+$/)) {
      const position = Number(String(box.props.testID).replace('check-word-', ''));
      fireEvent.changeText(box, NEW_WORDS[position - 1]);
    }
    fireEvent.press(screen.getByTestId('check-confirm'));
    await screen.findByTestId('home-screen');

    await openReceive();

    const created = ADDRESSES[NEW_WORDS.join(' ')];
    expect(screen.getByTestId('receive-address')).toHaveTextContent(created);
    expect(screen.getByTestId('qr-value')).toHaveTextContent(created);
    expect(mockBindings.accountZeroAddress).not.toHaveBeenCalled();
  });

  it('is not shown at all when the saved account cannot be read', async () => {
    mockCore.saved = IMPORTED_WORDS.join(' ');
    mockBindings.savedAccountZeroAddress.mockImplementation(() => {
      throw new Error('keychain refused');
    });
    await openApp();
    await screen.findByTestId('home-screen');

    expect(screen.getByTestId('balance-status')).toHaveTextContent('The account is not available in this build.');
    expect(screen.getByTestId('open-receive')).toBeDisabled();
    expect(screen.queryByText(TEST_WORDS_ACCOUNT_ZERO)).toBeNull();
    expect(mockBindings.accountZeroAddress).not.toHaveBeenCalled();
  });
});

describe("Home's balance", () => {
  it('is looked up for the saved account in native code, not from words in JavaScript', async () => {
    mockCore.saved = IMPORTED_WORDS.join(' ');
    const imported = ADDRESSES[IMPORTED_WORDS.join(' ')];

    const reading = await readAccountZero('http://node', imported);

    expect(reading).toEqual({ balanceWei: '7', nonce: 0, tipHeight: 120 });
    expect(mockBindings.RestoreLookup.savedAccount).toHaveBeenCalledTimes(1);
    expect(mockBindings.RestoreLookup).not.toHaveBeenCalled();
    expect(mockNode.getAccountState).toHaveBeenCalledWith('http://node', imported);
  });

  it('is refused when the core looks up another account than the one shown', async () => {
    mockCore.saved = IMPORTED_WORDS.join(' ');

    await expect(readAccountZero('http://node', TEST_WORDS_ACCOUNT_ZERO)).rejects.toThrow('another account');
  });
});
