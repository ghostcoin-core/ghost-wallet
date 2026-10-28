import { act, fireEvent, render, screen } from '@testing-library/react-native';

import HomeScreen from '../app/home';
import type { AccountReading } from '../lib/home/cache-refresh';

const ADDRESS = '0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd';
const GHOST = 10n ** 18n;

const mockPush = jest.fn();
jest.mock('expo-router', () => ({ useRouter: () => ({ push: mockPush, back: jest.fn() }) }));

const mockAccountZeroAddress = jest.fn((): string => ADDRESS);
jest.mock(
  '../modules/ghost-core/src/index',
  () => ({ accountZeroAddress: () => mockAccountZeroAddress() }),
  { virtual: true },
);

// Files in memory: the cache is what a test puts in it.
const mockFiles = new Map<string, unknown>();
jest.mock('../lib/storage', () => ({
  jsonFile: (name: string) => ({
    read: () => mockFiles.get(name) ?? null,
    write: async (value: unknown) => {
      mockFiles.set(name, JSON.parse(JSON.stringify(value)));
    },
  }),
}));

// The node, answered by each test.
let mockAnswer: () => Promise<AccountReading>;
jest.mock('../lib/home/read-account', () => ({
  readAccountZero: () => mockAnswer(),
}));

beforeEach(() => {
  mockFiles.clear();
  mockPush.mockClear();
  mockAccountZeroAddress.mockImplementation(() => ADDRESS);
  mockAnswer = () => new Promise(() => {});
});

describe('HomeScreen', () => {
  it('shows the cached balance and its age before the node answers', () => {
    mockFiles.set('home-cache.json', {
      version: 1,
      nodeUrl: 'http://127.0.0.1:8547',
      address: ADDRESS,
      balanceWei: (1284n * GHOST + GHOST / 2n).toString(),
      nonce: 0,
      tipHeight: 90,
      checkedAt: Date.now() - 5 * 60_000,
      activity: [
        {
          id: 'f',
          direction: 'sent',
          counterparty: '0x81d0' + '0'.repeat(32) + 'c7a4',
          amountWei: (10n * GHOST).toString(),
          state: 'failed',
          at: Date.now() - 60_000,
        },
      ],
    });

    render(<HomeScreen />);

    expect(screen.getByTestId('balance-amount')).toHaveTextContent('1,284.50 GHOST');
    expect(screen.getByTestId('balance-status')).toHaveTextContent('Last updated 5 minutes ago');
    expect(screen.getByText('Send to 0x81d0…c7a4')).toBeOnTheScreen();
    expect(screen.getByText('Failed, nothing spent')).toBeOnTheScreen();
  });

  it('shows the node balance once it answers, and caches it', async () => {
    mockAnswer = async () => ({ balanceWei: (3n * GHOST).toString(), nonce: 0, tipHeight: 120 });

    render(<HomeScreen />);
    await act(async () => {});

    expect(screen.getByTestId('balance-amount')).toHaveTextContent('3.00 GHOST');
    expect(screen.getByTestId('balance-status')).toHaveTextContent('Up to date, just now');
    expect(mockFiles.get('home-cache.json')).toMatchObject({ balanceWei: (3n * GHOST).toString(), address: ADDRESS });
    expect(screen.getByText('No activity yet. Payments to and from this account show here.')).toBeOnTheScreen();
  });

  it('says the node is not reachable without hiding the cached balance', async () => {
    mockFiles.set('home-cache.json', {
      version: 1,
      nodeUrl: 'http://127.0.0.1:8547',
      address: ADDRESS,
      balanceWei: GHOST.toString(),
      nonce: 0,
      tipHeight: 90,
      checkedAt: Date.now() - 2 * 60 * 60_000,
      activity: [],
    });
    mockAnswer = async () => {
      throw new Error('offline');
    };

    render(<HomeScreen />);
    await act(async () => {});

    expect(screen.getByTestId('balance-amount')).toHaveTextContent('1.00 GHOST');
    expect(screen.getByTestId('balance-status')).toHaveTextContent('Node not reachable, last updated 2 hours ago');
  });

  it('opens receive and settings', () => {
    render(<HomeScreen />);

    fireEvent.press(screen.getByTestId('open-receive'));
    fireEvent.press(screen.getByLabelText('Settings'));

    expect(mockPush.mock.calls).toEqual([['/receive'], ['/settings']]);
  });

  it('says the account is unavailable when the native core is missing', () => {
    mockAccountZeroAddress.mockImplementation(() => {
      throw new Error('native core missing');
    });

    render(<HomeScreen />);

    expect(screen.getByTestId('balance-status')).toHaveTextContent('The account is not available in this build.');
    expect(screen.queryByTestId('balance-amount')).toBeNull();
  });
});
