import { act, fireEvent, render, screen } from '@testing-library/react-native';
import type { ComponentType } from 'react';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import CheckWordsScreen from '../../app/check-words';
import SettingsScreen from '../../app/settings';
import { backupStatusStore, createBackupStatusStore, parseBackupStatus } from '../../lib/onboarding/backup-status';

// Plain test words stand in for the saved account.
const mockSavedWords = Array.from({ length: 24 }, (_, index) => `test${index + 1}`);

const mockCore = {
  savedAccountZeroAddress: () => '0x00000000000000000000000000000000000000aa',
  hasAccount: () => true,
  checkSavedAccountWords: jest.fn((positions: number[], words: string[]) =>
    positions.every((position, index) => mockSavedWords[position - 1] === words[index]),
  ),
};
jest.mock('../../modules/ghost-core/src/index', () => mockCore, { virtual: true });

const mockFiles: Record<string, unknown> = {};
jest.mock('../../lib/storage', () => ({
  jsonFile: (name: string) => ({
    read: () => mockFiles[name] ?? null,
    write: async (value: unknown) => {
      mockFiles[name] = value;
    },
  }),
}));

const mockPush = jest.fn();
const mockBack = jest.fn();
jest.mock('expo-router', () => ({ useRouter: () => ({ push: mockPush, back: mockBack }) }));

const mockAuthenticate = jest.fn();
jest.mock('../../lib/device-auth', () => ({
  ...jest.requireActual('../../lib/device-auth'),
  authenticate: (prompt: string) => mockAuthenticate(prompt),
}));

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

function askedPositions(): number[] {
  return screen
    .getAllByTestId(/^check-words-\d+$/)
    .map((field) => Number(field.props.testID.replace('check-words-', '')));
}

function typeWords(word: (position: number) => string) {
  for (const position of askedPositions()) {
    fireEvent.changeText(screen.getByTestId(`check-words-${position}`), word(position));
  }
}

async function pressCheck() {
  await act(async () => {
    fireEvent.press(screen.getByTestId('check-words-confirm'));
  });
}

beforeEach(async () => {
  jest.clearAllMocks();
  mockAuthenticate.mockResolvedValue({ ok: true });
  await backupStatusStore.setChecked(true);
});

describe('the backup status', () => {
  it('is checked unless the file says it is not', () => {
    expect(parseBackupStatus(null)).toBe(false);
    expect(parseBackupStatus('unchecked')).toBe(false);
    expect(parseBackupStatus({ unchecked: 'yes' })).toBe(false);
    expect(parseBackupStatus({ unchecked: false })).toBe(false);
    expect(parseBackupStatus({ unchecked: true })).toBe(true);
  });

  it('is read once, kept in its file, and tells listeners', async () => {
    let saved: unknown = { unchecked: true };
    const read = jest.fn(() => saved);
    const store = createBackupStatusStore({
      read,
      write: async (value) => {
        saved = value;
      },
    });
    const listener = jest.fn();
    const unsubscribe = store.subscribe(listener);
    expect(store.unchecked()).toBe(true);
    await store.setChecked(true);
    expect(store.unchecked()).toBe(false);
    expect(saved).toEqual({ unchecked: false });
    expect(listener).toHaveBeenCalledTimes(1);
    unsubscribe();
    await store.setChecked(false);
    expect(saved).toEqual({ unchecked: true });
    expect(listener).toHaveBeenCalledTimes(1);
    expect(read).toHaveBeenCalledTimes(1);
  });
});

describe.each(Object.keys(DEVICES) as Device[])('on the %s', (device) => {
  it('shows no marker in Settings while the backup is checked', () => {
    renderOn(device, SettingsScreen);
    expect(screen.queryByTestId('settings-backup-unchecked')).toBeNull();
    expect(screen.queryByText('Backup not checked')).toBeNull();
  });

  it('marks the account "Backup not checked" with a "Check my words now" entry, and drops it once checked', async () => {
    await backupStatusStore.setChecked(false);
    renderOn(device, SettingsScreen);
    expect(screen.getByText('Backup not checked')).toBeOnTheScreen();
    expect(screen.getByTestId('settings-backup-unchecked-detail')).toHaveTextContent('Check my words now');
    fireEvent.press(screen.getByTestId('settings-backup-unchecked'));
    expect(mockPush).toHaveBeenCalledWith('/check-words');

    await act(async () => {
      await backupStatusStore.setChecked(true);
    });
    expect(screen.queryByTestId('settings-backup-unchecked')).toBeNull();
  });

  it('checks three words after Face ID and then clears the marker', async () => {
    await backupStatusStore.setChecked(false);
    renderOn(device, CheckWordsScreen);
    expect(askedPositions()).toHaveLength(3);
    expect(screen.getByTestId('check-words-confirm').props.accessibilityState).toEqual({ disabled: true });

    typeWords(() => 'wrong');
    await pressCheck();
    expect(screen.getByTestId('check-words-message')).toHaveTextContent(/^These words do not match your backup\./);
    expect(backupStatusStore.unchecked()).toBe(true);

    // Face ID refused: the words are not checked at all.
    mockCore.checkSavedAccountWords.mockClear();
    mockAuthenticate.mockResolvedValueOnce({ ok: false, reason: 'cancelled' });
    typeWords((position) => ` ${mockSavedWords[position - 1].toUpperCase()} `);
    await pressCheck();
    expect(mockCore.checkSavedAccountWords).not.toHaveBeenCalled();
    expect(backupStatusStore.unchecked()).toBe(true);

    await pressCheck();
    const positions = mockCore.checkSavedAccountWords.mock.calls[0][0];
    expect(positions).toHaveLength(3);
    expect(mockCore.checkSavedAccountWords).toHaveBeenCalledWith(
      positions,
      positions.map((position: number) => mockSavedWords[position - 1]),
    );
    expect(screen.getByTestId('check-words-passed')).toBeOnTheScreen();
    expect(backupStatusStore.unchecked()).toBe(false);
    expect(mockFiles['backup-status.json']).toEqual({ unchecked: false });
  });
});
