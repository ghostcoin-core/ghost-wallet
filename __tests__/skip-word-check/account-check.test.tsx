import { act, fireEvent, render, screen, within } from '@testing-library/react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import CheckScreen from '../../app/check';
import { SKIP_CHECK_LABEL } from '../../components/skip-check';
import { backupStatusStore } from '../../lib/onboarding/backup-status';
import { SessionProvider } from '../../lib/session';

// Plain test words stand in for the new account the core holds.
const mockNewWords = Array.from({ length: 24 }, (_, index) => `test${index + 1}`);

const mockCore = {
  checkNewAccountWord: jest.fn((position: number, word: string) => mockNewWords[position - 1] === word),
  saveNewAccount: jest.fn(),
  saveNewAccountUnchecked: jest.fn(),
  discardNewAccount: jest.fn(),
  hasAccount: jest.fn(() => false),
};
jest.mock('../../modules/ghost-core/src/index', () => mockCore, { virtual: true });

// The backup status file, kept in memory.
const mockFiles: Record<string, unknown> = {};
jest.mock('../../lib/storage', () => ({
  jsonFile: (name: string) => ({
    read: () => mockFiles[name] ?? null,
    write: async (value: unknown) => {
      mockFiles[name] = value;
    },
  }),
}));
jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: jest.fn() }) }));

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
      <SessionProvider>
        <CheckScreen />
      </SessionProvider>
    </SafeAreaProvider>,
  );
}

function askedPositions(): number[] {
  return screen.getAllByTestId(/^check-word-\d+$/).map((field) => Number(field.props.testID.replace('check-word-', '')));
}

function typeWords(word: (position: number) => string) {
  for (const position of askedPositions()) {
    fireEvent.changeText(screen.getByTestId(`check-word-${position}`), word(position));
  }
}

function confirmDisabled(): boolean {
  return screen.getByTestId('check-confirm').props.accessibilityState?.disabled === true;
}

async function pressConfirm() {
  await act(async () => {
    fireEvent.press(screen.getByTestId('check-confirm'));
  });
}

beforeEach(async () => {
  jest.clearAllMocks();
  await backupStatusStore.setChecked(true);
});

describe.each(Object.keys(DEVICES) as Device[])('on the %s', (device) => {
  const open = device === 'iPhone Duo open';

  it('shows the skip box unticked, with the words in full, and keeps Confirm reachable', () => {
    renderOn(device);
    const box = screen.getByTestId('check-skip');
    expect(box.props.accessibilityRole).toBe('checkbox');
    expect(box.props.accessibilityState).toEqual({ checked: false });
    expect(screen.getByText(SKIP_CHECK_LABEL)).toBeOnTheScreen();
    expect(SKIP_CHECK_LABEL).toBe(
      "Skip the check. I wrote the words down and accept that if I made a mistake, the coins can't be recovered.",
    );
    // The box scrolls with the fields; Confirm sits in the footer, or in the second column on the open Duo.
    const scroll = screen.getByTestId('check-screen-scroll');
    expect(within(scroll).getByTestId('check-skip')).toBeOnTheScreen();
    if (open) {
      expect(within(scroll).getByTestId('check-confirm')).toBeOnTheScreen();
    } else {
      expect(within(scroll).queryByTestId('check-confirm')).toBeNull();
      expect(screen.getByTestId('check-confirm')).toBeOnTheScreen();
    }
  });

  it('keeps Confirm disabled until the words are typed, and saves only once they pass', async () => {
    // A mark left over from an account that was never saved goes with a checked save.
    await backupStatusStore.setChecked(false);
    renderOn(device);
    expect(confirmDisabled()).toBe(true);
    await pressConfirm();
    expect(mockCore.saveNewAccount).not.toHaveBeenCalled();

    typeWords(() => 'wrong');
    expect(confirmDisabled()).toBe(false);
    await pressConfirm();
    // Wrong words: nothing is saved, and the unchecked save is never used.
    expect(screen.getByTestId('check-error')).toHaveTextContent(/do not match your backup/);
    expect(mockCore.saveNewAccount).not.toHaveBeenCalled();
    expect(mockCore.saveNewAccountUnchecked).not.toHaveBeenCalled();

    typeWords((position) => mockNewWords[position - 1]);
    await pressConfirm();
    expect(mockCore.saveNewAccount).toHaveBeenCalledTimes(1);
    expect(mockCore.saveNewAccountUnchecked).not.toHaveBeenCalled();
    expect(backupStatusStore.unchecked()).toBe(false);
  });

  it('enables Confirm when the box is ticked, and saves unchecked with the backup marked not checked', async () => {
    renderOn(device);
    expect(confirmDisabled()).toBe(true);
    fireEvent.press(screen.getByTestId('check-skip'));
    expect(screen.getByTestId('check-skip').props.accessibilityState).toEqual({ checked: true });
    expect(confirmDisabled()).toBe(false);
    // Unticked again: back to the check.
    fireEvent.press(screen.getByTestId('check-skip'));
    expect(confirmDisabled()).toBe(true);
    fireEvent.press(screen.getByTestId('check-skip'));

    await pressConfirm();
    expect(mockCore.saveNewAccountUnchecked).toHaveBeenCalledTimes(1);
    expect(mockCore.saveNewAccount).not.toHaveBeenCalled();
    expect(mockCore.checkNewAccountWord).not.toHaveBeenCalled();
    expect(backupStatusStore.unchecked()).toBe(true);
    expect(mockFiles['backup-status.json']).toEqual({ unchecked: true });
  });

  it('marks the backup checked again when the unchecked save fails', async () => {
    mockCore.saveNewAccountUnchecked.mockImplementationOnce(() => {
      throw new Error('keychain refused');
    });
    renderOn(device);
    fireEvent.press(screen.getByTestId('check-skip'));
    await pressConfirm();
    expect(screen.getByTestId('check-error')).toHaveTextContent(/could not be saved/);
    expect(backupStatusStore.unchecked()).toBe(false);
  });

  it('never remembers the skip: a new check starts unticked', () => {
    const first = renderOn(device);
    fireEvent.press(screen.getByTestId('check-skip'));
    first.unmount();
    renderOn(device);
    expect(screen.getByTestId('check-skip').props.accessibilityState).toEqual({ checked: false });
    expect(confirmDisabled()).toBe(true);
  });
});
