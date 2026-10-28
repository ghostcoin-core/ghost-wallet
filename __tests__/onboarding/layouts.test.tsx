import { render, screen, within } from '@testing-library/react-native';
import type { ComponentType } from 'react';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import BackupScreen from '../../app/backup';
import CheckScreen from '../../app/check';
import ImportScreen from '../../app/import';
import { screenLayout } from '../../lib/layout';
import { SessionProvider } from '../../lib/session';

const mockNewWords = Array.from({ length: 24 }, (_, index) => `test${index + 1}`);

jest.mock(
  '../../modules/ghost-core/src/index',
  () => ({
    newAccountWords: () => [...mockNewWords],
    discardNewAccount: () => {},
    checkNewAccountWord: () => false,
    isAccountWord: () => true,
    hasAccount: () => false,
  }),
  { virtual: true },
);

jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: jest.fn() }) }));

// The window size of the device under test.
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
      <SessionProvider>
        <Screen />
      </SessionProvider>
    </SafeAreaProvider>,
  );
}

describe('screenLayout', () => {
  it('uses two columns only on the open iPhone Duo', () => {
    expect(screenLayout(DEVICES.iPhone.width)).toBe('one-column');
    expect(screenLayout(DEVICES['iPhone Duo folded'].width)).toBe('one-column');
    expect(screenLayout(DEVICES['iPhone Duo open'].width)).toBe('two-column');
  });
});

describe.each(Object.keys(DEVICES) as Device[])('on the %s', (device) => {
  const open = device === 'iPhone Duo open';

  it('scrolls the backup words and keeps Continue in view', () => {
    renderOn(device, BackupScreen);

    const scroll = screen.getByTestId('backup-screen-scroll');
    expect(within(scroll).getByTestId('word-grid')).toBeOnTheScreen();
    expect(within(scroll).getByTestId('backup-word-24')).toHaveTextContent('test24');
    // Continue sits below the scrolling content, so it is always reachable.
    expect(within(scroll).queryByTestId('backup-continue')).toBeNull();
    expect(screen.getByTestId('backup-continue')).toBeOnTheScreen();
  });

  it('keeps the import button reachable', () => {
    renderOn(device, ImportScreen);

    const scroll = screen.getByTestId('import-screen-scroll');
    expect(within(scroll).getByTestId('import-word-24')).toBeOnTheScreen();
    expect(within(scroll).queryByTestId('import-open')).toBeNull();
    expect(screen.getByTestId('import-open')).toBeOnTheScreen();
  });

  it(open ? 'shows the paper grid and puts Confirm in the second column' : 'stacks the check in one column', () => {
    renderOn(device, CheckScreen);

    const scroll = screen.getByTestId('check-screen-scroll');
    expect(within(scroll).getAllByTestId(/^check-word-\d+$/)).toHaveLength(3);
    if (open) {
      expect(screen.getByLabelText('Positions of the words to check')).toBeOnTheScreen();
      expect(within(scroll).getByTestId('check-confirm')).toBeOnTheScreen();
    } else {
      expect(screen.queryByLabelText('Positions of the words to check')).toBeNull();
      expect(within(scroll).queryByTestId('check-confirm')).toBeNull();
      expect(screen.getByTestId('check-confirm')).toBeOnTheScreen();
    }
  });
});
