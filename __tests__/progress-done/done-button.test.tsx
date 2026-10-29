import { act, fireEvent, render, screen } from '@testing-library/react-native';
import type { ComponentType } from 'react';
import { StyleSheet } from 'react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import SummonScreen from '../../app/summon';
import VanishScreen from '../../app/vanish';
import { LEAVE_NOTE } from '../../components/vanish-ui';
import { encodeDetails } from '../../lib/vanish/payments';
import { resetPending } from '../../lib/vanish/pending';
import type { PaymentStatus } from '../../lib/vanish/status-mapping';

// A Vanish and a Summon left mid-way, saved at Sent: each screen opens on its progress.
function mockSaved(id: string, details: object) {
  return {
    step: () => 3,
    record: () => ({ id, intent: { details: encodeDetails(details as never) } }),
    markBackedUp: jest.fn(),
  };
}
const mockSequences: Record<string, ReturnType<typeof mockSaved>> = {
  'vanish-1': mockSaved('vanish-1', { kind: 'vanish', commitData: '0x00', amountWei: '1500000000000000000', nonce: '0', at: 1 }),
  'summon-1': mockSaved('summon-1', { kind: 'summon', amountWei: '900000000000000000', feeWei: '1000', marker: '0x01', at: 1 }),
};

const mockCore = {
  checkKeyWords: jest.fn(() => ({ verdict: 'word-check', position: 0 })),
  checkPhantomKeyWord: jest.fn(() => true),
  confirmPhantomKeySaved: jest.fn(),
  forgetPhantomKey: jest.fn(),
  forgetCardKey: jest.fn(),
  savedAccountZeroAddress: () => '0x00000000000000000000000000000000000000aa',
  hasAccount: () => true,
  PaymentSequence: {
    open: (_store: unknown, id: string) => {
      const found = mockSequences[id];
      if (!found) throw new Error('no such payment');
      return found;
    },
  },
};
jest.mock('../../modules/ghost-core/src/index', () => mockCore, { virtual: true });

let mockStatus: PaymentStatus = 'sent';
const mockStore = { list: () => Object.keys(mockSequences), remove: jest.fn() };
jest.mock('../../lib/vanish/use-payment', () => ({
  paymentKit: () => ({ core: mockCore, store: mockStore, node: {}, nodeUrl: 'http://127.0.0.1:8547' }),
  usePayment: (_kit: unknown, sequence: unknown) =>
    sequence ? { status: mockStatus, step: 3, needsKey: false, error: null } : null,
}));

jest.mock('../../lib/vanish/actions', () => ({
  CARD_KEY: { card: true },
  // The progress does not need the minimum: its lookup never answers here.
  minimumVanish: () => new Promise(() => {}),
  startVanish: jest.fn(),
  lookUpKey: jest.fn(),
  signVanishAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
  proveRevealAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
  startReveal: jest.fn(),
}));

jest.mock('../../modules/ghost-nfc', () => ({
  ...jest.requireActual('../../modules/ghost-nfc'),
  cardsSupported: () => false,
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

function sideBySide(testID: string): boolean {
  return StyleSheet.flatten(screen.getByTestId(testID).props.contentContainerStyle).flexDirection === 'row';
}

beforeEach(() => {
  jest.clearAllMocks();
  resetPending();
  mockStatus = 'sent';
});

const SCREENS = [
  ['Vanish', VanishScreen, 'vanish'],
  ['Summon', SummonScreen, 'summon'],
] as const;

describe.each(Object.keys(DEVICES) as Device[])('on the %s', (device) => {
  const open = device === 'iPhone Duo open';

  describe.each(SCREENS)('the %s progress', (_name, Screen, prefix) => {
    it.each(['proving', 'sent', 'in-block'] as const)('has no Done while %s: it says the payment goes on and offers Leave', (status) => {
      mockStatus = status;
      renderOn(device, Screen);
      expect(sideBySide(`${prefix}-screen-content`)).toBe(open);
      expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
      expect(screen.queryByTestId(`${prefix}-done`)).toBeNull();
      expect(screen.queryByText('Done')).toBeNull();
      expect(screen.getByTestId(`${prefix}-leave-note`)).toHaveTextContent(LEAVE_NOTE, { exact: false });

      // Leave is words only, not a filled primary button.
      const leave = screen.getByTestId(`${prefix}-leave`);
      expect(leave).toHaveTextContent('Leave');
      expect(StyleSheet.flatten(leave.props.style).backgroundColor).toBeUndefined();
      fireEvent.press(leave);
      expect(mockBack).toHaveBeenCalledTimes(1);
    });

    it.each(['settled', 'failed'] as const)('shows Done once %s, and no longer the leave line', (status) => {
      mockStatus = status;
      renderOn(device, Screen);
      expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
      expect(screen.queryByTestId(`${prefix}-leave-note`)).toBeNull();
      expect(screen.queryByTestId(`${prefix}-leave`)).toBeNull();
      fireEvent.press(screen.getByTestId(`${prefix}-done`));
      expect(mockBack).toHaveBeenCalledTimes(1);
    });

    it('swaps Leave for Done when the payment settles while the screen shows', () => {
      mockStatus = 'in-block';
      const view = renderOn(device, Screen);
      expect(screen.queryByTestId(`${prefix}-done`)).toBeNull();
      mockStatus = 'settled';
      act(() => {
        view.rerender(
          <SafeAreaProvider
            initialMetrics={{
              frame: { x: 0, y: 0, width: DEVICES[device].width, height: DEVICES[device].height },
              insets: { top: 47, left: 0, right: 0, bottom: 34 },
            }}
          >
            <Screen />
          </SafeAreaProvider>,
        );
      });
      expect(screen.getByTestId(`${prefix}-done`)).toBeOnTheScreen();
      expect(screen.queryByTestId(`${prefix}-leave`)).toBeNull();
    });
  });
});
