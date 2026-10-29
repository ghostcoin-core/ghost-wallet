import { act, fireEvent, render, screen } from '@testing-library/react-native';
import type { ComponentType } from 'react';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import PaymentScreen from '../../app/payment';
import SendScreen from '../../app/send';
import type { SendStatus } from '../../lib/send/payment-status';
import { encodeDetails, type SendDetails } from '../../lib/vanish/payments';
import { reopenPayment, resetPending } from '../../lib/vanish/pending';

const ACCOUNT = '0x00000000000000000000000000000000000000aa';
const RECIPIENT = '0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd';
const GHOST = 10n ** 18n;

const mockDetails: SendDetails = {
  kind: 'send',
  to: RECIPIENT,
  amountWei: (25n * GHOST).toString(),
  nonce: '4',
  maxFeePerGas: '20000000000',
  fromHeight: 90,
  at: 1,
};
const mockSequence = {
  record: () => ({ id: 'send-abc', intent: { details: encodeDetails(mockDetails) } }),
  step: () => 3,
};
const mockKit = {
  core: { testSendGasLimit: () => 100_000n, PaymentSequence: { open: () => mockSequence } },
  store: { list: () => ['send-abc'] },
  node: {},
  nodeUrl: 'http://127.0.0.1:8547',
};

jest.mock('../../modules/ghost-core/src/index', () => ({ savedAccountZeroAddress: () => ACCOUNT }), { virtual: true });

const mockQuote = jest.fn(async () => ({ maxFeePerGas: 20_000_000_000n, feeWei: 2n * (GHOST / 1000n) }));
const mockStartSend = jest.fn(async (..._args: unknown[]) => mockSequence);
jest.mock('../../lib/send/send-payment', () => ({
  ...jest.requireActual('../../lib/send/send-payment'),
  sendKit: () => mockKit,
  quoteFee: () => mockQuote(),
  recentRecipients: () => [{ address: RECIPIENT, amountWei: (4n * GHOST).toString(), at: 1 }],
  startSend: (...args: unknown[]) => mockStartSend(...args),
}));

let mockStatus: SendStatus = 'sent';
jest.mock('../../lib/send/use-send-payment', () => ({
  useSendPayment: () => ({ status: mockStatus, step: 3, error: null }),
}));

const mockAuth = jest.fn(async (_prompt: string) => ({ ok: true }) as { ok: true } | { ok: false; reason: 'cancelled' });
jest.mock('../../lib/device-auth', () => ({
  ...jest.requireActual('../../lib/device-auth'),
  authenticate: (prompt: string) => mockAuth(prompt),
}));

jest.mock('expo-clipboard', () => ({ getStringAsync: async () => `  ${RECIPIENT}\n` }));
jest.mock('../../lib/storage', () => ({
  jsonFile: () => ({
    read: () => ({
      version: 1,
      nodeUrl: 'http://192.168.1.36:8547',
      address: ACCOUNT,
      balanceWei: (100n * GHOST).toString(),
      nonce: 4,
      tipHeight: 90,
      checkedAt: Date.now(),
      activity: [],
    }),
    write: async () => {},
  }),
}));
jest.mock('../../lib/home/read-account', () => ({ readAccountZero: () => new Promise(() => {}) }));

const mockReplace = jest.fn();
const mockBack = jest.fn();
jest.mock('expo-router', () => ({
  useRouter: () => ({ push: jest.fn(), back: mockBack, replace: mockReplace, canGoBack: () => true }),
}));

const mockWindow = { width: 393, height: 852, scale: 3, fontScale: 1 };
jest.mock('react-native/Libraries/Utilities/useWindowDimensions', () => ({ __esModule: true, default: () => mockWindow }));

const DEVICES = {
  iPhone: { width: 393, height: 852 },
  'iPhone Duo folded': { width: 466, height: 678 },
  'iPhone Duo open': { width: 626, height: 890 },
} as const;
type Device = keyof typeof DEVICES;

async function renderOn(device: Device, Screen: ComponentType) {
  const { width, height } = DEVICES[device];
  mockWindow.width = width;
  mockWindow.height = height;
  const view = render(
    <SafeAreaProvider initialMetrics={{ frame: { x: 0, y: 0, width, height }, insets: { top: 47, left: 0, right: 0, bottom: 34 } }}>
      <Screen />
    </SafeAreaProvider>,
  );
  await act(async () => {});
  return view;
}

beforeEach(() => {
  resetPending();
  mockStartSend.mockClear();
  mockReplace.mockClear();
  mockAuth.mockClear();
  mockQuote.mockClear();
});

describe('the Send screen', () => {
  it.each(Object.keys(DEVICES) as Device[])('shows the form, the review and Face ID on the %s', async (device) => {
    await renderOn(device, SendScreen);
    expect(screen.getByTestId('send-to')).toBeOnTheScreen();
    expect(screen.getByTestId('send-amount')).toBeOnTheScreen();
    expect(screen.getByText('You have 100.00 GHOST')).toBeOnTheScreen();
    expect(screen.getByTestId('send-fee')).toHaveTextContent('0.002 GHOST at most');
    expect(screen.getByTestId('send-arrives')).toHaveTextContent('In under a minute');
    expect(screen.getByText('Send with Face ID')).toBeOnTheScreen();
    // The content scrolls, so the folded Duo reaches the button.
    expect(screen.getByTestId('send-screen-content').type).toBe('RCTScrollView');
    // Recent addresses sit under the form only on the open Duo, as in the mockup.
    expect(screen.queryByTestId('send-recent') !== null).toBe(device === 'iPhone Duo open');
  });

  it('pastes the address, reviews the total and sends only after Face ID', async () => {
    await renderOn('iPhone Duo open', SendScreen);
    expect(screen.getByTestId('send-confirm')).toBeDisabled();
    await act(async () => fireEvent.press(screen.getByTestId('send-paste')));
    fireEvent.changeText(screen.getByTestId('send-amount'), '25.00');
    expect(screen.getByTestId('send-total')).toHaveTextContent('25.002 GHOST');
    expect(screen.getByTestId('send-review-hero')).toHaveTextContent(/25\.00 GHOST.*0xe5fb…55fd/);
    await act(async () => fireEvent.press(screen.getByTestId('send-confirm')));
    expect(mockAuth).toHaveBeenCalledWith('Send 25.00 GHOST');
    expect(mockStartSend).toHaveBeenCalledTimes(1);
    expect(mockStartSend.mock.calls[0][1]).toEqual({
      account: ACCOUNT,
      to: RECIPIENT,
      amountWei: 25n * GHOST,
      maxFeePerGas: 20_000_000_000n,
      cached: { nonce: 4, tipHeight: 90 },
    });
    expect(mockReplace).toHaveBeenCalledWith('/payment');
  });

  it('saves nothing when Face ID does not pass', async () => {
    mockAuth.mockResolvedValueOnce({ ok: false, reason: 'cancelled' });
    await renderOn('iPhone', SendScreen);
    fireEvent.changeText(screen.getByTestId('send-to'), RECIPIENT);
    fireEvent.changeText(screen.getByTestId('send-amount'), '1');
    await act(async () => fireEvent.press(screen.getByTestId('send-confirm')));
    expect(mockStartSend).not.toHaveBeenCalled();
    expect(screen.getByTestId('send-error')).toHaveTextContent('Cancelled.');
  });

  it('says what is wrong with the address or the amount, and keeps the button off', async () => {
    await renderOn('iPhone', SendScreen);
    fireEvent.changeText(screen.getByTestId('send-to'), '0x1234');
    fireEvent.changeText(screen.getByTestId('send-amount'), '200');
    expect(screen.getByTestId('send-to-problem')).toHaveTextContent(/0x and 40/);
    expect(screen.getByTestId('send-amount-problem')).toHaveTextContent(/Not enough GHOST/);
    expect(screen.getByTestId('send-confirm')).toBeDisabled();
  });

  it('offers to queue the send when the test node is out of reach', async () => {
    mockQuote.mockRejectedValueOnce(new Error('Network request failed'));
    await renderOn('iPhone Duo folded', SendScreen);
    expect(screen.getByTestId('send-fee')).toHaveTextContent('Set when it goes out');
    expect(screen.getByTestId('send-arrives')).toHaveTextContent('When the test node can be reached');
    expect(screen.getByTestId('send-offline')).toHaveTextContent(/queued on this phone/);
    fireEvent.changeText(screen.getByTestId('send-to'), RECIPIENT);
    fireEvent.changeText(screen.getByTestId('send-amount'), '1');
    expect(screen.getByTestId('send-confirm')).toBeEnabled();
  });
});

describe('the payment screen', () => {
  beforeEach(() => reopenPayment('send-abc'));

  it.each(Object.keys(DEVICES) as Device[])('shows the amount, the progress and the safety line on the %s', async (device) => {
    mockStatus = 'in-block';
    await renderOn(device, PaymentScreen);
    expect(screen.getByTestId('payment-amount')).toHaveTextContent('25.00 GHOST');
    expect(screen.getByText('0xe5fb…55fd')).toBeOnTheScreen();
    expect(screen.getByTestId('send-stage-in-block')).toBeOnTheScreen();
    expect(screen.getByTestId('payment-note')).toHaveTextContent('Safe to close the app. It never pays twice.');
    expect(screen.queryByTestId('payment-done')).toBeNull();
    expect(screen.queryByTestId('payment-details') !== null).toBe(device === 'iPhone Duo open');
  });

  it.each([
    ['queued', 'Queued, not sent yet.', false],
    ['sent', 'Safe to close the app.', false],
    ['settled', 'Settled.', true],
    ['failed', 'Nothing more is sent.', true],
    ['conflicted', 'Another payment from this account', true],
  ] as const)('shows a %s send', async (status, note, final) => {
    mockStatus = status;
    await renderOn('iPhone', PaymentScreen);
    expect(screen.getByTestId(`send-stage-${status}`)).toBeOnTheScreen();
    expect(screen.getByTestId('payment-note')).toHaveTextContent(new RegExp(note.replace('.', '\\.')));
    expect(screen.queryByTestId('payment-done') !== null).toBe(final);
    expect(screen.queryByTestId('payment-leave') !== null).toBe(!final);
  });

  it('never shows Sent as done for a queued send', async () => {
    mockStatus = 'queued';
    await renderOn('iPhone', PaymentScreen);
    expect(screen.getByTestId('send-stage-sent')).toHaveProp('accessibilityLabel', 'Sent, to come');
  });
});
