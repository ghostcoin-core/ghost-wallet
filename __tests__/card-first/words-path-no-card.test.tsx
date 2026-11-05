// A words Phantom Key never goes on a card. Once its 24 words were shown, a
// card of it would never be the only copy: someone could keep the words and
// hand the card over as if it were. So the words path's save and check steps
// offer no card, and nothing on it ever writes one. The only way to a card is
// "Put on a card" on the amount step, which makes a card-only key.
import { act, fireEvent, render, screen } from '@testing-library/react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import VanishScreen from '../../app/vanish';
import { buildNetwork } from '../../lib/network/build-network';
import { heldKey, holdVanish, resetPending } from '../../lib/vanish/pending';

const mockKeyWords = [
  'walrus', 'tundra', 'zephyr', 'quiver', 'mango', 'otter', 'pebble', 'lantern',
  'cobalt', 'falcon', 'gravel', 'harbor', 'igloo', 'jasmine', 'kettle', 'lizard',
  'meadow', 'nectar', 'oyster', 'parrot', 'quartz', 'raven', 'saddle', 'thistle',
];

type MockSequence = {
  id: string;
  stepNow: number;
  step: () => number;
  record: () => { id: string; intent: { details: ArrayBuffer } };
  markBackedUp: jest.Mock;
};
let mockSaved: Record<string, MockSequence> = {};

const mockCore = {
  checkKeyWords: jest.fn(() => ({ verdict: 'word-check', position: 0 })),
  prepareVanish: jest.fn((_chainId: bigint, amountWei: string) => ({
    commitData: new Uint8Array(430).fill(3).buffer,
    amountWei,
    commitment: new ArrayBuffer(32),
  })),
  prepareCardVanish: jest.fn((_chainId: bigint, amountWei: string) => ({
    commitData: new Uint8Array(430).fill(3).buffer,
    amountWei,
    commitment: new ArrayBuffer(32),
  })),
  takePhantomKeyWords: jest.fn(() => [...mockKeyWords]),
  checkPhantomKeyWord: jest.fn((position: number, word: string) => mockKeyWords[position - 1] === word),
  confirmPhantomKeySaved: jest.fn(),
  confirmPhantomKeySavedUnchecked: jest.fn(),
  forgetPhantomKey: jest.fn(),
  forgetCardKey: jest.fn(),
  feeWindow: jest.fn(() => ({ referenceHeight: 96n, validUntil: 103n })),
  minVanishWei: jest.fn(() => '1000'),
  vanishGasLimit: () => 500_000n,
  savedAccountZeroAddress: () => '0x00000000000000000000000000000000000000aa',
  hasAccount: () => true,
  PaymentSequence: {
    start: jest.fn((_store: unknown, id: string, intent: { details: ArrayBuffer }) => {
      const sequence: MockSequence = {
        id,
        stepNow: 0,
        step: () => sequence.stepNow,
        record: () => ({ id, intent: { details: intent.details } }),
        markBackedUp: jest.fn(() => {
          sequence.stepNow = 1;
        }),
      };
      mockSaved[id] = sequence;
      return sequence;
    }),
    open: (_store: unknown, id: string) => {
      const found = mockSaved[id];
      if (!found) throw new Error('no such payment');
      return found;
    },
  },
};
jest.mock('../../modules/ghost-core/src/index', () => mockCore, { virtual: true });

const mockStore = {
  list: () => Object.keys(mockSaved),
  remove: jest.fn((id: string) => {
    delete mockSaved[id];
  }),
};
const mockNode = {
  chainId: jest.fn(async () => buildNetwork.chainId),
  tipHeight: jest.fn(async () => 100),
  block: jest.fn(async (height: number) => ({ height, hash: `0x${'47'.repeat(32)}`, baseFeePerGas: 7n, transactions: [] })),
  nonce: jest.fn(async () => 2n),
  maxPriorityFeePerGas: jest.fn(async () => 1n),
};
jest.mock('../../lib/vanish/use-payment', () => ({
  paymentKit: () => ({ core: mockCore, store: mockStore, node: mockNode, nodeUrl: 'http://127.0.0.1:8547' }),
  treeAtTip: jest.fn(),
  usePayment: (_kit: unknown, sequence: unknown) =>
    sequence ? { status: 'sent', step: 3, needsKey: false, error: null } : null,
}));

// This phone reads cards: the words path still must not offer one.
const mockPut = jest.fn();
jest.mock('../../modules/ghost-nfc', () => ({
  ...jest.requireActual('../../modules/ghost-nfc'),
  cardsSupported: () => true,
  putPhantomKeyOnCard: () => mockPut(),
}));

jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));
jest.mock('../../lib/home/read-account', () => ({ readAccountZero: () => new Promise(() => {}) }));
jest.mock('../../lib/home/history', () => ({ scanHistory: async () => [] }));
jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: jest.fn(), replace: jest.fn() }) }));

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
      <VanishScreen />
    </SafeAreaProvider>,
  );
}

/** Makes a words key and goes on to its three-word check. */
async function reachCheck() {
  await act(async () => {});
  fireEvent.changeText(screen.getByTestId('vanish-amount'), '1.5');
  await act(async () => {
    fireEvent.press(screen.getByTestId('vanish-make-key'));
  });
  expect(screen.getByTestId('phantom-key-word-1')).toHaveTextContent(mockKeyWords[0]);
  expectNoCardOffered();
  fireEvent.press(screen.getByTestId('vanish-saved'));
}

function checkPositions(): number[] {
  return screen.getAllByTestId(/^vanish-check-\d+$/).map((field) => Number(field.props.testID.replace('vanish-check-', '')));
}

/** No button on the screen puts this key on a card, or goes on without one. */
function expectNoCardOffered() {
  expect(screen.queryByTestId('vanish-card')).toBeNull();
  expect(screen.queryByTestId('vanish-make-card')).toBeNull();
  expect(screen.queryByTestId('vanish-card-retry')).toBeNull();
  expect(screen.queryByTestId('vanish-without-card')).toBeNull();
  expect(screen.queryByText(/Put on a card, then Vanish/)).toBeNull();
  expect(screen.queryAllByRole('button', { name: /card/i })).toEqual([]);
}

beforeEach(() => {
  jest.clearAllMocks();
  resetPending();
  mockSaved = {};
  mockPut.mockResolvedValue({ uidHex: '04518DFAA96180' });
});

describe.each(Object.keys(DEVICES) as Device[])('on the %s', (device) => {
  it('offers the card on the amount step, as the card-only Vanish', async () => {
    renderOn(device);
    await act(async () => {});
    expect(screen.getByTestId('vanish-make-card')).toHaveTextContent('Put on a card');
  });

  it('renders no card button on the check step, and never writes a card', async () => {
    renderOn(device);
    await reachCheck();
    expect(checkPositions()).toHaveLength(3);
    expect(screen.getByTestId('vanish-send')).toBeOnTheScreen();
    expectNoCardOffered();

    // Ticking the skip box offers no card either.
    fireEvent.press(screen.getByTestId('vanish-skip-check'));
    expectNoCardOffered();
    fireEvent.press(screen.getByTestId('vanish-skip-check'));

    for (const position of checkPositions()) {
      fireEvent.changeText(screen.getByTestId(`vanish-check-${position}`), mockKeyWords[position - 1]);
    }
    expectNoCardOffered();
    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-send'));
    });
    expect(mockCore.confirmPhantomKeySaved).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
    expect(mockPut).not.toHaveBeenCalled();
    expect(mockCore.prepareCardVanish).not.toHaveBeenCalled();
  });

  it('a words key held at a card step from before returns to its check, never to a card', async () => {
    const first = renderOn(device);
    await reachCheck();
    const held = heldKey();
    expect(held).toEqual(expect.objectContaining({ step: 'check' }));
    fireEvent.press(screen.getByTestId('back'));
    first.unmount();
    // A words key left at a card step by an older screen: it is not card-only.
    holdVanish({ id: held!.id, step: 'card', words: [], positions: [3, 9, 17], checked: false });
    // Opening the screen the first time forgot a stray key, before any was made.
    mockCore.forgetPhantomKey.mockClear();

    renderOn(device);
    await act(async () => {});
    expect(checkPositions()).toEqual([3, 9, 17]);
    expectNoCardOffered();
    expect(screen.queryByTestId('vanish-card-hold')).toBeNull();
    expect(mockPut).not.toHaveBeenCalled();
    expect(mockCore.forgetPhantomKey).not.toHaveBeenCalled();
  });
});
