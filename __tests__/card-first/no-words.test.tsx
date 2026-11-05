// A card Vanish with no words: on a phone that reads cards, "Put on a card"
// makes a card-only Phantom Key in the core, writes it straight to a blank
// card and sends only after the card holds it and the core dropped it. No word
// of the key is ever asked for, typed, held or rendered. A card that is not
// written sends nothing and offers another blank card or a cancel, never words.
import { act, fireEvent, render, screen } from '@testing-library/react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import VanishScreen from '../../app/vanish';
import { CARD_ONLY_TEXT } from '../../components/vanish-ui';
import { buildNetwork } from '../../lib/network/build-network';
import { heldKey, resetPending } from '../../lib/vanish/pending';
import { CardCancelled } from '../../modules/ghost-nfc';
import { CardError } from '../../modules/ghost-nfc/card';

// Words no screen text uses, so any of them in the tree would be the key leaking.
const mockKeyWords = [
  'walrus', 'tundra', 'zephyr', 'quiver', 'mango', 'otter', 'pebble', 'lantern',
  'cobalt', 'falcon', 'gravel', 'harbor', 'igloo', 'jasmine', 'kettle', 'lizard',
  'meadow', 'nectar', 'oyster', 'parrot', 'quartz', 'raven', 'saddle', 'thistle',
];

/** What happened, in order: the card must hold the key before anything is sent. */
let mockEvents: string[] = [];

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
  prepareVanish: jest.fn((_chainId: bigint, amountWei: string) => {
    mockEvents.push('prepareVanish');
    return { commitData: new Uint8Array(430).fill(3).buffer, amountWei, commitment: new ArrayBuffer(32) };
  }),
  prepareCardVanish: jest.fn((_chainId: bigint, amountWei: string) => {
    mockEvents.push('prepareCardVanish');
    return { commitData: new Uint8Array(430).fill(3).buffer, amountWei, commitment: new ArrayBuffer(32) };
  }),
  takePhantomKeyWords: jest.fn(() => [...mockKeyWords]),
  checkPhantomKeyWord: jest.fn((position: number, word: string) => mockKeyWords[position - 1] === word),
  confirmPhantomKeySaved: jest.fn(() => {
    mockEvents.push('confirmPhantomKeySaved');
  }),
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
          mockEvents.push('markBackedUp');
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
  // The payment moves (is signed and sent) only once the screen hands it a sequence.
  usePayment: (_kit: unknown, sequence: unknown) => {
    if (!sequence) {
      return null;
    }
    if (!mockEvents.includes('sent')) {
      mockEvents.push('sent');
    }
    return { status: 'sent', step: 3, needsKey: false, error: null };
  },
}));

let mockCards = true;
const mockPut = jest.fn();
jest.mock('../../modules/ghost-nfc', () => ({
  ...jest.requireActual('../../modules/ghost-nfc'),
  cardsSupported: () => mockCards,
  putPhantomKeyOnCard: () => mockPut(),
}));

jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));
// Home's balance is never known here: the amount is checked against nothing.
jest.mock('../../lib/home/read-account', () => ({ readAccountZero: () => new Promise(() => {}) }));
jest.mock('../../lib/home/history', () => ({ scanHistory: async () => [] }));
const mockBack = jest.fn();
jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: mockBack, replace: jest.fn() }) }));

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

/** Every string rendered, as one text. */
function renderedText(): string {
  const parts: string[] = [];
  const walk = (node: unknown) => {
    if (typeof node === 'string') {
      parts.push(node);
    } else if (Array.isArray(node)) {
      node.forEach(walk);
    } else if (node && typeof node === 'object') {
      const { props, children } = node as { props?: Record<string, unknown>; children?: unknown };
      if (props) {
        for (const value of Object.values(props)) {
          if (typeof value === 'string') parts.push(value);
        }
      }
      walk(children ?? null);
    }
  };
  walk(screen.toJSON());
  return parts.join(' ');
}

function expectNoWords() {
  const text = renderedText().toLowerCase();
  for (const word of mockKeyWords) {
    expect(text).not.toMatch(new RegExp(`\\b${word}\\b`));
  }
  expect(screen.queryByTestId('phantom-key')).toBeNull();
  expect(screen.queryAllByTestId(/^phantom-key-word-/)).toEqual([]);
  expect(screen.queryAllByTestId(/^vanish-check-\d+$/)).toEqual([]);
  expect(screen.queryByTestId('vanish-skip-check')).toBeNull();
  expect(screen.queryByTestId('vanish-without-card')).toBeNull();
  expect(screen.queryByTestId('vanish-show-again')).toBeNull();
}

function expectNoWordCalls() {
  expect(mockCore.takePhantomKeyWords).not.toHaveBeenCalled();
  expect(mockCore.checkPhantomKeyWord).not.toHaveBeenCalled();
  expect(mockCore.confirmPhantomKeySavedUnchecked).not.toHaveBeenCalled();
  expect(mockCore.prepareVanish).not.toHaveBeenCalled();
}

/** Types an amount and waits for the minimum, so the buttons are enabled. */
async function typeAmount() {
  await act(async () => {});
  fireEvent.changeText(screen.getByTestId('vanish-amount'), '1.5');
}

async function putOnCard() {
  await typeAmount();
  await act(async () => {
    fireEvent.press(screen.getByTestId('vanish-make-card'));
  });
}

/**
 * How often the core was told to forget the key after the card Vanish made it
 * (opening the screen with no key held forgets a stray one, before that).
 */
function forgotSinceStart(): number {
  const [started] = mockCore.prepareCardVanish.mock.invocationCallOrder;
  expect(started).toBeDefined();
  return mockCore.forgetPhantomKey.mock.invocationCallOrder.filter((order) => order > started).length;
}

function onlySequence(): MockSequence {
  const all = Object.values(mockSaved);
  expect(all).toHaveLength(1);
  return all[0];
}

beforeEach(() => {
  jest.clearAllMocks();
  resetPending();
  mockSaved = {};
  mockEvents = [];
  mockCards = true;
  mockPut.mockImplementation(async () => {
    mockEvents.push('card written and read back');
    return { uidHex: '04518DFAA96180' };
  });
});

describe.each(Object.keys(DEVICES) as Device[])('on the %s', (device) => {
  it('offers the card first, and the words second, on the amount step', async () => {
    renderOn(device);
    await typeAmount();
    const card = screen.getByTestId('vanish-make-card');
    const words = screen.getByTestId('vanish-make-key');
    expect(card).toHaveTextContent('Put on a card');
    expect(words).toHaveTextContent('Write down 24 words');
    const ids = screen.getAllByTestId(/^vanish-make-(card|key)$/).map((button) => button.props.testID);
    expect(ids).toEqual(['vanish-make-card', 'vanish-make-key']);
  });

  it('offers only the words when this phone cannot read cards', async () => {
    mockCards = false;
    renderOn(device);
    await typeAmount();
    expect(screen.queryByTestId('vanish-make-card')).toBeNull();
    expect(screen.getByTestId('vanish-make-key')).toHaveTextContent('Make a Phantom Key');
  });

  it('puts a card-only key on a card, with no word asked or shown, and sends only after', async () => {
    renderOn(device);
    let finishWrite: () => void = () => {};
    mockPut.mockImplementation(
      () =>
        new Promise((resolve) => {
          finishWrite = () => {
            mockEvents.push('card written and read back');
            resolve({ uidHex: '04518DFAA96180' });
          };
        }),
    );
    await putOnCard();

    expect(mockCore.prepareCardVanish).toHaveBeenCalledTimes(1);
    expect(mockCore.prepareCardVanish).toHaveBeenCalledWith(buildNetwork.chainId, '1500000000000000000');
    expect(mockPut).toHaveBeenCalledTimes(1);
    // While the card is being written: nothing dropped, nothing sent, no words.
    expect(screen.getByTestId('vanish-card-only-text')).toHaveTextContent(CARD_ONLY_TEXT);
    expect(screen.getByTestId('vanish-card-hold')).toHaveTextContent(/Hold a blank NTAG 424 DNA card/);
    expect(mockCore.confirmPhantomKeySaved).not.toHaveBeenCalled();
    expect(onlySequence().markBackedUp).not.toHaveBeenCalled();
    expect(mockEvents).not.toContain('sent');
    expect(heldKey()).toEqual(expect.objectContaining({ step: 'card', words: [], cardOnly: true }));
    expectNoWords();

    await act(async () => finishWrite());
    expect(mockEvents).toEqual([
      'prepareCardVanish',
      'card written and read back',
      'confirmPhantomKeySaved',
      'markBackedUp',
      'sent',
    ]);
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
    expect(heldKey()).toBeNull();
    expectNoWordCalls();
    expectNoWords();
  });

  it('never calls the card "sealed" or tells a receiver to take it', async () => {
    renderOn(device);
    mockPut.mockRejectedValue(new CardCancelled());
    await putOnCard();
    const text = renderedText();
    expect(text).not.toMatch(/sealed/i);
    expect(text).not.toMatch(/safe\s+to\s+(accept|take)/i);
    expect(text).toContain(CARD_ONLY_TEXT);
  });

  it('sends nothing when the card is cancelled, and offers another blank card or a cancel', async () => {
    renderOn(device);
    mockPut.mockRejectedValueOnce(new CardCancelled());
    await putOnCard();

    expect(mockCore.confirmPhantomKeySaved).not.toHaveBeenCalled();
    expect(forgotSinceStart()).toBe(0);
    expect(onlySequence().markBackedUp).not.toHaveBeenCalled();
    expect(mockEvents).not.toContain('sent');
    expect(screen.getByTestId('vanish-card-retry')).toHaveTextContent('Try again with a blank card');
    expect(screen.getByTestId('vanish-cancel')).toHaveTextContent('Cancel this Vanish');
    expect(screen.getByTestId('vanish-error')).toHaveTextContent(/Nothing was sent/);
    expect(screen.getByTestId('vanish-error')).not.toHaveTextContent(/word/i);
    // Still held, for the next card.
    expect(heldKey()).toEqual(expect.objectContaining({ step: 'card', cardOnly: true }));
    expectNoWords();

    // Another blank card takes it, and only then is it sent.
    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-card-retry'));
    });
    expect(mockPut).toHaveBeenCalledTimes(2);
    expect(mockEvents).toEqual(['prepareCardVanish', 'card written and read back', 'confirmPhantomKeySaved', 'markBackedUp', 'sent']);
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
    expectNoWordCalls();
  });

  it('sends nothing when the card write fails, and its message never offers words', async () => {
    renderOn(device);
    mockPut.mockRejectedValueOnce(new CardError('write-failed'));
    await putOnCard();
    expect(mockCore.confirmPhantomKeySaved).not.toHaveBeenCalled();
    expect(onlySequence().markBackedUp).not.toHaveBeenCalled();
    expect(mockEvents).not.toContain('sent');
    expect(screen.getByTestId('vanish-error')).toHaveTextContent(/Nothing was sent/);
    expect(screen.getByTestId('vanish-error')).not.toHaveTextContent(/word/i);
    expect(screen.getByTestId('vanish-card-retry')).toBeOnTheScreen();
    expect(screen.getByTestId('vanish-cancel')).toBeOnTheScreen();
    expectNoWords();
    expectNoWordCalls();
  });

  it('cancels a Vanish whose card was not written: the core forgets the key and nothing is sent', async () => {
    renderOn(device);
    mockPut.mockRejectedValueOnce(new CardError('not-blank'));
    await putOnCard();
    const sequence = onlySequence();
    expect(forgotSinceStart()).toBe(0);
    fireEvent.press(screen.getByTestId('vanish-cancel'));
    expect(forgotSinceStart()).toBe(1);
    expect(mockStore.remove).toHaveBeenCalledWith(sequence.id);
    expect(mockSaved).toEqual({});
    expect(heldKey()).toBeNull();
    expect(mockBack).toHaveBeenCalled();
    expect(mockCore.confirmPhantomKeySaved).not.toHaveBeenCalled();
    expect(sequence.markBackedUp).not.toHaveBeenCalled();
    expect(mockEvents).not.toContain('sent');
    expectNoWordCalls();
  });

  it('opened again while the key is held, returns to the card step with no words', async () => {
    const first = renderOn(device);
    mockPut.mockRejectedValueOnce(new CardCancelled());
    await putOnCard();
    fireEvent.press(screen.getByTestId('back'));
    first.unmount();

    renderOn(device);
    await act(async () => {});
    // Not written yet: nothing was dropped, the key is still held.
    expect(forgotSinceStart()).toBe(0);
    expect(heldKey()).toEqual(expect.objectContaining({ step: 'card', words: [], cardOnly: true }));
    expect(screen.getByTestId('vanish-card-only-text')).toHaveTextContent(CARD_ONLY_TEXT);
    expect(screen.getByTestId('vanish-card-retry')).toBeOnTheScreen();
    expect(screen.getByTestId('vanish-cancel')).toBeOnTheScreen();
    expect(screen.queryByTestId('vanish-amount')).toBeNull();
    expectNoWords();

    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-card-retry'));
    });
    expect(mockCore.confirmPhantomKeySaved).toHaveBeenCalledTimes(1);
    expect(onlySequence().markBackedUp).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
    expectNoWordCalls();
  });

  it('opened again once sent, shows its progress, not the card step', async () => {
    const first = renderOn(device);
    await putOnCard();
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
    first.unmount();

    renderOn(device);
    await act(async () => {});
    expect(screen.getByTestId('payment-progress')).toBeOnTheScreen();
    expect(screen.queryByTestId('vanish-card-retry')).toBeNull();
    expect(mockPut).toHaveBeenCalledTimes(1);
    expectNoWords();
    expectNoWordCalls();
  });

  it('keeps the words Vanish as it was', async () => {
    renderOn(device);
    await typeAmount();
    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-make-key'));
    });
    expect(mockCore.prepareVanish).toHaveBeenCalledTimes(1);
    expect(mockCore.prepareCardVanish).not.toHaveBeenCalled();
    expect(mockCore.takePhantomKeyWords).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('phantom-key-word-1')).toHaveTextContent(mockKeyWords[0]);
    expect(mockPut).not.toHaveBeenCalled();
  });
});
