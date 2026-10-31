import { act, fireEvent, render, screen } from '@testing-library/react-native';
import type { ComponentType } from 'react';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import SummonScreen from '../../app/summon';
import VanishScreen from '../../app/vanish';
import { PaymentProgress } from '../../components/vanish-ui';
import { failureReason } from '../../lib/node/failure-reason';
import { fromNode, rpcBatch, type FetchLike } from '../../lib/node/rpc';

const NODE = 'http://192.168.1.36:8547';

describe('failureReason', () => {
  it.each([
    [new TypeError('Network request failed'), `Can't reach the test node at ${NODE}. Check that it is running and that this phone is on the same network.`],
    [new Error('the node did not answer in time'), `The test node at ${NODE} did not answer in time. Check that it is running and try again.`],
    [new Error('the node answered HTTP 503'), `The test node at ${NODE} answered with an error (HTTP 503).`],
    [new Error('the node is not the Ghost test network'), `The node at ${NODE} is not the Ghost test network. Check the node in Settings.`],
    [
      new Error('the node refused a call: insufficient funds for gas * price + value: balance 0'),
      'Not enough test GHOST in this account for the amount and its fee. Tap Get test GHOST on Home.',
    ],
    [new Error('InsufficientBalance'), 'Not enough test GHOST in this account for the amount and its fee. Tap Get test GHOST on Home.'],
    [new Error('the node refused a call: nonce too low'), 'Another payment from this account went first. Try again.'],
    [new Error('the node refused a call: transaction underpriced'), 'The fee was too low for the test node. Try again.'],
    [new Error('the node sent a malformed chain id'), `The test node at ${NODE} sent an answer this app cannot read.`],
    [new Error('the node refused a call: invalid sender'), `The test node at ${NODE} refused it: invalid sender.`],
    [new Error('the node refused a call: no reason given'), `The test node at ${NODE} refused it and gave no reason.`],
    [new Error('this key does not hold the coin of this Summon'), 'This key does not hold the coin of this Summon.'],
  ])('words %p in plain words', (error, expected) => {
    expect(failureReason(error, NODE)).toBe(expected);
  });

  it('never says only "Transaction failed"', () => {
    for (const error of [new Error('Transaction failed'), new Error('transaction failed.'), new Error(''), 'Transaction failed', null, {}]) {
      const reason = failureReason(error, NODE);
      expect(reason).not.toMatch(/^transaction failed\.?$/i);
      expect(reason).toBe(`The test node at ${NODE} did not take it and gave no reason.`);
    }
  });
});

describe('PaymentProgress', () => {
  it('shows the reason while it tries again', () => {
    render(<PaymentProgress status="sent" kind="vanish" error={failureReason(new TypeError('Network request failed'), NODE)} />);
    expect(screen.getByTestId('payment-error')).toHaveTextContent(
      `Can't reach the test node at ${NODE}. Check that it is running and that this phone is on the same network. Trying again.`,
    );
  });
});

// The Vanish and Summon screens, with the core and the node mocked.
const mockCore = {
  checkKeyWords: jest.fn(() => ({ verdict: 'phantom-key', position: 0 })),
  checkPhantomKeyWord: jest.fn(() => true),
  confirmPhantomKeySaved: jest.fn(),
  forgetPhantomKey: jest.fn(),
  forgetCardKey: jest.fn(),
  savedAccountZeroAddress: () => '0x00000000000000000000000000000000000000aa',
  hasAccount: () => true,
};
jest.mock('../../modules/ghost-core/src/index', () => mockCore, { virtual: true });
jest.mock('../../lib/vanish/use-payment', () => ({
  paymentKit: () => ({ core: mockCore, store: { list: () => [], remove: jest.fn() }, node: {}, nodeUrl: 'http://192.168.1.36:8547' }),
  usePayment: () => null,
}));

let mockMinimum: () => Promise<bigint>;
const mockStartVanish = jest.fn();
const mockLookUp = jest.fn();
jest.mock('../../lib/vanish/actions', () => ({
  CARD_KEY: { card: true },
  minimumVanish: () => mockMinimum(),
  vanishFee: () => new Promise(() => {}),
  startVanish: (...args: unknown[]) => mockStartVanish(...args),
  lookUpKey: (...args: unknown[]) => mockLookUp(...args),
  signVanishAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
  proveRevealAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
  startReveal: jest.fn(),
}));
jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));
jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: jest.fn() }) }));

function renderScreen(Screen: ComponentType) {
  return render(
    <SafeAreaProvider
      initialMetrics={{ frame: { x: 0, y: 0, width: 393, height: 852 }, insets: { top: 47, left: 0, right: 0, bottom: 34 } }}
    >
      <Screen />
    </SafeAreaProvider>,
  );
}

describe('a failed Vanish', () => {
  beforeEach(() => {
    mockMinimum = async () => 10n ** 17n;
    mockStartVanish.mockReset();
  });

  it('says there is not enough test GHOST, not only that it failed', async () => {
    mockStartVanish.mockRejectedValue(new Error('the node refused a call: insufficient funds for gas * price + value'));
    renderScreen(VanishScreen);
    await act(async () => {});

    fireEvent.changeText(screen.getByTestId('vanish-amount'), '1');
    await act(async () => {
      fireEvent.press(screen.getByTestId('vanish-make-key'));
    });

    expect(screen.getByTestId('vanish-error')).toHaveTextContent(
      'The Vanish could not start. Not enough test GHOST in this account for the amount and its fee. Tap Get test GHOST on Home.',
    );
  });

  it('says it cannot reach the test node as soon as the screen opens', async () => {
    mockMinimum = async () => {
      throw new TypeError('Network request failed');
    };
    renderScreen(VanishScreen);
    await act(async () => {});

    expect(screen.getByTestId('vanish-error')).toHaveTextContent(/^Can't reach the test node at http:\/\/192\.168\.1\.36:8547\./);
  });
});

describe('a failed Summon lookup', () => {
  it('says it cannot reach the test node', async () => {
    mockMinimum = async () => 10n ** 17n;
    mockLookUp.mockRejectedValue(new TypeError('Network request failed'));
    renderScreen(SummonScreen);
    await act(async () => {});

    fireEvent.changeText(screen.getByTestId('summon-key'), Array.from({ length: 24 }, () => 'abandon').join(' '));
    await act(async () => {
      fireEvent.press(screen.getByTestId('summon-find'));
    });

    expect(screen.getByTestId('summon-error')).toHaveTextContent(
      /^The coins could not be looked up\. Can't reach the test node at http:\/\/192\.168\.1\.36:8547\./,
    );
  });

  it('names the backup node when it was the backup node that timed out', async () => {
    const backup = 'http://backup-node.test:8545';
    const silent: FetchLike = (_url, init) =>
      new Promise((_, reject) => init.signal?.addEventListener('abort', () => reject(new Error('Aborted'))));
    const timedOut = await rpcBatch(backup, [['eth_chainId', []]], silent, 5).catch((error: unknown) => error);
    mockMinimum = async () => 10n ** 17n;
    mockLookUp.mockRejectedValue(timedOut);
    renderScreen(SummonScreen);
    await act(async () => {});

    fireEvent.changeText(screen.getByTestId('summon-key'), Array.from({ length: 24 }, () => 'abandon').join(' '));
    await act(async () => {
      fireEvent.press(screen.getByTestId('summon-find'));
    });

    const message = screen.getByTestId('summon-error');
    expect(message).toHaveTextContent(
      `The coins could not be looked up. The test node at ${backup} did not answer in time. Check that it is running and try again.`,
    );
    expect(message).not.toHaveTextContent(NODE);
  });
});

describe('a failed Vanish on a backup node', () => {
  it('names the node that failed, not the node in Settings', async () => {
    const backup = 'http://backup-node.test:8545';
    mockMinimum = async () => {
      throw fromNode(new Error('the node answered HTTP 503'), backup);
    };
    renderScreen(VanishScreen);
    await act(async () => {});

    expect(screen.getByTestId('vanish-error')).toHaveTextContent(`The test node at ${backup} answered with an error (HTTP 503).`);
  });
});
