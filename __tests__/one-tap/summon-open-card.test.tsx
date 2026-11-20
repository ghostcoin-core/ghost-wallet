// Summon's Open a card is the go-ahead: Open a card starts the card read at
// once, so the next thing to do is hold the card to the phone.
import { act, fireEvent, render, screen } from '@testing-library/react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import SummonScreen from '../../app/(tabs)/(home)/summon';

const mockCore = {
  checkKeyWords: jest.fn(() => ({ verdict: 'phantom-key', position: 0 })),
  forgetCardKey: jest.fn(),
  savedAccountZeroAddress: () => '0x00000000000000000000000000000000000000aa',
  hasAccount: () => true,
};
jest.mock('../../modules/ghost-core/src/index', () => mockCore, { virtual: true });

jest.mock('../../lib/vanish/use-payment', () => ({
  paymentKit: () => ({ core: mockCore, store: { list: () => [], remove: jest.fn() }, node: {}, nodeUrl: 'http://127.0.0.1:8547' }),
  usePayment: () => null,
}));
jest.mock('../../lib/vanish/actions', () => ({
  CARD_KEY: { card: true },
  lookUpKey: jest.fn(),
  proveRevealAgain: () => async () => ({ signed: new ArrayBuffer(1) }),
  startReveal: jest.fn(),
}));
jest.mock('../../modules/ghost-nfc', () => ({
  ...jest.requireActual('../../modules/ghost-nfc'),
  cardsSupported: () => true,
}));
jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));
const mockPush = jest.fn();
jest.mock('expo-router', () => ({ useRouter: () => ({ push: mockPush, back: jest.fn() }) }));

it('Open a card goes straight to the card read', async () => {
  render(
    <SafeAreaProvider
      initialMetrics={{ frame: { x: 0, y: 0, width: 393, height: 852 }, insets: { top: 47, left: 0, right: 0, bottom: 34 } }}
    >
      <SummonScreen />
    </SafeAreaProvider>,
  );
  expect(screen.getByTestId('summon-open-card')).toHaveTextContent('Open a card');
  await act(async () => {
    fireEvent.press(screen.getByTestId('summon-open-card'));
  });
  expect(mockPush).toHaveBeenCalledWith({ pathname: '/open-ghost-card', params: { start: '1' } });
});
