import { render, screen } from '@testing-library/react-native';

import HomeScreen from '../app/home';
import { buildNetwork } from '../lib/network/build-network';

jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn(), back: jest.fn() }) }));
jest.mock(
  '../modules/ghost-core/src/index',
  () => ({ savedAccountZeroAddress: () => '0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd' }),
  { virtual: true },
);
jest.mock('../lib/storage', () => ({
  jsonFile: () => ({ read: () => null, write: async () => {} }),
}));
jest.mock('../lib/home/read-account', () => ({ readAccountZero: () => new Promise(() => {}) }));
// The node always says it is the test network here: only the build decides.
jest.mock('../lib/node/test-network', () => ({ useTestNetwork: () => true }));

// Home reads this copy of the dev network; each test sets its flag.
jest.mock('../lib/network/build-network', () => {
  const actual = jest.requireActual('../lib/network/build-network');
  return { ...actual, buildNetwork: { ...actual.DEV_NETWORK } };
});
const mockNetwork = buildNetwork as { realValue: boolean };

afterEach(() => {
  mockNetwork.realValue = false;
});

describe('Get test GHOST on Home', () => {
  it('shows on a chain without value', () => {
    render(<HomeScreen />);
    expect(screen.getByTestId('get-test-ghost')).toBeOnTheScreen();
  });

  it('is hidden on a chain with real value, though the node says test network', () => {
    mockNetwork.realValue = true;
    render(<HomeScreen />);
    expect(screen.queryByTestId('get-test-ghost')).toBeNull();
    expect(screen.getByTestId('open-send')).toBeOnTheScreen();
  });
});
