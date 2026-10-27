import { render, screen } from '@testing-library/react-native';

import HomeScreen from '../app/index';
import { TEST_WORDS } from '../modules/ghost-core/test-words';

// Account 0 (rescue-key scheme 0x0003) of Ghost's counting-bytes test seed,
// the first vector of client/tests/rescue_accounts.rs in the ghost repository.
const EXPECTED_ADDRESS = '0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd';

const COUNTING_SEED_WORDS =
  'abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware';

// The generated native bindings run only on the phone. This stand-in answers
// like the Rust core: the expected address for the counting-seed words only.
const mockAccountZeroAddress = jest.fn((words: string): string => {
  if (words !== COUNTING_SEED_WORDS) {
    throw new Error('invalid account words');
  }
  return EXPECTED_ADDRESS;
});

jest.mock(
  '../modules/ghost-core/src/index',
  () => ({ accountZeroAddress: (words: string) => mockAccountZeroAddress(words) }),
  { virtual: true },
);

describe('Account 0 on the home screen', () => {
  beforeEach(() => {
    mockAccountZeroAddress.mockClear();
  });

  it('shows the address the native core derives from the fixed test words', () => {
    render(<HomeScreen />);

    expect(screen.getByText('Account 0')).toBeOnTheScreen();
    expect(screen.getByTestId('account-zero-address')).toHaveTextContent(EXPECTED_ADDRESS);
    expect(screen.getByText('test words')).toBeOnTheScreen();
    expect(mockAccountZeroAddress).toHaveBeenCalledWith(COUNTING_SEED_WORDS);
  });

  it('uses the words of the counting-bytes test seed', () => {
    expect(TEST_WORDS).toBe(COUNTING_SEED_WORDS);
    expect(TEST_WORDS.split(' ')).toHaveLength(24);
  });

  it('never puts the words on the screen', () => {
    render(<HomeScreen />);

    expect(screen.queryByText(TEST_WORDS, { exact: false })).toBeNull();
    expect(screen.queryByText('abandon amount liar', { exact: false })).toBeNull();
  });

  it('says the address is unavailable when the native core fails', () => {
    mockAccountZeroAddress.mockImplementationOnce(() => {
      throw new Error('native core missing');
    });

    render(<HomeScreen />);

    expect(screen.getByTestId('account-zero-address')).toHaveTextContent('Address unavailable');
    expect(screen.queryByText(EXPECTED_ADDRESS)).toBeNull();
  });
});
