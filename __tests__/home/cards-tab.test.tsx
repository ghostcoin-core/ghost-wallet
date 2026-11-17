import { fireEvent, render, screen } from '@testing-library/react-native';

import CardsScreen from '../../app/(tabs)/cards';

const mockPush = jest.fn();

jest.mock('expo-router', () => ({
  useRouter: () => ({ push: mockPush }),
}));

beforeEach(() => {
  mockPush.mockClear();
});

describe('Cards tab', () => {
  it.each([
    ['cards-check', '/check-card'],
    ['cards-fill', '/fill-ghost-card'],
    ['cards-open', '/open-ghost-card'],
    ['cards-fill-ntag', '/fill-card'],
    ['cards-open-ntag', '/open-card'],
    ['cards-wipe-ntag', '/wipe-card'],
  ])('%s opens %s', (testID, route) => {
    render(<CardsScreen />);

    fireEvent.press(screen.getByTestId(testID));

    expect(mockPush.mock.calls).toEqual([[route]]);
  });
});
