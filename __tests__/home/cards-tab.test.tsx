import { fireEvent, render, screen } from '@testing-library/react-native';

import CardsScreen from '../../app/(tabs)/cards';
import OlderCardsScreen from '../../app/older-cards';

const mockPush = jest.fn();
const mockBack = jest.fn();

jest.mock('expo-router', () => ({
  useRouter: () => ({ push: mockPush, back: mockBack }),
}));

beforeEach(() => {
  mockPush.mockClear();
  mockBack.mockClear();
});

describe('Cards tab', () => {
  it.each([
    ['cards-check', '/check-card'],
    ['cards-fill', '/fill-ghost-card'],
    ['cards-open', '/open-ghost-card'],
    ['cards-older', '/older-cards'],
  ])('%s opens %s', (testID, route) => {
    render(<CardsScreen />);

    fireEvent.press(screen.getByTestId(testID));

    expect(mockPush.mock.calls).toEqual([[route]]);
  });

  it('has one button to check a card, and says what to do after pressing it', () => {
    render(<CardsScreen />);

    expect(screen.getAllByRole('button', { name: 'Check a card' })).toHaveLength(1);
    expect(screen.getByText('Press the button, then hold the card to the back of your phone.')).toBeOnTheScreen();
  });

  it('explains how cards work in four notes under their own heading', () => {
    render(<CardsScreen />);

    expect(screen.getByRole('header', { name: 'How cards work' })).toBeOnTheScreen();
    expect(screen.getAllByTestId(/^cards-note-/)).toHaveLength(4);
  });
});

describe('Older cards', () => {
  it.each([
    ['older-cards-fill', '/fill-card'],
    ['older-cards-open', '/open-card'],
    ['older-cards-wipe', '/wipe-card'],
  ])('%s opens %s', (testID, route) => {
    render(<OlderCardsScreen />);

    fireEvent.press(screen.getByTestId(testID));

    expect(mockPush.mock.calls).toEqual([[route]]);
  });

  it('goes back', () => {
    render(<OlderCardsScreen />);

    fireEvent.press(screen.getByTestId('back'));

    expect(mockBack).toHaveBeenCalledTimes(1);
  });
});
