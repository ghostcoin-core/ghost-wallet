import { render, screen } from '@testing-library/react-native';
import { StyleSheet } from 'react-native';

import HomeScreen from '../app/index';

describe('HomeScreen', () => {
  it('shows the Ghost Wallet title as the page header', () => {
    render(<HomeScreen />);

    expect(screen.getByRole('header', { name: 'Ghost Wallet' })).toBeOnTheScreen();
  });

  it('uses the dark page colour', () => {
    render(<HomeScreen />);

    const page = StyleSheet.flatten(screen.getByTestId('home-screen').props.style);
    expect(page.backgroundColor).toBe('#0A0A12');
  });
});
