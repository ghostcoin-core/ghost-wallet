import { render, screen } from '@testing-library/react-native';
import { StyleSheet } from 'react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import CardsScreen from '../../app/(tabs)/(cards)/cards';
import { FOLD_GAP } from '../../lib/layout';

jest.mock('expo-router', () => ({ useRouter: () => ({ push: jest.fn() }) }));

const mockWindow = { width: 393, height: 852, scale: 3, fontScale: 1 };
jest.mock('react-native/Libraries/Utilities/useWindowDimensions', () => ({ __esModule: true, default: () => mockWindow }));

const TOP = 47;
// What sits above the top section: the status bar, the page's top padding, and the header with its gap.
const ABOVE = TOP + 4 + 52 + 12;

function renderAt(width: number, height: number, right = 0) {
  mockWindow.width = width;
  mockWindow.height = height;
  return render(
    <SafeAreaProvider initialMetrics={{ frame: { x: 0, y: 0, width, height }, insets: { top: TOP, left: 0, right, bottom: 0 } }}>
      <CardsScreen />
    </SafeAreaProvider>,
  );
}

describe('Cards on the open Duo held upright', () => {
  it('keeps the actions above the fold: the top section ends half a gap above the middle of the screen', () => {
    renderAt(626, 890);

    const top = StyleSheet.flatten(screen.getByTestId('cards-top').props.style);
    expect(ABOVE + top.minHeight + FOLD_GAP / 2).toBe(890 / 2);
  });

  it('does not hold the top section open when held sideways, where the fold runs down the screen', () => {
    renderAt(890, 626, 84);

    expect(StyleSheet.flatten(screen.getByTestId('cards-top').props.style).minHeight).toBeUndefined();
  });

  it('has no fold to keep clear on the folded Duo', () => {
    renderAt(466, 678, 84);

    expect(screen.queryByTestId('cards-top')).toBeNull();
  });
});
