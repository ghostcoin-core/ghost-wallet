import { render, screen } from '@testing-library/react-native';
import { StyleSheet } from 'react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import ReceiveScreen from '../../app/receive';
import { FOLD_GAP } from '../../lib/layout';

const ADDRESS = '0x00000000000000000000000000000000000000aa';

jest.mock('../../lib/account', () => ({ accountZeroAddress: () => ADDRESS }));
jest.mock('expo-router', () => ({ useRouter: () => ({ back: jest.fn() }) }));
jest.mock('expo-clipboard', () => ({ setStringAsync: jest.fn() }));
jest.mock('react-native-qrcode-svg', () => {
  const { View } = jest.requireActual('react-native');
  return { __esModule: true, default: ({ size }: { size: number }) => <View testID="qr-code" accessibilityValue={{ now: size }} /> };
});

const mockWindow = { width: 393, height: 852, scale: 3, fontScale: 1 };
jest.mock('react-native/Libraries/Utilities/useWindowDimensions', () => ({ __esModule: true, default: () => mockWindow }));

const TOP = 47;

function renderAt(width: number, height: number, right = 0) {
  mockWindow.width = width;
  mockWindow.height = height;
  return render(
    <SafeAreaProvider initialMetrics={{ frame: { x: 0, y: 0, width, height }, insets: { top: TOP, left: 0, right, bottom: 0 } }}>
      <ReceiveScreen />
    </SafeAreaProvider>,
  );
}

function parts() {
  return { first: screen.getByTestId('receive-screen-first'), holder: screen.getByTestId('receive-screen-parts') };
}

describe('Receive around the fold', () => {
  it('stacks the code over the address on the folded Duo, and shows both', () => {
    renderAt(466, 678, 84);

    expect(screen.getByTestId('receive-address')).toHaveTextContent(ADDRESS);
    expect(screen.getByTestId('copy-address')).toBeOnTheScreen();
    expect(screen.getByTestId('share-address')).toBeOnTheScreen();
    expect(screen.queryByTestId('receive-screen-parts')).toBeNull();
  });

  it('held sideways, puts the code left of the fold: its part ends half a gap before the middle of the screen', () => {
    renderAt(890, 626, 84);
    const { first, holder } = parts();

    expect(StyleSheet.flatten(holder.props.style)).toMatchObject({ flexDirection: 'row', gap: FOLD_GAP });
    expect(28 + StyleSheet.flatten(first.props.style).width + FOLD_GAP / 2).toBe(890 / 2);
  });

  it('held upright, puts the code above the fold: its part is tall enough to end half a gap above the middle', () => {
    renderAt(626, 890);
    const { first, holder } = parts();
    const above = TOP + 4 + 52 + 12;

    expect(StyleSheet.flatten(holder.props.style)).toMatchObject({ gap: FOLD_GAP });
    expect(StyleSheet.flatten(holder.props.style).flexDirection).toBeUndefined();
    expect(above + StyleSheet.flatten(first.props.style).minHeight + FOLD_GAP / 2).toBe(890 / 2);
  });

  it('held upright, sizes the code to fit above the fold', () => {
    renderAt(626, 890);
    const above = TOP + 4 + 52 + 12;
    const room = 890 / 2 - above - FOLD_GAP / 2;

    expect(screen.getByTestId('qr-code').props.accessibilityValue.now + 2 * (16 + 16)).toBeLessThanOrEqual(room);
  });
});
