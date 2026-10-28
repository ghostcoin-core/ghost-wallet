// The frame of every phase 1 screen: the top bar (back, test network, logo),
// content that scrolls (the folded iPhone Duo is shorter than the screens) and
// a footer whose buttons always stay in view.
import type { ReactNode } from 'react';
import { KeyboardAvoidingView, ScrollView, StyleSheet, useWindowDimensions, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { screenLayout, type ScreenLayout } from '../lib/layout';
import { colours } from '../lib/theme';
import { BackButton, Logo, TestNetworkBadge } from './onboarding-ui';

// On the open Duo, single-column screens keep one readable centred column.
const READABLE_WIDTH = 520;

export function useScreenLayout(): ScreenLayout {
  return screenLayout(useWindowDimensions().width);
}

type ScreenProps = {
  label: string;
  testID: string;
  /** Shows the top bar with a back button. */
  onBack?: () => void;
  /** Centres the content (welcome, lock). */
  centred?: boolean;
  /** The content spans the open Duo's full width, for screens with two columns. */
  wide?: boolean;
  footer?: ReactNode;
  children: ReactNode;
};

export function Screen({ label, testID, onBack, centred, wide, footer, children }: ScreenProps) {
  const insets = useSafeAreaInsets();
  const twoColumn = useScreenLayout() === 'two-column';
  const column = twoColumn && !wide ? styles.readable : null;

  return (
    <View
      accessibilityLabel={label}
      style={[styles.page, { paddingTop: insets.top, paddingBottom: Math.max(insets.bottom, 16) }]}
      testID={testID}
    >
      {onBack ? (
        <View style={styles.topBar}>
          <BackButton onPress={onBack} />
          <View style={styles.grow} />
          <TestNetworkBadge />
          <Logo />
        </View>
      ) : null}
      <KeyboardAvoidingView behavior="padding" style={styles.grow}>
        <ScrollView
          contentContainerStyle={[
            styles.content,
            twoColumn && wide && styles.contentWide,
            centred && styles.centred,
            column,
          ]}
          keyboardShouldPersistTaps="handled"
          style={styles.grow}
          testID={`${testID}-scroll`}
        >
          {children}
        </ScrollView>
        {footer ? <View style={[styles.footer, column]}>{footer}</View> : null}
      </KeyboardAvoidingView>
    </View>
  );
}

const styles = StyleSheet.create({
  page: {
    flex: 1,
    backgroundColor: colours.paper,
  },
  grow: {
    flex: 1,
  },
  topBar: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    minHeight: 56,
    paddingHorizontal: 16,
  },
  content: {
    flexGrow: 1,
    gap: 16,
    paddingVertical: 8,
    paddingHorizontal: 24,
  },
  contentWide: {
    paddingHorizontal: 32,
  },
  centred: {
    justifyContent: 'center',
    alignItems: 'center',
    gap: 12,
  },
  readable: {
    width: '100%',
    maxWidth: READABLE_WIDTH,
    alignSelf: 'center',
  },
  footer: {
    gap: 8,
    paddingTop: 16,
    paddingHorizontal: 24,
    paddingBottom: 24,
  },
});
