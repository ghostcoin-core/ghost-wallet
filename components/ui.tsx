// The building blocks of the app's screens, after docs/mockups/mockups.css.
import type { ReactNode } from 'react';
import { Image, Pressable, ScrollView, StyleSheet, Text, View, type StyleProp, type ViewStyle } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { useLayout } from '../lib/layout';
import { Icon, type IconName } from './icons';
import { colors, monoFont } from './theme';

// The kit's primary logo, for light backgrounds.
const LOGO = require('../brand/png/ghost-logo-primary-256.png');

type ScreenProps = {
  testID: string;
  /** Paper (white) or Mist (the page behind cards). */
  background?: 'paper' | 'mist';
  topBar: ReactNode;
  children: ReactNode;
  /**
   * On the iPhone Duo open, how the two children sit: `columns` flows them
   * as two columns of cards, `split` as two equal halves, one each side of
   * the fold with nothing in it. Elsewhere they stack.
   */
  wide?: 'columns' | 'split';
};

/**
 * A screen: a top bar, then the content, which scrolls so every field and
 * button can be reached on the folded Duo.
 */
export function Screen({ testID, background = 'paper', topBar, children, wide }: ScreenProps) {
  const { twoColumns } = useLayout();
  const pageColor = background === 'mist' ? colors.mist : colors.paper;
  const split = twoColumns && wide !== undefined;
  return (
    <SafeAreaView edges={['top', 'left', 'right']} style={[styles.page, { backgroundColor: pageColor }]} testID={testID}>
      <View style={styles.topBar}>{topBar}</View>
      <ScrollView
        style={styles.scroll}
        contentContainerStyle={[
          styles.content,
          twoColumns && !split && styles.contentCentered,
          split && (wide === 'split' ? styles.split : styles.columns),
        ]}
        testID={`${testID}-content`}
      >
        {children}
      </ScrollView>
    </SafeAreaView>
  );
}

/** One column of a two-column screen; stacks on a phone or the folded Duo. */
export function Column({ children, style }: { children: ReactNode; style?: StyleProp<ViewStyle> }) {
  const { twoColumns } = useLayout();
  return <View style={[styles.column, twoColumns && styles.columnWide, style]}>{children}</View>;
}

export function Logo() {
  return (
    <View style={styles.logo}>
      <Image source={LOGO} style={styles.logoImage} accessibilityLabel="Ghost" accessibilityRole="image" />
    </View>
  );
}

export function NetworkBadge({ background = colors.mist }: { background?: string }) {
  return (
    <View style={[styles.badge, { backgroundColor: background }]}>
      <Icon name="dot" size={14} color={colors.body} />
      <Text style={styles.badgeText}>Test network</Text>
    </View>
  );
}

export function Spacer() {
  return <View style={styles.spacer} />;
}

export function IconButton({
  icon,
  label,
  onPress,
  background = colors.paper,
  testID,
}: {
  icon: IconName;
  label: string;
  onPress: () => void;
  background?: string;
  testID?: string;
}) {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={label}
      onPress={onPress}
      hitSlop={4}
      style={[styles.iconButton, { backgroundColor: background }]}
      testID={testID}
    >
      <Icon name={icon} />
    </Pressable>
  );
}

export function Button({
  label,
  icon,
  onPress,
  secondary,
  disabled,
  testID,
}: {
  label: string;
  icon?: IconName;
  onPress: () => void;
  secondary?: boolean;
  disabled?: boolean;
  testID?: string;
}) {
  const color = secondary ? colors.ink : colors.paper;
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ disabled: !!disabled }}
      disabled={disabled}
      onPress={onPress}
      style={({ pressed }) => [
        styles.button,
        secondary && styles.buttonSecondary,
        (pressed || disabled) && styles.buttonDimmed,
      ]}
      testID={testID}
    >
      {icon ? <Icon name={icon} color={color} /> : null}
      <Text style={[styles.buttonText, { color }]}>{label}</Text>
    </Pressable>
  );
}

export function ButtonRow({ children }: { children: ReactNode }) {
  return <View style={styles.buttonRow}>{children}</View>;
}

export function Panel({ children, style, testID }: { children: ReactNode; style?: StyleProp<ViewStyle>; testID?: string }) {
  return (
    <View style={[styles.panel, style]} testID={testID}>
      {children}
    </View>
  );
}

export function SectionTitle({ children }: { children: string }) {
  return (
    <Text accessibilityRole="header" style={styles.sectionTitle}>
      {children}
    </Text>
  );
}

export function Title({ children }: { children: string }) {
  return (
    <Text accessibilityRole="header" style={styles.title}>
      {children}
    </Text>
  );
}

type RowProps = {
  icon: IconName;
  title: string;
  detail?: string;
  detailMono?: boolean;
  /** What sits at the end of the row: a value, a switch, an amount. */
  end?: ReactNode;
  onPress?: () => void;
  /** A chevron at the end, for rows that open another screen. */
  opens?: boolean;
  first?: boolean;
  testID?: string;
  accessibilityLabel?: string;
};

export function Row({ icon, title, detail, detailMono, end, onPress, opens, first, testID, accessibilityLabel }: RowProps) {
  const body = (
    <>
      <View style={styles.rowIcon}>
        <Icon name={icon} />
      </View>
      <View style={styles.rowText}>
        <Text numberOfLines={1} style={styles.rowTitle}>
          {title}
        </Text>
        {detail ? (
          <Text style={[styles.rowDetail, detailMono && styles.mono]} testID={testID ? `${testID}-detail` : undefined}>
            {detail}
          </Text>
        ) : null}
      </View>
      {end}
      {opens ? <Icon name="chevron" color={colors.quiet} /> : null}
    </>
  );
  const style = [styles.row, !first && styles.rowDivider];
  if (onPress) {
    return (
      <Pressable
        accessibilityRole="button"
        accessibilityLabel={accessibilityLabel}
        onPress={onPress}
        style={({ pressed }) => [style, pressed && styles.rowPressed]}
        testID={testID}
      >
        {body}
      </Pressable>
    );
  }
  return (
    <View style={style} testID={testID} accessibilityLabel={accessibilityLabel}>
      {body}
    </View>
  );
}

export const textStyles = StyleSheet.create({
  body: {
    color: colors.body,
    fontSize: 16,
    lineHeight: 22,
  },
  quiet: {
    color: colors.quiet,
    fontSize: 14,
  },
});

const styles = StyleSheet.create({
  page: {
    flex: 1,
  },
  topBar: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    minHeight: 56,
    paddingHorizontal: 16,
  },
  scroll: {
    flex: 1,
  },
  content: {
    flexGrow: 1,
    gap: 16,
    paddingHorizontal: 24,
    paddingTop: 8,
    paddingBottom: 40,
  },
  contentCentered: {
    width: '100%',
    maxWidth: 520,
    alignSelf: 'center',
  },
  columns: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 24,
    paddingHorizontal: 32,
  },
  split: {
    flexDirection: 'row',
    alignItems: 'stretch',
    gap: 56,
    paddingHorizontal: 32,
    paddingTop: 16,
    paddingBottom: 32,
  },
  column: {
    gap: 16,
  },
  columnWide: {
    flex: 1,
    minWidth: 0,
  },
  logo: {
    padding: 8,
  },
  logoImage: {
    width: 28,
    height: 28,
  },
  badge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    paddingVertical: 4,
    paddingHorizontal: 10,
    borderWidth: 1,
    borderColor: colors.line,
    borderRadius: 999,
  },
  badgeText: {
    color: colors.body,
    fontSize: 13,
    fontWeight: '500',
  },
  spacer: {
    flex: 1,
  },
  iconButton: {
    alignItems: 'center',
    justifyContent: 'center',
    width: 44,
    height: 44,
    borderRadius: 22,
  },
  button: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
    minHeight: 52,
    paddingHorizontal: 16,
    borderWidth: 1,
    borderColor: colors.violet,
    borderRadius: 14,
    backgroundColor: colors.violet,
  },
  buttonSecondary: {
    borderColor: colors.line,
    backgroundColor: colors.paper,
  },
  buttonDimmed: {
    opacity: 0.6,
  },
  buttonText: {
    fontSize: 16,
    fontWeight: '600',
  },
  buttonRow: {
    flexDirection: 'row',
    gap: 12,
  },
  panel: {
    borderWidth: 1,
    borderColor: colors.line,
    borderRadius: 16,
    backgroundColor: colors.paper,
    overflow: 'hidden',
  },
  sectionTitle: {
    marginTop: 8,
    color: colors.quiet,
    fontSize: 13,
    fontWeight: '600',
    letterSpacing: 0.26,
  },
  title: {
    color: colors.ink,
    fontSize: 28,
    fontWeight: '600',
    letterSpacing: -0.84,
  },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    minHeight: 56,
    paddingVertical: 10,
    paddingHorizontal: 16,
  },
  rowDivider: {
    borderTopWidth: 1,
    borderTopColor: colors.line,
  },
  rowPressed: {
    backgroundColor: colors.mist,
  },
  rowIcon: {
    alignItems: 'center',
    justifyContent: 'center',
    width: 36,
    height: 36,
    borderRadius: 18,
    backgroundColor: colors.mist,
  },
  rowText: {
    flex: 1,
    minWidth: 0,
  },
  rowTitle: {
    color: colors.ink,
    fontSize: 16,
    fontWeight: '500',
  },
  rowDetail: {
    color: colors.quiet,
    fontSize: 13,
  },
  mono: {
    fontFamily: monoFont,
  },
});
