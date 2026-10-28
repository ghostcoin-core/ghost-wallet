// Building blocks of the onboarding screens (welcome, backup, check, import and
// lock), after docs/mockups/mockups.css.
import type { ReactNode } from 'react';
import {
  Image,
  Pressable,
  StyleSheet,
  Text,
  View,
  type StyleProp,
  type TextStyle,
  type ViewStyle,
} from 'react-native';

import { colours, fonts } from '../lib/theme';

const LOGO = require('../brand/png/ghost-logo-primary-256.png');
const LOCKUP = require('../brand/png/ghost-lockup-primary-2400.png');
const APP_ICON = require('../brand/app-icon/ghost-app-icon-violet-512.png');

// brand/svg/ghost-lockup-primary.svg is 486.3 x 130.9.
const LOCKUP_RATIO = 486.31339 / 130.89999;

export function Title({ children, style }: { children: ReactNode; style?: StyleProp<TextStyle> }) {
  return (
    <Text accessibilityRole="header" style={[styles.title, style]}>
      {children}
    </Text>
  );
}

export function Body({ children, quiet, style }: { children: ReactNode; quiet?: boolean; style?: StyleProp<TextStyle> }) {
  return <Text style={[quiet ? styles.quiet : styles.body, style]}>{children}</Text>;
}

type ButtonProps = {
  label: string;
  onPress(): void;
  variant?: 'primary' | 'secondary';
  disabled?: boolean;
  icon?: ReactNode;
  testID?: string;
};

export function Button({ label, onPress, variant = 'primary', disabled, icon, testID }: ButtonProps) {
  const secondary = variant === 'secondary';
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ disabled: !!disabled }}
      disabled={disabled}
      onPress={onPress}
      style={({ pressed }) => [
        styles.button,
        secondary && styles.buttonSecondary,
        disabled && styles.buttonDisabled,
        pressed && styles.buttonPressed,
      ]}
      testID={testID}
    >
      {icon}
      <Text style={[styles.buttonLabel, secondary && styles.buttonLabelSecondary]}>{label}</Text>
    </Pressable>
  );
}

export function TestNetworkBadge() {
  return (
    <View style={styles.badge} testID="test-network-badge">
      <View style={styles.badgeDot} />
      <Text style={styles.badgeText}>Test network</Text>
    </View>
  );
}

/** The logo with its clear space of one square on every side. */
export function Logo() {
  return (
    <View style={styles.logo}>
      <Image accessibilityLabel="Ghost" source={LOGO} style={styles.logoImage} />
    </View>
  );
}

export function Lockup({ width = 220 }: { width?: number }) {
  return (
    <View style={styles.lockup}>
      <Image accessibilityLabel="ghost" source={LOCKUP} style={{ width, height: width / LOCKUP_RATIO }} />
    </View>
  );
}

export function AppIcon() {
  return (
    <View style={styles.appIconSpace}>
      <Image accessibilityLabel="Ghost Wallet" source={APP_ICON} style={styles.appIcon} />
    </View>
  );
}

export function BackButton({ onPress }: { onPress(): void }) {
  return (
    <Pressable
      accessibilityLabel="Back"
      accessibilityRole="button"
      hitSlop={4}
      onPress={onPress}
      style={styles.iconButton}
      testID="back-button"
    >
      <View style={styles.chevron} />
    </Pressable>
  );
}

export function Highlight({ children }: { children: ReactNode }) {
  return (
    <View style={styles.highlight}>
      <View style={styles.highlightMark} />
      <Text style={styles.highlightText}>{children}</Text>
    </View>
  );
}

export function Strong({ children }: { children: ReactNode }) {
  return <Text style={styles.strong}>{children}</Text>;
}

/** The 1-to-24 slots of the backup screen, three to a row. */
export function WordGrid({ words, style }: { words: readonly string[]; style?: StyleProp<ViewStyle> }) {
  return (
    <View accessibilityLabel="Your 24 backup words" style={[styles.grid, style]} testID="word-grid">
      {words.map((word, index) => (
        <View key={index} style={styles.gridCell}>
          <View style={styles.wordSlot}>
            <Text style={styles.wordNumber}>{index + 1}</Text>
            <Text style={styles.word} testID={`backup-word-${index + 1}`}>
              {word}
            </Text>
          </View>
        </View>
      ))}
    </View>
  );
}

export const styles = StyleSheet.create({
  title: {
    color: colours.ink,
    fontFamily: fonts.sans,
    fontSize: 28,
    fontWeight: '600',
    lineHeight: 32,
    letterSpacing: -0.84,
  },
  body: {
    color: colours.body,
    fontFamily: fonts.sans,
    fontSize: 16,
    lineHeight: 22,
  },
  quiet: {
    color: colours.quiet,
    fontFamily: fonts.sans,
    fontSize: 14,
    lineHeight: 20,
  },
  strong: {
    fontWeight: '600',
  },
  button: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
    minHeight: 52,
    paddingHorizontal: 20,
    borderWidth: 1,
    borderColor: colours.violet,
    borderRadius: 14,
    backgroundColor: colours.violet,
  },
  buttonSecondary: {
    borderColor: colours.line,
    backgroundColor: colours.paper,
  },
  buttonDisabled: {
    opacity: 0.45,
  },
  buttonPressed: {
    opacity: 0.8,
  },
  buttonLabel: {
    color: colours.paper,
    fontFamily: fonts.sans,
    fontSize: 16,
    fontWeight: '600',
  },
  buttonLabelSecondary: {
    color: colours.ink,
  },
  badge: {
    flexDirection: 'row',
    alignItems: 'center',
    alignSelf: 'center',
    gap: 6,
    paddingVertical: 4,
    paddingHorizontal: 10,
    borderWidth: 1,
    borderColor: colours.line,
    borderRadius: 999,
    backgroundColor: colours.mist,
  },
  badgeDot: {
    width: 10,
    height: 10,
    borderWidth: 1.75,
    borderColor: colours.body,
    borderRadius: 5,
  },
  badgeText: {
    color: colours.body,
    fontFamily: fonts.sans,
    fontSize: 13,
    fontWeight: '500',
  },
  logo: {
    padding: 8,
  },
  logoImage: {
    width: 28,
    height: 28,
  },
  lockup: {
    padding: 16,
  },
  appIconSpace: {
    padding: 24,
  },
  appIcon: {
    width: 88,
    height: 88,
    borderRadius: 20,
  },
  iconButton: {
    alignItems: 'center',
    justifyContent: 'center',
    width: 44,
    height: 44,
    borderRadius: 22,
    backgroundColor: colours.paper,
  },
  chevron: {
    width: 11,
    height: 11,
    marginLeft: 4,
    borderLeftWidth: 1.75,
    borderBottomWidth: 1.75,
    borderColor: colours.ink,
    transform: [{ rotate: '45deg' }],
  },
  highlight: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 10,
    paddingVertical: 12,
    paddingHorizontal: 14,
    borderRadius: 12,
    backgroundColor: colours.violetTint,
  },
  highlightMark: {
    width: 4,
    alignSelf: 'stretch',
    borderRadius: 2,
    backgroundColor: colours.violet,
  },
  highlightText: {
    flex: 1,
    color: colours.ink,
    fontFamily: fonts.sans,
    fontSize: 15,
    lineHeight: 21,
  },
  grid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    marginHorizontal: -4,
  },
  gridCell: {
    width: '33.333%',
    padding: 4,
  },
  wordSlot: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    minHeight: 36,
    paddingHorizontal: 8,
    borderWidth: 1,
    borderColor: colours.line,
    borderRadius: 10,
    backgroundColor: colours.mist,
  },
  wordNumber: {
    minWidth: 18,
    color: colours.quiet,
    fontFamily: fonts.mono,
    fontSize: 12,
  },
  word: {
    flexShrink: 1,
    color: colours.ink,
    fontFamily: fonts.mono,
    fontSize: 14,
  },
});
