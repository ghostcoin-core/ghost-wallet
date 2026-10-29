// The "Skip the check" box on the word-check screens (the new account's
// recovery words, and the Phantom Key after Vanish). It starts unticked on
// every check: the check stays the default, and skipping is never remembered.
import { Pressable, StyleSheet, Text, View } from 'react-native';

import { colors } from './theme';
import { Icon } from './icons';

export const SKIP_CHECK_LABEL =
  "Skip the check. I wrote the words down and accept that if I made a mistake, the coins can't be recovered.";

export function SkipCheckBox({
  checked,
  onChange,
  testID,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  testID?: string;
}) {
  return (
    <Pressable
      accessibilityRole="checkbox"
      accessibilityState={{ checked }}
      accessibilityLabel={SKIP_CHECK_LABEL}
      hitSlop={4}
      onPress={() => onChange(!checked)}
      style={({ pressed }) => [styles.row, pressed && styles.pressed]}
      testID={testID}
    >
      <View style={[styles.box, checked && styles.boxChecked]}>
        {checked ? <Icon name="check" size={16} color={colors.paper} /> : null}
      </View>
      <Text style={styles.label}>{SKIP_CHECK_LABEL}</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  row: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 12,
    minHeight: 44,
    paddingVertical: 8,
  },
  pressed: {
    opacity: 0.6,
  },
  box: {
    alignItems: 'center',
    justifyContent: 'center',
    width: 24,
    height: 24,
    marginTop: 1,
    borderWidth: 1.5,
    borderColor: colors.quiet,
    borderRadius: 6,
    backgroundColor: colors.paper,
  },
  boxChecked: {
    borderColor: colors.violet,
    backgroundColor: colors.violet,
  },
  label: {
    flex: 1,
    minWidth: 0,
    color: colors.body,
    fontSize: 14,
    lineHeight: 20,
  },
});
