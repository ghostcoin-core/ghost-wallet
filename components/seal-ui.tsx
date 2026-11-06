// The pieces the Sealed card screens share: the card's status, the spinner of
// a deliberate tap, and the PIN field. A status that failed its check is red
// and never shows an amount.
import { ActivityIndicator, StyleSheet, Text, TextInput, View } from 'react-native';

import { statusDetail, statusIsAlarm, statusText, type CardStatus } from '../lib/seal/card-status';
import { PIN_MAX_DIGITS } from '../lib/seal/pin';
import { colors, monoFont } from './theme';
import { Panel, textStyles } from './ui';

/** The card's status after a tap, as one line and a quieter one. */
export function CardStatusPanel({ status, testID }: { status: CardStatus; testID: string }) {
  const alarm = statusIsAlarm(status);
  const detail = statusDetail(status);
  return (
    <Panel style={styles.panel} testID={testID}>
      <Text style={textStyles.quiet}>This card</Text>
      <Text
        accessibilityLiveRegion="polite"
        style={[styles.status, alarm && styles.alarm]}
        testID={`${testID}-text`}
      >
        {statusText(status)}
      </Text>
      {detail ? (
        <Text style={[textStyles.body, alarm && styles.alarm]} testID={`${testID}-detail`}>
          {detail}
        </Text>
      ) : null}
    </Panel>
  );
}

/** Shown while a tap's flow runs; the screen waits for it on purpose. */
export function CardBusy({ text, testID }: { text: string; testID: string }) {
  return (
    <View accessibilityLiveRegion="polite" style={styles.busy} testID={testID}>
      <ActivityIndicator color={colors.violet} />
      <Text style={textStyles.body}>{text}</Text>
    </View>
  );
}

/** A PIN field: digits only, hidden, never saved by the keyboard. */
export function PinInput({
  value,
  onChange,
  label,
  testID,
}: {
  value: string;
  onChange: (text: string) => void;
  label: string;
  testID: string;
}) {
  return (
    <TextInput
      accessibilityLabel={label}
      autoComplete="off"
      autoCorrect={false}
      importantForAutofill="no"
      keyboardType="number-pad"
      maxLength={PIN_MAX_DIGITS}
      onChangeText={(text) => onChange(text.replace(/[^0-9]/g, ''))}
      placeholder={label}
      placeholderTextColor={colors.quiet}
      secureTextEntry
      style={styles.pin}
      testID={testID}
      textContentType="none"
      value={value}
    />
  );
}

const styles = StyleSheet.create({
  panel: {
    gap: 8,
    padding: 16,
  },
  status: {
    color: colors.ink,
    fontSize: 22,
    fontWeight: '600',
  },
  alarm: {
    color: colors.danger,
  },
  busy: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    paddingVertical: 8,
  },
  pin: {
    minHeight: 52,
    paddingHorizontal: 14,
    borderWidth: 1,
    borderColor: colors.line,
    borderRadius: 12,
    backgroundColor: colors.paper,
    color: colors.ink,
    fontFamily: monoFont,
    fontSize: 20,
    letterSpacing: 4,
  },
});
