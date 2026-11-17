// The pieces the Ghost card screens share: the card's status after a Check,
// the open code shown once (QR code and text) and the open code field.
import { useState } from 'react';
import { StyleSheet, Text, TextInput, View } from 'react-native';
import QRCode from 'react-native-qrcode-svg';

import { openCodeGroups } from '../lib/ghost-card/flows';
import {
  ghostStatusDetail,
  ghostStatusIsAlarm,
  ghostStatusText,
  safeToAccept,
  type GhostCardStatus,
} from '../lib/ghost-card/status';
import { colors, monoFont } from './theme';
import { Panel, textStyles } from './ui';

/** The card's status after a tap, as one line and a quieter one. */
export function GhostCardStatusPanel({ status, testID }: { status: GhostCardStatus; testID: string }) {
  const alarm = ghostStatusIsAlarm(status);
  const safe = safeToAccept(status);
  const detail = ghostStatusDetail(status);
  return (
    <Panel style={styles.panel} testID={testID}>
      <Text style={textStyles.quiet}>This card</Text>
      <Text
        accessibilityLiveRegion="polite"
        style={[styles.status, alarm && styles.alarm, safe && styles.safe]}
        testID={`${testID}-text`}
      >
        {ghostStatusText(status)}
      </Text>
      {detail ? (
        <Text style={[textStyles.body, alarm && styles.alarm]} testID={`${testID}-detail`}>
          {detail}
        </Text>
      ) : null}
    </Panel>
  );
}

/** An open code, shown once: QR code and its 32 characters in groups of eight. */
export function OpenCodeShown({ text, testID }: { text: string; testID: string }) {
  return (
    <Panel style={styles.panel} testID={testID}>
      <Text style={textStyles.quiet}>Open code</Text>
      <View style={styles.qr}>
        <QRCode value={text} size={180} color={colors.ink} backgroundColor={colors.paper} ecl="M" />
      </View>
      <Text selectable style={styles.code} testID={`${testID}-text`}>
        {openCodeGroups(text)}
      </Text>
      <Text style={textStyles.body}>
        Write it down or print it, and keep it with the card. Whoever you give the card to needs this code to open it.
        This app keeps no copy: a lost code means nobody can ever take the GHOST off the card.
      </Text>
    </Panel>
  );
}

/** The open code field: 32 characters, any case, spaces allowed; never saved by the keyboard. */
export function OpenCodeInput({
  value,
  onChange,
  testID,
}: {
  value: string;
  onChange: (text: string) => void;
  testID: string;
}) {
  const [shown, setShown] = useState(false);
  return (
    <TextInput
      accessibilityLabel="Open code"
      autoCapitalize="characters"
      autoComplete="off"
      autoCorrect={false}
      importantForAutofill="no"
      onChangeText={(text) => onChange(text.replace(/[^A-Za-z2-7 -]/g, ''))}
      onFocus={() => setShown(true)}
      onBlur={() => setShown(false)}
      placeholder="Open code (32 letters and digits)"
      placeholderTextColor={colors.quiet}
      secureTextEntry={!shown}
      spellCheck={false}
      style={styles.input}
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
  safe: {
    color: colors.violet,
  },
  qr: {
    alignItems: 'center',
    paddingVertical: 8,
  },
  code: {
    color: colors.ink,
    fontFamily: monoFont,
    fontSize: 20,
    letterSpacing: 1,
    textAlign: 'center',
  },
  input: {
    minHeight: 52,
    paddingHorizontal: 14,
    borderWidth: 1,
    borderColor: colors.line,
    borderRadius: 12,
    backgroundColor: colors.paper,
    color: colors.ink,
    fontFamily: monoFont,
    fontSize: 16,
  },
});
