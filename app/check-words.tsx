// Check my words now: for an account saved with the word check skipped.
// Three of the 24 recovery words are typed from paper and, after Face ID (or
// the passcode), the native core says whether all three match the saved
// account, never which one is wrong. Once they match, Settings no longer says
// the backup is not checked.
import { useRouter } from 'expo-router';
import { useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';

import { colors, monoFont } from '../components/theme';
import { Button, Column, IconButton, Logo, NetworkBadge, Panel, Screen, Spacer, textStyles, Title } from '../components/ui';
import { WordField } from '../components/word-field';
import { authenticate, authFailureMessage } from '../lib/device-auth';
import { backupStatusStore } from '../lib/onboarding/backup-status';
import { allTyped, normaliseWord, pickCheckPositions } from '../lib/onboarding/word-check';
import { checkSavedAccountWords } from '../modules/ghost-core';

export default function CheckWordsScreen() {
  const router = useRouter();
  const [positions] = useState(() => pickCheckPositions());
  const [typed, setTyped] = useState<Record<number, string>>({});
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [passed, setPassed] = useState(false);

  async function check() {
    setMessage(null);
    setBusy(true);
    try {
      const result = await authenticate('Check your recovery words');
      if (!result.ok) {
        setMessage(authFailureMessage(result.reason));
        return;
      }
      let matches: boolean;
      try {
        matches = checkSavedAccountWords(
          positions,
          positions.map((position) => normaliseWord(typed[position] ?? '')),
        );
      } catch {
        setMessage('Your words could not be checked on this phone.');
        return;
      }
      if (!matches) {
        setMessage('These words do not match your backup. Look at your paper again.');
        return;
      }
      setTyped({});
      setPassed(true);
      await backupStatusStore.setChecked(true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Screen
      testID="check-words-screen"
      wide="columns"
      topBar={
        <>
          <IconButton icon="back" label="Back" onPress={() => router.back()} testID="back" />
          <Spacer />
          <NetworkBadge />
          <Logo />
        </>
      }
    >
      <Column>
        <Title>Check my words</Title>
        <Text style={textStyles.body}>
          Your account was saved without checking your recovery words. Type these three words from your paper, so you
          know the backup is right.
        </Text>
      </Column>
      <Column>
        {passed ? (
          <>
            <Text accessibilityLiveRegion="polite" style={textStyles.body} testID="check-words-passed">
              The words match. Your backup is checked.
            </Text>
            <Button label="Done" onPress={() => router.back()} testID="check-words-done" />
          </>
        ) : (
          <>
            <Panel style={styles.form}>
              {positions.map((position) => (
                <View key={position} style={styles.checkRow}>
                  <Text style={styles.checkNumber}>{position}</Text>
                  <WordField
                    accessibilityLabel={`Word ${position}`}
                    onChangeText={(text) => {
                      setTyped((current) => ({ ...current, [position]: text }));
                      setMessage(null);
                    }}
                    placeholder={`Word ${position}`}
                    style={styles.checkField}
                    testID={`check-words-${position}`}
                    value={typed[position] ?? ''}
                  />
                </View>
              ))}
            </Panel>
            {message ? (
              <Text accessibilityLiveRegion="polite" style={[textStyles.body, styles.error]} testID="check-words-message">
                {message}
              </Text>
            ) : null}
            <Button
              label="Check with Face ID"
              icon="lock"
              disabled={busy || !allTyped(positions, typed)}
              onPress={() => void check()}
              testID="check-words-confirm"
            />
          </>
        )}
      </Column>
    </Screen>
  );
}

const styles = StyleSheet.create({
  form: {
    gap: 8,
    padding: 16,
  },
  checkRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    borderBottomWidth: 1,
    borderBottomColor: colors.line,
  },
  checkNumber: {
    minWidth: 24,
    color: colors.quiet,
    fontFamily: monoFont,
  },
  checkField: {
    flex: 1,
  },
  error: {
    color: colors.danger,
  },
});
