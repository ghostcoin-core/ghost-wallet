// The account's recovery words, shown only after Face ID (or the passcode),
// and hidden again as soon as the app leaves the screen.
import { useRouter } from 'expo-router';
import { useEffect, useState } from 'react';
import { AppState, StyleSheet, Text, View } from 'react-native';
import { testRecoveryWords } from 'ghost-core';

import { colors, monoFont } from '../components/theme';
import { Button, ButtonRow, IconButton, Logo, NetworkBadge, Screen, Spacer, textStyles, Title } from '../components/ui';
import { authenticate, authFailureMessage } from '../lib/device-auth';

export default function RecoveryWordsScreen() {
  const router = useRouter();
  const [words, setWords] = useState<string[] | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    const subscription = AppState.addEventListener('change', (state) => {
      if (state !== 'active') {
        setWords(null);
      }
    });
    return () => subscription.remove();
  }, []);

  async function show() {
    setMessage(null);
    const result = await authenticate('Show your recovery words');
    if (!result.ok) {
      setMessage(authFailureMessage(result.reason));
      return;
    }
    setWords(testRecoveryWords());
  }

  return (
    <Screen
      testID="recovery-words-screen"
      topBar={
        <>
          <IconButton icon="back" label="Back" onPress={() => router.back()} testID="back" />
          <Spacer />
          <NetworkBadge />
          <Logo />
        </>
      }
    >
      <Title>Recovery words</Title>
      <Text style={textStyles.body}>
        Anyone with these words can spend your GHOST. This account uses Ghost&apos;s public test words, so
        they guard nothing.
      </Text>
      {words ? (
        <View style={styles.grid} testID="recovery-words">
          {words.map((word, i) => (
            <View key={i} style={styles.word}>
              <Text style={styles.number}>{i + 1}</Text>
              <Text style={styles.wordText}>{word}</Text>
            </View>
          ))}
        </View>
      ) : (
        <>
          <ButtonRow>
            <Button label="Show with Face ID" icon="lock" onPress={show} testID="show-recovery-words" />
          </ButtonRow>
          {message ? (
            <Text style={textStyles.quiet} testID="recovery-words-message">
              {message}
            </Text>
          ) : null}
        </>
      )}
    </Screen>
  );
}

const styles = StyleSheet.create({
  grid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
  },
  word: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    width: '31%',
    minHeight: 36,
    paddingHorizontal: 8,
    borderWidth: 1,
    borderColor: colors.line,
    borderRadius: 10,
    backgroundColor: colors.mist,
  },
  number: {
    minWidth: 18,
    color: colors.quiet,
    fontFamily: monoFont,
    fontSize: 12,
  },
  wordText: {
    color: colors.ink,
    fontFamily: monoFont,
    fontSize: 14,
  },
});
