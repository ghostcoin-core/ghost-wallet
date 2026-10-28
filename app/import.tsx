// 4. Import (docs/mockups/import.html): 24 boxes, or all 24 words pasted into
// one. The native core says which words are in the word list, checks the
// whole phrase and saves it to the Keychain.
import { useRouter } from 'expo-router';
import { useRef, useState } from 'react';
import { StyleSheet, Text, View, type TextInputInstance } from 'react-native';

import { Screen, useScreenLayout } from '../components/screen';
import { Body, Button, Title } from '../components/onboarding-ui';
import { WordField } from '../components/word-field';
import {
  applyFieldText,
  emptyFields,
  importMessage,
  importStatus,
  joinWords,
} from '../lib/onboarding/import-validation';
import { useSession } from '../lib/session';
import { colours, fonts } from '../lib/theme';
import { walletFieldRule } from '../lib/vanish/field-rules';
import { parseWordsCheck } from '../lib/vanish/word-validation';
import { checkKeyWords, importAccountWords, isAccountWord } from '../modules/ghost-core';

function knownWord(word: string): boolean {
  try {
    return isAccountWord(word);
  } catch {
    // Without the core no word is known, so the account cannot be opened.
    return false;
  }
}

export default function ImportScreen() {
  const router = useRouter();
  const session = useSession();
  const twoColumn = useScreenLayout() === 'two-column';
  const [fields, setFields] = useState(emptyFields);
  const [error, setError] = useState<string | null>(null);
  const boxes = useRef<(TextInputInstance | null)[]>([]);

  const [focused, setFocused] = useState<number | null>(null);

  const status = importStatus(fields, knownWord);
  // A word still being typed is not marked yet.
  const shown = { ...status, unknown: status.unknown.filter((position) => position !== (focused ?? -1) + 1) };
  const message = error ?? importMessage(shown);

  function change(index: number, text: string) {
    const next = applyFieldText(fields, index, text);
    setFields(next.fields);
    setError(null);
    if (next.focus !== null) {
      boxes.current[next.focus]?.focus();
    }
  }

  function open() {
    if (!status.ready) {
      return;
    }
    const words = joinWords(fields);
    const rule = walletFieldRule(words, (text) => parseWordsCheck(checkKeyWords(text)));
    if (!rule.accept) {
      setError(rule.message);
      return;
    }
    try {
      importAccountWords(words);
    } catch {
      setError('These 24 words are not a Ghost account. Check their order and spelling.');
      return;
    }
    // The onboarding screens close now and the router opens Home.
    session.accountSaved();
  }

  return (
    <Screen
      footer={<Button disabled={!status.ready} label="Open my account" onPress={open} testID="import-open" />}
      label="Enter your 24 words"
      onBack={() => router.back()}
      testID="import-screen"
      wide
    >
      <View style={twoColumn ? styles.row : styles.stack}>
        <View style={[styles.stack, twoColumn && styles.column]}>
          <Title>Enter your 24 words</Title>
          <Body>Type them in order. Pasting all 24 into the first box works too.</Body>
          {message ? (
            <Text accessibilityLiveRegion="polite" style={styles.error} testID="import-error">
              {message}
            </Text>
          ) : null}
        </View>
        <View style={[styles.grid, twoColumn && styles.column]}>
          {fields.map((word, index) => {
            const unknown = shown.unknown.includes(index + 1);
            return (
              <View key={index} style={styles.cell}>
                <View style={[styles.slot, unknown && styles.slotUnknown]}>
                  <Text style={styles.number}>{index + 1}</Text>
                  <WordField
                    ref={(box) => {
                      boxes.current[index] = box;
                    }}
                    accessibilityLabel={`Word ${index + 1}`}
                    submitBehavior="submit"
                    invalid={unknown}
                    onBlur={() => setFocused((current) => (current === index ? null : current))}
                    onChangeText={(text) => change(index, text)}
                    onFocus={() => setFocused(index)}
                    onSubmitEditing={() => boxes.current[index + 1]?.focus()}
                    returnKeyType={index + 1 < fields.length ? 'next' : 'done'}
                    style={styles.input}
                    testID={`import-word-${index + 1}`}
                    value={word}
                  />
                </View>
              </View>
            );
          })}
        </View>
      </View>
    </Screen>
  );
}

const styles = StyleSheet.create({
  row: {
    flexDirection: 'row',
    gap: 24,
  },
  stack: {
    gap: 16,
  },
  column: {
    flex: 1,
  },
  grid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    marginHorizontal: -4,
  },
  cell: {
    width: '33.333%',
    padding: 4,
  },
  slot: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    minHeight: 44,
    paddingHorizontal: 8,
    borderWidth: 1,
    borderColor: colours.line,
    borderRadius: 10,
    backgroundColor: colours.paper,
  },
  slotUnknown: {
    borderColor: colours.danger,
  },
  number: {
    minWidth: 18,
    color: colours.quiet,
    fontFamily: fonts.mono,
    fontSize: 12,
  },
  input: {
    flex: 1,
    minWidth: 0,
  },
  error: {
    color: colours.danger,
    fontFamily: fonts.sans,
    fontSize: 14,
    lineHeight: 20,
  },
});
