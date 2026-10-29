// 3. Check words (docs/mockups/backup-check.html): three of the 24 words, typed
// from paper. The native core compares them with the words it holds and, once
// all three match, saves the account to the Keychain. The person may tick
// "Skip the check" instead (unticked every time): the core then saves the
// account unchecked, and Settings says the backup is not checked.
import { useRouter } from 'expo-router';
import { useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';

import { Screen, useScreenLayout } from '../components/screen';
import { Body, Button, Title } from '../components/onboarding-ui';
import { SkipCheckBox } from '../components/skip-check';
import { WordField } from '../components/word-field';
import { backupStatusStore } from '../lib/onboarding/backup-status';
import { allTyped, checkTypedWords, pickCheckPositions, WORD_COUNT } from '../lib/onboarding/word-check';
import { useSession } from '../lib/session';
import { colours, fonts } from '../lib/theme';
import { checkNewAccountWord, saveNewAccount, saveNewAccountUnchecked } from '../modules/ghost-core';

function checkMessage(wrong: number[]): string {
  return wrong.length === 1
    ? `Word ${wrong[0]} does not match your backup. Look at your paper again.`
    : `Words ${wrong.join(', ')} do not match your backup. Look at your paper again.`;
}

export default function CheckScreen() {
  const router = useRouter();
  const session = useSession();
  const twoColumn = useScreenLayout() === 'two-column';
  const [positions] = useState(() => pickCheckPositions());
  const [typed, setTyped] = useState<Record<number, string>>({});
  const [wrong, setWrong] = useState<number[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [skip, setSkip] = useState(false);
  const [saving, setSaving] = useState(false);

  async function confirm() {
    if (skip) {
      await saveUnchecked();
      return;
    }
    let result;
    try {
      result = checkTypedWords(positions, typed, checkNewAccountWord);
    } catch {
      setError('Your words could not be checked on this phone.');
      return;
    }
    setWrong(result.wrong);
    if (!result.passed) {
      setError(result.wrong.length > 0 ? checkMessage(result.wrong) : null);
      return;
    }
    try {
      saveNewAccount();
    } catch {
      setError('Your account could not be saved on this phone. Go back and try again.');
      return;
    }
    if (backupStatusStore.unchecked()) {
      // Left over from an account that was never saved.
      backupStatusStore.setChecked(true).catch(() => {});
    }
    setError(null);
    // The onboarding screens close now and the router opens Home.
    session.accountSaved();
  }

  /** The person ticked "Skip the check": the backup is marked not checked first, so the mark is never lost. */
  async function saveUnchecked() {
    setSaving(true);
    try {
      await backupStatusStore.setChecked(false);
    } catch {
      setSaving(false);
      setError('Your account could not be saved on this phone. Go back and try again.');
      return;
    }
    try {
      saveNewAccountUnchecked();
    } catch {
      backupStatusStore.setChecked(true).catch(() => {});
      setSaving(false);
      setError('Your account could not be saved on this phone. Go back and try again.');
      return;
    }
    setError(null);
    session.accountSaved();
  }

  const skipBox = (
    <SkipCheckBox
      checked={skip}
      onChange={(checked) => {
        setSkip(checked);
        setError(null);
        setWrong([]);
      }}
      testID="check-skip"
    />
  );

  const confirmButton = (
    <Button
      disabled={saving || (!skip && !allTyped(positions, typed))}
      label="Confirm and open my account"
      onPress={() => void confirm()}
      testID="check-confirm"
    />
  );

  const intro = (
    <View style={[styles.pane, twoColumn && styles.half]}>
      <Title style={twoColumn && styles.largeTitle}>Check three words</Title>
      <Body>Type these words from your paper, so you know the backup is right.</Body>
      {twoColumn ? (
        <>
          <Text style={styles.sectionTitle}>On your paper</Text>
          <View accessibilityLabel="Positions of the words to check" style={styles.paperGrid}>
            {Array.from({ length: WORD_COUNT }, (_, index) => index + 1).map((position) => {
              const asked = positions.includes(position);
              return (
                <View key={position} style={styles.paperCell}>
                  <View style={[styles.paperSlot, asked && styles.paperSlotAsked]}>
                    <Text style={[styles.paperNumber, asked && styles.paperNumberAsked]}>{position}</Text>
                  </View>
                </View>
              );
            })}
          </View>
        </>
      ) : null}
      <Body quiet>Wrong word? You can go back and look again. Nothing is lost.</Body>
    </View>
  );

  const fields = (
    <View style={[styles.pane, twoColumn && styles.half]}>
      {positions.map((position) => (
        <View key={position} style={styles.field}>
          <Text nativeID={`word-${position}-label`} style={styles.label}>
            Word {position}
          </Text>
          <WordField
            accessibilityLabel={`Word ${position}`}
            invalid={wrong.includes(position)}
            onChangeText={(text) => {
              setTyped((current) => ({ ...current, [position]: text }));
              setWrong((current) => current.filter((item) => item !== position));
            }}
            placeholder={`Word ${position}`}
            returnKeyType="next"
            style={[styles.input, twoColumn && styles.inputLarge, wrong.includes(position) && styles.inputWrong]}
            testID={`check-word-${position}`}
            value={typed[position] ?? ''}
          />
        </View>
      ))}
      {error ? (
        <Text accessibilityLiveRegion="polite" style={styles.error} testID="check-error">
          {error}
        </Text>
      ) : null}
      {skipBox}
      {twoColumn ? (
        <>
          <View style={styles.grow} />
          {confirmButton}
        </>
      ) : null}
    </View>
  );

  return (
    <Screen
      footer={twoColumn ? undefined : confirmButton}
      label="Check your backup words"
      onBack={() => router.back()}
      testID="check-screen"
      wide
    >
      {twoColumn ? (
        <View style={styles.split}>
          {intro}
          {fields}
        </View>
      ) : (
        <>
          {intro}
          {fields}
        </>
      )}
    </Screen>
  );
}

const styles = StyleSheet.create({
  split: {
    flex: 1,
    flexDirection: 'row',
    gap: 56,
    paddingTop: 8,
    paddingBottom: 8,
  },
  pane: {
    gap: 16,
  },
  half: {
    flex: 1,
  },
  grow: {
    flex: 1,
  },
  largeTitle: {
    fontSize: 32,
    lineHeight: 36,
  },
  sectionTitle: {
    marginTop: 8,
    color: colours.quiet,
    fontFamily: fonts.sans,
    fontSize: 13,
    fontWeight: '600',
  },
  paperGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    marginHorizontal: -3,
  },
  paperCell: {
    width: '25%',
    padding: 3,
  },
  paperSlot: {
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: 34,
    borderWidth: 1,
    borderColor: colours.line,
    borderRadius: 8,
    backgroundColor: colours.mist,
  },
  paperSlotAsked: {
    borderColor: colours.violet,
    backgroundColor: colours.violetTint,
  },
  paperNumber: {
    color: colours.quiet,
    fontFamily: fonts.mono,
    fontSize: 12,
  },
  paperNumberAsked: {
    color: colours.violet,
    fontFamily: fonts.monoMedium,
  },
  field: {
    gap: 6,
  },
  label: {
    color: colours.body,
    fontFamily: fonts.sans,
    fontSize: 14,
    fontWeight: '500',
  },
  input: {
    minHeight: 52,
    paddingHorizontal: 14,
    borderWidth: 1,
    borderColor: colours.line,
    borderRadius: 12,
    backgroundColor: colours.paper,
  },
  inputLarge: {
    minHeight: 60,
    fontSize: 17,
  },
  inputWrong: {
    borderColor: colours.danger,
  },
  error: {
    color: colours.danger,
    fontFamily: fonts.sans,
    fontSize: 14,
    lineHeight: 20,
  },
});
