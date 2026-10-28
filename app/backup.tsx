// 2. Create and back up (docs/mockups/backup.html): the native core makes 24
// new words and holds them until the check passes. This screen shows them and
// holds them only while it is open.
import { useRouter } from 'expo-router';
import { useEffect, useState } from 'react';
import { StyleSheet, View } from 'react-native';

import { Screen, useScreenLayout } from '../components/screen';
import { Body, Button, Highlight, Strong, Title, WordGrid } from '../components/onboarding-ui';
import { WORD_COUNT } from '../lib/onboarding/word-check';
import { discardNewAccount, newAccountWords } from '../modules/ghost-core';

type Words = { status: 'ready'; words: string[] } | { status: 'failed' };

function createWords(): Words {
  try {
    const created = newAccountWords();
    return created.length === WORD_COUNT ? { status: 'ready', words: created } : { status: 'failed' };
  } catch {
    return { status: 'failed' };
  }
}

export default function BackupScreen() {
  const router = useRouter();
  const twoColumn = useScreenLayout() === 'two-column';
  const [words] = useState(createWords);

  // Leaving without saving (back to Welcome) forgets the words in the core.
  // After a save the core holds nothing, so this does nothing.
  useEffect(() => discardNewAccount, []);

  const intro = (
    <View style={[styles.stack, twoColumn && styles.column]}>
      <Title>Your 24 backup words</Title>
      <Body>Write them on paper, in this order. They are the only way back into your account.</Body>
      <Highlight>
        <Strong>Anyone with these words can spend your GHOST.</Strong> Never share them or type them into a
        website.
      </Highlight>
    </View>
  );

  const list =
    words.status === 'ready' ? (
      <WordGrid words={words.words} />
    ) : (
      <Body quiet>Your words could not be created on this phone.</Body>
    );

  return (
    <Screen
      footer={
        <Button
          disabled={words.status !== 'ready'}
          label="Continue"
          onPress={() => router.push('/check')}
          testID="backup-continue"
        />
      }
      label="Backup words"
      onBack={() => router.back()}
      testID="backup-screen"
      wide
    >
      {twoColumn ? (
        <View style={styles.row}>
          {intro}
          <View style={styles.column}>{list}</View>
        </View>
      ) : (
        <>
          {intro}
          {list}
        </>
      )}
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
    gap: 16,
  },
});
