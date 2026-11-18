// The Cards tab: check what a card holds, fill one, open one, and how cards
// work. On the open iPhone Duo held sideways, the check sits left of the fold
// and the other actions right of it, with the notes two each side.
import { useRouter } from 'expo-router';
import { useContext } from 'react';
import { Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';
import { SafeAreaInsetsContext, SafeAreaView } from 'react-native-safe-area-context';

import { useFold } from '../../../components/fold-page';
import { Icon } from '../../../components/icons';
import { colors } from '../../../components/theme';
import { NetworkBadge, Panel, Row, Title } from '../../../components/ui';
import { FOLD_GAP, leftColumnWidth, useLayout } from '../../../lib/layout';

type Note = { id: string; title: string; body: string };

const NOTES: readonly Note[] = [
  { id: 'cash', title: 'Like cash', body: 'Whoever holds the card holds the coins.' },
  { id: 'fill', title: 'Fill it', body: 'Move coins onto it from your wallet.' },
  { id: 'hand', title: 'Hand it over', body: 'They can check it is real first.' },
  { id: 'open', title: 'Open it', body: 'Move the coins out into a wallet.' },
];

const NO_INSETS = { left: 0, right: 0 };

/** The page's side padding on the open Duo. */
const WIDE_PADDING = 28;

function NoteCard({ note }: { note: Note }) {
  return (
    <View style={styles.note} testID={`cards-note-${note.id}`}>
      <Text style={styles.noteTitle}>{note.title}</Text>
      <Text style={styles.noteBody}>{note.body}</Text>
    </View>
  );
}

export default function CardsScreen() {
  const router = useRouter();
  const { twoColumns, width, height } = useLayout();
  // No insets are known outside a safe-area provider; none are needed on one column.
  const insets = useContext(SafeAreaInsetsContext) ?? NO_INSETS;
  // On the open Duo, the width left of the fold.
  const leftWidth = twoColumns
    ? leftColumnWidth({ width, height, insetLeft: insets.left, insetRight: insets.right, padding: WIDE_PADDING })
    : undefined;
  // Held sideways there is room for all four notes in a row, two each side of the fold.
  const notesAcrossFold = leftWidth !== undefined && width > height;
  const fold = useFold();

  const check = (
    <View style={styles.check}>
      <Text style={styles.checkTitle}>See what a card holds</Text>
      <Text style={styles.checkBody}>Press the button, then hold the card to the back of your phone.</Text>
      <Pressable
        accessibilityRole="button"
        onPress={() => router.push('/check-card')}
        style={({ pressed }) => [styles.checkButton, pressed && styles.pressed]}
        testID="cards-check"
      >
        <Icon name="tap" />
        <Text style={styles.checkButtonText}>Check a card</Text>
      </Pressable>
    </View>
  );

  const actions = (
    <Panel>
      <Row
        first
        icon="send"
        title="Fill a card"
        detail="Move coins from your wallet onto it"
        opens
        onPress={() => router.push('/fill-ghost-card')}
        testID="cards-fill"
      />
      <Row
        icon="receive"
        title="Open a card"
        detail="Move its coins into your wallet"
        opens
        onPress={() => router.push('/open-ghost-card')}
        testID="cards-open"
      />
      <Row
        icon="card"
        title="Older NTAG 424 cards"
        opens
        onPress={() => router.push('/older-cards')}
        testID="cards-older"
      />
    </Panel>
  );

  return (
    <SafeAreaView edges={['top', 'left', 'right']} style={styles.page} testID="cards-screen">
      <ScrollView
        contentInsetAdjustmentBehavior="automatic"
        contentContainerStyle={[styles.content, twoColumns && styles.contentWide]}
        style={styles.scroll}
        testID="cards-screen-content"
      >
        <View style={styles.header}>
          <Title>Cards</Title>
          <NetworkBadge background={colors.paper} />
        </View>

        {leftWidth !== undefined ? (
          // Held upright the fold runs across the screen: the actions stay
          // above it and the notes start below it.
          <View style={[styles.foldRow, fold.mode === 'upright' && { minHeight: fold.topHeight }]} testID="cards-top">
            <View style={{ width: leftWidth }}>{check}</View>
            <View style={styles.rest}>{actions}</View>
          </View>
        ) : (
          <View style={styles.stack}>
            {check}
            {actions}
          </View>
        )}

        <Text accessibilityRole="header" style={styles.notesHeading}>
          How cards work
        </Text>
        {notesAcrossFold ? (
          <View style={styles.foldRow}>
            <View style={[styles.noteRow, { width: leftWidth }]}>
              {NOTES.slice(0, 2).map((note) => (
                <NoteCard key={note.id} note={note} />
              ))}
            </View>
            <View style={[styles.noteRow, styles.rest]}>
              {NOTES.slice(2).map((note) => (
                <NoteCard key={note.id} note={note} />
              ))}
            </View>
          </View>
        ) : (
          <View style={styles.stack}>
            <View style={styles.noteRow}>
              {NOTES.slice(0, 2).map((note) => (
                <NoteCard key={note.id} note={note} />
              ))}
            </View>
            <View style={styles.noteRow}>
              {NOTES.slice(2).map((note) => (
                <NoteCard key={note.id} note={note} />
              ))}
            </View>
          </View>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

const GAP = 12;

const styles = StyleSheet.create({
  page: {
    flex: 1,
    backgroundColor: colors.mist,
  },
  scroll: {
    flex: 1,
  },
  content: {
    flexGrow: 1,
    paddingHorizontal: 20,
    paddingTop: 4,
    paddingBottom: 32,
  },
  contentWide: {
    paddingHorizontal: WIDE_PADDING,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    minHeight: 52,
    marginBottom: GAP,
  },
  stack: {
    gap: GAP,
  },
  // The gap is where the open Duo folds: nothing sits in it.
  foldRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: FOLD_GAP,
  },
  rest: {
    flex: 1,
    minWidth: 0,
  },
  check: {
    padding: 20,
    borderRadius: 20,
    backgroundColor: colors.violet,
  },
  checkTitle: {
    color: colors.paper,
    fontSize: 20,
    fontWeight: '600',
  },
  checkBody: {
    marginTop: 6,
    color: colors.violetTint,
    fontSize: 14,
    lineHeight: 20,
  },
  checkButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
    minHeight: 52,
    marginTop: 20,
    borderRadius: 14,
    backgroundColor: colors.paper,
  },
  checkButtonText: {
    color: colors.ink,
    fontSize: 16,
    fontWeight: '600',
  },
  pressed: {
    opacity: 0.6,
  },
  // Set apart from the actions above and the notes below.
  notesHeading: {
    marginTop: 32,
    marginBottom: 14,
    color: colors.ink,
    fontSize: 18,
    fontWeight: '600',
  },
  noteRow: {
    flexDirection: 'row',
    alignItems: 'stretch',
    gap: GAP,
  },
  note: {
    flex: 1,
    minWidth: 0,
    padding: 14,
    borderWidth: 1,
    borderColor: colors.line,
    borderRadius: 16,
    backgroundColor: colors.paper,
  },
  noteTitle: {
    color: colors.ink,
    fontSize: 15,
    fontWeight: '600',
  },
  noteBody: {
    marginTop: 6,
    color: colors.quiet,
    fontSize: 13,
    lineHeight: 19,
  },
});
