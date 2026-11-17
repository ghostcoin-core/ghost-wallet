// The news cards under Home: a tinted block and a headline each.
import { StyleSheet, Text, View } from 'react-native';

import { useLayout } from '../lib/layout';
import { newsColumns, newsRows, type NewsStory, type NewsTint } from '../lib/home/news';
import { colors } from './theme';

const TINTS: Record<NewsTint, string> = {
  violet: colors.violetTint,
  mist: colors.line,
};

export function NewsCards({ stories }: { stories: readonly NewsStory[] }) {
  const { width, height, twoColumns } = useLayout();
  const columns = newsColumns(width, height, twoColumns);
  return (
    <View style={styles.rows} testID="news">
      {newsRows(stories, columns).map((row) => (
        <View key={row[0].id} style={styles.row}>
          {row.map((story, index) => (
            <View
              key={story.id}
              accessible
              accessibilityLabel={story.title}
              // Four across: the middle gap is wider, where the open Duo folds.
              style={[styles.card, columns === 4 && index === 2 && styles.afterFold]}
              testID={`news-${story.id}`}
            >
              <View style={[styles.picture, { backgroundColor: TINTS[story.tint] }]} />
              <Text style={styles.headline}>{story.title}</Text>
            </View>
          ))}
        </View>
      ))}
    </View>
  );
}

const GAP = 12;

const styles = StyleSheet.create({
  rows: {
    gap: GAP,
  },
  row: {
    flexDirection: 'row',
    alignItems: 'stretch',
    gap: GAP,
  },
  card: {
    flex: 1,
    minWidth: 0,
    borderWidth: 1,
    borderColor: colors.line,
    borderRadius: 16,
    backgroundColor: colors.paper,
    overflow: 'hidden',
  },
  afterFold: {
    marginLeft: 32 - GAP,
  },
  picture: {
    height: 56,
  },
  headline: {
    padding: 12,
    color: colors.ink,
    fontSize: 14,
    lineHeight: 19,
    fontWeight: '500',
  },
});
