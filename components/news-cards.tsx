// The news cards under Home: a tinted block and a headline each.
import { StyleSheet, Text, View } from 'react-native';

import { FOLD_GAP, useLayout } from '../lib/layout';
import { newsColumns, newsRows, type NewsStory, type NewsTint } from '../lib/home/news';
import { colors } from './theme';

const TINTS: Record<NewsTint, string> = {
  violet: colors.violetTint,
  mist: colors.line,
};

function NewsCard({ story }: { story: NewsStory }) {
  return (
    <View accessible accessibilityLabel={story.title} style={styles.card} testID={`news-${story.id}`}>
      <View style={[styles.picture, { backgroundColor: TINTS[story.tint] }]} />
      <Text style={styles.headline}>{story.title}</Text>
    </View>
  );
}

/**
 * `leftWidth` is the width left of the fold on the open Duo. Four across, two
 * stories sit each side of it with the fold between them.
 */
export function NewsCards({ stories, leftWidth }: { stories: readonly NewsStory[]; leftWidth?: number }) {
  const { width, height, twoColumns } = useLayout();
  const columns = newsColumns(width, height, twoColumns);
  const acrossFold = columns === 4 && leftWidth !== undefined;
  return (
    <View style={styles.rows} testID="news">
      {newsRows(stories, columns).map((row) =>
        acrossFold ? (
          <View key={row[0].id} style={styles.foldRow}>
            <View style={[styles.row, { width: leftWidth }]}>
              {row.slice(0, 2).map((story) => (
                <NewsCard key={story.id} story={story} />
              ))}
            </View>
            <View style={[styles.row, styles.rest]}>
              {row.slice(2).map((story) => (
                <NewsCard key={story.id} story={story} />
              ))}
            </View>
          </View>
        ) : (
          <View key={row[0].id} style={styles.row}>
            {row.map((story) => (
              <NewsCard key={story.id} story={story} />
            ))}
          </View>
        ),
      )}
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
  foldRow: {
    flexDirection: 'row',
    alignItems: 'stretch',
    gap: FOLD_GAP,
  },
  rest: {
    flex: 1,
    minWidth: 0,
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
