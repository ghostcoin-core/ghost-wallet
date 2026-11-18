// A screen opened from a tab, laid out around the iPhone Duo's fold. It has
// two parts. On one column they stack. Open and held sideways they sit left
// and right of the fold; open and held upright, above and below it. Nothing
// sits on the fold while the page is at its top.
import { useContext, type ReactNode } from 'react';
import { KeyboardAvoidingView, ScrollView, StyleSheet, View } from 'react-native';
import { SafeAreaInsetsContext, SafeAreaView } from 'react-native-safe-area-context';

import { FOLD_GAP, foldMode, leftColumnWidth, topOfFoldHeight, useLayout, type FoldMode } from '../lib/layout';
import { useSystemBarHeight } from './system-bar';
import { colors } from './theme';
import { NetworkBadge, Title } from './ui';

const NO_INSETS = { top: 0, left: 0, right: 0 };

const SIDES = ['left', 'right'] as const;
const TOP_AND_SIDES = ['top', 'left', 'right'] as const;

const PADDING = 20;
const WIDE_PADDING = 28;
const CONTENT_TOP = 4;
const HEADER_HEIGHT = 52;
const HEADER_GAP = 12;

export type Fold = {
  mode: FoldMode;
  /** Held sideways: the width of the part left of the fold. */
  leftWidth: number;
  /** Held upright: the height of the part above the fold. */
  topHeight: number;
  /** The width the first part has to draw in. */
  firstWidth: number;
};

/** Where the fold is for a page of this kind, and how much room its first part has. */
export function useFold(): Fold {
  const { width, height } = useLayout();
  // No insets are known outside a safe-area provider; none are needed on one column.
  const insets = useContext(SafeAreaInsetsContext) ?? NO_INSETS;
  // Under the system's bar the page starts below it; otherwise below the status area.
  const bar = useSystemBarHeight();
  const mode = foldMode(width, height);
  const padding = mode === 'one' ? PADDING : WIDE_PADDING;
  const contentWidth = Math.max(0, width - insets.left - insets.right - 2 * padding);
  const leftWidth = leftColumnWidth({ width, height, insetLeft: insets.left, insetRight: insets.right, padding });
  const topHeight = topOfFoldHeight(height, (bar > 0 ? bar : insets.top) + CONTENT_TOP + HEADER_HEIGHT + HEADER_GAP);
  return { mode, leftWidth, topHeight, firstWidth: mode === 'sideways' ? leftWidth : contentWidth };
}

type Props = {
  testID: string;
  title: string;
  /** Left of the fold, or above it. */
  first: ReactNode;
  /** Right of the fold, or below it. */
  second: ReactNode;
};

export function FoldPage({ testID, title, first, second }: Props) {
  const fold = useFold();
  const bar = useSystemBarHeight();
  const wide = fold.mode !== 'one';

  return (
    <SafeAreaView edges={bar > 0 ? SIDES : TOP_AND_SIDES} style={styles.page} testID={testID}>
      <KeyboardAvoidingView behavior="padding" style={styles.grow}>
        <ScrollView
          contentInsetAdjustmentBehavior="automatic"
          contentContainerStyle={[styles.content, wide && styles.contentWide]}
          keyboardShouldPersistTaps="handled"
          style={styles.grow}
          testID={`${testID}-content`}
        >
          <View style={styles.header}>
            <Title>{title}</Title>
            <NetworkBadge background={colors.paper} />
          </View>
          {fold.mode === 'sideways' ? (
            <View style={styles.sideways} testID={`${testID}-parts`}>
              <View style={[styles.part, { width: fold.leftWidth }]} testID={`${testID}-first`}>
                {first}
              </View>
              <View style={[styles.part, styles.rest]}>{second}</View>
            </View>
          ) : fold.mode === 'upright' ? (
            <View style={styles.upright} testID={`${testID}-parts`}>
              <View style={[styles.part, { minHeight: fold.topHeight }]} testID={`${testID}-first`}>
                {first}
              </View>
              <View style={styles.part}>{second}</View>
            </View>
          ) : (
            <View style={styles.part}>
              {first}
              {second}
            </View>
          )}
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  page: {
    flex: 1,
    backgroundColor: colors.mist,
  },
  grow: {
    flex: 1,
  },
  content: {
    flexGrow: 1,
    paddingHorizontal: PADDING,
    paddingTop: CONTENT_TOP,
    paddingBottom: 32,
  },
  contentWide: {
    paddingHorizontal: WIDE_PADDING,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    height: HEADER_HEIGHT,
    marginBottom: HEADER_GAP,
  },
  // The gap is where the open Duo folds.
  sideways: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: FOLD_GAP,
  },
  upright: {
    gap: FOLD_GAP,
  },
  part: {
    gap: 16,
  },
  rest: {
    flex: 1,
    minWidth: 0,
  },
});
