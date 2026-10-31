// The parts the Vanish and Summon screens share: the Phantom Key's words in
// their own colour (ink, so they are never mistaken for recovery words on
// paper), and the payment's progress.
import { ActivityIndicator, StyleSheet, Text, View } from 'react-native';

import { LOOKING_UP, SLOW_NOTE, useSlowAfter } from '../lib/vanish/lookup-progress';
import { progressRows, statusDetail, type PaymentStatus, type RevealKind } from '../lib/vanish/status-mapping';
import { Icon } from './icons';
import { colors, monoFont } from './theme';
import { Button, Panel, TextButton, textStyles } from './ui';

export const PHANTOM_KEY_LABEL = 'Phantom Key: holds coins, not your wallet.';

/** The 24 words of a new Phantom Key, numbered, on ink. Nothing here copies or saves them. */
export function PhantomKeyWords({ words, twoColumns }: { words: readonly string[]; twoColumns: boolean }) {
  return (
    <View style={styles.key} testID="phantom-key" accessibilityLabel="Phantom Key, 24 words">
      <Text style={styles.keyLabel} testID="phantom-key-label">
        {PHANTOM_KEY_LABEL}
      </Text>
      <View style={styles.keyGrid}>
        {words.map((word, index) => (
          <View key={index} style={[styles.keyCell, twoColumns ? styles.keyCellWide : styles.keyCellNarrow]}>
            <Text style={styles.keyNumber}>{index + 1}</Text>
            <Text selectable={false} style={styles.keyWord} testID={`phantom-key-word-${index + 1}`}>
              {word}
            </Text>
          </View>
        ))}
      </View>
    </View>
  );
}

const ICONS = { done: 'check', current: 'clock', waiting: 'dot' } as const;

/** Proving (or signing), sent, in a block, settled; or failed. */
export function PaymentProgress({
  status,
  kind,
  step,
  error,
}: {
  status: PaymentStatus;
  kind: RevealKind;
  step?: number | string;
  error?: string | null;
}) {
  const rows = progressRows(status, kind);
  return (
    <Panel style={styles.progress} testID="payment-progress">
      {rows.map((row) => (
        <View key={row.status} style={styles.progressRow} testID={`progress-${row.status}`}>
          <Icon
            name={row.status === 'failed' ? 'cross' : ICONS[row.state]}
            color={row.state === 'waiting' ? colors.quiet : colors.ink}
          />
          <Text
            style={[styles.progressLabel, row.state === 'waiting' && styles.progressWaiting]}
            accessibilityState={{ selected: row.state === 'current' }}
          >
            {row.label}
          </Text>
        </View>
      ))}
      <Text style={[textStyles.quiet, styles.progressDetail]} testID="payment-status">
        {statusDetail(status, kind, step)}
      </Text>
      {error ? (
        <Text style={[textStyles.quiet, styles.progressDetail]} testID="payment-error">
          {error} Trying again.
        </Text>
      ) : null}
    </Panel>
  );
}

export const LEAVE_NOTE = 'You can leave this screen. The payment keeps going.';

/**
 * Under the progress: Done once the payment is in a block (settling goes on
 * without the screen), settled or failed. Until then the screen says the
 * payment goes on without it, with a quiet Leave.
 */
export function PaymentExit({
  final,
  onLeave,
  testPrefix,
}: {
  final: boolean;
  onLeave: () => void;
  testPrefix: string;
}) {
  if (final) {
    return <Button label="Done" secondary onPress={onLeave} testID={`${testPrefix}-done`} />;
  }
  return (
    <View style={styles.leave} testID={`${testPrefix}-leave-note`}>
      <Text style={textStyles.body}>{LEAVE_NOTE}</Text>
      <TextButton label="Leave" onPress={onLeave} testID={`${testPrefix}-leave`} />
    </View>
  );
}

/**
 * The lookup of a Phantom Key's coins: a spinner and "Looking up this key's
 * coins…", a note once it is slow, or why it failed with Try again.
 */
export function KeyLookupProgress({ failure, onRetry }: { failure: string | null; onRetry: () => void }) {
  const slow = useSlowAfter(failure === null);
  if (failure !== null) {
    return (
      <Panel style={styles.lookup} testID="key-lookup-failed">
        <Text accessibilityLiveRegion="polite" style={[textStyles.body, styles.lookupError]} testID="summon-error">
          {failure}
        </Text>
        <Button label="Try again" onPress={onRetry} testID="key-lookup-retry" />
      </Panel>
    );
  }
  return (
    <Panel style={styles.lookup} testID="key-lookup-progress">
      <View style={styles.lookupRow}>
        <ActivityIndicator color={colors.ink} testID="key-lookup-spinner" />
        <Text accessibilityLiveRegion="polite" style={styles.progressLabel} testID="key-lookup-status">
          {LOOKING_UP}
        </Text>
      </View>
      {slow ? (
        <Text accessibilityLiveRegion="polite" style={textStyles.quiet} testID="key-lookup-slow">
          {SLOW_NOTE}
        </Text>
      ) : null}
    </Panel>
  );
}

/** Coins back in the account: the brand's Summon mint, as a fill with ink text. */
export function CoinsBack({ text }: { text: string }) {
  return (
    <View style={styles.back} testID="coins-back">
      <Text style={styles.backText}>{text}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  key: {
    gap: 12,
    padding: 16,
    borderRadius: 16,
    backgroundColor: colors.ink,
  },
  keyLabel: {
    color: colors.paper,
    fontSize: 15,
    fontWeight: '600',
  },
  keyGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    marginHorizontal: -4,
  },
  keyCell: {
    flexDirection: 'row',
    alignItems: 'baseline',
    gap: 6,
    paddingHorizontal: 4,
    paddingVertical: 5,
  },
  keyCellNarrow: {
    width: '33.333%',
  },
  keyCellWide: {
    width: '25%',
  },
  keyNumber: {
    minWidth: 18,
    color: colors.line,
    fontFamily: monoFont,
    fontSize: 11,
  },
  keyWord: {
    flexShrink: 1,
    color: colors.paper,
    fontFamily: monoFont,
    fontSize: 14,
  },
  progress: {
    paddingVertical: 8,
  },
  progressRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    minHeight: 40,
    paddingHorizontal: 16,
  },
  progressLabel: {
    color: colors.ink,
    fontSize: 16,
    fontWeight: '500',
  },
  progressWaiting: {
    color: colors.quiet,
    fontWeight: '400',
  },
  progressDetail: {
    paddingHorizontal: 16,
    paddingVertical: 8,
  },
  leave: {
    gap: 4,
  },
  lookup: {
    gap: 8,
    padding: 16,
  },
  lookupRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    minHeight: 40,
  },
  lookupError: {
    color: colors.danger,
  },
  back: {
    padding: 14,
    borderRadius: 12,
    backgroundColor: colors.mint,
  },
  backText: {
    color: colors.ink,
    fontSize: 15,
    fontWeight: '500',
  },
});
