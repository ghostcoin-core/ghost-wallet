// What the Ghost card screens share: the card's status after a Check.
import { StyleSheet, Text } from 'react-native';

import {
  ghostStatusDetail,
  ghostStatusIsAlarm,
  ghostStatusText,
  safeToAccept,
  type GhostCardStatus,
} from '../lib/ghost-card/status';
import { colors } from './theme';
import { Panel, textStyles } from './ui';

/** The card's status after a tap, as one line and a quieter one. */
export function GhostCardStatusPanel({ status, testID }: { status: GhostCardStatus; testID: string }) {
  const alarm = ghostStatusIsAlarm(status);
  const safe = safeToAccept(status);
  const detail = ghostStatusDetail(status);
  return (
    <Panel style={styles.panel} testID={testID}>
      <Text style={textStyles.quiet}>This card</Text>
      <Text
        accessibilityLiveRegion="polite"
        style={[styles.status, alarm && styles.alarm, safe && styles.safe]}
        testID={`${testID}-text`}
      >
        {ghostStatusText(status)}
      </Text>
      {detail ? (
        <Text style={[textStyles.body, alarm && styles.alarm]} testID={`${testID}-detail`}>
          {detail}
        </Text>
      ) : null}
    </Panel>
  );
}

const styles = StyleSheet.create({
  panel: {
    gap: 8,
    padding: 16,
  },
  status: {
    color: colors.ink,
    fontSize: 22,
    fontWeight: '600',
  },
  alarm: {
    color: colors.danger,
  },
  safe: {
    color: colors.violet,
  },
});
