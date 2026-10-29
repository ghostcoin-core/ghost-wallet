// The progress of a send on the payment screen, after docs/mockups/payment.html:
// each stage with its mark (done in violet, current outlined, still to come
// quiet) and a quiet line under its name.
import { StyleSheet, Text, View } from 'react-native';

import { sendProgressRows, type SendProgressRow, type SendStatus } from '../lib/send/payment-status';
import { Icon, type IconName } from './icons';
import { colors } from './theme';
import { Panel, textStyles } from './ui';

const PROBLEMS: readonly SendStatus[] = ['failed', 'conflicted'];

function markOf(status: SendStatus, state: SendProgressRow['state']): IconName {
  if (status === 'failed') {
    return 'cross';
  }
  if (status === 'conflicted') {
    return 'warning';
  }
  return state === 'done' ? 'check' : state === 'current' ? 'clock' : 'dot';
}

export function SendProgress({ status }: { status: SendStatus }) {
  const rows = sendProgressRows(status);
  return (
    <Panel style={styles.panel} testID="send-progress">
      {rows.map((row) => {
        const problem = PROBLEMS.includes(row.status);
        const color =
          row.state === 'done' ? colors.paper : problem ? colors.danger : row.state === 'current' ? colors.violet : colors.quiet;
        return (
          <View
            key={row.status}
            style={styles.row}
            testID={`send-stage-${row.status}`}
            accessibilityLabel={`${row.label}, ${row.state === 'done' ? 'done' : row.state === 'current' ? 'now' : 'to come'}`}
            accessibilityState={{ selected: row.state === 'current' }}
          >
            <View
              style={[
                styles.mark,
                row.state === 'done' && styles.markDone,
                row.state === 'current' && styles.markCurrent,
                problem && styles.markProblem,
              ]}
            >
              <Icon name={markOf(row.status, row.state)} size={16} color={color} />
            </View>
            <View style={styles.text}>
              <Text style={[styles.title, row.state === 'waiting' && styles.titleWaiting]}>{row.label}</Text>
              <Text style={textStyles.quiet}>{row.note}</Text>
            </View>
          </View>
        );
      })}
    </Panel>
  );
}

const styles = StyleSheet.create({
  panel: {
    gap: 18,
    padding: 20,
  },
  row: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 14,
  },
  mark: {
    alignItems: 'center',
    justifyContent: 'center',
    width: 28,
    height: 28,
    borderWidth: 2,
    borderColor: colors.line,
    borderRadius: 14,
    backgroundColor: colors.paper,
  },
  markDone: {
    borderColor: colors.violet,
    backgroundColor: colors.violet,
  },
  markCurrent: {
    borderColor: colors.violet,
  },
  markProblem: {
    borderColor: colors.danger,
    backgroundColor: colors.paper,
  },
  text: {
    flex: 1,
    gap: 2,
  },
  title: {
    color: colors.ink,
    fontSize: 16,
    fontWeight: '600',
  },
  titleWaiting: {
    color: colors.quiet,
    fontWeight: '500',
  },
});
