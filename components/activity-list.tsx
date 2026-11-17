// The activity list, on Home and on the Activity tab. A send, Vanish, Summon
// or Claim still going heads it as pending, with the step it is at; tapping it
// opens its progress again. Once it settles, fails or conflicts it stays in
// the list with that state, read from its saved record.
import { useRouter } from 'expo-router';
import { StyleSheet, Text } from 'react-native';

import { describeActivity, type ActivityItem, type ActivityRow } from '../lib/home/activity';
import { formatSignedGhost } from '../lib/home/balance-format';
import { useActivity, useNow } from '../lib/home/use-home';
import { usePendingPayments } from '../lib/home/use-pending';
import { reopenPayment, type PendingPayment } from '../lib/vanish/pending';
import { colors, monoFont } from './theme';
import { Panel, Row, textStyles } from './ui';

function ActivityRowView({ row, first }: { row: ActivityRow; first: boolean }) {
  return (
    <Row
      icon={row.icon}
      title={row.title}
      detail={row.detail}
      first={first}
      testID={`activity-${row.id}`}
      end={<Text style={[styles.amount, row.struck && styles.amountStruck]}>{row.amount}</Text>}
    />
  );
}

const NO_ACTIVITY: ActivityItem[] = [];

const PENDING_TITLES = { send: 'Send', vanish: 'Vanish', summon: 'Summon', claim: 'Claim' } as const;

/** Where each kind of payment shows its progress. */
const PROGRESS_ROUTES = { send: '/payment', vanish: '/vanish', summon: '/summon', claim: '/summon' } as const;

/** A send, Vanish, Summon or Claim still going: tapping it opens its progress again. */
function PendingRowView({ payment, first, onOpen }: { payment: PendingPayment; first: boolean; onOpen: () => void }) {
  const title = PENDING_TITLES[payment.kind];
  const detail = `Pending: ${payment.stepText}`;
  return (
    <Row
      icon="clock"
      title={title}
      detail={detail}
      first={first}
      opens
      onPress={onOpen}
      accessibilityLabel={`${title}, ${detail}. Opens its progress.`}
      testID={`pending-${payment.id}`}
      end={
        payment.amountWei !== null ? (
          <Text style={styles.amount}>
            {formatSignedGhost(payment.amountWei, payment.kind === 'vanish' || payment.kind === 'send' ? 'sent' : 'received')}
          </Text>
        ) : undefined
      }
    />
  );
}

/**
 * The account's activity: its pending payments, then `kept` (the activity of
 * the saved balance snapshot) joined with what the saved records show.
 */
export function ActivityList({ nodeUrl, kept }: { nodeUrl: string; kept: readonly ActivityItem[] | undefined }) {
  const router = useRouter();
  const pending = usePendingPayments(nodeUrl);
  const now = useNow();
  const activity = useActivity(nodeUrl, kept ?? NO_ACTIVITY);
  const rows = activity.map((item) => describeActivity(item, now));

  return (
    <Panel testID="activity">
      {pending.map((payment, i) => (
        <PendingRowView
          key={payment.id}
          payment={payment}
          first={i === 0}
          onOpen={() => {
            reopenPayment(payment.id);
            router.push(PROGRESS_ROUTES[payment.kind]);
          }}
        />
      ))}
      {rows.length === 0 && pending.length === 0 ? (
        <Text style={[textStyles.quiet, styles.empty]}>
          No activity yet. Payments to and from this account show here.
        </Text>
      ) : (
        rows.map((row, i) => <ActivityRowView key={row.id} row={row} first={i === 0 && pending.length === 0} />)
      )}
    </Panel>
  );
}

const styles = StyleSheet.create({
  empty: {
    padding: 16,
  },
  amount: {
    color: colors.ink,
    fontFamily: monoFont,
    fontSize: 14,
    fontWeight: '500',
  },
  amountStruck: {
    color: colors.quiet,
    textDecorationLine: 'line-through',
  },
});
