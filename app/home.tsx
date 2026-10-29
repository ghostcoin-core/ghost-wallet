// Home: the balance and the activity, after docs/mockups/home.html. The
// balance shows at once from the cache with its age, then the node is asked in
// the background; nothing waits for it. A send, Vanish, Summon or Claim still
// going heads the activity as pending, with the step it is at; tapping it
// opens its progress again.
import { useRouter } from 'expo-router';
import { useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';

import { colors, monoFont } from '../components/theme';
import {
  Button,
  ButtonRow,
  Column,
  IconButton,
  Logo,
  NetworkBadge,
  Panel,
  Row,
  Screen,
  SectionTitle,
  Spacer,
  textStyles,
} from '../components/ui';
import { accountZeroAddress } from '../lib/account';
import { describeActivity, sortActivity, type ActivityRow } from '../lib/home/activity';
import { formatGhost, formatSignedGhost } from '../lib/home/balance-format';
import { balanceStatus } from '../lib/home/cache-refresh';
import { useFaucet } from '../lib/home/use-faucet';
import { useHome, useNow } from '../lib/home/use-home';
import { usePendingPayments } from '../lib/home/use-pending';
import { useTestNetwork } from '../lib/node/test-network';
import { useSettings } from '../lib/settings/settings';
import { reopenPayment, type PendingPayment } from '../lib/vanish/pending';

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

export default function HomeScreen() {
  const router = useRouter();
  const { nodeUrl } = useSettings();
  const [address] = useState(accountZeroAddress);
  const { view, refresh } = useHome(nodeUrl, address);
  const pending = usePendingPayments(nodeUrl);
  const testNetwork = useTestNetwork(nodeUrl);
  const faucet = useFaucet(nodeUrl, address, refresh);
  const now = useNow();
  const snapshot = view.snapshot;
  const rows = sortActivity(snapshot?.activity ?? []).map((item) => describeActivity(item, now));

  return (
    <Screen
      testID="home-screen"
      background="mist"
      wide="columns"
      topBar={
        <>
          <Logo />
          <NetworkBadge />
          <Spacer />
          <IconButton
            icon="settings"
            label="Settings"
            background={colors.mist}
            onPress={() => router.push('/settings')}
            testID="open-settings"
          />
        </>
      }
    >
      <Column>
        <Panel style={styles.balancePanel} testID="balance">
          <Text style={textStyles.quiet}>Balance</Text>
          {address === null ? (
            <Text style={[textStyles.body, styles.balanceGap]} testID="balance-status">
              The account is not available in this build.
            </Text>
          ) : (
            <>
              <Text style={styles.balance} testID="balance-amount" accessibilityLabel={snapshot ? `${formatGhost(snapshot.balanceWei)} GHOST` : 'Balance not known yet'}>
                {snapshot ? formatGhost(snapshot.balanceWei) : '–'}
                <Text style={styles.balanceUnit}> GHOST</Text>
              </Text>
              <Text style={[textStyles.quiet, styles.balanceGap]} testID="balance-status">
                {balanceStatus(view, now)}
              </Text>
            </>
          )}
          <View style={styles.actions}>
            <ButtonRow>
              <Button
                label="Send"
                icon="send"
                disabled={address === null}
                onPress={() => router.push('/send')}
                testID="open-send"
              />
              <Button
                label="Receive"
                icon="receive"
                secondary
                disabled={address === null}
                onPress={() => router.push('/receive')}
                testID="open-receive"
              />
            </ButtonRow>
            <ButtonRow>
              <Button
                label="Vanish"
                icon="key"
                disabled={address === null}
                onPress={() => router.push('/vanish')}
                testID="open-vanish"
              />
              <Button
                label="Summon"
                icon="receive"
                secondary
                disabled={address === null}
                onPress={() => router.push('/summon')}
                testID="open-summon"
              />
            </ButtonRow>
            {testNetwork && address !== null ? (
              <>
                <Button
                  label={faucet.state.name === 'asking' ? 'Getting test GHOST…' : 'Get test GHOST'}
                  icon="receive"
                  secondary
                  disabled={faucet.state.name === 'asking'}
                  onPress={() => void faucet.ask()}
                  testID="get-test-ghost"
                />
                {faucet.state.name === 'sent' ? (
                  <Text accessibilityLiveRegion="polite" style={textStyles.quiet} testID="faucet-status">
                    10 test GHOST arrived. Test GHOST has no value.
                  </Text>
                ) : null}
                {faucet.state.name === 'failed' ? (
                  <Text accessibilityLiveRegion="polite" style={[textStyles.body, styles.faucetError]} testID="faucet-status">
                    {faucet.state.message}
                  </Text>
                ) : null}
              </>
            ) : null}
          </View>
        </Panel>
      </Column>
      <Column>
        <SectionTitle>Activity</SectionTitle>
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
      </Column>
    </Screen>
  );
}

const styles = StyleSheet.create({
  balancePanel: {
    padding: 20,
  },
  balance: {
    marginTop: 4,
    color: colors.ink,
    fontFamily: monoFont,
    fontSize: 38,
    fontWeight: '500',
    letterSpacing: -0.76,
  },
  balanceUnit: {
    fontSize: 18,
    letterSpacing: 0,
  },
  balanceGap: {
    marginTop: 4,
  },
  actions: {
    gap: 12,
    marginTop: 20,
  },
  empty: {
    padding: 16,
  },
  faucetError: {
    color: colors.danger,
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
