// Home: the balance and the activity, after docs/mockups/home.html. The
// balance shows at once from the cache with its age, then the node is asked in
// the background; nothing waits for it.
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
import { formatGhost } from '../lib/home/balance-format';
import { balanceStatus } from '../lib/home/cache-refresh';
import { useHome, useNow } from '../lib/home/use-home';
import { useSettings } from '../lib/settings/settings';

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

export default function HomeScreen() {
  const router = useRouter();
  const { nodeUrl } = useSettings();
  const [address] = useState(accountZeroAddress);
  const { view } = useHome(nodeUrl, address);
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
          </View>
        </Panel>
      </Column>
      <Column>
        <SectionTitle>Activity</SectionTitle>
        <Panel testID="activity">
          {rows.length === 0 ? (
            <Text style={[textStyles.quiet, styles.empty]}>
              No activity yet. Payments to and from this account show here.
            </Text>
          ) : (
            rows.map((row, i) => <ActivityRowView key={row.id} row={row} first={i === 0} />)
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
