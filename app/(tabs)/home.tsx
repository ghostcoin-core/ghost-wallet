// Home: the balance on a card, the four things to do with it, the activity
// and the news. The balance shows at once from the cache with its age, then
// the node is asked in the background; nothing waits for it. On the open
// iPhone Duo the card and the activity sit side by side with the fold between
// them, and the news runs underneath.
import { useRouter } from 'expo-router';
import { useContext, useState } from 'react';
import { ScrollView, StyleSheet, Text, View } from 'react-native';
import { SafeAreaInsetsContext, SafeAreaView } from 'react-native-safe-area-context';

import { ActivityList } from '../../components/activity-list';
import { NewsCards } from '../../components/news-cards';
import { colors, monoFont } from '../../components/theme';
import { Button, ButtonRow, IconButton, NetworkBadge, SectionTitle, Spacer, textStyles, Title } from '../../components/ui';
import { accountZeroAddress } from '../../lib/account';
import { formatGhost } from '../../lib/home/balance-format';
import { balanceStatus } from '../../lib/home/cache-refresh';
import { SAMPLE_NEWS } from '../../lib/home/news';
import { useFaucet } from '../../lib/home/use-faucet';
import { useHome, useNow } from '../../lib/home/use-home';
import { FOLD_GAP, leftColumnWidth, useLayout } from '../../lib/layout';
import { buildNetwork, offersTestGhost } from '../../lib/network/build-network';
import { useTestNetwork } from '../../lib/node/test-network';
import { useSettings } from '../../lib/settings/settings';

const NO_INSETS = { left: 0, right: 0 };

/** The page's side padding on the open Duo. */
const WIDE_PADDING = 28;

export default function HomeScreen() {
  const router = useRouter();
  const { twoColumns, width, height } = useLayout();
  // No insets are known outside a safe-area provider; none are needed on one column.
  const insets = useContext(SafeAreaInsetsContext) ?? NO_INSETS;
  // On the open Duo, the width of the left column: the gap after it is the fold.
  const leftWidth = twoColumns
    ? leftColumnWidth({ width, height, insetLeft: insets.left, insetRight: insets.right, padding: WIDE_PADDING })
    : undefined;
  const { nodeUrl } = useSettings();
  const [address] = useState(accountZeroAddress);
  const { view, refresh } = useHome(nodeUrl, address);
  const testNetwork = offersTestGhost(buildNetwork, useTestNetwork(nodeUrl));
  const faucet = useFaucet(nodeUrl, address, refresh);
  const now = useNow();
  const snapshot = view.snapshot;

  return (
    <SafeAreaView edges={['top', 'left', 'right']} style={styles.page} testID="home-screen">
      <ScrollView
        contentInsetAdjustmentBehavior="automatic"
        contentContainerStyle={[styles.content, twoColumns && styles.contentWide]}
        style={styles.scroll}
        testID="home-screen-content"
      >
        <View style={styles.header}>
          <Title>Home</Title>
          <NetworkBadge background={colors.paper} />
          <Spacer />
          <IconButton
            icon="tap"
            label="Tap a card"
            onPress={() => router.push('/check-card')}
            testID="open-check-card"
          />
        </View>

        <View style={twoColumns ? styles.columns : styles.stack}>
          <View style={[styles.column, leftWidth !== undefined && { width: leftWidth }]}>
            <View style={styles.card} testID="balance">
              <Text style={styles.cardName}>Specter</Text>
              {address === null ? (
                <Text style={[styles.cardStatus, styles.cardPush]} testID="balance-status">
                  The account is not available in this build.
                </Text>
              ) : (
                <>
                  <Text
                    style={[styles.balance, styles.cardPush]}
                    adjustsFontSizeToFit
                    numberOfLines={1}
                    testID="balance-amount"
                    accessibilityLabel={snapshot ? `${formatGhost(snapshot.balanceWei)} GHOST` : 'Balance not known yet'}
                  >
                    {snapshot ? formatGhost(snapshot.balanceWei) : '–'}
                    <Text style={styles.balanceUnit}> GHOST</Text>
                  </Text>
                  <Text style={styles.cardStatus} testID="balance-status">
                    {balanceStatus(view, now)}
                  </Text>
                </>
              )}
            </View>

            <ButtonRow>
              <Button label="Send" ink disabled={address === null} onPress={() => router.push('/send')} testID="open-send" />
              <Button
                label="Receive"
                secondary
                disabled={address === null}
                onPress={() => router.push('/receive')}
                testID="open-receive"
              />
            </ButtonRow>
            <ButtonRow>
              <Button
                label="Vanish"
                secondary
                disabled={address === null}
                onPress={() => router.push('/vanish')}
                testID="open-vanish"
              />
              <Button
                label="Summon"
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

          <View style={[styles.column, twoColumns && styles.rest]}>
            {twoColumns ? null : <SectionTitle>Activity</SectionTitle>}
            <ActivityList nodeUrl={nodeUrl} kept={snapshot?.activity} />
          </View>
        </View>

        <SectionTitle>News</SectionTitle>
        <NewsCards stories={SAMPLE_NEWS} leftWidth={leftWidth} />
      </ScrollView>
    </SafeAreaView>
  );
}

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
    gap: 12,
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
  },
  stack: {
    gap: 12,
  },
  // The gap between the columns is where the open Duo folds: nothing sits in it.
  columns: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: FOLD_GAP,
  },
  column: {
    gap: 12,
  },
  rest: {
    flex: 1,
    minWidth: 0,
  },
  card: {
    minHeight: 168,
    padding: 20,
    borderRadius: 20,
    backgroundColor: colors.violet,
  },
  cardName: {
    color: colors.paper,
    fontSize: 16,
    fontWeight: '600',
  },
  cardPush: {
    marginTop: 'auto',
  },
  balance: {
    color: colors.paper,
    fontFamily: monoFont,
    fontSize: 34,
    fontWeight: '500',
    letterSpacing: -0.68,
  },
  balanceUnit: {
    fontSize: 16,
    letterSpacing: 0,
  },
  cardStatus: {
    marginTop: 4,
    color: colors.violetTint,
    fontSize: 13,
  },
  faucetError: {
    color: colors.danger,
  },
});
