// The payment screen of a send, after docs/mockups/payment.html: what was sent
// and to whom, its progress (queued, sent, in a block, settled; or failed, or
// conflicted) and that it is safe to close the app. The send moves while the
// screen is open; leaving it (Close) keeps the send going from Home. Done shows
// once nothing more can happen to it. On the iPhone Duo open the amount and
// its details sit on one side of the fold and the progress on the other.
import { useRouter } from 'expo-router';
import { useMemo, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';

import { SendProgress } from '../components/send-ui';
import { colors, monoFont } from '../components/theme';
import { Button, Column, IconButton, Logo, NetworkBadge, Panel, Screen, Spacer, TextButton, textStyles } from '../components/ui';
import { formatGhost, formatWhen, shortAddress } from '../lib/home/balance-format';
import { useNow } from '../lib/home/use-home';
import { useLayout } from '../lib/layout';
import { isFinalSend, sendHeadline, sendStatusDetail } from '../lib/send/payment-status';
import { sendDetailsOf, sendKit, type SendKit } from '../lib/send/send-payment';
import { useSendPayment } from '../lib/send/use-send-payment';
import { useSettings } from '../lib/settings/settings';
import { newestShared, openShared, takeReopened } from '../lib/vanish/pending';
import type { CorePaymentSequence } from '../modules/ghost-core';

/** The send Home or the Send screen asked for, or else the newest one. */
function resumeSend(kit: SendKit | null): CorePaymentSequence | null {
  if (!kit) {
    return null;
  }
  const wanted = takeReopened(['send']);
  return wanted ? openShared(kit, wanted) : newestShared(kit, ['send']);
}

export default function PaymentScreen() {
  const router = useRouter();
  const { twoColumns } = useLayout();
  const { nodeUrl } = useSettings();
  const kit = useMemo(() => sendKit(nodeUrl), [nodeUrl]);
  const [sequence] = useState(() => resumeSend(kit));
  const payment = useSendPayment(kit, sequence);
  const now = useNow();
  const details = sequence ? sendDetailsOf(sequence.record()) : null;
  const leave = () => (router.canGoBack() ? router.back() : router.replace('/home'));

  const topBar = (
    <>
      <IconButton icon="cross" label="Close" onPress={leave} testID="close" />
      <Spacer />
      <NetworkBadge />
      <Logo />
    </>
  );

  if (!payment || !details) {
    return (
      <Screen testID="payment-screen" topBar={topBar}>
        <Text style={textStyles.body} testID="payment-none">
          No send to show.
        </Text>
        <Button label="Done" onPress={leave} testID="payment-done" />
      </Screen>
    );
  }

  const { status } = payment;
  const final = isFinalSend(status);
  const gasLimit = kit ? kit.core.testSendGasLimit() : null;
  const feeWei = details.maxFeePerGas !== null && gasLimit !== null ? BigInt(details.maxFeePerGas) * gasLimit : null;
  const problem = status === 'failed' || status === 'conflicted';

  return (
    <Screen testID="payment-screen" wide="split" topBar={topBar}>
      <Column>
        <View testID="payment-summary">
          <Text style={textStyles.quiet}>{sendHeadline(status)}</Text>
          <Text style={styles.hero} testID="payment-amount">
            {formatGhost(details.amountWei)}
            <Text style={styles.heroUnit}> GHOST</Text>
          </Text>
          <Text style={textStyles.quiet}>
            to <Text style={styles.mono}>{shortAddress(details.to)}</Text>
          </Text>
        </View>
        {twoColumns ? (
          <Panel testID="payment-details">
            <DetailRow label="Fee" first>
              {feeWei !== null ? `${formatGhost(feeWei)} GHOST at most` : 'Set when it goes out'}
            </DetailRow>
            <DetailRow label="Total">
              {`${formatGhost(BigInt(details.amountWei) + (feeWei ?? 0n))} GHOST${feeWei === null ? ' and the fee' : ''}`}
            </DetailRow>
            <DetailRow label="Saved at">{formatWhen(details.at, now)}</DetailRow>
          </Panel>
        ) : null}
        <View style={[styles.highlight, problem && styles.highlightProblem]} accessibilityRole="text" testID="payment-note">
          <Text style={styles.highlightText}>{sendStatusDetail(status)}</Text>
        </View>
        {payment.error ? (
          <Text accessibilityLiveRegion="polite" style={textStyles.quiet} testID="payment-error">
            {payment.error} Trying again.
          </Text>
        ) : null}
      </Column>
      <Column style={twoColumns ? styles.progressPane : undefined}>
        <SendProgress status={status} />
        {twoColumns ? <Spacer /> : null}
        {final ? (
          <Button label="Done" onPress={leave} testID="payment-done" />
        ) : (
          <View style={styles.leave} testID="payment-leave-note">
            <Text style={textStyles.body}>You can close this screen. The send keeps going.</Text>
            <TextButton label="Close" onPress={leave} testID="payment-leave" />
          </View>
        )}
      </Column>
    </Screen>
  );
}

function DetailRow({ label, first, children }: { label: string; first?: boolean; children: string }) {
  return (
    <View style={[styles.detailRow, !first && styles.detailDivider]}>
      <Text style={styles.detailLabel}>{label}</Text>
      <Text style={styles.detailValue}>{children}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  hero: {
    color: colors.ink,
    fontFamily: monoFont,
    fontSize: 34,
    fontWeight: '500',
  },
  heroUnit: {
    fontSize: 17,
  },
  mono: {
    fontFamily: monoFont,
  },
  highlight: {
    paddingVertical: 12,
    paddingHorizontal: 14,
    borderRadius: 12,
    backgroundColor: colors.violetTint,
  },
  highlightProblem: {
    borderWidth: 1,
    borderColor: colors.danger,
    backgroundColor: colors.paper,
  },
  highlightText: {
    color: colors.ink,
    fontSize: 15,
  },
  progressPane: {
    alignSelf: 'stretch',
  },
  leave: {
    gap: 4,
  },
  detailRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    minHeight: 52,
    paddingVertical: 10,
    paddingHorizontal: 16,
  },
  detailDivider: {
    borderTopWidth: 1,
    borderTopColor: colors.line,
  },
  detailLabel: {
    flex: 1,
    color: colors.body,
    fontSize: 16,
  },
  detailValue: {
    flexShrink: 1,
    color: colors.ink,
    fontFamily: monoFont,
    fontSize: 14,
    textAlign: 'right',
  },
});
