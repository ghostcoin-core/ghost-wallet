// Send: an address (pasted or typed), an amount, the fee, a review, then Face
// ID, after docs/mockups/send.html. Face ID passed, the send is saved through
// the native core's step sequence and the payment screen takes over: it signs
// the send in the native core (ML-DSA-44, the words never leave native code)
// and sends it. With the test node out of reach the send is saved as queued
// and goes out once the node answers, from the payment screen or from Home.
// On the iPhone Duo open the form and the review sit side by side, with the
// addresses sent to last under the form.
import * as Clipboard from 'expo-clipboard';
import { useRouter } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { StyleSheet, Text, TextInput, View } from 'react-native';

import { colors, monoFont } from '../components/theme';
import {
  Button,
  Column,
  IconButton,
  Logo,
  NetworkBadge,
  Panel,
  Row,
  Screen,
  SectionTitle,
  Spacer,
  TextButton,
  textStyles,
  Title,
} from '../components/ui';
import { accountZeroAddress } from '../lib/account';
import { authenticate, authFailureMessage } from '../lib/device-auth';
import { formatGhost, formatWhen, shortAddress } from '../lib/home/balance-format';
import { useHome, useNow } from '../lib/home/use-home';
import { useLayout } from '../lib/layout';
import { failureReason } from '../lib/node/failure-reason';
import { quoteFee, recentRecipients, sendKit, startSend, type FeeQuote } from '../lib/send/send-payment';
import { addressMessage, amountMessage, checkAddress, checkAmount, totalWei } from '../lib/send/validation';
import { useSettings } from '../lib/settings/settings';
import { reopenPayment } from '../lib/vanish/pending';

type FeeState = { name: 'asking' } | { name: 'known'; quote: FeeQuote } | { name: 'unknown'; reason: string };

export default function SendScreen() {
  const router = useRouter();
  const { twoColumns } = useLayout();
  const { nodeUrl } = useSettings();
  const [address] = useState(accountZeroAddress);
  const kit = useMemo(() => sendKit(nodeUrl), [nodeUrl]);
  const { view } = useHome(nodeUrl, address);
  const snapshot = view.snapshot;
  const now = useNow();
  const [toText, setToText] = useState('');
  const [amountText, setAmountText] = useState('');
  const [fee, setFee] = useState<FeeState>({ name: 'asking' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recent] = useState(() => (kit ? recentRecipients(kit) : []));

  useEffect(() => {
    if (!kit) {
      return;
    }
    let current = true;
    quoteFee(kit).then(
      (quote) => current && setFee({ name: 'known', quote }),
      (failure) => current && setFee({ name: 'unknown', reason: failureReason(failure, kit.nodeUrl) }),
    );
    return () => {
      current = false;
    };
  }, [kit]);

  const balanceWei = snapshot ? BigInt(snapshot.balanceWei) : null;
  const feeWei = fee.name === 'known' ? fee.quote.feeWei : null;
  const to = checkAddress(toText, address);
  const amount = checkAmount(amountText, balanceWei, feeWei);
  const unavailable = !kit || !address;
  const ready = !unavailable && to.ok && amount.ok && fee.name !== 'asking' && !busy;

  async function paste() {
    try {
      const text = await Clipboard.getStringAsync();
      setToText(text.trim());
      setError(null);
    } catch {
      setError('Nothing could be pasted. Type the address instead.');
    }
  }

  async function send() {
    if (!kit || !address || !to.ok || !amount.ok) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const auth = await authenticate(`Send ${formatGhost(amount.wei)} GHOST`);
      if (!auth.ok) {
        setError(authFailureMessage(auth.reason));
        return;
      }
      const sequence = await startSend(kit, {
        account: address,
        to: to.address,
        amountWei: amount.wei,
        maxFeePerGas: fee.name === 'known' ? fee.quote.maxFeePerGas : null,
        cached: snapshot ? { nonce: snapshot.nonce, tipHeight: snapshot.tipHeight } : null,
      });
      reopenPayment(sequence.record().id);
      router.replace('/payment');
    } catch (failure) {
      setError(`Nothing was sent. ${failureReason(failure, nodeUrl)}`);
    } finally {
      setBusy(false);
    }
  }

  const shownTo = to.ok ? shortAddress(to.address) : null;
  const toProblem = !to.ok && to.problem !== 'empty' ? addressMessage(to.problem) : null;
  const amountProblem = !amount.ok && amount.problem !== 'empty' ? amountMessage(amount.problem, balanceWei) : null;

  return (
    <Screen
      testID="send-screen"
      wide="split"
      topBar={
        <>
          <IconButton icon="back" label="Back" onPress={() => router.back()} testID="back" />
          <Spacer />
          <NetworkBadge />
          <Logo />
        </>
      }
    >
      <Column>
        <Title>Send GHOST</Title>
        <View style={styles.field}>
          <Text style={styles.label}>To</Text>
          <TextInput
            accessibilityLabel="To"
            autoCapitalize="none"
            autoComplete="off"
            autoCorrect={false}
            onChangeText={(text) => {
              setToText(text);
              setError(null);
            }}
            placeholder="0x…"
            placeholderTextColor={colors.quiet}
            spellCheck={false}
            style={[styles.input, styles.addressInput]}
            testID="send-to"
            value={toText}
          />
          <TextButton label="Paste" onPress={() => void paste()} testID="send-paste" />
          {toProblem ? (
            <Text accessibilityLiveRegion="polite" style={[textStyles.quiet, styles.problem]} testID="send-to-problem">
              {toProblem}
            </Text>
          ) : null}
        </View>
        <View style={styles.field}>
          <Text style={styles.label}>Amount</Text>
          <View style={styles.amountRow}>
            <TextInput
              accessibilityLabel="Amount in GHOST"
              keyboardType="decimal-pad"
              onChangeText={(text) => {
                setAmountText(text);
                setError(null);
              }}
              placeholder="0.00"
              placeholderTextColor={colors.quiet}
              style={[styles.input, styles.amountInput]}
              testID="send-amount"
              value={amountText}
            />
            <Text style={styles.unit}>GHOST</Text>
          </View>
          <Text style={textStyles.quiet} testID="send-balance">
            {balanceWei !== null ? `You have ${formatGhost(balanceWei)} GHOST` : 'Balance not known yet'}
          </Text>
          {amountProblem ? (
            <Text accessibilityLiveRegion="polite" style={[textStyles.quiet, styles.problem]} testID="send-amount-problem">
              {amountProblem}
            </Text>
          ) : null}
        </View>
        {twoColumns && recent.length > 0 ? (
          <>
            <SectionTitle>Recent</SectionTitle>
            <Panel testID="send-recent">
              {recent.map((item, index) => (
                <Row
                  key={item.address}
                  icon="send"
                  title={shortAddress(item.address)}
                  detail={`Sent ${formatGhost(item.amountWei)} ${formatWhen(item.at, now)}`}
                  first={index === 0}
                  onPress={() => setToText(item.address)}
                  accessibilityLabel={`Send to ${shortAddress(item.address)} again`}
                  testID={`send-recent-${index}`}
                />
              ))}
            </Panel>
          </>
        ) : null}
      </Column>
      <Column style={twoColumns ? styles.reviewPane : undefined}>
        <SectionTitle>Review</SectionTitle>
        {twoColumns && amount.ok && shownTo ? (
          <View testID="send-review-hero">
            <Text style={textStyles.quiet}>You send</Text>
            <Text style={styles.hero}>
              {formatGhost(amount.wei)}
              <Text style={styles.heroUnit}> GHOST</Text>
            </Text>
            <Text style={textStyles.quiet}>to {shownTo}</Text>
          </View>
        ) : null}
        <Panel testID="send-summary">
          <SummaryRow label="Fee" first testID="send-fee">
            {fee.name === 'known'
              ? `${formatGhost(fee.quote.feeWei)} GHOST at most`
              : fee.name === 'asking'
                ? 'Asking the test node'
                : 'Set when it goes out'}
          </SummaryRow>
          <SummaryRow label="Arrives" testID="send-arrives">
            {fee.name === 'unknown' ? 'When the test node can be reached' : 'In under a minute'}
          </SummaryRow>
          <SummaryRow label="Total" testID="send-total">
            {amount.ok ? `${formatGhost(totalWei(amount.wei, feeWei))} GHOST${feeWei === null ? ' and the fee' : ''}` : '–'}
          </SummaryRow>
        </Panel>
        {fee.name === 'unknown' ? (
          <Text style={textStyles.quiet} testID="send-offline">
            {fee.reason} The send will be queued on this phone and go out by itself, once only.
          </Text>
        ) : null}
        {error ? (
          <Text accessibilityLiveRegion="polite" style={[textStyles.body, styles.error]} testID="send-error">
            {error}
          </Text>
        ) : null}
        {unavailable ? (
          <Text style={textStyles.quiet} testID="send-unavailable">
            Send is not available in this build.
          </Text>
        ) : null}
        {twoColumns ? <Spacer /> : null}
        <Button
          label={busy ? 'Sending…' : 'Send with Face ID'}
          icon="lock"
          disabled={!ready}
          onPress={() => void send()}
          testID="send-confirm"
        />
      </Column>
    </Screen>
  );
}

function SummaryRow({ label, first, testID, children }: { label: string; first?: boolean; testID: string; children: string }) {
  return (
    <View style={[styles.summaryRow, !first && styles.summaryDivider]}>
      <Text style={styles.summaryLabel}>{label}</Text>
      <Text style={styles.summaryValue} testID={testID}>
        {children}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  field: {
    gap: 6,
  },
  label: {
    color: colors.body,
    fontSize: 14,
    fontWeight: '600',
  },
  input: {
    minHeight: 52,
    paddingHorizontal: 14,
    borderWidth: 1,
    borderColor: colors.line,
    borderRadius: 14,
    backgroundColor: colors.paper,
    color: colors.ink,
    fontFamily: monoFont,
  },
  addressInput: {
    fontSize: 14,
  },
  amountRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  amountInput: {
    flex: 1,
    fontSize: 22,
  },
  unit: {
    color: colors.body,
    fontSize: 16,
  },
  problem: {
    color: colors.danger,
  },
  reviewPane: {
    alignSelf: 'stretch',
  },
  hero: {
    color: colors.ink,
    fontFamily: monoFont,
    fontSize: 34,
    fontWeight: '500',
  },
  heroUnit: {
    fontSize: 17,
  },
  summaryRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    minHeight: 52,
    paddingVertical: 10,
    paddingHorizontal: 16,
  },
  summaryDivider: {
    borderTopWidth: 1,
    borderTopColor: colors.line,
  },
  summaryLabel: {
    flex: 1,
    color: colors.body,
    fontSize: 16,
  },
  summaryValue: {
    flexShrink: 1,
    color: colors.ink,
    fontFamily: monoFont,
    fontSize: 14,
    textAlign: 'right',
  },
  error: {
    color: colors.danger,
  },
});
