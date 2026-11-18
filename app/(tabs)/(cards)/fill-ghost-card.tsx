// Fill a Ghost card: pick an amount, then tap a blank Ghost card.
// The card makes the Phantom Key itself and hands back only the coin's
// public commit data; in the same tap it signs a seal statement over this
// iPhone's challenge, and the native core checks it says Sealed with exactly
// that commit data before anything is paid. Then the usual Vanish pays the
// amount into it. No words and no key are ever on this phone, and no Seal or
// Ghost server takes part. The card is a bearer object: no code goes with it.
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { StyleSheet, Text, TextInput, View } from 'react-native';

import { GhostCardStatusPanel } from '../../../components/ghost-card-ui';
import { CardBusy } from '../../../components/seal-ui';
import { colors, monoFont } from '../../../components/theme';
import { Button, Column, Logo, NetworkBadge, Panel, Screen, Spacer, textStyles, Title } from '../../../components/ui';
import { PaymentExit, PaymentProgress } from '../../../components/vanish-ui';
import { accountZeroAddress } from '../../../lib/account';
import { ghostCardDeps } from '../../../lib/ghost-card/deps';
import { fillGhostCard } from '../../../lib/ghost-card/flows';
import type { GhostCardStatus } from '../../../lib/ghost-card/status';
import { failureReason } from '../../../lib/node/failure-reason';
import { ghostText } from '../../../lib/seal/card-status';
import { useSettings } from '../../../lib/settings/settings';
import { minimumVanish, signVanishAgain, startSealedCardVanish } from '../../../lib/vanish/actions';
import { parseGhostAmount } from '../../../lib/vanish/amount';
import { paymentsChanged, shared } from '../../../lib/vanish/pending';
import { screenDone } from '../../../lib/vanish/status-mapping';
import { paymentKit, usePayment } from '../../../lib/vanish/use-payment';
import type { CorePaymentSequence } from '../../../modules/ghost-core';

/** Below this many seal checks the writer is told the card is near its end. */
const LOW_CHECKS = 64;

export default function FillGhostCardScreen() {
  const router = useRouter();
  const { nodeUrl } = useSettings();
  const [address] = useState(accountZeroAddress);
  const kit = useMemo(() => paymentKit(nodeUrl), [nodeUrl]);
  const deps = useMemo(() => ghostCardDeps(kit), [kit]);
  const cards = deps.nfc !== null && deps.core !== null;

  // Vanish hands over the amount typed there; it is still checked here like any typed amount.
  const { amount: asked } = useLocalSearchParams<{ amount?: string }>();
  const [amountText, setAmountText] = useState(typeof asked === 'string' ? asked : '');
  const [minimum, setMinimum] = useState<bigint | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<GhostCardStatus | null>(null);
  const [sequence, setSequence] = useState<CorePaymentSequence | null>(null);
  const [filled, setFilled] = useState<{
    cardNumber: string;
    fill: number;
    amountWei: bigint;
    checksLeft: number;
    ms: number;
    commitData: Uint8Array;
  } | null>(null);

  useEffect(() => {
    if (!kit) {
      return;
    }
    minimumVanish(kit).then(setMinimum, () => setMinimum(null));
  }, [kit]);

  const rebuild = useMemo(() => (kit && sequence ? signVanishAgain(kit, sequence) : null), [kit, sequence]);
  const payment = usePayment(kit, sequence, rebuild, false);

  const amount = parseGhostAmount(amountText);
  const tooSmall = amount !== null && minimum !== null && amount < minimum;
  const amountOk = !!kit && !!address && cards && amount !== null && amount > 0n && !tooSmall;

  async function fill() {
    if (!kit || !address || amount === null || !amountOk || busy) {
      return;
    }
    setBusy(true);
    setError(null);
    setStatus(null);
    try {
      const result = await fillGhostCard(deps, amount);
      if (!result.ok) {
        setStatus(result.status);
        return;
      }
      const made = {
        cardNumber: result.cardNumber,
        fill: result.fill,
        amountWei: result.amountWei,
        checksLeft: result.checksLeft,
        ms: result.ms,
        commitData: result.commitData,
      };
      setFilled(made);
      await pay(made.amountWei, made.commitData);
    } finally {
      setBusy(false);
    }
  }

  /** The Vanish into the card's commit data; the same bytes every time, so it is never paid twice. */
  async function pay(amountWei: bigint, commitData: Uint8Array) {
    if (!kit || !address) {
      return;
    }
    setError(null);
    try {
      const started = await startSealedCardVanish(kit, address, amountWei, commitData);
      setSequence(shared(started.sequence));
      paymentsChanged();
    } catch (failure) {
      setError(`The card is sealed, but the payment could not start. ${failureReason(failure, kit.nodeUrl)}`);
    }
  }

  return (
    <Screen
      testID="fill-ghost-card-screen"
      wide="columns"
      topBar={
        <>
          <Spacer />
          <NetworkBadge />
          <Logo />
        </>
      }
    >
      <Column>
        <Title>Fill a Ghost card</Title>
        {!filled ? (
          <>
            <Text style={textStyles.body}>
              The card makes its own key: no words are shown, and whoever holds the card holds the GHOST. A lost or
              broken card is lost GHOST, like cash.
            </Text>
            <Panel style={styles.form}>
              <Text style={textStyles.quiet}>Amount</Text>
              <View style={styles.amountRow}>
                <TextInput
                  accessibilityLabel="Amount in GHOST"
                  editable={!busy}
                  keyboardType="decimal-pad"
                  onChangeText={setAmountText}
                  placeholder="0.0"
                  placeholderTextColor={colors.quiet}
                  style={styles.amount}
                  testID="ghost-fill-amount"
                  value={amountText}
                />
                <Text style={textStyles.body}>GHOST</Text>
              </View>
              {tooSmall && minimum !== null ? (
                <Text style={textStyles.quiet} testID="ghost-fill-amount-error">
                  The smallest card is {ghostText(minimum)} GHOST.
                </Text>
              ) : null}
            </Panel>
            <Button
              label={busy ? 'Hold the card near the iPhone' : `Tap a blank card to put ${ghostText(amount ?? 0n)} GHOST on it`}
              icon="key"
              disabled={busy || !amountOk}
              onPress={() => void fill()}
              testID="ghost-fill-tap"
            />
          </>
        ) : null}
        {busy ? <CardBusy text="Making the key on the card and checking its seal…" testID="ghost-fill-spinner" /> : null}
        {error ? (
          <Text accessibilityLiveRegion="polite" style={[textStyles.body, styles.error]} testID="ghost-fill-error">
            {error}
          </Text>
        ) : null}
        {!cards ? (
          <Text style={textStyles.quiet} testID="ghost-fill-unavailable">
            This iPhone cannot read Ghost cards in this build.
          </Text>
        ) : null}
      </Column>
      <Column>
        {status ? <GhostCardStatusPanel status={status} testID="ghost-fill-status" /> : null}
        {filled ? (
          <Panel style={styles.form} testID="ghost-fill-summary">
            <Text style={textStyles.quiet}>Card {filled.cardNumber}</Text>
            <Text style={textStyles.body}>
              Sealed (fill {filled.fill}) with a key made on the card. Paying {ghostText(filled.amountWei)} GHOST into it
              now. Tap took {(filled.ms / 1000).toFixed(1)} s.
            </Text>
            {filled.checksLeft < LOW_CHECKS ? (
              <Text style={[textStyles.body, styles.error]} testID="ghost-fill-low-checks">
                Only {filled.checksLeft} seal checks left on this card: it is near the end of its life.
              </Text>
            ) : null}
          </Panel>
        ) : null}
        {filled && !sequence && !busy ? (
          <Button
            label="Try the payment again"
            onPress={() => void pay(filled.amountWei, filled.commitData)}
            testID="ghost-fill-pay-again"
          />
        ) : null}
        {sequence && payment ? (
          <>
            <PaymentProgress status={payment.status} kind="vanish" step={payment.step} error={payment.error} />
            <PaymentExit final={screenDone(payment.status)} onLeave={() => router.back()} testPrefix="ghost-fill" />
          </>
        ) : null}
      </Column>
    </Screen>
  );
}

const styles = StyleSheet.create({
  form: {
    gap: 8,
    padding: 16,
  },
  amountRow: {
    flexDirection: 'row',
    alignItems: 'baseline',
    gap: 8,
  },
  amount: {
    flex: 1,
    minHeight: 44,
    color: colors.ink,
    fontFamily: monoFont,
    fontSize: 22,
  },
  error: {
    color: colors.danger,
  },
});
