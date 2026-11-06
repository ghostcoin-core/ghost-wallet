// Fill a card: pick an amount (and, if wanted, an Open PIN), then tap a Ghost
// Sealed card that is set up and empty. The Seal writes a fresh key to the
// card and hands back only the coin's public commit data; the app Vanishes
// exactly that amount into it with the usual Vanish payment, and shows
// "Filling" until the Seal, asked again with a tap, answers Sealed once the
// chain check finds the coin paid and settled. No words and no key are ever
// shown or held on this phone. The PIN goes to the Seal only and leaves this
// screen's state as soon as the Fill is asked for.
import { useRouter } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { StyleSheet, Text, TextInput, View } from 'react-native';

import { CardBusy, CardStatusPanel, PinInput } from '../components/seal-ui';
import { colors, monoFont } from '../components/theme';
import { Button, Column, IconButton, Logo, NetworkBadge, Panel, Screen, Spacer, textStyles, Title } from '../components/ui';
import { PaymentExit, PaymentProgress } from '../components/vanish-ui';
import { accountZeroAddress } from '../lib/account';
import { failureReason } from '../lib/node/failure-reason';
import { ghostText, statusText, type CardStatus } from '../lib/seal/card-status';
import { confirmFill, fillCard, sealDeps } from '../lib/seal/flows';
import { pinRule } from '../lib/seal/pin';
import { useSettings } from '../lib/settings/settings';
import { minimumVanish, signVanishAgain, startSealedCardVanish } from '../lib/vanish/actions';
import { parseGhostAmount } from '../lib/vanish/amount';
import { paymentsChanged, shared } from '../lib/vanish/pending';
import { screenDone } from '../lib/vanish/status-mapping';
import { paymentKit, usePayment } from '../lib/vanish/use-payment';
import type { CorePaymentSequence } from '../modules/ghost-core';
import { cardsSupported } from '../modules/ghost-nfc';

export default function FillCardScreen() {
  const router = useRouter();
  const { nodeUrl } = useSettings();
  const [address] = useState(accountZeroAddress);
  const kit = useMemo(() => paymentKit(nodeUrl), [nodeUrl]);
  const [deps] = useState(sealDeps);
  const [cards] = useState(cardsSupported);

  const [amountText, setAmountText] = useState('');
  const [pin, setPin] = useState('');
  const [pinAgain, setPinAgain] = useState('');
  const [minimum, setMinimum] = useState<bigint | null>(null);
  const [busy, setBusy] = useState<'fill' | 'confirm' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<CardStatus | null>(null);
  const [sequence, setSequence] = useState<CorePaymentSequence | null>(null);
  const [filled, setFilled] = useState<{ uid: string; amountWei: bigint } | null>(null);

  useEffect(() => {
    if (!kit) {
      return;
    }
    minimumVanish(kit).then(setMinimum, () => setMinimum(null));
  }, [kit]);

  const rebuild = useMemo(() => (kit && sequence ? signVanishAgain(kit, sequence) : null), [kit, sequence]);
  const payment = usePayment(kit, sequence, rebuild, false);

  const amount = parseGhostAmount(amountText);
  const rule = pinRule(pin, pinAgain, true);
  const tooSmall = amount !== null && minimum !== null && amount < minimum;
  const canFill = !!kit && !!address && cards && amount !== null && amount > 0n && !tooSmall && rule.ok && busy === null;

  async function fill() {
    if (!kit || !address || amount === null || !canFill || !rule.ok) {
      return;
    }
    const chosen = rule.pin;
    // The PIN goes to the Seal with this call and is not kept on the screen.
    setPin('');
    setPinAgain('');
    setBusy('fill');
    setError(null);
    setStatus(null);
    try {
      const result = await fillCard(deps, amount, chosen);
      if (!result.ok) {
        setStatus(result.status);
        return;
      }
      try {
        const started = await startSealedCardVanish(kit, address, result.amountWei, result.commitData);
        setSequence(shared(started.sequence));
        setFilled({ uid: result.uid, amountWei: result.amountWei });
        setStatus({ kind: 'filling' });
        paymentsChanged();
      } catch (failure) {
        setError(
          `The card holds a new key, but the Vanish could not start. ${failureReason(failure, kit.nodeUrl)} Tap the same card again to try again: it gets no second key.`,
        );
      }
    } finally {
      setBusy(null);
    }
  }

  async function confirm() {
    if (busy !== null) {
      return;
    }
    setBusy('confirm');
    setError(null);
    try {
      const result = await confirmFill(deps);
      if (result) {
        setStatus(result);
      }
    } finally {
      setBusy(null);
    }
  }

  const secured = status?.kind === 'secured';

  return (
    <Screen
      testID="fill-card-screen"
      wide="columns"
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
        <Title>Fill a card</Title>
        {!sequence ? (
          <>
            <Text style={textStyles.body}>
              The Seal writes a fresh key to an empty Ghost card. No words are shown: whoever holds the card holds the
              GHOST.
            </Text>
            <Panel style={styles.form}>
              <Text style={textStyles.quiet}>Amount</Text>
              <View style={styles.amountRow}>
                <TextInput
                  accessibilityLabel="Amount in GHOST"
                  keyboardType="decimal-pad"
                  onChangeText={setAmountText}
                  placeholder="0.0"
                  placeholderTextColor={colors.quiet}
                  style={styles.amount}
                  testID="fill-amount"
                  value={amountText}
                />
                <Text style={textStyles.body}>GHOST</Text>
              </View>
              {tooSmall && minimum !== null ? (
                <Text style={textStyles.quiet} testID="fill-amount-error">
                  The smallest card is {ghostText(minimum)} GHOST.
                </Text>
              ) : null}
              <Text style={textStyles.quiet}>Card PIN (optional, 4 to 8 digits)</Text>
              <PinInput value={pin} onChange={setPin} label="Card PIN" testID="fill-pin" />
              {pin !== '' ? <PinInput value={pinAgain} onChange={setPinAgain} label="Card PIN again" testID="fill-pin-again" /> : null}
              {!rule.ok && (pin !== '' || pinAgain !== '') ? (
                <Text style={textStyles.quiet} testID="fill-pin-error">
                  {rule.message}
                </Text>
              ) : null}
              <Text style={textStyles.quiet}>
                With a PIN, opening the card asks for it, and five wrong PINs lock the card for good. Give the PIN to
                whoever you give the card.
              </Text>
            </Panel>
            <Button
              label={busy === 'fill' ? 'Hold the card near the iPhone' : 'Tap an empty card'}
              icon="key"
              disabled={!canFill}
              onPress={() => void fill()}
              testID="fill-tap"
            />
          </>
        ) : null}
        {busy !== null ? (
          <CardBusy text={busy === 'fill' ? 'Filling the card with the Seal…' : 'Checking the card with the Seal…'} testID="fill-spinner" />
        ) : null}
        {error ? (
          <Text accessibilityLiveRegion="polite" style={[textStyles.body, styles.error]} testID="fill-error">
            {error}
          </Text>
        ) : null}
        {!cards ? (
          <Text style={textStyles.quiet} testID="fill-unavailable">
            This iPhone cannot read cards in this build.
          </Text>
        ) : null}
      </Column>
      <Column>
        {status ? <CardStatusPanel status={status} testID="fill-status" /> : null}
        {sequence && payment ? (
          <>
            <PaymentProgress status={payment.status} kind="vanish" step={payment.step} error={payment.error} />
            {filled ? (
              <Text style={textStyles.quiet} testID="fill-summary">
                {ghostText(filled.amountWei)} GHOST to card {filled.uid}.
              </Text>
            ) : null}
            {!secured ? (
              <>
                <Text style={textStyles.body}>
                  Once the payment settles, tap the card again: the Seal marks it Secured when the chain shows the
                  exact amount paid. Until then it is {statusText({ kind: 'filling' }).toLowerCase()}.
                </Text>
                <Button
                  label={busy === 'confirm' ? 'Hold the card near the iPhone' : 'Check the card'}
                  icon="check"
                  secondary
                  disabled={busy !== null}
                  onPress={() => void confirm()}
                  testID="fill-confirm"
                />
              </>
            ) : null}
            <PaymentExit final={secured || screenDone(payment.status)} onLeave={() => router.back()} testPrefix="fill" />
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
