// Open a Ghost card into my wallet: tap the card. It is a bearer object, so
// nothing else is needed. In one tap the card signs a seal statement over
// this iPhone's challenge, then releases its seed material. The native core
// checks the card's signature, recomputes the Phantom Key, F, the commitment
// and the marker, and holds the key only when it makes exactly the card's
// coin. The app then at once Summons the coin into this account with the
// usual restart-safe payment. Once that settles and the chain shows the coin
// spent, the card can be reused: Refill empties it, and Fill gives it a new
// key.
import { useRouter } from 'expo-router';
import { useEffect, useMemo, useRef, useState } from 'react';
import { StyleSheet, Text } from 'react-native';

import { GhostCardStatusPanel } from '../components/ghost-card-ui';
import { CardBusy } from '../components/seal-ui';
import { colors } from '../components/theme';
import { Button, Column, IconButton, Logo, NetworkBadge, Panel, Screen, Spacer, textStyles, Title } from '../components/ui';
import { CoinsBack, PaymentExit, PaymentProgress } from '../components/vanish-ui';
import { accountZeroAddress } from '../lib/account';
import { ghostCardDeps } from '../lib/ghost-card/deps';
import { openGhostCard, refillGhostCard, type RefillTarget } from '../lib/ghost-card/flows';
import type { GhostCardStatus } from '../lib/ghost-card/status';
import { ghostText } from '../lib/seal/card-status';
import { useSettings } from '../lib/settings/settings';
import { CARD_KEY, proveRevealAgain, startReveal } from '../lib/vanish/actions';
import { paymentsChanged, shared } from '../lib/vanish/pending';
import { arrivedText, notSentReason, screenDone } from '../lib/vanish/status-mapping';
import { paymentKit, usePayment, type PaymentKit } from '../lib/vanish/use-payment';
import type { CorePaymentSequence } from '../modules/ghost-core';

function forgetCardKey(kit: PaymentKit | null) {
  try {
    kit?.core.forgetCardKey();
  } catch {
    // A core without the card calls holds no card key.
  }
}

export default function OpenGhostCardScreen() {
  const router = useRouter();
  const { nodeUrl } = useSettings();
  const [address] = useState(accountZeroAddress);
  const kit = useMemo(() => paymentKit(nodeUrl), [nodeUrl]);
  const deps = useMemo(() => ghostCardDeps(kit), [kit]);
  const cards = deps.nfc !== null && deps.core !== null;

  const [busy, setBusy] = useState<'open' | 'summon' | 'refill' | null>(null);
  const [status, setStatus] = useState<GhostCardStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [opened, setOpened] = useState<{
    amountWei: bigint | null;
    cardId: Uint8Array;
    fill: number;
    cardNumber: string;
    ms: number;
  } | null>(null);
  const [sequence, setSequence] = useState<CorePaymentSequence | null>(null);
  // A card opened before whose coin is already taken off: it can only be reused.
  const [spentCard, setSpentCard] = useState<RefillTarget | null>(null);
  const [refilled, setRefilled] = useState<{ fill: number; ms: number } | null>(null);
  const settled = useRef(false);

  const rebuild = useMemo(
    () => (kit && sequence && address ? proveRevealAgain(kit, sequence, CARD_KEY, address) : null),
    [kit, sequence, address],
  );
  const payment = usePayment(kit, sequence, rebuild, true);

  // The card's key leaves the native core with the screen, as on Summon.
  useEffect(
    () => () => {
      forgetCardKey(kit);
      deps.core?.forgetJavaCardRelease();
    },
    [kit, deps],
  );

  useEffect(() => {
    if (payment?.status === 'settled' && !settled.current) {
      settled.current = true;
      forgetCardKey(kit);
    }
  }, [payment?.status, kit]);

  async function open() {
    if (busy !== null || !kit || !address) {
      return;
    }
    setBusy('open');
    setError(null);
    setStatus(null);
    setSpentCard(null);
    let result;
    try {
      result = await openGhostCard(deps);
    } finally {
      setBusy(null);
    }
    if (!result.ok) {
      setStatus(result.status);
      setSpentCard(result.reuse ?? null);
      return;
    }
    setOpened({
      amountWei: result.amountWei,
      cardId: result.cardId,
      fill: result.fill,
      cardNumber: result.cardNumber,
      ms: result.ms,
    });
    await summon();
  }

  /** Summons the whole coin of the opened card into this wallet's account. */
  async function summon() {
    if (!kit || !address) {
      return;
    }
    setBusy('summon');
    setError(null);
    try {
      const started = await startReveal(kit, CARD_KEY, address, null);
      setSequence(shared(started));
      paymentsChanged();
    } catch (failure) {
      setError(`The card is open, but its coin could not be summoned yet. ${notSentReason(failure, kit.nodeUrl)}`);
    } finally {
      setBusy(null);
    }
  }

  /** Empties the card just opened, or the spent one just tapped (no other card), then goes on to fill it again. */
  async function refill() {
    const target = opened ? { cardId: opened.cardId, fill: opened.fill } : spentCard;
    if (busy !== null || !target) {
      return;
    }
    setBusy('refill');
    setError(null);
    try {
      const result = await refillGhostCard(deps, target);
      if (!result.ok) {
        if (result.status) {
          setStatus(result.status);
        }
        return;
      }
      setRefilled({ fill: result.fill, ms: result.ms });
    } finally {
      setBusy(null);
    }
  }

  const paid = payment?.status;
  const arrived = paid ? arrivedText(paid, 'summon') : null;
  const done = paid === 'settled';

  return (
    <Screen
      testID="open-ghost-card-screen"
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
        <Title>Open a Ghost card</Title>
        {!opened ? (
          <>
            <Text style={textStyles.body}>
              Opening releases the card&apos;s key to this iPhone and brings its GHOST into this wallet at once. After that
              the card says Opened to everyone who checks it. Nothing but the card is needed.
            </Text>
            <Button
              label={busy === 'open' ? 'Hold the card near the iPhone' : 'Tap the card to open it'}
              icon="receive"
              disabled={busy !== null || !cards}
              onPress={() => void open()}
              testID="ghost-open-run"
            />
          </>
        ) : null}
        {busy !== null ? (
          <CardBusy
            text={
              busy === 'open'
                ? 'Checking the card and opening it…'
                : busy === 'summon'
                  ? 'Summoning the coin into this wallet…'
                  : 'Emptying the card for its next fill…'
            }
            testID="ghost-open-spinner"
          />
        ) : null}
        {error ? (
          <Text accessibilityLiveRegion="polite" style={[textStyles.body, styles.error]} testID="ghost-open-error">
            {error}
          </Text>
        ) : null}
        {opened && !sequence && busy === null ? (
          <Button label="Summon it now" onPress={() => void summon()} testID="ghost-open-summon-again" />
        ) : null}
        {(done || spentCard) && !refilled ? (
          <Panel style={styles.form} testID="ghost-open-reuse">
            <Text style={textStyles.quiet}>Reuse this card</Text>
            <Text style={textStyles.body}>
              Its coin is spent, so the card can be emptied and filled again with a new key.
            </Text>
            <Button
              label={busy === 'refill' ? 'Hold the card near the iPhone' : 'Reuse this card'}
              icon="key"
              secondary
              disabled={busy !== null}
              onPress={() => void refill()}
              testID="ghost-open-refill"
            />
          </Panel>
        ) : null}
        {refilled ? (
          <Panel style={styles.form} testID="ghost-open-refilled">
            <Text style={textStyles.body}>
              The card is blank again (fill {refilled.fill}), ready for its next fill. Tap took {(refilled.ms / 1000).toFixed(1)} s.
            </Text>
            <Button label="Fill it now" icon="key" onPress={() => router.replace('/fill-ghost-card')} testID="ghost-open-fill-next" />
          </Panel>
        ) : null}
        {!cards ? (
          <Text style={textStyles.quiet} testID="ghost-open-unavailable">
            This iPhone cannot read Ghost cards in this build.
          </Text>
        ) : null}
      </Column>
      <Column>
        {opened ? (
          <Panel style={styles.form} testID="ghost-open-summary">
            <Text style={textStyles.quiet}>Card {opened.cardNumber}</Text>
            <Text style={textStyles.body}>
              Opened (fill {opened.fill})
              {opened.amountWei !== null ? `: ${ghostText(opened.amountWei)} GHOST coming to this wallet` : ''}. Tap took{' '}
              {(opened.ms / 1000).toFixed(1)} s.
            </Text>
          </Panel>
        ) : null}
        {paid ? (
          <>
            <PaymentProgress status={paid} kind="summon" step={payment?.step} error={payment?.error} />
            {arrived ? <CoinsBack text={arrived} /> : null}
            <PaymentExit final={screenDone(paid)} onLeave={() => router.back()} testPrefix="ghost-open" />
          </>
        ) : status ? (
          <GhostCardStatusPanel status={status} testID="ghost-open-status" />
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
  error: {
    color: colors.danger,
  },
});
