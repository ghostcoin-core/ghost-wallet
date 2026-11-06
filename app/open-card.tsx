// Open a card into my wallet: Check the card first (its amount, and whether
// opening it needs its PIN and how many tries are left, all from the Seal's
// signed answer), then Open it. The native core makes an ML-KEM key; the Seal
// releases the card's key to it, and the core checks the signed Open answer,
// opens the release and holds the key. The app then at once Claims the coin
// into this wallet's account with the usual Claim payment and shows its
// status until it settles. The key stays in native code. The phone key is
// kept on this iPhone only until that Claim settles, so an Open cut off can
// be asked again and is still released here.
import { useRouter } from 'expo-router';
import { useEffect, useMemo, useRef, useState } from 'react';
import { StyleSheet, Text } from 'react-native';

import { CardBusy, CardStatusPanel, PinInput } from '../components/seal-ui';
import { colors } from '../components/theme';
import { Button, Column, IconButton, Logo, NetworkBadge, Panel, Screen, Spacer, textStyles, Title } from '../components/ui';
import { CoinsBack, PaymentExit, PaymentProgress } from '../components/vanish-ui';
import { accountZeroAddress } from '../lib/account';
import { ghostText, type CardStatus } from '../lib/seal/card-status';
import { checkCard, finishOpenClaim, openCard, openUnderWay, sealDeps, type OpenResult } from '../lib/seal/flows';
import { pinRule, triesText } from '../lib/seal/pin';
import { useSettings } from '../lib/settings/settings';
import { CARD_KEY, proveRevealAgain, startReveal } from '../lib/vanish/actions';
import { paymentsChanged, shared } from '../lib/vanish/pending';
import { arrivedText, notSentReason, screenDone } from '../lib/vanish/status-mapping';
import { paymentKit, usePayment, type PaymentKit } from '../lib/vanish/use-payment';
import type { CorePaymentSequence } from '../modules/ghost-core';
import { cardsSupported } from '../modules/ghost-nfc';

function forgetCardKey(kit: PaymentKit | null) {
  try {
    kit?.core.forgetCardKey();
  } catch {
    // A core without the card calls holds no card key.
  }
}

export default function OpenCardScreen() {
  const router = useRouter();
  const { nodeUrl } = useSettings();
  const [address] = useState(accountZeroAddress);
  const kit = useMemo(() => paymentKit(nodeUrl), [nodeUrl]);
  const [deps] = useState(sealDeps);
  const [cards] = useState(cardsSupported);
  // An Open of this iPhone not yet claimed: it can be asked again.
  const [underWay, setUnderWay] = useState(() => openUnderWay(deps));

  const [busy, setBusy] = useState<'check' | 'open' | 'claim' | null>(null);
  const [checked, setChecked] = useState<CardStatus | null>(null);
  const [pin, setPin] = useState('');
  const [error, setError] = useState<string | null>(null);
  // The card's key is in the native core, waiting for its Claim to start.
  const [opened, setOpened] = useState<{ amountWei: bigint } | null>(null);
  const [sequence, setSequence] = useState<CorePaymentSequence | null>(null);
  const finished = useRef(false);

  const rebuild = useMemo(
    () => (kit && sequence && address ? proveRevealAgain(kit, sequence, CARD_KEY, address) : null),
    [kit, sequence, address],
  );
  const payment = usePayment(kit, sequence, rebuild, true);

  // The card's key leaves the native core with the screen, as on Summon. The
  // phone key stays until the Claim settles: the card can be opened again.
  useEffect(
    () => () => {
      forgetCardKey(kit);
    },
    [kit],
  );

  useEffect(() => {
    if (payment?.status === 'settled' && !finished.current) {
      finished.current = true;
      finishOpenClaim(deps, () => forgetCardKey(kit));
      setUnderWay(false);
    }
  }, [payment?.status, deps, kit]);

  const secured = checked?.kind === 'secured' ? checked : null;
  const needsPin = secured?.pinRequired === true;
  const lockedByTries = secured !== null && needsPin && secured.pinTriesLeft === 0;
  const resumable = underWay && checked?.kind === 'opened';
  const rule = pinRule(pin);
  const canOpen =
    !!kit && !!address && busy === null && !opened && ((secured !== null && !lockedByTries && (!needsPin || rule.ok)) || resumable);

  async function check() {
    setBusy('check');
    setError(null);
    setChecked(null);
    try {
      const status = await checkCard(deps);
      if (status) {
        setChecked(status);
      }
    } finally {
      setBusy(null);
    }
  }

  async function open() {
    if (!canOpen) {
      return;
    }
    const given = needsPin && rule.ok ? rule.pin : null;
    // The PIN goes to the Seal with this call and is not kept on the screen.
    setPin('');
    setBusy('open');
    setError(null);
    let result: OpenResult;
    try {
      result = await openCard(deps, given);
    } finally {
      setBusy(null);
    }
    setUnderWay(openUnderWay(deps));
    if (!result.ok) {
      if (result.wrongPin) {
        // Tries left are shown only from a signed answer: Check again.
        setChecked(null);
        setError('Wrong PIN. Check the card again to see how many tries are left.');
      } else if (result.pinRequired) {
        setChecked(null);
        setError('This card needs its PIN. Check the card again, then enter the PIN.');
      } else if (result.status) {
        setChecked(result.status);
      }
      return;
    }
    setOpened({ amountWei: result.amountWei });
    await claim();
  }

  /** Claims the whole coin of the opened card into this wallet's account. */
  async function claim() {
    if (!kit || !address) {
      return;
    }
    setBusy('claim');
    setError(null);
    try {
      const started = await startReveal(kit, CARD_KEY, address, null);
      setSequence(shared(started));
      paymentsChanged();
    } catch (failure) {
      setError(`The card is open, but its coin could not be claimed yet. ${notSentReason(failure, kit.nodeUrl)}`);
    } finally {
      setBusy(null);
    }
  }

  const status = payment?.status;
  const arrived = status ? arrivedText(status, 'summon') : null;

  return (
    <Screen
      testID="open-card-screen"
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
        <Title>Open into my wallet</Title>
        {!opened ? (
          <>
            <Text style={textStyles.body}>
              Opening empties the card for good: its GHOST comes into this wallet. Check the card first.
            </Text>
            <Button
              label={busy === 'check' ? 'Hold the card near the iPhone' : 'Check the card'}
              icon="check"
              secondary={secured !== null}
              disabled={busy !== null || !cards}
              onPress={() => void check()}
              testID="open-check"
            />
            {needsPin && secured ? (
              <Panel style={styles.form} testID="open-pin-panel">
                <Text style={textStyles.quiet}>Card PIN</Text>
                <Text style={textStyles.body} testID="open-pin-tries">
                  {lockedByTries ? 'No tries left: this card can never be opened.' : triesText(secured.pinTriesLeft)}
                </Text>
                {!lockedByTries ? <PinInput value={pin} onChange={setPin} label="Card PIN" testID="open-pin" /> : null}
              </Panel>
            ) : null}
            {secured || resumable ? (
              <Button
                label={
                  busy === 'open'
                    ? 'Hold the card near the iPhone'
                    : resumable
                      ? 'Finish opening into my wallet'
                      : `Open ${ghostText(secured?.amountWei ?? 0n)} GHOST into my wallet`
                }
                icon="receive"
                disabled={!canOpen}
                onPress={() => void open()}
                testID="open-run"
              />
            ) : null}
          </>
        ) : null}
        {busy !== null ? (
          <CardBusy
            text={busy === 'check' ? 'Checking the card with the Seal…' : busy === 'open' ? 'Opening the card with the Seal…' : 'Claiming the coin…'}
            testID="open-spinner"
          />
        ) : null}
        {error ? (
          <Text accessibilityLiveRegion="polite" style={[textStyles.body, styles.error]} testID="open-error">
            {error}
          </Text>
        ) : null}
        {opened && !sequence && busy === null ? (
          <Button label="Claim it now" onPress={() => void claim()} testID="open-claim-again" />
        ) : null}
        {!cards ? (
          <Text style={textStyles.quiet} testID="open-unavailable">
            This iPhone cannot read cards in this build.
          </Text>
        ) : null}
      </Column>
      <Column>
        {status ? (
          <>
            <PaymentProgress status={status} kind="summon" step={payment?.step} error={payment?.error} />
            {arrived ? <CoinsBack text={arrived} /> : null}
            <PaymentExit final={screenDone(status)} onLeave={() => router.back()} testPrefix="open" />
          </>
        ) : checked ? (
          <CardStatusPanel status={checked} testID="open-status" />
        ) : (
          <Panel style={styles.form}>
            <Text style={textStyles.quiet}>How it works</Text>
            <Text style={textStyles.body}>
              The Seal wipes the card&apos;s key, changes the card&apos;s keys and only then releases the key, sealed
              to a key this iPhone made just now. The key stays in this iPhone&apos;s native core, never on screen,
              and its coin comes to your account at once.
            </Text>
          </Panel>
        )}
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
