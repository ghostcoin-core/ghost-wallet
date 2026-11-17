// Check NFC Chip: tap a card and see what it holds. A Ghost card (the Java
// Card applet) is checked on this iPhone alone: its certificate against the
// issuer keys this app pins, its seal statement's signature over this tap's
// own challenge, the card number, and its coin on chain, buried and unspent.
// No Seal or Ghost server takes part. An open code, if given, is confirmed
// by the card without opening it. A card is shown Sealed only when every
// check passes; anything else is "not safe to accept".
//
// An NTAG 424 card is told apart in the same tap: it is "Carry to Claim",
// and a Ghost Sealed card among them can still be checked with its Seal.
import { useRouter } from 'expo-router';
import { useMemo, useRef, useState } from 'react';
import { StyleSheet, Text } from 'react-native';

import { GhostCardStatusPanel, OpenCodeInput } from '../components/ghost-card-ui';
import { CardBusy, CardStatusPanel } from '../components/seal-ui';
import { colors } from '../components/theme';
import { Button, Column, IconButton, Logo, NetworkBadge, Panel, Screen, Spacer, textStyles, Title } from '../components/ui';
import { PaymentExit, PaymentProgress } from '../components/vanish-ui';
import { accountZeroAddress } from '../lib/account';
import { ghostCardDeps } from '../lib/ghost-card/deps';
import { checkGhostCard, readOpenCode, refillGhostCard, type CheckResult } from '../lib/ghost-card/flows';
import type { CardStatus } from '../lib/seal/card-status';
import { checkCard, confirmFill, sealDeps } from '../lib/seal/flows';
import { failureReason } from '../lib/node/failure-reason';
import { useSettings } from '../lib/settings/settings';
import { signVanishAgain, startSealedCardVanish } from '../lib/vanish/actions';
import { paymentsChanged, shared } from '../lib/vanish/pending';
import { screenDone } from '../lib/vanish/status-mapping';
import { paymentKit, usePayment } from '../lib/vanish/use-payment';
import type { CorePaymentSequence } from '../modules/ghost-core';
import { cardsSupported } from '../modules/ghost-nfc';

export default function CheckCardScreen() {
  const router = useRouter();
  const { nodeUrl } = useSettings();
  const [address] = useState(accountZeroAddress);
  const kit = useMemo(() => paymentKit(nodeUrl), [nodeUrl]);
  const deps = useMemo(() => ghostCardDeps(kit), [kit]);
  const [seal] = useState(sealDeps);
  const [cards] = useState(cardsSupported);
  const ghostCards = deps.nfc !== null && deps.core !== null;
  const [busy, setBusy] = useState<'check' | 'seal' | 'refill' | 'pay' | null>(null);
  const [codeText, setCodeText] = useState('');
  const [result, setResult] = useState<CheckResult | null>(null);
  const [sealStatus, setSealStatus] = useState<CardStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sequence, setSequence] = useState<CorePaymentSequence | null>(null);
  const run = useRef(0);

  const code = deps.core && codeText !== '' ? readOpenCode(deps.core, codeText) : null;
  const codeBad = codeText !== '' && code === null;
  const status = result?.status ?? null;

  const rebuild = useMemo(() => (kit && sequence ? signVanishAgain(kit, sequence) : null), [kit, sequence]);
  const payment = usePayment(kit, sequence, rebuild, false);

  /**
   * A Check of the next card tapped; an earlier answer is never shown for it.
   * A Ghost card is checked here; an NTAG 424 card goes on to its Seal, with
   * one more tap. A build without the Ghost card flows checks with the Seal.
   */
  async function check() {
    if (busy !== null || codeBad) {
      return;
    }
    if (!ghostCards) {
      await checkWithSeal();
      return;
    }
    const mine = ++run.current;
    setBusy('check');
    setResult(null);
    setSealStatus(null);
    setError(null);
    let checked: CheckResult | null = null;
    try {
      checked = await checkGhostCard(deps, code);
      if (mine === run.current && checked) {
        setResult(checked);
      }
    } finally {
      if (mine === run.current) {
        setBusy(null);
      }
    }
    if (mine === run.current && checked?.status.kind === 'carry-to-claim') {
      await checkWithSeal();
    }
  }

  /** An NTAG 424 card: a Ghost Sealed card is checked with its Seal (or asked to mark a settled Fill). */
  async function checkWithSeal(confirm = false) {
    if (busy !== null) {
      return;
    }
    const mine = ++run.current;
    setBusy('seal');
    setSealStatus(null);
    try {
      const answer = await (confirm ? confirmFill(seal) : checkCard(seal));
      if (mine === run.current) {
        setSealStatus(answer);
      }
    } finally {
      if (mine === run.current) {
        setBusy(null);
      }
    }
  }

  /** An opened card whose coin is spent: Refill with its code, then fill it again. */
  async function reuse() {
    if (!code || busy !== null) {
      return;
    }
    setBusy('refill');
    setError(null);
    try {
      const refilled = await refillGhostCard(deps, code);
      if (!refilled.ok) {
        if (refilled.status) {
          setResult({ status: refilled.status, statement: null, ms: null, commitData: null });
        }
        return;
      }
      setCodeText('');
      router.replace('/fill-ghost-card');
    } finally {
      setBusy(null);
    }
  }

  /** A sealed card whose Vanish never reached the chain: pay it from this account. */
  async function pay() {
    const statement = result?.statement;
    if (!kit || !address || !statement || !result?.commitData || busy !== null) {
      return;
    }
    setBusy('pay');
    setError(null);
    try {
      const started = await startSealedCardVanish(kit, address, BigInt(statement.amountWei), result.commitData);
      setSequence(shared(started.sequence));
      paymentsChanged();
    } catch (failure) {
      setError(`The payment could not start. ${failureReason(failure, kit.nodeUrl)}`);
    } finally {
      setBusy(null);
    }
  }

  return (
    <Screen
      testID="check-card-screen"
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
        <Title>Check NFC Chip</Title>
        <Text style={textStyles.body}>
          Tap a Ghost card to see what it holds. This iPhone checks the card&apos;s own signature over a fresh challenge,
          and its coin on the chain.
        </Text>
        <Panel style={styles.form}>
          <Text style={textStyles.quiet}>Open code (optional): the card confirms it without opening</Text>
          <OpenCodeInput value={codeText} onChange={setCodeText} testID="check-card-code" />
          {codeBad ? (
            <Text style={textStyles.quiet} testID="check-card-code-error">
              An open code is 32 letters (A to Z) and digits (2 to 7).
            </Text>
          ) : null}
        </Panel>
        <Button
          label={busy === 'check' ? 'Hold the card near the iPhone' : 'Check NFC Chip'}
          icon="check"
          disabled={busy !== null || !cards || codeBad}
          onPress={() => void check()}
          testID="check-card-run"
        />
        {busy !== null ? (
          <CardBusy
            text={
              busy === 'check'
                ? 'Checking the card…'
                : busy === 'seal'
                  ? 'Checking the card with the Seal…'
                  : busy === 'refill'
                    ? 'Emptying the card for its next fill…'
                    : 'Starting the payment…'
            }
            testID="check-card-spinner"
          />
        ) : null}
        {error ? (
          <Text accessibilityLiveRegion="polite" style={[textStyles.body, styles.error]} testID="check-card-error">
            {error}
          </Text>
        ) : null}
        {!cards ? (
          <Text style={textStyles.quiet} testID="check-card-unavailable">
            This iPhone cannot read cards in this build.
          </Text>
        ) : null}
      </Column>
      <Column>
        {sealStatus ? (
          <CardStatusPanel status={sealStatus} testID="check-card-status" />
        ) : status ? (
          <GhostCardStatusPanel status={status} testID="check-card-status" />
        ) : null}
        {status?.kind === 'carry-to-claim' && !sealStatus && busy === null ? (
          <Button
            label="Check it with its Seal"
            icon="check"
            secondary
            onPress={() => void checkWithSeal()}
            testID="check-card-seal"
          />
        ) : null}
        {sealStatus?.kind === 'filling' ? (
          <Button
            label="Check its payment"
            icon="clock"
            secondary
            disabled={busy !== null}
            onPress={() => void checkWithSeal(true)}
            testID="check-card-confirm"
          />
        ) : null}
        {status?.kind === 'blank' ? (
          <Button label="Fill this card" icon="key" onPress={() => router.push('/fill-ghost-card')} testID="check-card-fill" />
        ) : null}
        {status?.kind === 'sealed' || status?.kind === 'no-checks' ? (
          <Button
            label="Open it into my wallet"
            icon="receive"
            secondary
            onPress={() => router.push('/open-ghost-card')}
            testID="check-card-open"
          />
        ) : null}
        {status?.kind === 'opened' && status.spent === true ? (
          <Panel style={styles.form} testID="check-card-reuse">
            <Text style={textStyles.quiet}>Reuse this card</Text>
            <Text style={textStyles.body}>
              Its coin was taken off. With its open code above, the card can be emptied and filled again with a new key
              and a new open code.
            </Text>
            <Button
              label={busy === 'refill' ? 'Hold the card near the iPhone' : 'Reuse this card'}
              icon="key"
              secondary
              disabled={busy !== null || !code}
              onPress={() => void reuse()}
              testID="check-card-refill"
            />
          </Panel>
        ) : null}
        {status?.kind === 'not-on-chain' && result?.commitData && !sequence ? (
          <Button
            label="Pay its Vanish from my account"
            icon="key"
            secondary
            disabled={busy !== null || !kit || !address}
            onPress={() => void pay()}
            testID="check-card-pay"
          />
        ) : null}
        {sequence && payment ? (
          <>
            <PaymentProgress status={payment.status} kind="vanish" step={payment.step} error={payment.error} />
            <PaymentExit final={screenDone(payment.status)} onLeave={() => router.back()} testPrefix="check-card" />
          </>
        ) : null}
        <Panel style={styles.form}>
          <Text style={textStyles.quiet}>What a Check proves</Text>
          <Text style={textStyles.body}>
            The card signs its state over this iPhone&apos;s own random challenge, with a key certified by the card&apos;s
            issuer. A card shown Sealed holds its GHOST on the chain and was never opened. Check that the card number
            matches the one printed on the card, and check again just before you accept it.
          </Text>
        </Panel>
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
