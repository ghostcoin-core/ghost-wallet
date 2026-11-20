// See what a card holds: tap a card and see its one balance. A Ghost card
// (the Java Card applet) is read on this iPhone alone: its certificate
// against the issuer keys this app pins, its signature over this tap's own
// challenge, and its coin on chain. What it holds is shown as one amount
// (lib/ghost-card/vault.ts): a card whose last change is still going
// through shows what it will hold, an emptied card shows Empty, and only a
// fake or broken card is shown as a problem.
//
// An NTAG 424 card is told apart in the same tap, and a Ghost Sealed card
// among them can still be checked with its Seal.
import { useRouter } from 'expo-router';
import { useMemo, useRef, useState } from 'react';
import { Text } from 'react-native';

import { CardBalancePanel } from '../../../components/ghost-card-ui';
import { CardBusy, CardStatusPanel } from '../../../components/seal-ui';
import { Button, Column, Logo, NetworkBadge, Screen, Spacer, textStyles, Title } from '../../../components/ui';
import { accountZeroAddress } from '../../../lib/account';
import { ghostCardDeps } from '../../../lib/ghost-card/deps';
import { checkGhostCard, type CheckResult } from '../../../lib/ghost-card/flows';
import { cardBalance } from '../../../lib/ghost-card/vault';
import { vaultDeps } from '../../../lib/ghost-card/vault-deps';
import type { CardStatus } from '../../../lib/seal/card-status';
import { checkCard, confirmFill, sealDeps } from '../../../lib/seal/flows';
import { useSettings } from '../../../lib/settings/settings';
import { paymentKit } from '../../../lib/vanish/use-payment';
import { cardsSupported } from '../../../modules/ghost-nfc';

export default function CheckCardScreen() {
  const router = useRouter();
  const { nodeUrl } = useSettings();
  const [address] = useState(accountZeroAddress);
  const kit = useMemo(() => paymentKit(nodeUrl), [nodeUrl]);
  const deps = useMemo(() => ghostCardDeps(kit), [kit]);
  const vault = useMemo(() => vaultDeps(kit, address), [kit, address]);
  const [seal] = useState(sealDeps);
  const [cards] = useState(cardsSupported);
  const ghostCards = deps.nfc !== null && deps.core !== null;
  const [busy, setBusy] = useState<'check' | 'seal' | null>(null);
  const [result, setResult] = useState<CheckResult | null>(null);
  const [sealStatus, setSealStatus] = useState<CardStatus | null>(null);
  const run = useRef(0);

  const status = result?.status ?? null;
  const balance = result && status?.kind !== 'carry-to-claim' ? cardBalance(vault, result) : null;

  /**
   * A Check of the next card tapped; an earlier answer is never shown for it.
   * A Ghost card is checked here; an NTAG 424 card goes on to its Seal, with
   * one more tap. A build without the Ghost card flows checks with the Seal.
   */
  async function check() {
    if (busy !== null) {
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
    let checked: CheckResult | null = null;
    try {
      checked = await checkGhostCard(deps);
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

  return (
    <Screen
      testID="check-card-screen"
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
        <Title>What&apos;s on this card</Title>
        <Text style={textStyles.body}>
          Hold a Ghost card to the iPhone to see how much GHOST it holds.
        </Text>
        <Button
          label={busy === 'check' ? 'Hold the card near the iPhone' : 'Hold your card to see what it holds'}
          icon="tap"
          disabled={busy !== null || !cards}
          onPress={() => void check()}
          testID="check-card-run"
        />
        {busy !== null ? (
          <CardBusy
            text={
              busy === 'check' ? 'Reading the card…' : 'Checking the card with the Seal…'
            }
            testID="check-card-spinner"
          />
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
        ) : balance ? (
          <CardBalancePanel balance={balance} testID="check-card-status" />
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
        {balance && balance.kind !== 'problem' && busy === null ? (
          <Button label="Add to this card" icon="send" onPress={() => router.push('/fill-ghost-card')} testID="check-card-fill" />
        ) : null}
        {balance?.kind === 'holds' && busy === null ? (
          <Button
            label="Take some off"
            icon="receive"
            secondary
            onPress={() => router.push('/open-ghost-card')}
            testID="check-card-open"
          />
        ) : null}
      </Column>
    </Screen>
  );
}

