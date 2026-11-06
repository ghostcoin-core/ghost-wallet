// Check NFC Chip: tap a Ghost Sealed card and see what it holds. The relay
// sends the Seal a fresh random challenge with the card's traffic, and the
// native core verifies the Seal's signed answer: the Seal's measurement on
// the pinned list, its ML-DSA-65 signature, the challenge, the card and the
// expiry. A card is shown Secured only from such a fresh answer; an answer
// that fails any check is "Can't verify this card", in red, with no amount.
// The Check is a deliberate tap, so it shows a spinner while it runs; Home
// and Send never wait on it.
import { useRouter } from 'expo-router';
import { useRef, useState } from 'react';
import { StyleSheet, Text } from 'react-native';

import { CardBusy, CardStatusPanel } from '../components/seal-ui';
import { Button, Column, IconButton, Logo, NetworkBadge, Panel, Screen, Spacer, textStyles, Title } from '../components/ui';
import type { CardStatus } from '../lib/seal/card-status';
import { checkCard, confirmFill, sealDeps } from '../lib/seal/flows';
import { cardsSupported } from '../modules/ghost-nfc';

export default function CheckCardScreen() {
  const router = useRouter();
  const [deps] = useState(sealDeps);
  const [cards] = useState(cardsSupported);
  const [checking, setChecking] = useState(false);
  const [status, setStatus] = useState<CardStatus | null>(null);
  const run = useRef(0);

  /** A Check, or (`confirm`) the Seal asked to mark a filled card Sealed once its payment settled. */
  async function check(confirm = false) {
    if (checking) {
      return;
    }
    const mine = ++run.current;
    setChecking(true);
    // An earlier answer is never shown for the card tapped now.
    setStatus(null);
    try {
      const result = await (confirm ? confirmFill(deps) : checkCard(deps));
      if (mine === run.current) {
        setStatus(result);
      }
    } finally {
      if (mine === run.current) {
        setChecking(false);
      }
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
          Tap a Ghost card to see what it holds, checked with the Seal just now.
        </Text>
        <Button
          label={checking ? 'Hold the card near the iPhone' : 'Check NFC Chip'}
          icon="check"
          disabled={checking || !cards}
          onPress={() => void check()}
          testID="check-card-run"
        />
        {checking ? <CardBusy text="Checking the card with the Seal…" testID="check-card-spinner" /> : null}
        {!cards ? (
          <Text style={textStyles.quiet} testID="check-card-unavailable">
            This iPhone cannot read cards in this build.
          </Text>
        ) : null}
      </Column>
      <Column>
        {status ? <CardStatusPanel status={status} testID="check-card-status" /> : null}
        {status?.kind === 'filling' ? (
          <Button
            label="Check its payment"
            icon="clock"
            secondary
            disabled={checking}
            onPress={() => void check(true)}
            testID="check-card-confirm"
          />
        ) : null}
        <Panel style={styles.about}>
          <Text style={textStyles.quiet}>What a Check proves</Text>
          <Text style={textStyles.body}>
            The Seal answers over this iPhone&apos;s own random challenge, about this card, and signs its answer. The
            card&apos;s key never left the Seal and the card, so a card shown Secured holds its GHOST and was never
            opened. Check again just before you accept a card.
          </Text>
        </Panel>
      </Column>
    </Screen>
  );
}

const styles = StyleSheet.create({
  about: {
    gap: 8,
    padding: 16,
  },
});
