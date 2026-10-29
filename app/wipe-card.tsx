// Wipe a card: a card this iPhone wrote goes back to a blank NTAG 424 DNA
// (its file plain and empty, its keys the factory keys), and this iPhone
// forgets the card's keys. The Phantom Key's coins stay with the key: its
// words still Summon them.
import { useRouter } from 'expo-router';
import { useState } from 'react';
import { StyleSheet, Text } from 'react-native';

import { colors } from '../components/theme';
import { Button, Column, IconButton, Logo, NetworkBadge, Panel, Screen, Spacer, textStyles, Title } from '../components/ui';
import { CardCancelled, cardsSupported, wipePhantomKeyCard } from '../modules/ghost-nfc';

export default function WipeCardScreen() {
  const router = useRouter();
  const [cards] = useState(cardsSupported);
  const [wiping, setWiping] = useState(false);
  const [wiped, setWiped] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function wipe() {
    setWiping(true);
    setWiped(false);
    setError(null);
    try {
      await wipePhantomKeyCard();
      setWiped(true);
    } catch (failure) {
      if (!(failure instanceof CardCancelled)) {
        setError(failure instanceof Error ? failure.message : 'The card could not be wiped.');
      }
    } finally {
      setWiping(false);
    }
  }

  return (
    <Screen
      testID="wipe-card-screen"
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
        <Title>Wipe a card</Title>
        <Text style={textStyles.body}>
          Wiping erases the Phantom Key on a card this iPhone wrote and makes it a blank card again. The coins stay with
          the key: keep its words, or Summon them first.
        </Text>
        <Button
          label={wiping ? 'Hold the card near the iPhone' : 'Wipe a card'}
          icon="cross"
          disabled={!cards || wiping}
          onPress={() => void wipe()}
          testID="wipe-card"
        />
        {wiped ? (
          <Text accessibilityLiveRegion="polite" style={textStyles.body} testID="wipe-card-done">
            The card is blank again, and this iPhone forgot its keys.
          </Text>
        ) : null}
        {error ? (
          <Text accessibilityLiveRegion="polite" style={[textStyles.body, styles.error]} testID="wipe-card-error">
            {error}
          </Text>
        ) : null}
        {!cards ? (
          <Text style={textStyles.quiet} testID="wipe-card-unavailable">
            This iPhone cannot read cards in this build.
          </Text>
        ) : null}
      </Column>
      <Column>
        <Panel style={styles.form}>
          <Text style={textStyles.quiet}>About cards</Text>
          <Text style={textStyles.body}>
            Each card has its own random keys, kept in this iPhone&apos;s Keychain and nowhere else. Only this iPhone
            can read or wipe the cards it wrote.
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
