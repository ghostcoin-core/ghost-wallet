// The older NTAG 424 cards: fill one, open one into the wallet, or wipe one.
import { useRouter } from 'expo-router';

import { colors } from '../../../components/theme';
import { NetworkBadge, Panel, Row, Screen, Spacer, Title } from '../../../components/ui';

export default function OlderCardsScreen() {
  const router = useRouter();

  return (
    <Screen
      testID="older-cards-screen"
      background="mist"
      topBar={
        <>
          <Spacer />
          <NetworkBadge background={colors.paper} />
        </>
      }
    >
      <Title>Older NTAG 424 cards</Title>
      <Panel>
        <Row
          first
          icon="send"
          title="Fill an NTAG 424 card"
          opens
          onPress={() => router.push('/fill-card')}
          testID="older-cards-fill"
        />
        <Row
          icon="receive"
          title="Open an NTAG 424 card"
          opens
          onPress={() => router.push('/open-card')}
          testID="older-cards-open"
        />
        <Row
          icon="cross"
          title="Wipe an NTAG 424 card"
          opens
          onPress={() => router.push('/wipe-card')}
          testID="older-cards-wipe"
        />
      </Panel>
    </Screen>
  );
}
