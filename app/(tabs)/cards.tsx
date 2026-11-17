// The Cards tab: everything done by holding a card to the phone.
import { useRouter } from 'expo-router';

import { colors } from '../../components/theme';
import { NetworkBadge, Panel, Row, Screen, SectionTitle, Spacer, Title } from '../../components/ui';

export default function CardsScreen() {
  const router = useRouter();

  return (
    <Screen
      testID="cards-screen"
      background="mist"
      topBar={
        <>
          <Spacer />
          <NetworkBadge background={colors.paper} />
        </>
      }
    >
      <Title>Cards</Title>

      <Panel>
        <Row
          first
          icon="tap"
          title="Check a card"
          detail="See what a card holds"
          opens
          onPress={() => router.push('/check-card')}
          testID="cards-check"
        />
        <Row
          icon="send"
          title="Fill a card"
          detail="Move GHOST from your wallet onto a card"
          opens
          onPress={() => router.push('/fill-ghost-card')}
          testID="cards-fill"
        />
        <Row
          icon="receive"
          title="Open a card"
          detail="Move a card's GHOST into your wallet"
          opens
          onPress={() => router.push('/open-ghost-card')}
          testID="cards-open"
        />
      </Panel>

      <SectionTitle>NTAG 424 cards (older)</SectionTitle>
      <Panel>
        <Row
          first
          icon="send"
          title="Fill an NTAG 424 card"
          opens
          onPress={() => router.push('/fill-card')}
          testID="cards-fill-ntag"
        />
        <Row
          icon="receive"
          title="Open an NTAG 424 card"
          opens
          onPress={() => router.push('/open-card')}
          testID="cards-open-ntag"
        />
        <Row
          icon="cross"
          title="Wipe an NTAG 424 card"
          opens
          onPress={() => router.push('/wipe-card')}
          testID="cards-wipe-ntag"
        />
      </Panel>
    </Screen>
  );
}
