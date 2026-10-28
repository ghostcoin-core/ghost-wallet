// 1. Welcome (docs/mockups/welcome.html): create a new account or bring 24 words.
import { useRouter } from 'expo-router';
import { StyleSheet, View } from 'react-native';

import { Body, Button, Lockup, TestNetworkBadge, Title } from '../components/onboarding-ui';
import { Screen } from '../components/screen';

export default function WelcomeScreen() {
  const router = useRouter();

  return (
    <Screen
      centred
      footer={
        <>
          <Button label="Create a new account" onPress={() => router.push('/backup')} testID="welcome-create" />
          <Button
            label="I already have 24 words"
            onPress={() => router.push('/import')}
            testID="welcome-import"
            variant="secondary"
          />
          <View style={styles.badge}>
            <TestNetworkBadge />
          </View>
        </>
      }
      label="Welcome"
      testID="welcome-screen"
    >
      <Lockup />
      <Title style={styles.centre}>Your coins, one among many.</Title>
      <Body style={styles.centre}>
        A private, quantum-safe wallet for GHOST. Your balance shows the moment you open it.
      </Body>
    </Screen>
  );
}

const styles = StyleSheet.create({
  centre: {
    textAlign: 'center',
  },
  badge: {
    paddingTop: 8,
  },
});
