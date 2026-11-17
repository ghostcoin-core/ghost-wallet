// 9. Lock (docs/mockups/lock.html): shown when the app opens and an account is
// saved. Touch ID, Face ID or the passcode opens Home.
import { useCallback, useEffect, useRef, useState } from 'react';
import { StyleSheet, Text } from 'react-native';

import { Screen } from '../components/screen';
import { AppIcon, Body, Button, TestNetworkBadge, Title } from '../components/onboarding-ui';
import { unlock } from '../lib/app-lock';
import { useBiometric, withBiometric } from '../lib/biometric';
import { useSession } from '../lib/session';
import { colours, fonts } from '../lib/theme';

export default function LockScreen() {
  const { unlock: unlockSession } = useSession();
  // The first prompt starts as the screen opens, so the buttons start off.
  const [busy, setBusy] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const asking = useRef(false);
  const biometric = useBiometric();
  // The prompt starts before the phone has said which check it has.
  const biometricNow = useRef(biometric);
  useEffect(() => {
    biometricNow.current = biometric;
  }, [biometric]);
  const hasBiometric = biometric !== null && biometric.enrolled;

  const prompt = useCallback(() => {
    if (asking.current) {
      return;
    }
    asking.current = true;
    void unlock(biometricNow.current).then((outcome) => {
      asking.current = false;
      setBusy(false);
      if (outcome.unlocked) {
        // The lock closes now and the router opens Home.
        unlockSession();
      } else {
        setMessage(outcome.message);
      }
    });
  }, [unlockSession]);

  function ask() {
    setBusy(true);
    setMessage(null);
    prompt();
  }

  // Ask once as the app opens, as other wallets do.
  useEffect(prompt, [prompt]);

  return (
    <Screen
      centred
      footer={
        <>
          {biometric === null || hasBiometric ? (
            <Button disabled={busy} label={withBiometric('Unlock', biometric)} onPress={ask} testID="lock-unlock" />
          ) : null}
          <Button
            disabled={busy}
            label="Use passcode"
            onPress={ask}
            testID="lock-passcode"
            variant={hasBiometric || biometric === null ? 'secondary' : 'primary'}
          />
        </>
      }
      label="Locked"
      testID="lock-screen"
    >
      <AppIcon />
      <Title style={styles.centre}>Ghost Wallet is locked</Title>
      <Body style={styles.centre}>Unlock to see your balance and send.</Body>
      <TestNetworkBadge />
      {message ? (
        <Text accessibilityLiveRegion="polite" style={styles.message} testID="lock-message">
          {message}
        </Text>
      ) : null}
    </Screen>
  );
}

const styles = StyleSheet.create({
  centre: {
    textAlign: 'center',
  },
  message: {
    color: colours.danger,
    fontFamily: fonts.sans,
    fontSize: 14,
    textAlign: 'center',
  },
});
