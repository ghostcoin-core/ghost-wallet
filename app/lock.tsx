// 9. Lock (docs/mockups/lock.html): shown when the app opens and an account is
// saved. Face ID or the passcode opens Home.
import { useCallback, useEffect, useRef, useState } from 'react';
import { StyleSheet, Text } from 'react-native';

import { Screen } from '../components/screen';
import { AppIcon, Body, Button, TestNetworkBadge, Title } from '../components/onboarding-ui';
import { unlock } from '../lib/app-lock';
import { useSession } from '../lib/session';
import { colours, fonts } from '../lib/theme';

export default function LockScreen() {
  const { unlock: unlockSession } = useSession();
  // The first prompt starts as the screen opens, so the buttons start off.
  const [busy, setBusy] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const asking = useRef(false);

  const prompt = useCallback(() => {
    if (asking.current) {
      return;
    }
    asking.current = true;
    void unlock().then((outcome) => {
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
          <Button disabled={busy} label="Unlock with Face ID" onPress={ask} testID="lock-face-id" />
          <Button disabled={busy} label="Use passcode" onPress={ask} testID="lock-passcode" variant="secondary" />
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
