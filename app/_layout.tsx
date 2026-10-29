import { useFonts } from 'expo-font';
import { Stack } from 'expo-router';
import { StatusBar } from 'expo-status-bar';

import { colors } from '../components/theme';
import { openGroups } from '../lib/onboarding/route-guards';
import { SessionProvider, useSession } from '../lib/session';
import { fontFiles } from '../lib/theme';

function GuardedStack() {
  const session = useSession();
  const open = openGroups(session);

  // Screen order matters: when a guard closes the open screen, the router
  // falls back to the first screen still open.
  return (
    <Stack screenOptions={{ headerShown: false, contentStyle: { backgroundColor: colors.paper } }}>
      <Stack.Protected guard={open.onboarding}>
        <Stack.Screen name="index" />
        <Stack.Screen name="backup" />
        <Stack.Screen name="check" />
        <Stack.Screen name="import" />
      </Stack.Protected>
      <Stack.Protected guard={open.lock}>
        <Stack.Screen name="lock" options={{ gestureEnabled: false }} />
      </Stack.Protected>
      <Stack.Protected guard={open.wallet}>
        <Stack.Screen name="home" options={{ gestureEnabled: false }} />
        <Stack.Screen name="send" />
        <Stack.Screen name="payment" />
        <Stack.Screen name="receive" />
        <Stack.Screen name="settings" />
        <Stack.Screen name="recovery-words" />
        <Stack.Screen name="check-words" />
        <Stack.Screen name="vanish" />
        <Stack.Screen name="summon" />
        <Stack.Screen name="wipe-card" />
      </Stack.Protected>
      <Stack.Protected guard={open.developer}>
        <Stack.Screen name="bench" options={{ contentStyle: { backgroundColor: '#0A0A12' } }} />
      </Stack.Protected>
    </Stack>
  );
}

export default function RootLayout() {
  const [fontsLoaded, fontError] = useFonts(fontFiles);

  // Wait for the brand fonts so no screen draws in the system font first; a
  // font that fails to load falls back to the system font.
  if (!fontsLoaded && !fontError) {
    return null;
  }

  return (
    <SessionProvider>
      <StatusBar style="dark" />
      <GuardedStack />
    </SessionProvider>
  );
}
