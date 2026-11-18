// The Home tab: Home, and the screens it opens, which keep the tab bar.
import { Stack } from 'expo-router';

import { onMist, pushedScreenOptions, tabRootOptions } from '../../../components/stack-options';
import { useCloseOnLeavingTab } from '../../../components/tab-stack';

export const unstable_settings = { anchor: 'home' };

export default function HomeTab() {
  useCloseOnLeavingTab('(home)');

  return (
    <Stack screenOptions={pushedScreenOptions}>
      <Stack.Screen name="home" options={tabRootOptions} />
      <Stack.Screen name="send" options={onMist} />
      <Stack.Screen name="receive" options={onMist} />
      <Stack.Screen name="payment" />
      <Stack.Screen name="vanish" options={onMist} />
      <Stack.Screen name="summon" options={onMist} />
    </Stack>
  );
}
