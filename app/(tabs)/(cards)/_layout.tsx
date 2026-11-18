// The Cards tab: Cards, and the card screens it opens, which keep the tab bar.
import { Stack } from 'expo-router';

import { onMist, pushedScreenOptions, tabRootOptions } from '../../../components/stack-options';

export const unstable_settings = { anchor: 'cards' };

export default function CardsTab() {
  return (
    <Stack screenOptions={pushedScreenOptions}>
      <Stack.Screen name="cards" options={tabRootOptions} />
      <Stack.Screen name="check-card" />
      <Stack.Screen name="fill-ghost-card" />
      <Stack.Screen name="open-ghost-card" />
      <Stack.Screen name="older-cards" options={onMist} />
      <Stack.Screen name="fill-card" />
      <Stack.Screen name="open-card" />
      <Stack.Screen name="wipe-card" />
    </Stack>
  );
}
