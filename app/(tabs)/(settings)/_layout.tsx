// The Settings tab: Settings, and the screens it opens, which keep the tab bar.
import { Stack } from 'expo-router';

import { pushedScreenOptions, tabRootOptions } from '../../../components/stack-options';
import { useCloseOnLeavingTab } from '../../../components/tab-stack';

export const unstable_settings = { anchor: 'settings' };

export default function SettingsTab() {
  useCloseOnLeavingTab('(settings)');

  return (
    <Stack screenOptions={pushedScreenOptions}>
      <Stack.Screen name="settings" options={tabRootOptions} />
      <Stack.Screen name="recovery-words" />
      <Stack.Screen name="check-words" />
    </Stack>
  );
}
