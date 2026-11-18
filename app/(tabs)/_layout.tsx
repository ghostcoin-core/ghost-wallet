// The four tabs of the wallet. Home, Cards and Settings each hold the screens
// they open, so the tab bar stays on those too. iOS draws the tab bar itself, so on the iPhone
// Duo it moves to the side rail when the phone is folded or held sideways,
// and stays a floating bar at the bottom when it is open upright.
import { NativeTabs } from 'expo-router/native-tabs';

import { colors } from '../../components/theme';

export default function TabsLayout() {
  return (
    <NativeTabs tintColor={colors.violet}>
      <NativeTabs.Trigger name="(home)">
        <NativeTabs.Trigger.Icon sf={{ default: 'house', selected: 'house.fill' }} />
        <NativeTabs.Trigger.Label>Home</NativeTabs.Trigger.Label>
      </NativeTabs.Trigger>
      <NativeTabs.Trigger name="(cards)">
        <NativeTabs.Trigger.Icon sf={{ default: 'creditcard', selected: 'creditcard.fill' }} />
        <NativeTabs.Trigger.Label>Cards</NativeTabs.Trigger.Label>
      </NativeTabs.Trigger>
      <NativeTabs.Trigger name="activity">
        <NativeTabs.Trigger.Icon sf={{ default: 'clock', selected: 'clock.fill' }} />
        <NativeTabs.Trigger.Label>Activity</NativeTabs.Trigger.Label>
      </NativeTabs.Trigger>
      <NativeTabs.Trigger name="(settings)">
        <NativeTabs.Trigger.Icon sf={{ default: 'gearshape', selected: 'gearshape.fill' }} />
        <NativeTabs.Trigger.Label>Settings</NativeTabs.Trigger.Label>
      </NativeTabs.Trigger>
    </NativeTabs>
  );
}
