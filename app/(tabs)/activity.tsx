// The Activity tab: every payment to and from the account, pending ones first.
import { useState } from 'react';

import { ActivityList } from '../../components/activity-list';
import { colors } from '../../components/theme';
import { NetworkBadge, Screen, Spacer, Title } from '../../components/ui';
import { accountZeroAddress } from '../../lib/account';
import { useHome } from '../../lib/home/use-home';
import { useSettings } from '../../lib/settings/settings';

export default function ActivityScreen() {
  const { nodeUrl } = useSettings();
  const [address] = useState(accountZeroAddress);
  const { view } = useHome(nodeUrl, address);

  return (
    <Screen
      testID="activity-screen"
      background="mist"
      topBar={
        <>
          <Spacer />
          <NetworkBadge background={colors.paper} />
        </>
      }
    >
      <Title>Activity</Title>
      <ActivityList nodeUrl={nodeUrl} kept={view.snapshot?.activity} />
    </Screen>
  );
}
