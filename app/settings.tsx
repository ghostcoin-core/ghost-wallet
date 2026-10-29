// Settings, after docs/mockups/settings.html: the account, the recovery words
// (behind Face ID), "Backup not checked" when the word check was skipped,
// app lock, the node, and the app version. Tapping the
// version seven times opens the bench screen.
import Constants from 'expo-constants';
import { useRouter } from 'expo-router';
import { useMemo, useState } from 'react';
import { StyleSheet, Switch, Text, TextInput, View } from 'react-native';

import { colors, monoFont } from '../components/theme';
import {
  Button,
  ButtonRow,
  IconButton,
  Logo,
  NetworkBadge,
  Panel,
  Row,
  Screen,
  SectionTitle,
  Spacer,
  textStyles,
  Title,
} from '../components/ui';
import { accountZeroAddress } from '../lib/account';
import { authenticate, authFailureMessage } from '../lib/device-auth';
import { shortAddress } from '../lib/home/balance-format';
import { useBackupUnchecked } from '../lib/onboarding/backup-status';
import { createTapCounter } from '../lib/settings/developer-entry';
import { DEFAULT_NODE_URL, normaliseNodeUrl, settingsStore, useSettings } from '../lib/settings/settings';

function appVersion(): string {
  return Constants.expoConfig?.version ?? 'unknown';
}

function NodeEditor({ nodeUrl, onDone }: { nodeUrl: string; onDone: () => void }) {
  const [text, setText] = useState(nodeUrl);
  const [invalid, setInvalid] = useState(false);

  async function save() {
    const url = normaliseNodeUrl(text);
    if (!url) {
      setInvalid(true);
      return;
    }
    await settingsStore.update({ nodeUrl: url });
    onDone();
  }

  return (
    <View style={styles.editor}>
      <Text style={styles.label}>Node address</Text>
      <TextInput
        value={text}
        onChangeText={(value) => {
          setText(value);
          setInvalid(false);
        }}
        autoCapitalize="none"
        autoCorrect={false}
        keyboardType="url"
        placeholder={DEFAULT_NODE_URL}
        placeholderTextColor={colors.quiet}
        style={styles.input}
        testID="node-url-input"
        accessibilityLabel="Node address"
        onSubmitEditing={save}
      />
      {invalid ? (
        <Text style={styles.error} testID="node-url-error">
          Enter an address that starts with http:// or https://
        </Text>
      ) : null}
      <ButtonRow>
        <Button label="Save" onPress={save} testID="node-url-save" />
        <Button label="Cancel" secondary onPress={onDone} testID="node-url-cancel" />
      </ButtonRow>
    </View>
  );
}

export default function SettingsScreen() {
  const router = useRouter();
  const settings = useSettings();
  const backupUnchecked = useBackupUnchecked();
  const [address] = useState(accountZeroAddress);
  const [editingNode, setEditingNode] = useState(false);
  const [lockMessage, setLockMessage] = useState<string | null>(null);
  const tapVersion = useMemo(() => createTapCounter(), []);

  async function setAppLock(on: boolean) {
    setLockMessage(null);
    const result = await authenticate(on ? 'Turn on app lock' : 'Turn off app lock');
    if (!result.ok) {
      setLockMessage(authFailureMessage(result.reason));
      return;
    }
    await settingsStore.update({ appLock: on });
  }

  return (
    <Screen
      testID="settings-screen"
      background="mist"
      topBar={
        <>
          <IconButton icon="back" label="Back" background={colors.mist} onPress={() => router.back()} testID="back" />
          <Spacer />
          <NetworkBadge background={colors.paper} />
          <Logo />
        </>
      }
    >
      <Title>Settings</Title>

      <SectionTitle>Account</SectionTitle>
      <Panel>
        <Row
          first
          icon="account"
          title="Account 1"
          detail={address ? shortAddress(address) : 'Not available in this build'}
          detailMono
          opens
          onPress={() => router.push('/receive')}
          testID="settings-account"
        />
        <Row
          icon="key"
          title="Recovery words"
          detail="Shown after Face ID"
          opens
          onPress={() => router.push('/recovery-words')}
          testID="settings-recovery-words"
        />
        {backupUnchecked ? (
          <Row
            icon="warning"
            title="Backup not checked"
            detail="Check my words now"
            opens
            onPress={() => router.push('/check-words')}
            testID="settings-backup-unchecked"
          />
        ) : null}
        <Row
          icon="cross"
          title="Wipe a card"
          detail="Phantom Key cards this iPhone wrote"
          opens
          onPress={() => router.push('/wipe-card')}
          testID="settings-wipe-card"
        />
      </Panel>

      <SectionTitle>Security</SectionTitle>
      <Panel>
        <Row
          first
          icon="lock"
          title="App lock"
          detail="Face ID or passcode"
          end={
            <Switch
              value={settings.appLock}
              onValueChange={setAppLock}
              trackColor={{ false: colors.line, true: colors.violet }}
              accessibilityLabel="App lock"
              testID="app-lock-switch"
            />
          }
        />
      </Panel>
      {lockMessage ? (
        <Text style={textStyles.quiet} testID="app-lock-message">
          {lockMessage}
        </Text>
      ) : null}

      <SectionTitle>Network</SectionTitle>
      <Panel>
        <Row
          first
          icon="globe"
          title="Network"
          detail="Coins here have no value"
          end={<Text style={styles.value}>Test network</Text>}
        />
        {editingNode ? (
          <NodeEditor nodeUrl={settings.nodeUrl} onDone={() => setEditingNode(false)} />
        ) : (
          <Row
            icon="node"
            title="Node"
            detail={settings.nodeUrl}
            detailMono
            opens
            onPress={() => setEditingNode(true)}
            testID="settings-node"
          />
        )}
      </Panel>

      <SectionTitle>About</SectionTitle>
      <Panel>
        <Row
          first
          icon="info"
          title="Ghost Wallet"
          detail={`Version ${appVersion()}, experimental`}
          onPress={() => {
            if (tapVersion()) {
              router.push('/bench');
            }
          }}
          accessibilityLabel={`Ghost Wallet version ${appVersion()}`}
          testID="settings-version"
        />
      </Panel>
    </Screen>
  );
}

const styles = StyleSheet.create({
  value: {
    color: colors.body,
    fontSize: 15,
  },
  editor: {
    gap: 8,
    padding: 16,
    borderTopWidth: 1,
    borderTopColor: colors.line,
  },
  label: {
    color: colors.body,
    fontSize: 14,
    fontWeight: '500',
  },
  input: {
    minHeight: 52,
    paddingHorizontal: 14,
    borderWidth: 1,
    borderColor: colors.line,
    borderRadius: 12,
    backgroundColor: colors.paper,
    color: colors.ink,
    fontFamily: monoFont,
    fontSize: 14,
  },
  error: {
    color: colors.ink,
    fontSize: 14,
  },
});
