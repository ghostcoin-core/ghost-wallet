// Receive: the account's address as text and as a QR code, with copy and
// share, after docs/mockups/receive.html.
import * as Clipboard from 'expo-clipboard';
import { useRouter } from 'expo-router';
import { useEffect, useState } from 'react';
import { Share, StyleSheet, Text, View } from 'react-native';
import QRCode from 'react-native-qrcode-svg';

import { colors, monoFont } from '../components/theme';
import {
  Button,
  ButtonRow,
  Column,
  IconButton,
  Logo,
  NetworkBadge,
  Panel,
  Screen,
  Spacer,
  textStyles,
  Title,
} from '../components/ui';
import { accountZeroAddress } from '../lib/account';
import { useLayout } from '../lib/layout';

const PHONE_QR_SIZE = 240;

export default function ReceiveScreen() {
  const router = useRouter();
  const { twoColumns, width } = useLayout();
  const [address] = useState(accountZeroAddress);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) {
      return;
    }
    const timer = setTimeout(() => setCopied(false), 2_000);
    return () => clearTimeout(timer);
  }, [copied]);

  // On the Duo open the code fills its half: the window less the side
  // padding (2 x 32) and the fold gap (56), halved, less the QR's own margin.
  const qrSize = twoColumns ? Math.floor((width - 64 - 56) / 2) - 32 : PHONE_QR_SIZE;

  async function copy() {
    if (!address) {
      return;
    }
    await Clipboard.setStringAsync(address);
    setCopied(true);
  }

  async function share() {
    if (!address) {
      return;
    }
    try {
      await Share.share({ message: address });
    } catch {
      // Closing the share sheet without sharing is not an error to show.
    }
  }

  return (
    <Screen
      testID="receive-screen"
      wide="split"
      topBar={
        <>
          <IconButton icon="back" label="Back" onPress={() => router.back()} testID="back" />
          <Spacer />
          <NetworkBadge />
          <Logo />
        </>
      }
    >
      <Column style={styles.centered}>
        <Title>Receive GHOST</Title>
        <Text style={[textStyles.body, styles.centerText]}>
          Share this address. Only send GHOST on the test network to it.
        </Text>
        <View style={styles.qr} testID="receive-qr" accessibilityRole="image" accessibilityLabel="QR code of the address">
          {address ? (
            <QRCode value={address} size={qrSize} color={colors.ink} backgroundColor={colors.paper} ecl="M" />
          ) : (
            <Text style={textStyles.quiet}>No address in this build</Text>
          )}
        </View>
      </Column>
      <Column style={twoColumns ? styles.actionPane : undefined}>
        <Panel style={styles.addressPanel}>
          <Text style={textStyles.quiet}>Your address</Text>
          <Text selectable style={styles.address} testID="receive-address">
            {address ?? 'Address unavailable'}
          </Text>
        </Panel>
        {twoColumns ? (
          <View style={styles.highlight}>
            <Text style={styles.highlightText}>Payments to this address show on Home once the node has them.</Text>
          </View>
        ) : null}
        {twoColumns ? <Spacer /> : null}
        <ButtonRow>
          <Button label={copied ? 'Copied' : 'Copy'} icon="copy" onPress={copy} disabled={!address} testID="copy-address" />
          <Button label="Share" icon="share" secondary onPress={share} disabled={!address} testID="share-address" />
        </ButtonRow>
      </Column>
    </Screen>
  );
}

const styles = StyleSheet.create({
  centered: {
    alignItems: 'center',
  },
  centerText: {
    textAlign: 'center',
  },
  qr: {
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 8,
    padding: 16,
    borderWidth: 1,
    borderColor: colors.line,
    borderRadius: 20,
    backgroundColor: colors.paper,
  },
  actionPane: {
    alignSelf: 'stretch',
  },
  addressPanel: {
    padding: 16,
  },
  address: {
    marginTop: 6,
    color: colors.ink,
    fontFamily: monoFont,
    fontSize: 15,
  },
  highlight: {
    paddingVertical: 12,
    paddingHorizontal: 14,
    borderRadius: 12,
    backgroundColor: colors.violetTint,
  },
  highlightText: {
    color: colors.ink,
    fontSize: 15,
  },
});
