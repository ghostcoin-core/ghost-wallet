// Receive: the account's address as a QR code and as text, with copy and
// share. On the open iPhone Duo the code sits one side of the fold and the
// address and buttons the other.
import * as Clipboard from 'expo-clipboard';
import { useRouter } from 'expo-router';
import { useEffect, useState } from 'react';
import { Share, StyleSheet, Text, View } from 'react-native';
import QRCode from 'react-native-qrcode-svg';

import { FoldPage, useFold } from '../components/fold-page';
import { colors, monoFont } from '../components/theme';
import { Button, ButtonRow, Panel, textStyles } from '../components/ui';
import { accountZeroAddress } from '../lib/account';

const MIN_QR_SIZE = 120;
const MAX_QR_SIZE = 280;
const CARD_PADDING = 16;
const QR_PADDING = 16;

export default function ReceiveScreen() {
  const router = useRouter();
  const fold = useFold();
  const [address] = useState(accountZeroAddress);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) {
      return;
    }
    const timer = setTimeout(() => setCopied(false), 2_000);
    return () => clearTimeout(timer);
  }, [copied]);

  // The code fills the width of its part, less the card's and its own padding.
  // Held upright it must also fit above the fold.
  const fits = fold.firstWidth - 2 * (CARD_PADDING + QR_PADDING);
  const qrSize = Math.max(
    MIN_QR_SIZE,
    Math.min(MAX_QR_SIZE, fits, fold.mode === 'upright' ? fold.topHeight - 2 * (CARD_PADDING + QR_PADDING) : fits),
  );

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

  const code = (
    <View style={styles.card}>
      <View style={styles.qr} testID="receive-qr" accessibilityRole="image" accessibilityLabel="QR code of the address">
        {address ? (
          <QRCode value={address} size={qrSize} color={colors.ink} backgroundColor={colors.paper} ecl="M" />
        ) : (
          <Text style={textStyles.quiet}>No address in this build</Text>
        )}
      </View>
    </View>
  );

  const details = (
    <>
      <Panel style={styles.addressPanel}>
        <Text style={textStyles.quiet}>Your address</Text>
        <Text selectable style={styles.address} testID="receive-address">
          {address ?? 'Address unavailable'}
        </Text>
      </Panel>
      <Text style={textStyles.quiet}>Anyone can pay you with this code or address. It is safe to share.</Text>
      <ButtonRow>
        <Button label={copied ? 'Copied' : 'Copy'} icon="copy" ink onPress={copy} disabled={!address} testID="copy-address" />
        <Button label="Share" icon="share" secondary onPress={share} disabled={!address} testID="share-address" />
      </ButtonRow>
    </>
  );

  return <FoldPage testID="receive-screen" title="Receive" onBack={() => router.back()} first={code} second={details} />;
}

const styles = StyleSheet.create({
  card: {
    alignSelf: 'center',
    padding: CARD_PADDING,
    borderRadius: 20,
    backgroundColor: colors.violet,
  },
  qr: {
    alignItems: 'center',
    justifyContent: 'center',
    padding: QR_PADDING,
    borderRadius: 12,
    backgroundColor: colors.paper,
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
});
