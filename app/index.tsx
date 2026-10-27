import { testWordsAccountZeroAddress } from 'ghost-core';
import { StyleSheet, Text, View } from 'react-native';

const PAGE_COLOUR = '#0A0A12';

function accountZeroAddress(): string | null {
  try {
    return testWordsAccountZeroAddress();
  } catch {
    return null;
  }
}

export default function HomeScreen() {
  const address = accountZeroAddress();

  return (
    <View style={styles.page} testID="home-screen">
      <Text accessibilityRole="header" style={styles.title}>
        Ghost Wallet
      </Text>
      <View style={styles.account} testID="account-zero">
        <Text style={styles.label}>Account 0</Text>
        <Text selectable style={styles.address} testID="account-zero-address">
          {address ?? 'Address unavailable'}
        </Text>
        <Text style={styles.note}>test words</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  page: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: PAGE_COLOUR,
    paddingHorizontal: 24,
  },
  title: {
    color: '#FFFFFF',
    fontSize: 32,
    fontWeight: '700',
  },
  account: {
    marginTop: 32,
    alignItems: 'center',
  },
  label: {
    color: '#FFFFFF',
    fontSize: 18,
    fontWeight: '600',
  },
  address: {
    marginTop: 8,
    color: '#C8C8D8',
    fontFamily: 'Menlo',
    fontSize: 13,
    textAlign: 'center',
  },
  note: {
    marginTop: 4,
    color: '#8A8AA0',
    fontSize: 12,
  },
});
