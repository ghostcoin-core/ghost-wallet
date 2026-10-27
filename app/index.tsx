import { StyleSheet, Text, View } from 'react-native';

const PAGE_COLOUR = '#0A0A12';

export default function HomeScreen() {
  return (
    <View style={styles.page} testID="home-screen">
      <Text accessibilityRole="header" style={styles.title}>
        Ghost Wallet
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  page: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: PAGE_COLOUR,
  },
  title: {
    color: '#FFFFFF',
    fontSize: 32,
    fontWeight: '700',
  },
});
