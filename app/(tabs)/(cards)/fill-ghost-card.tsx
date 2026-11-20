// Add to a Ghost card: pick an amount, then hold the card to the iPhone. The
// card works like a vault: whatever it held, it now holds that plus the
// amount. Empty or not, it is the same one hold (lib/ghost-card/vault.ts):
// the card gives up its old key to this phone's Keychain, makes a new key
// for the new total and signs that it holds it; the old coin comes home and
// the new total goes onto the card in the background. No words, no code and
// no card states: the card holds one balance.
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useEffect, useMemo, useRef, useState } from 'react';
import { StyleSheet, Text, TextInput, View } from 'react-native';

import { CardBalancePanel } from '../../../components/ghost-card-ui';
import { CardBusy } from '../../../components/seal-ui';
import { colors, monoFont } from '../../../components/theme';
import { Button, Column, Logo, NetworkBadge, Panel, Screen, Spacer, textStyles, Title } from '../../../components/ui';
import { accountZeroAddress } from '../../../lib/account';
import { changeCard, moveChanges } from '../../../lib/ghost-card/vault';
import { vaultDeps } from '../../../lib/ghost-card/vault-deps';
import { formatGhost } from '../../../lib/home/balance-format';
import { useHome } from '../../../lib/home/use-home';
import { ghostText } from '../../../lib/seal/card-status';
import { useSettings } from '../../../lib/settings/settings';
import { minimumVanish, summonFee, vanishFee } from '../../../lib/vanish/actions';
import { coversVanish, parseGhostAmount } from '../../../lib/vanish/amount';
import { paymentKit } from '../../../lib/vanish/use-payment';

export default function AddToCardScreen() {
  const router = useRouter();
  const { nodeUrl } = useSettings();
  const [address] = useState(accountZeroAddress);
  const kit = useMemo(() => paymentKit(nodeUrl), [nodeUrl]);
  const vault = useMemo(() => vaultDeps(kit, address), [kit, address]);
  const cards = vault.card.nfc !== null && vault.card.core !== null && vault.keys !== null;

  // Vanish hands over the amount typed there; it is still checked here like any typed amount.
  // With `start`, Vanish's own button was the go-ahead: the hold starts at once.
  const { amount: asked, start } = useLocalSearchParams<{ amount?: string; start?: string }>();
  const started = useRef(false);
  const [amountText, setAmountText] = useState(typeof asked === 'string' ? asked : '');
  const [minimum, setMinimum] = useState<bigint | null>(null);
  // The Vanish of the new total and the Summon of what the card held.
  const [fees, setFees] = useState<bigint | null>(null);
  const { view: home } = useHome(nodeUrl, address);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<{ cardNumber: string; afterWei: bigint; addedWei: bigint } | null>(null);

  useEffect(() => {
    if (!kit) {
      return;
    }
    minimumVanish(kit).then(setMinimum, () => setMinimum(null));
    Promise.all([vanishFee(kit), summonFee(kit)]).then(([v, s]) => setFees(v + s), () => setFees(null));
  }, [kit]);

  const amount = parseGhostAmount(amountText);
  const balance = home.snapshot ? BigInt(home.snapshot.balanceWei) : null;
  const tooSmall = amount !== null && minimum !== null && amount < minimum;
  const tooMuch = amount !== null && !coversVanish(amount, balance, fees);
  const amountOk = !!kit && !!address && cards && amount !== null && amount > 0n && minimum !== null && !tooSmall && !tooMuch;

  async function add() {
    if (!amountOk || amount === null || minimum === null || busy) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const result = await changeCard(vault, { kind: 'add', amountWei: amount }, minimum);
      if (!result.ok) {
        setError(result.message);
        return;
      }
      setDone({ cardNumber: result.cardNumber, afterWei: result.afterWei, addedWei: amount });
      // The rest goes on in the background; started now, not at Home's next move.
      void moveChanges(vault);
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    if (start === '1' && amountOk && !started.current) {
      started.current = true;
      void add();
    }
    // Runs once, as soon as the handed-over amount is ready to go.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [start, amountOk]);

  return (
    <Screen
      testID="fill-ghost-card-screen"
      wide="columns"
      topBar={
        <>
          <Spacer />
          <NetworkBadge />
          <Logo />
        </>
      }
    >
      <Column>
        <Title>Add to card</Title>
        {!done ? (
          <>
            <Text style={textStyles.body}>
              Move GHOST from your wallet onto your card. It adds to what the card already holds. Whoever holds the
              card holds the GHOST, like cash.
            </Text>
            <Panel style={styles.form}>
              <Text style={textStyles.quiet}>Amount to add</Text>
              <View style={styles.amountRow}>
                <TextInput
                  accessibilityLabel="Amount in GHOST"
                  editable={!busy}
                  keyboardType="decimal-pad"
                  onChangeText={setAmountText}
                  placeholder="0.0"
                  placeholderTextColor={colors.quiet}
                  style={styles.amount}
                  testID="ghost-fill-amount"
                  value={amountText}
                />
                <Text style={textStyles.body}>GHOST</Text>
              </View>
              {tooSmall && minimum !== null ? (
                <Text style={[textStyles.quiet, styles.error]} testID="ghost-fill-amount-error">
                  Add at least {ghostText(minimum)} GHOST.
                </Text>
              ) : null}
              {tooMuch && !tooSmall ? (
                <Text style={[textStyles.body, styles.error]} testID="ghost-fill-not-enough">
                  {balance === null ? 'Not enough GHOST in your wallet.' : `Your wallet has ${formatGhost(balance)} GHOST, and the fee is on top.`}
                </Text>
              ) : null}
            </Panel>
          </>
        ) : null}
        {!cards ? (
          <Text style={textStyles.quiet} testID="ghost-fill-unavailable">
            This iPhone cannot read Ghost cards in this build.
          </Text>
        ) : null}
      </Column>
      <Column>
        {!done ? (
          <Button
            label={busy ? 'Keep holding the card' : `Hold your card to add ${ghostText(amount ?? 0n)} GHOST`}
            icon="tap"
            disabled={busy || !amountOk}
            onPress={() => void add()}
            testID="ghost-fill-tap"
          />
        ) : null}
        {busy ? <CardBusy text="Keep the card near the top of the iPhone…" testID="ghost-fill-spinner" /> : null}
        {error ? (
          <Text accessibilityLiveRegion="polite" style={[textStyles.body, styles.error]} testID="ghost-fill-error">
            {error}
          </Text>
        ) : null}
        {done ? (
          <>
            <CardBalancePanel
              balance={{ kind: 'holds', cardNumber: done.cardNumber, amountWei: done.afterWei, updating: true }}
              testID="ghost-fill-balance"
            />
            <Text style={textStyles.body} testID="ghost-fill-done">
              Added {ghostText(done.addedWei)} GHOST. You can put the card away: the rest finishes by itself.
            </Text>
            <Button label="Done" onPress={() => router.back()} testID="ghost-fill-leave" />
          </>
        ) : null}
      </Column>
    </Screen>
  );
}

const styles = StyleSheet.create({
  form: {
    gap: 8,
    padding: 16,
  },
  amountRow: {
    flexDirection: 'row',
    alignItems: 'baseline',
    gap: 8,
  },
  amount: {
    flex: 1,
    minHeight: 44,
    color: colors.ink,
    fontFamily: monoFont,
    fontSize: 22,
  },
  error: {
    color: colors.danger,
  },
});
