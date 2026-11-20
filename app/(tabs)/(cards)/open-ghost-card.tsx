// Take GHOST off a Ghost card, like a withdrawal from a bank account: hold
// the card to see what it holds, say how much to take (or all of it), then
// hold it again. The card works like a vault (lib/ghost-card/vault.ts): in
// that one hold it gives up its old key to this phone's Keychain and makes a
// new key for what is left; what was taken reaches the wallet, and what is
// left goes back onto the card, in the background. Nothing else is asked:
// no code, no card states.
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Pressable, StyleSheet, Text, TextInput, View } from 'react-native';

import { CardBalancePanel } from '../../../components/ghost-card-ui';
import { CardBusy } from '../../../components/seal-ui';
import { colors, monoFont } from '../../../components/theme';
import { Button, Column, Logo, NetworkBadge, Panel, Screen, Spacer, textStyles, Title } from '../../../components/ui';
import { accountZeroAddress } from '../../../lib/account';
import { checkGhostCard } from '../../../lib/ghost-card/flows';
import { cardBalance, changeCard, moveChanges, takeProblem, type CardBalance } from '../../../lib/ghost-card/vault';
import { vaultDeps } from '../../../lib/ghost-card/vault-deps';
import { useHome } from '../../../lib/home/use-home';
import { ghostText } from '../../../lib/seal/card-status';
import { useSettings } from '../../../lib/settings/settings';
import { minimumVanish, summonFee, vanishFee } from '../../../lib/vanish/actions';
import { parseGhostAmount } from '../../../lib/vanish/amount';
import { paymentKit } from '../../../lib/vanish/use-payment';

export default function TakeOffCardScreen() {
  const router = useRouter();
  const { nodeUrl } = useSettings();
  const [address] = useState(accountZeroAddress);
  const kit = useMemo(() => paymentKit(nodeUrl), [nodeUrl]);
  const vault = useMemo(() => vaultDeps(kit, address), [kit, address]);
  const cards = vault.card.nfc !== null && vault.card.core !== null && vault.keys !== null;
  const { view: home } = useHome(nodeUrl, address);

  // With `start`, Summon's own button was the go-ahead: the card is read at once.
  const { start } = useLocalSearchParams<{ start?: string }>();
  const started = useRef(false);
  const [busy, setBusy] = useState<'look' | 'take' | null>(null);
  const [balance, setBalance] = useState<CardBalance | null>(null);
  const [amountText, setAmountText] = useState('');
  const [all, setAll] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [minimum, setMinimum] = useState<bigint | null>(null);
  const [fees, setFees] = useState<{ summon: bigint; vanish: bigint } | null>(null);
  const [done, setDone] = useState<{ cardNumber: string; takenWei: bigint; afterWei: bigint } | null>(null);

  useEffect(() => {
    if (!kit) {
      return;
    }
    minimumVanish(kit).then(setMinimum, () => setMinimum(null));
    Promise.all([summonFee(kit), vanishFee(kit)]).then(([summon, v]) => setFees({ summon, vanish: v }), () => setFees(null));
  }, [kit]);

  const held = balance?.kind === 'holds' ? balance.amountWei : 0n;
  const typed = all ? held : parseGhostAmount(amountText);
  const wallet = home.snapshot ? BigInt(home.snapshot.balanceWei) : null;
  const problem = balance?.kind === 'holds' ? takeProblem(typed, held, minimum, wallet, fees) : null;
  const takeOk = balance?.kind === 'holds' && typed !== null && typed > 0n && minimum !== null && problem === null;

  async function look() {
    if (busy !== null || !cards) {
      return;
    }
    setBusy('look');
    setError(null);
    setBalance(null);
    setAll(false);
    setAmountText('');
    try {
      const checked = await checkGhostCard(vault.card);
      if (checked) {
        setBalance(cardBalance(vault, checked));
      }
    } finally {
      setBusy(null);
    }
  }

  useEffect(() => {
    if (start === '1' && cards && !started.current) {
      started.current = true;
      void look();
    }
    // Runs once, when Summon's button opened this screen.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [start, cards]);

  async function take() {
    if (!takeOk || typed === null || minimum === null || busy !== null) {
      return;
    }
    setBusy('take');
    setError(null);
    try {
      const takeAll = all || typed === held;
      const result = await changeCard(vault, { kind: 'take', amountWei: takeAll ? null : typed }, minimum);
      if (!result.ok) {
        setError(result.message);
        return;
      }
      setDone({ cardNumber: result.cardNumber, takenWei: result.beforeWei - result.afterWei, afterWei: result.afterWei });
      // The rest goes on in the background; started now, not at Home's next move.
      void moveChanges(vault);
    } finally {
      setBusy(null);
    }
  }

  return (
    <Screen
      testID="open-ghost-card-screen"
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
        <Title>Take off card</Title>
        {!done ? (
          <Text style={textStyles.body}>
            Move GHOST from your card into your wallet. Take some or all of it; the rest stays on the card.
          </Text>
        ) : null}
        {!balance && !done ? (
          <Button
            label={busy === 'look' ? 'Hold the card near the iPhone' : 'Hold your card to see what it holds'}
            icon="tap"
            disabled={busy !== null || !cards}
            onPress={() => void look()}
            testID="ghost-open-look"
          />
        ) : null}
        {balance && !done ? <CardBalancePanel balance={balance} testID="ghost-open-balance" /> : null}
        {balance && balance.kind !== 'holds' && !done ? (
          <Button label="Try another card" secondary onPress={() => void look()} testID="ghost-open-look-again" />
        ) : null}
        {!cards ? (
          <Text style={textStyles.quiet} testID="ghost-open-unavailable">
            This iPhone cannot read Ghost cards in this build.
          </Text>
        ) : null}
      </Column>
      <Column>
        {balance?.kind === 'holds' && !done ? (
          <>
            <Panel style={styles.form}>
              <Text style={textStyles.quiet}>How much to take off</Text>
              <View style={styles.amountRow}>
                <TextInput
                  accessibilityLabel="Amount in GHOST"
                  editable={busy === null}
                  keyboardType="decimal-pad"
                  onChangeText={(text) => {
                    setAll(false);
                    setAmountText(text);
                  }}
                  placeholder="0.0"
                  placeholderTextColor={colors.quiet}
                  style={styles.amount}
                  testID="ghost-open-amount"
                  value={all ? ghostText(held) : amountText}
                />
                <Pressable
                  accessibilityRole="button"
                  accessibilityState={{ selected: all }}
                  onPress={() => setAll(true)}
                  style={({ pressed }) => [styles.all, all && styles.allOn, pressed && styles.pressed]}
                  testID="ghost-open-all"
                >
                  <Text style={[styles.allText, all && styles.allTextOn]}>All</Text>
                </Pressable>
              </View>
              {problem ? (
                <Text style={[textStyles.body, styles.error]} testID="ghost-open-amount-error">
                  {problem}
                </Text>
              ) : null}
            </Panel>
            <Button
              label={busy === 'take' ? 'Keep holding the card' : `Hold your card to take off ${ghostText(typed ?? 0n)} GHOST`}
              icon="tap"
              disabled={busy !== null || !takeOk}
              onPress={() => void take()}
              testID="ghost-open-take"
            />
          </>
        ) : null}
        {busy !== null ? (
          <CardBusy
            text={busy === 'look' ? 'Reading the card…' : 'Keep the card near the top of the iPhone…'}
            testID="ghost-open-spinner"
          />
        ) : null}
        {error ? (
          <Text accessibilityLiveRegion="polite" style={[textStyles.body, styles.error]} testID="ghost-open-error">
            {error}
          </Text>
        ) : null}
        {done ? (
          <>
            <CardBalancePanel
              balance={
                done.afterWei === 0n
                  ? { kind: 'empty', cardNumber: done.cardNumber }
                  : { kind: 'holds', cardNumber: done.cardNumber, amountWei: done.afterWei, updating: true }
              }
              testID="ghost-open-after"
            />
            <Text style={textStyles.body} testID="ghost-open-done">
              Took off {ghostText(done.takenWei)} GHOST. It reaches your wallet in about a minute, less the network
              fee. You can put the card away.
            </Text>
            <Button label="Done" onPress={() => router.back()} testID="ghost-open-leave" />
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
    alignItems: 'center',
    gap: 8,
  },
  amount: {
    flex: 1,
    minHeight: 44,
    color: colors.ink,
    fontFamily: monoFont,
    fontSize: 22,
  },
  all: {
    minHeight: 36,
    paddingHorizontal: 14,
    justifyContent: 'center',
    borderRadius: 18,
    borderWidth: 1,
    borderColor: colors.line,
  },
  allOn: {
    backgroundColor: colors.violet,
    borderColor: colors.violet,
  },
  allText: {
    color: colors.ink,
    fontSize: 15,
    fontWeight: '600',
  },
  allTextOn: {
    color: colors.paper,
  },
  pressed: {
    opacity: 0.6,
  },
  error: {
    color: colors.danger,
  },
});
