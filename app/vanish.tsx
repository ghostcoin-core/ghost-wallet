// Vanish: an amount from the account goes into a fresh Phantom Key. As in
// Ghost's web app, the key is written down before anything is sent: the core
// makes the key, its 24 words show once (on ink, labelled as a key, never
// copied or saved to photos), three of them are typed back, the core drops
// the key, and only then is the Vanish signed (ML-DSA-44) and sent. The
// payment is saved at every step, so it survives the app being killed.
import { useRouter } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { StyleSheet, Text, TextInput, View } from 'react-native';

import { colors, monoFont } from '../components/theme';
import { Button, Column, IconButton, Logo, NetworkBadge, Panel, Screen, Spacer, textStyles, Title } from '../components/ui';
import { PaymentProgress, PhantomKeyWords } from '../components/vanish-ui';
import { WordField } from '../components/word-field';
import { accountZeroAddress } from '../lib/account';
import { formatGhost } from '../lib/home/balance-format';
import { useLayout } from '../lib/layout';
import { pickCheckPositions } from '../lib/onboarding/word-check';
import { useSettings } from '../lib/settings/settings';
import { minimumVanish, signVanishAgain, startVanish } from '../lib/vanish/actions';
import { parseGhostAmount } from '../lib/vanish/amount';
import { newestPayment } from '../lib/vanish/payments';
import { isFinal, statusOfStep, stepName } from '../lib/vanish/status-mapping';
import { paymentKit, usePayment, type PaymentKit } from '../lib/vanish/use-payment';
import type { CorePaymentSequence } from '../modules/ghost-core';

/**
 * The Vanish the app was closed in, to show again. One still waiting for
 * its key to be written down cannot go on (the key was never saved) and
 * nothing of it was signed: it is dropped, with any key still held.
 */
function resumeVanish(kit: PaymentKit | null): CorePaymentSequence | null {
  if (!kit) {
    return null;
  }
  kit.core.forgetPhantomKey();
  const saved = newestPayment(kit.core, kit.store, ['vanish']);
  if (!saved) {
    return null;
  }
  if (stepName(saved.step()) === 'Prepared') {
    kit.store.remove(saved.record().id);
    return null;
  }
  return isFinal(statusOfStep(saved.step())) ? null : saved;
}

type Phase =
  | { name: 'amount' }
  | { name: 'save'; words: string[] }
  | { name: 'check'; words: string[]; positions: number[] }
  | { name: 'sending' };

export default function VanishScreen() {
  const router = useRouter();
  const { twoColumns } = useLayout();
  const { nodeUrl } = useSettings();
  const [address] = useState(accountZeroAddress);
  const kit = useMemo(() => paymentKit(nodeUrl), [nodeUrl]);
  const [resumed] = useState(() => resumeVanish(kit));
  const [phase, setPhase] = useState<Phase>(resumed ? { name: 'sending' } : { name: 'amount' });
  const [sequence, setSequence] = useState<CorePaymentSequence | null>(resumed);
  const [amountText, setAmountText] = useState('');
  const [minimum, setMinimum] = useState<bigint | null>(null);
  const [typed, setTyped] = useState<Record<number, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!kit) {
      return;
    }
    minimumVanish(kit).then(setMinimum, () => setMinimum(null));
  }, [kit]);

  const rebuild = useMemo(() => (kit && sequence ? signVanishAgain(kit, sequence) : null), [kit, sequence]);
  const payment = usePayment(kit, phase.name === 'sending' ? sequence : null, rebuild, false);

  const amount = parseGhostAmount(amountText);
  const tooSmall = amount !== null && minimum !== null && amount < minimum;

  async function makeKey() {
    if (!kit || !address || amount === null || tooSmall) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const started = await startVanish(kit, address, amount);
      setSequence(started.sequence);
      setPhase({ name: 'save', words: started.words });
    } catch (failure) {
      setError(failure instanceof Error ? `The Vanish could not start: ${failure.message}` : 'The Vanish could not start.');
    } finally {
      setBusy(false);
    }
  }

  function confirm() {
    if (!kit || !sequence || phase.name !== 'check') {
      return;
    }
    const wrong = phase.positions.filter((position) => {
      try {
        return !kit.core.checkPhantomKeyWord(position, (typed[position] ?? '').trim().toLowerCase());
      } catch {
        return true;
      }
    });
    if (wrong.length > 0) {
      setError(`Word ${wrong.join(', ')} does not match your Phantom Key. Check what you wrote down.`);
      return;
    }
    try {
      kit.core.confirmPhantomKeySaved();
      sequence.markBackedUp();
    } catch {
      setError('The Vanish could not be saved. Nothing was sent.');
      return;
    }
    setTyped({});
    setError(null);
    // The words leave the screen's memory here.
    setPhase({ name: 'sending' });
  }

  function cancel() {
    if (kit && sequence && stepName(sequence.step()) === 'Prepared') {
      kit.core.forgetPhantomKey();
      kit.store.remove(sequence.record().id);
    }
    router.back();
  }

  const unavailable = !kit || !address;

  return (
    <Screen
      testID="vanish-screen"
      wide="columns"
      topBar={
        <>
          <IconButton icon="back" label="Back" onPress={cancel} testID="back" />
          <Spacer />
          <NetworkBadge />
          <Logo />
        </>
      }
    >
      <Column>
        <Title>Vanish</Title>
        {phase.name === 'amount' ? (
          <>
            <Text style={textStyles.body}>
              Move GHOST from your account into a new Phantom Key. You will write the key down before anything is sent.
            </Text>
            <Panel style={styles.form}>
              <Text style={textStyles.quiet}>Amount</Text>
              <View style={styles.amountRow}>
                <TextInput
                  accessibilityLabel="Amount in GHOST"
                  keyboardType="decimal-pad"
                  onChangeText={setAmountText}
                  placeholder="0.0"
                  placeholderTextColor={colors.quiet}
                  style={styles.amount}
                  testID="vanish-amount"
                  value={amountText}
                />
                <Text style={styles.unit}>GHOST</Text>
              </View>
              {minimum !== null ? (
                <Text style={[textStyles.quiet, tooSmall && styles.error]} testID="vanish-minimum">
                  At least {formatGhost(minimum)} GHOST: four times the fee to Summon it back.
                </Text>
              ) : null}
            </Panel>
            <Button
              label="Make a Phantom Key"
              icon="key"
              disabled={unavailable || busy || amount === null || tooSmall}
              onPress={() => void makeKey()}
              testID="vanish-make-key"
            />
          </>
        ) : null}
        {phase.name === 'save' ? (
          <>
            <Text style={textStyles.body}>
              Write these 24 words down, in order, on paper. They are the only way to summon this GHOST. Anyone with them
              can take it. If you lose them, no one can get it back. This phone does not keep them.
            </Text>
            <PhantomKeyWords words={phase.words} twoColumns={twoColumns} />
            <Button
              label="I wrote it down"
              onPress={() => setPhase({ name: 'check', words: phase.words, positions: pickCheckPositions() })}
              testID="vanish-saved"
            />
          </>
        ) : null}
        {phase.name === 'check' ? (
          <>
            <Text style={textStyles.body}>Type these three words from the key you wrote down.</Text>
            <Panel style={styles.form}>
              {phase.positions.map((position) => (
                <View key={position} style={styles.checkRow}>
                  <Text style={styles.checkNumber}>{position}</Text>
                  <WordField
                    accessibilityLabel={`Key word ${position}`}
                    onChangeText={(text) => setTyped((current) => ({ ...current, [position]: text }))}
                    style={styles.checkField}
                    testID={`vanish-check-${position}`}
                    value={typed[position] ?? ''}
                  />
                </View>
              ))}
            </Panel>
            <Button
              label={amount !== null ? `Vanish ${formatGhost(amount)} GHOST` : 'Vanish'}
              disabled={phase.positions.some((position) => (typed[position] ?? '').trim() === '')}
              onPress={confirm}
              testID="vanish-send"
            />
            <Button label="Show the key again" secondary onPress={() => setPhase({ name: 'save', words: phase.words })} />
          </>
        ) : null}
        {error ? (
          <Text accessibilityLiveRegion="polite" style={[textStyles.body, styles.error]} testID="vanish-error">
            {error}
          </Text>
        ) : null}
        {unavailable ? (
          <Text style={textStyles.quiet} testID="vanish-unavailable">
            Vanish is not available in this build.
          </Text>
        ) : null}
      </Column>
      <Column>
        {phase.name === 'sending' && payment ? (
          <PaymentProgress status={payment.status} kind="vanish" step={payment.step} error={payment.error} />
        ) : (
          <Panel style={styles.form}>
            <Text style={textStyles.quiet}>How it works</Text>
            <Text style={textStyles.body}>
              The key is made on this phone and shown once. The Vanish is signed with your account and sent only after
              you have checked three of its words. Summon it back any time by typing the key.
            </Text>
          </Panel>
        )}
        {phase.name === 'sending' ? (
          <Button label="Done" secondary onPress={() => router.back()} testID="vanish-done" />
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
    fontSize: 28,
  },
  unit: {
    color: colors.body,
    fontSize: 16,
  },
  checkRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    borderBottomWidth: 1,
    borderBottomColor: colors.line,
  },
  checkNumber: {
    minWidth: 24,
    color: colors.quiet,
    fontFamily: monoFont,
  },
  checkField: {
    flex: 1,
  },
  error: {
    color: colors.danger,
  },
});
