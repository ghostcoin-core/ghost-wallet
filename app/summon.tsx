// Summon / Claim: the person types a Phantom Key's 24 words (or its digits).
// The field refuses recovery words; the native core finds the key's coin in
// the coin tree this phone rebuilt from the test chain, proves the reveal here
// on the phone and sends it to the account. Summon brings the whole coin back,
// less the fee; Claim brings part of it, and the rest stays with the key. A
// key this phone cannot find shows as not found yet, never as zero.
import { useRouter } from 'expo-router';
import { useMemo, useState } from 'react';
import { StyleSheet, Text, TextInput, View } from 'react-native';

import { colors, monoFont } from '../components/theme';
import { Button, ButtonRow, Column, IconButton, Logo, NetworkBadge, Panel, Screen, Spacer, textStyles, Title } from '../components/ui';
import { CoinsBack, PaymentProgress } from '../components/vanish-ui';
import { WordField } from '../components/word-field';
import { accountZeroAddress } from '../lib/account';
import { formatGhost } from '../lib/home/balance-format';
import { useSettings } from '../lib/settings/settings';
import { lookUpKey, proveRevealAgain, startReveal, type KeyLookup } from '../lib/vanish/actions';
import { parseGhostAmount } from '../lib/vanish/amount';
import { keyFieldRule } from '../lib/vanish/field-rules';
import { decodeDetails, newestPayment } from '../lib/vanish/payments';
import { isFinal, lookupMessage, statusOfStep, type RevealKind } from '../lib/vanish/status-mapping';
import { paymentKit, usePayment, type PaymentKit } from '../lib/vanish/use-payment';
import { normaliseKeyText, parseWordsCheck } from '../lib/vanish/word-validation';
import { checkKeyWords, type CorePaymentSequence } from '../modules/ghost-core';

function checkWords(text: string) {
  return parseWordsCheck(checkKeyWords(text));
}

/** The Summon or Claim the app was closed in, to show again. */
function resumeReveal(kit: PaymentKit | null): { sequence: CorePaymentSequence; kind: RevealKind } | null {
  if (!kit) {
    return null;
  }
  const saved = newestPayment(kit.core, kit.store, ['summon', 'claim']);
  if (!saved || isFinal(statusOfStep(saved.step()))) {
    return null;
  }
  const details = decodeDetails(saved.record().intent.details);
  return { sequence: saved, kind: details?.kind === 'claim' ? 'claim' : 'summon' };
}

export default function SummonScreen() {
  const router = useRouter();
  const { nodeUrl } = useSettings();
  const [address] = useState(accountZeroAddress);
  const kit = useMemo(() => paymentKit(nodeUrl), [nodeUrl]);
  const [keyText, setKeyText] = useState('');
  const [lookup, setLookup] = useState<KeyLookup | null>(null);
  const [claimText, setClaimText] = useState('');
  const [claiming, setClaiming] = useState(false);
  const [resumed] = useState(() => resumeReveal(kit));
  const [sequence, setSequence] = useState<CorePaymentSequence | null>(resumed?.sequence ?? null);
  const [kind, setKind] = useState<RevealKind>(resumed?.kind ?? 'summon');
  const [proving, setProving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const rule = keyFieldRule(keyText, checkWords);
  const typedKey = rule.accept ? normaliseKeyText(keyText) : null;
  const rebuild = useMemo(
    () => (kit && sequence && typedKey && address ? proveRevealAgain(kit, sequence, typedKey, address) : null),
    [kit, sequence, typedKey, address],
  );
  const payment = usePayment(kit, sequence, rebuild, true);

  const claimWei = parseGhostAmount(claimText);
  const most = lookup ? BigInt(lookup.amountWei) - BigInt(lookup.feeWei) : 0n;
  const canReveal = lookup?.status === 'found' && most > 0n && (!claiming || (claimWei !== null && claimWei <= most));

  async function find() {
    if (!kit || !typedKey) {
      return;
    }
    setError(null);
    setLookup(null);
    try {
      setLookup(await lookUpKey(kit, typedKey));
    } catch (failure) {
      setError(failure instanceof Error ? `The coins could not be looked up: ${failure.message}` : 'The coins could not be looked up.');
    }
  }

  function reveal() {
    if (!kit || !typedKey || !address || !canReveal) {
      return;
    }
    const out = claiming ? claimWei : null;
    setKind(out === null ? 'summon' : 'claim');
    setProving(true);
    setError(null);
    // Let the screen show "Proving on this phone" before the proof starts.
    setTimeout(() => {
      startReveal(kit, typedKey, address, out).then(
        (started) => {
          setProving(false);
          setSequence(started);
        },
        (failure) => {
          setProving(false);
          setError(failure instanceof Error ? `The coins could not be summoned: ${failure.message}` : 'The coins could not be summoned.');
        },
      );
    }, 50);
  }

  const unavailable = !kit || !address;
  const status = proving ? 'proving' : payment?.status;
  const keyNeeded = payment?.needsKey && !typedKey;

  return (
    <Screen
      testID="summon-screen"
      wide="columns"
      topBar={
        <>
          <IconButton icon="back" label="Back" onPress={() => router.back()} testID="back" />
          <Spacer />
          <NetworkBadge />
          <Logo />
        </>
      }
    >
      <Column>
        <Title>Summon</Title>
        {!sequence || keyNeeded ? (
          <>
            <Text style={textStyles.body}>
              {keyNeeded
                ? 'The fee changed while the app was closed. Type the Phantom Key again to make a new proof.'
                : 'Type or paste a Phantom Key: 24 words, or its digits. Its coins come back to your account.'}
            </Text>
            <Panel style={styles.form}>
              <Text style={textStyles.quiet}>Phantom Key</Text>
              <WordField
                accessibilityLabel="Phantom Key"
                multiline
                onChangeText={(text) => {
                  setKeyText(text);
                  setLookup(null);
                }}
                placeholder="24 words"
                style={styles.keyField}
                testID="summon-key"
                value={keyText}
                invalid={rule.message !== null}
              />
            </Panel>
            {rule.message ? (
              <Text accessibilityLiveRegion="polite" style={[textStyles.body, styles.error]} testID="summon-key-error">
                {rule.message}
              </Text>
            ) : null}
            {!sequence ? (
              <Button label="Find its coins" disabled={!rule.accept || unavailable} onPress={() => void find()} testID="summon-find" />
            ) : null}
          </>
        ) : null}
        {error ? (
          <Text accessibilityLiveRegion="polite" style={[textStyles.body, styles.error]} testID="summon-error">
            {error}
          </Text>
        ) : null}
        {unavailable ? (
          <Text style={textStyles.quiet} testID="summon-unavailable">
            Summon is not available in this build.
          </Text>
        ) : null}
      </Column>
      <Column>
        {status ? (
          <>
            <PaymentProgress status={status} kind={kind} step={payment?.step} error={payment?.error} />
            {status === 'settled' ? <CoinsBack text="The coins are back in your account." /> : null}
            {status !== 'proving' ? (
              <Button label="Done" secondary onPress={() => router.back()} testID="summon-done" />
            ) : null}
          </>
        ) : lookup ? (
          <Panel style={styles.form} testID="summon-lookup">
            {lookup.status === 'found' ? (
              <>
                <Text style={textStyles.quiet}>This key holds</Text>
                <Text style={styles.amount} testID="summon-amount">
                  {formatGhost(lookup.amountWei)} GHOST
                </Text>
                <Text style={textStyles.quiet}>Fee {formatGhost(lookup.feeWei)} GHOST</Text>
                <ButtonRow>
                  <Button label="All" secondary={claiming} onPress={() => setClaiming(false)} testID="summon-all" />
                  <Button label="Part" secondary={!claiming} onPress={() => setClaiming(true)} testID="summon-part" />
                </ButtonRow>
                {claiming ? (
                  <View style={styles.amountRow}>
                    <TextInput
                      accessibilityLabel="Amount to claim in GHOST"
                      keyboardType="decimal-pad"
                      onChangeText={setClaimText}
                      placeholder="0.0"
                      placeholderTextColor={colors.quiet}
                      style={styles.claim}
                      testID="summon-claim-amount"
                      value={claimText}
                    />
                    <Text style={textStyles.body}>GHOST</Text>
                  </View>
                ) : null}
                <Button
                  label={claiming ? 'Claim' : `Summon ${formatGhost(most > 0n ? most : 0n)} GHOST`}
                  disabled={!canReveal}
                  onPress={reveal}
                  testID="summon-reveal"
                />
              </>
            ) : (
              <Text style={textStyles.body} testID="summon-lookup-message">
                {lookupMessage(lookup.status)}
              </Text>
            )}
          </Panel>
        ) : (
          <Panel style={styles.form}>
            <Text style={textStyles.quiet}>How it works</Text>
            <Text style={textStyles.body}>
              The proof is made on this phone; the key never leaves it and is not kept. Recovery words never go here:
              a Phantom Key holds coins, not your wallet.
            </Text>
          </Panel>
        )}
      </Column>
    </Screen>
  );
}

const styles = StyleSheet.create({
  form: {
    gap: 8,
    padding: 16,
  },
  keyField: {
    minHeight: 120,
    textAlignVertical: 'top',
  },
  amount: {
    color: colors.ink,
    fontFamily: monoFont,
    fontSize: 28,
  },
  amountRow: {
    flexDirection: 'row',
    alignItems: 'baseline',
    gap: 8,
  },
  claim: {
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
