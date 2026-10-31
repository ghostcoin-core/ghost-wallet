// Summon / Claim: the person types a Phantom Key's 24 words (or its digits).
// The field refuses recovery words; the native core finds the key's coin in
// the coin tree this phone rebuilt from the test chain, proves the reveal here
// on the phone and sends it to the account. Summon brings the whole coin back,
// less the fee; Claim brings part of it, and the rest stays with the key. A
// key this phone cannot find shows as not found yet, never as zero. Or the
// person taps a card this iPhone wrote: the card's key goes straight to the
// native core, and the same lookup and proof run on it there. While the lookup
// runs the screen says so, notes when it is slow, and offers Try again if it
// fails. If the spent markers hint, unchecked, that the coins may be summoned
// already, the screen says so quietly but still offers Summon. Once the payment is in a block the coins show as in the account and
// Done shows; settling goes on and Activity shows Settled later. Before that
// the person may leave, and Home lists it as pending.
import { useRouter } from 'expo-router';
import { useEffect, useMemo, useRef, useState } from 'react';
import { StyleSheet, Text, TextInput, View } from 'react-native';

import { colors, monoFont } from '../components/theme';
import { Button, ButtonRow, Column, IconButton, Logo, NetworkBadge, Panel, Screen, Spacer, textStyles, Title } from '../components/ui';
import { CoinsBack, KeyLookupProgress, PaymentExit, PaymentProgress } from '../components/vanish-ui';
import { WordField } from '../components/word-field';
import { accountZeroAddress } from '../lib/account';
import { formatGhost } from '../lib/home/balance-format';
import { failureReason } from '../lib/node/failure-reason';
import { useSettings } from '../lib/settings/settings';
import { CARD_KEY, lookUpKey, proveRevealAgain, startReveal, type KeyLookup, type KeySource } from '../lib/vanish/actions';
import { parseGhostAmount } from '../lib/vanish/amount';
import type { SpentHint } from '../lib/vanish/coin-pages';
import { keyFieldRule } from '../lib/vanish/field-rules';
import { decodeDetails } from '../lib/vanish/payments';
import { newestShared, openShared, paymentsChanged, shared, takeReopened } from '../lib/vanish/pending';
import { arrivedText, isFinal, lookupMessage, screenDone, statusOfStep, type RevealKind } from '../lib/vanish/status-mapping';
import { paymentKit, usePayment, type PaymentKit } from '../lib/vanish/use-payment';
import { normaliseKeyText, parseWordsCheck } from '../lib/vanish/word-validation';
import { checkKeyWords, type CorePaymentSequence } from '../modules/ghost-core';
import { CardCancelled, cardsSupported, readPhantomKeyFromCard } from '../modules/ghost-nfc';

function checkWords(text: string) {
  return parseWordsCheck(checkKeyWords(text));
}

function forgetCardKey(kit: PaymentKit | null) {
  try {
    kit?.core.forgetCardKey();
  } catch {
    // A core without the card calls holds no card key.
  }
}

/** The Summon or Claim to show again: the one Home asked for, or the newest one still going. */
function resumeReveal(kit: PaymentKit | null): { sequence: CorePaymentSequence; kind: RevealKind } | null {
  if (!kit) {
    return null;
  }
  const wanted = takeReopened(['summon', 'claim']);
  const saved = wanted ? openShared(kit, wanted) : newestShared(kit, ['summon', 'claim']);
  if (!saved || (!wanted && isFinal(statusOfStep(saved.step())))) {
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
  // The key being looked up (or whose lookup failed), and why it failed.
  const [lookingUp, setLookingUp] = useState<KeySource | null>(null);
  const [lookupFailure, setLookupFailure] = useState<string | null>(null);
  const lookupRun = useRef(0);
  const [claimText, setClaimText] = useState('');
  const [claiming, setClaiming] = useState(false);
  const [resumed] = useState(() => resumeReveal(kit));
  const [sequence, setSequence] = useState<CorePaymentSequence | null>(resumed?.sequence ?? null);
  const [kind, setKind] = useState<RevealKind>(resumed?.kind ?? 'summon');
  const [proving, setProving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [cards] = useState(cardsSupported);
  const [fromCard, setFromCard] = useState(false);
  const [tapping, setTapping] = useState(false);

  const rule = keyFieldRule(keyText, checkWords);
  const typedKey = rule.accept ? normaliseKeyText(keyText) : null;
  const key: KeySource | null = fromCard ? CARD_KEY : typedKey;
  const rebuild = useMemo(
    () => (kit && sequence && key && address ? proveRevealAgain(kit, sequence, key, address) : null),
    [kit, sequence, key, address],
  );

  // The card's key leaves the native core with the screen, as a typed key does.
  useEffect(
    () => () => {
      forgetCardKey(kit);
    },
    [kit],
  );
  const payment = usePayment(kit, sequence, rebuild, true);

  // What the spent markers hint about the coins found: unchecked, never waited
  // on, and never a reason to hold Summon or Claim back.
  const spentHint = lookup?.spentHint;
  // Kept with the hint it came from, so a new lookup clears it.
  const [hintRead, setHintRead] = useState<{ from: Promise<SpentHint>; spent: boolean } | null>(null);
  const maybeSpent = spentHint !== undefined && hintRead?.from === spentHint && hintRead.spent;
  useEffect(() => {
    if (!spentHint) {
      return;
    }
    let current = true;
    spentHint.then(
      (hint) => {
        if (current) {
          setHintRead({ from: spentHint, spent: hint.spent === true });
        }
      },
      () => {
        // No hint is no warning.
      },
    );
    return () => {
      current = false;
    };
  }, [spentHint]);

  const claimWei = parseGhostAmount(claimText);
  const most = lookup ? BigInt(lookup.amountWei) - BigInt(lookup.feeWei) : 0n;
  const canReveal = lookup?.status === 'found' && most > 0n && (!claiming || (claimWei !== null && claimWei <= most));

  async function find(source: KeySource | null = key) {
    if (!kit || !source) {
      return;
    }
    const run = ++lookupRun.current;
    setError(null);
    setLookup(null);
    setLookupFailure(null);
    setLookingUp(source);
    try {
      const found = await lookUpKey(kit, source);
      if (run === lookupRun.current) {
        setLookingUp(null);
        setLookup(found);
      }
    } catch (failure) {
      if (run === lookupRun.current) {
        setLookupFailure(`The coins could not be looked up. ${failureReason(failure, kit.nodeUrl)}`);
      }
    }
  }

  /** Drops the lookup shown, and any answer still on its way, when the key changes. */
  function forgetLookup() {
    lookupRun.current += 1;
    setLookingUp(null);
    setLookupFailure(null);
    setLookup(null);
  }

  /** Reads a card this iPhone wrote into the native core, then looks its key up. */
  async function tapCard() {
    if (!kit) {
      return;
    }
    setTapping(true);
    setError(null);
    forgetLookup();
    try {
      await readPhantomKeyFromCard();
    } catch (failure) {
      if (!(failure instanceof CardCancelled)) {
        setError(failure instanceof Error ? failure.message : 'The card could not be read.');
      }
      return;
    } finally {
      setTapping(false);
    }
    setKeyText('');
    setFromCard(true);
    await find(CARD_KEY);
  }

  function typeKeyInstead() {
    forgetCardKey(kit);
    setFromCard(false);
    forgetLookup();
  }

  function reveal() {
    if (!kit || !key || !address || !canReveal) {
      return;
    }
    const out = claiming ? claimWei : null;
    setKind(out === null ? 'summon' : 'claim');
    setProving(true);
    setError(null);
    // Let the screen show "Proving on this phone" before the proof starts.
    setTimeout(() => {
      startReveal(kit, key, address, out).then(
        (started) => {
          setProving(false);
          setSequence(shared(started));
          paymentsChanged();
        },
        (failure) => {
          // Only a failure before sending, or the node's refusal: a send that
          // timed out comes back above as a payment still sending.
          setProving(false);
          setError(`The coins could not be summoned. ${failureReason(failure, kit.nodeUrl)}`);
        },
      );
    }, 50);
  }

  const unavailable = !kit || !address;
  const status = proving ? 'proving' : payment?.status;
  const arrived = status ? arrivedText(status, kind) : null;
  const keyNeeded = payment?.needsKey && !key;

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
        {(!sequence || keyNeeded) && fromCard ? (
          <Panel style={styles.form} testID="summon-card-key">
            <Text style={textStyles.quiet}>Phantom Key</Text>
            <Text style={textStyles.body}>Read from your card. It stays in this iPhone&apos;s native core, not on screen.</Text>
            {!sequence ? (
              <Button label="Type a key instead" secondary onPress={typeKeyInstead} testID="summon-type-instead" />
            ) : null}
          </Panel>
        ) : null}
        {(!sequence || keyNeeded) && !fromCard ? (
          <>
            <Text style={textStyles.body}>
              {keyNeeded
                ? 'The fee changed while the app was closed. Type the Phantom Key again, or tap its card, to make a new proof.'
                : 'Type or paste a Phantom Key: 24 words, or its digits. Its coins come back to your account.'}
            </Text>
            <Panel style={styles.form}>
              <Text style={textStyles.quiet}>Phantom Key</Text>
              <WordField
                accessibilityLabel="Phantom Key"
                multiline
                onChangeText={(text) => {
                  setKeyText(text);
                  forgetLookup();
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
              <Button label="Find its coins" disabled={!rule.accept || unavailable || (lookingUp !== null && lookupFailure === null)} onPress={() => void find()} testID="summon-find" />
            ) : null}
            {cards ? (
              <Button
                label={tapping ? 'Hold the card near the iPhone' : 'Tap a card'}
                icon="key"
                secondary
                disabled={unavailable || tapping}
                onPress={() => void tapCard()}
                testID="summon-tap-card"
              />
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
            {arrived ? <CoinsBack text={arrived} /> : null}
            <PaymentExit final={screenDone(status)} onLeave={() => router.back()} testPrefix="summon" />
          </>
        ) : lookingUp ? (
          <KeyLookupProgress failure={lookupFailure} onRetry={() => void find(lookingUp)} />
        ) : lookup ? (
          <Panel style={styles.form} testID="summon-lookup">
            {lookup.status === 'found' ? (
              <>
                <Text style={textStyles.quiet}>This key holds</Text>
                <Text style={styles.amount} testID="summon-amount">
                  {formatGhost(lookup.amountWei)} GHOST
                </Text>
                <Text style={textStyles.quiet}>Fee {formatGhost(lookup.feeWei)} GHOST</Text>
                {maybeSpent ? (
                  <Text accessibilityLiveRegion="polite" style={textStyles.quiet} testID="summon-spent-hint">
                    Not checked: these coins may have been summoned already.
                  </Text>
                ) : null}
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
            {cards ? (
              <Text style={textStyles.quiet} testID="summon-card-note">
                A card can be read only on the iPhone that wrote it; its keys are in this iPhone&apos;s Keychain. On
                another phone, type the key&apos;s words instead.
              </Text>
            ) : null}
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
