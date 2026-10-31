// Vanish: an amount from the account goes into a fresh Phantom Key. As in
// Ghost's web app, the key is written down before anything is sent: the core
// makes the key, its 24 words show once (on ink, labelled as a key, never
// copied or saved to photos), three of them are typed back, the core drops
// the key, and only then is the Vanish signed (ML-DSA-44) and sent. The
// payment is saved at every step, so it survives the app being killed.
// The person may tick "Skip the check" instead of typing the words (unticked
// every time); the core then drops the key unchecked. Once the words were
// shown the key can also be put on a blank NTAG 424 card before the core
// drops it, with no word check: the card is never the only copy.
// Done shows only once the Vanish is settled or failed; until then the person
// may leave, and Home lists it as pending. Leaving before the key is written
// down (or on its card) keeps the key: opening the Vanish again returns there.
import { useRouter } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { StyleSheet, Text, TextInput, View } from 'react-native';

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
  TextButton,
  textStyles,
  Title,
} from '../components/ui';
import { SkipCheckBox } from '../components/skip-check';
import { PaymentExit, PaymentProgress, PhantomKeyWords } from '../components/vanish-ui';
import { WordField } from '../components/word-field';
import { accountZeroAddress } from '../lib/account';
import { formatGhost } from '../lib/home/balance-format';
import { useHome } from '../lib/home/use-home';
import { useLayout } from '../lib/layout';
import { failureReason } from '../lib/node/failure-reason';
import { pickCheckPositions } from '../lib/onboarding/word-check';
import { amountMessage } from '../lib/send/validation';
import { useSettings } from '../lib/settings/settings';
import { minimumVanish, signVanishAgain, startVanish, vanishFee } from '../lib/vanish/actions';
import { coversVanish, parseGhostAmount } from '../lib/vanish/amount';
import {
  forgetShared,
  heldKey,
  heldVanish,
  holdVanish,
  newestShared,
  openShared,
  paymentAmountWei,
  releaseHeldVanish,
  shared,
  stoppedVanish,
  takeReopened,
  type HeldVanish,
} from '../lib/vanish/pending';
import { isFinal, statusOfStep, stepName } from '../lib/vanish/status-mapping';
import { paymentKit, usePayment, type PaymentKit } from '../lib/vanish/use-payment';
import type { CorePaymentSequence } from '../modules/ghost-core';
import { CardCancelled, cardsSupported, putPhantomKeyOnCard } from '../modules/ghost-nfc';

function isPrepared(sequence: CorePaymentSequence | null): boolean {
  return sequence !== null && stepName(sequence.step()) === 'Prepared';
}

/**
 * The Vanish to show again: the one Home asked for, or the newest. One left
 * while the core still holds its new key returns to the step it was at (the
 * words, the check or the card). One still waiting for its key after the
 * app was closed cannot go on (the key was never saved) and nothing of it
 * was signed: it is dropped. A key no Vanish waits for is forgotten.
 */
function resumeVanish(kit: PaymentKit | null): { sequence: CorePaymentSequence; held: HeldVanish | null } | null {
  if (!kit) {
    return null;
  }
  const holding = heldKey();
  if (!holding || !isPrepared(openShared(kit, holding.id))) {
    releaseHeldVanish();
    kit.core.forgetPhantomKey();
  }
  const wanted = takeReopened(['vanish']);
  const saved = wanted ? openShared(kit, wanted) : newestShared(kit, ['vanish']);
  if (!saved) {
    return null;
  }
  const id = saved.record().id;
  if (isPrepared(saved)) {
    const held = heldVanish(id);
    if (held) {
      return { sequence: saved, held };
    }
    kit.store.remove(id);
    forgetShared(id);
    return null;
  }
  return wanted || !isFinal(statusOfStep(saved.step())) ? { sequence: saved, held: null } : null;
}

type Phase =
  | { name: 'amount' }
  | { name: 'save'; words: string[] }
  | { name: 'check'; words: string[]; positions: number[] }
  /** `checked`: the three words were typed back before the card. */
  | { name: 'card'; checked: boolean; positions: number[] | null }
  | { name: 'sending' };

function resumedPhase(resumed: ReturnType<typeof resumeVanish>): Phase {
  if (!resumed) {
    return { name: 'amount' };
  }
  const { held } = resumed;
  switch (held?.step) {
    case 'save':
      return { name: 'save', words: held.words };
    case 'check':
      return { name: 'check', words: held.words, positions: held.positions ?? pickCheckPositions() };
    case 'card':
      return { name: 'card', checked: held.checked === true, positions: held.positions };
    default:
      return { name: 'sending' };
  }
}

export default function VanishScreen() {
  const router = useRouter();
  const { twoColumns } = useLayout();
  const { nodeUrl } = useSettings();
  const [address] = useState(accountZeroAddress);
  const kit = useMemo(() => paymentKit(nodeUrl), [nodeUrl]);
  const [resumed] = useState(() => resumeVanish(kit));
  const [phase, setPhase] = useState<Phase>(() => resumedPhase(resumed));
  const [sequence, setSequence] = useState<CorePaymentSequence | null>(resumed?.sequence ?? null);
  const [amountText, setAmountText] = useState('');
  const [minimum, setMinimum] = useState<bigint | null>(null);
  const [fee, setFee] = useState<bigint | null>(null);
  // The balance Send checks against: Home's snapshot, null while not known.
  const { view: home } = useHome(nodeUrl, address);
  const [typed, setTyped] = useState<Record<number, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [cards] = useState(cardsSupported);
  const [writing, setWriting] = useState(false);
  // Never remembered: every check starts unticked.
  const [skip, setSkip] = useState(false);

  useEffect(() => {
    if (!kit) {
      return;
    }
    minimumVanish(kit).then(setMinimum, (failure) => {
      setMinimum(null);
      setError(failureReason(failure, kit.nodeUrl));
    });
    // Not known yet, the amount is checked against the balance alone, as on Send.
    vanishFee(kit).then(setFee, () => setFee(null));
  }, [kit]);

  const rebuild = useMemo(() => (kit && sequence ? signVanishAgain(kit, sequence) : null), [kit, sequence]);
  const payment = usePayment(kit, phase.name === 'sending' ? sequence : null, rebuild, false);

  const amount = parseGhostAmount(amountText);
  const tooSmall = amount !== null && minimum !== null && amount < minimum;
  const balance = home.snapshot ? BigInt(home.snapshot.balanceWei) : null;
  const tooMuch = amount !== null && !coversVanish(amount, balance, fee);
  // A Vanish opened again has no amount typed: its saved one is shown.
  const vanishAmount = amount ?? (sequence ? paymentAmountWei(sequence) : null);

  /**
   * Moves to a step before the key is dropped, and keeps which one it is, so
   * leaving now and opening the Vanish again comes back to it.
   */
  function keyStep(next: Extract<Phase, { name: 'save' | 'check' | 'card' }>, of: CorePaymentSequence | null = sequence) {
    setPhase(next);
    setSkip(false);
    if (!of) {
      return;
    }
    const id = of.record().id;
    if (next.name === 'save') {
      holdVanish({ id, step: 'save', words: next.words, positions: null });
    } else if (next.name === 'check') {
      holdVanish({ id, step: 'check', words: next.words, positions: next.positions });
    } else {
      // The words were shown: the card step needs only the key the core holds.
      holdVanish({ id, step: 'card', words: [], positions: next.positions, checked: next.checked });
    }
  }

  async function makeKey() {
    if (!kit || !address || amount === null || tooSmall || tooMuch) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const started = await startVanish(kit, address, amount);
      const made = shared(started.sequence);
      setSequence(made);
      keyStep({ name: 'save', words: started.words }, made);
    } catch (failure) {
      setError(`The Vanish could not start. ${failureReason(failure, nodeUrl)}`);
    } finally {
      setBusy(false);
    }
  }

  /** Whether the three typed words match the key; says which do not. */
  function wordsMatch(): boolean {
    if (!kit || phase.name !== 'check') {
      return false;
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
      return false;
    }
    return true;
  }

  function confirm() {
    if (!kit || !sequence || phase.name !== 'check') {
      return;
    }
    if (skip) {
      // The person chose to skip: the core drops the key with no word typed back.
      send(true);
      return;
    }
    if (wordsMatch()) {
      send();
    }
  }

  /**
   * Drops the key in the core and sends the Vanish. `unchecked` only when the
   * person ticked "Skip the check".
   */
  function send(unchecked = false) {
    if (!kit || !sequence) {
      return;
    }
    try {
      if (unchecked) {
        kit.core.confirmPhantomKeySavedUnchecked();
      } else {
        kit.core.confirmPhantomKeySaved();
      }
      sequence.markBackedUp();
    } catch {
      setError('The Vanish could not be saved. Nothing was sent.');
      return;
    }
    releaseHeldVanish();
    setTyped({});
    setError(null);
    // The words leave the screen's memory here.
    setPhase({ name: 'sending' });
  }

  /**
   * Writes the key the core still holds to a blank card, then sends. A card
   * needs no word check; words typed in full are still checked, so a mistake
   * on the paper is caught.
   */
  function putOnCard() {
    if (!kit || !sequence || phase.name !== 'check') {
      return;
    }
    const typedAll = phase.positions.every((position) => (typed[position] ?? '').trim() !== '');
    const checked = !skip && typedAll;
    if (checked && !wordsMatch()) {
      return;
    }
    setTyped({});
    keyStep({ name: 'card', checked, positions: phase.positions });
    void writeCard();
  }

  /** After a card was not written: sends if the words were checked, or goes back to the check. */
  function vanishWithoutCard() {
    if (phase.name !== 'card') {
      return;
    }
    if (phase.checked) {
      send();
      return;
    }
    setError(null);
    // The words left the screen at the card step: the check goes on without them.
    keyStep({ name: 'check', words: [], positions: phase.positions ?? pickCheckPositions() });
  }

  async function writeCard() {
    setWriting(true);
    setError(null);
    try {
      await putPhantomKeyOnCard();
    } catch (failure) {
      setError(
        failure instanceof CardCancelled
          ? 'No card was written. Try again, or Vanish without a card: your key words still work.'
          : failure instanceof Error
            ? failure.message
            : 'The card could not be written.',
      );
      return;
    } finally {
      setWriting(false);
    }
    send();
  }

  /** Drops a Vanish not signed yet, with its key. Leaving (Back) keeps both. */
  function cancel() {
    if (kit && sequence && isPrepared(sequence)) {
      const id = sequence.record().id;
      kit.core.forgetPhantomKey();
      kit.store.remove(id);
      forgetShared(id);
      releaseHeldVanish();
    }
    router.back();
  }

  /** Drops a Vanish held stopped for lack of funds: nothing of it landed, and it is never sent. */
  function cancelStopped() {
    if (kit && sequence && stoppedVanish(sequence.record().id) !== null) {
      const id = sequence.record().id;
      kit.store.remove(id);
      forgetShared(id);
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
          <IconButton icon="back" label="Back" onPress={() => router.back()} testID="back" />
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
              {tooMuch ? (
                <Text style={[textStyles.body, styles.error]} testID="vanish-not-enough">
                  {amountMessage('not-enough', balance)}
                </Text>
              ) : null}
            </Panel>
            <Button
              label="Make a Phantom Key"
              icon="key"
              disabled={unavailable || busy || amount === null || tooSmall || tooMuch}
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
              onPress={() => keyStep({ name: 'check', words: phase.words, positions: pickCheckPositions() })}
              testID="vanish-saved"
            />
            <TextButton label="Cancel the Vanish" onPress={cancel} testID="vanish-cancel" />
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
            <SkipCheckBox
              checked={skip}
              onChange={(checked) => {
                setSkip(checked);
                setError(null);
              }}
              testID="vanish-skip-check"
            />
            <Button
              label={vanishAmount !== null ? `Vanish ${formatGhost(vanishAmount)} GHOST` : 'Vanish'}
              disabled={!skip && phase.positions.some((position) => (typed[position] ?? '').trim() === '')}
              onPress={confirm}
              testID="vanish-send"
            />
            {cards ? (
              <Button label="Put on a card, then Vanish" icon="key" secondary onPress={putOnCard} testID="vanish-card" />
            ) : null}
            {phase.words.length > 0 ? (
              <Button
                label="Show the key again"
                secondary
                onPress={() => keyStep({ name: 'save', words: phase.words })}
                testID="vanish-show-again"
              />
            ) : null}
            <TextButton label="Cancel the Vanish" onPress={cancel} testID="vanish-cancel" />
          </>
        ) : null}
        {phase.name === 'card' ? (
          <>
            <Text style={textStyles.body} testID="vanish-card-hold">
              {writing
                ? 'Hold a blank NTAG 424 DNA card near the top of the iPhone until it says the key is on the card.'
                : 'The card was not written. Nothing has been sent yet.'}
            </Text>
            {!writing ? (
              <ButtonRow>
                <Button label="Try the card again" icon="key" onPress={() => void writeCard()} testID="vanish-card-retry" />
                <Button
                  label={vanishAmount !== null ? `Vanish ${formatGhost(vanishAmount)} GHOST` : 'Vanish'}
                  secondary
                  onPress={vanishWithoutCard}
                  testID="vanish-without-card"
                />
              </ButtonRow>
            ) : null}
            {!writing ? <TextButton label="Cancel the Vanish" onPress={cancel} testID="vanish-cancel" /> : null}
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
          <PaymentProgress
            status={payment.status}
            kind="vanish"
            step={payment.step}
            error={payment.stopped ? null : payment.error}
          />
        ) : (
          <Panel style={styles.form}>
            <Text style={textStyles.quiet}>How it works</Text>
            <Text style={textStyles.body}>
              The key is made on this phone and shown once. The Vanish is signed with your account and sent only after
              you have checked three of its words, or chosen to skip the check. Summon it back any time by typing the
              key.
            </Text>
            {cards ? (
              <Text style={textStyles.quiet} testID="vanish-card-note">
                A blank NTAG 424 DNA card can hold the key too. The card must pass NXP&apos;s genuineness check, gets
                its own random keys kept in this iPhone&apos;s Keychain, and can be read only on this iPhone. The words
                stay your backup.
              </Text>
            ) : null}
          </Panel>
        )}
        {phase.name === 'sending' && payment?.stopped ? (
          <>
            <Text accessibilityLiveRegion="polite" style={[textStyles.body, styles.error]} testID="vanish-stopped">
              {payment.error} This Vanish is stopped and will not be sent. Cancel it; the Phantom Key you wrote down
              holds nothing.
            </Text>
            <Button label="Cancel the Vanish" onPress={cancelStopped} testID="vanish-stopped-cancel" />
            <TextButton label="Leave" onPress={() => router.back()} testID="vanish-leave" />
          </>
        ) : phase.name === 'sending' ? (
          <PaymentExit final={payment ? isFinal(payment.status) : false} onLeave={() => router.back()} testPrefix="vanish" />
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
