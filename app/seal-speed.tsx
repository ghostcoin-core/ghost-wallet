// Speed test: a Check of a Ghost Sealed card through the Seal relay, timed
// round trip by round trip. A bare test screen at /seal-speed, like the
// bench, not product UI. Runs are kept in memory only.
import { useState } from 'react';
import { Pressable, ScrollView, StyleSheet, Text, TextInput, View } from 'react-native';

import { checkWithSeal, type SealCheck } from '../modules/ghost-nfc/relay';

/** The target for a whole Check, over Wi-Fi and over mobile data. */
export const TARGET_MS = 2000;
/** How many runs the screen keeps. */
export const KEPT_RUNS = 20;

type Run = { number: number; check: SealCheck } | { number: number; error: string };

function ms(value: number): string {
  return `${Math.round(value)} ms`;
}

function total(check: SealCheck, kind: 'card' | 'seal'): string {
  const rounds = check.rounds.filter((round) => round.kind === kind);
  return `${rounds.length}, ${ms(rounds.reduce((sum, round) => sum + round.ms, 0))}`;
}

/** A Check's timings as plain text lines. */
export function describeCheck(check: SealCheck): string {
  return [
    `total: ${ms(check.totalMs)} (${check.totalMs <= TARGET_MS ? 'within' : 'over'} the 2 s target)`,
    `card ${check.uid}: ${check.state}, ${check.amountWei.toString()} wei`,
    `card round trips: ${total(check, 'card')}`,
    `Seal round trips: ${total(check, 'seal')}`,
    ...check.rounds.map((round, i) => `${i + 1}. ${round.kind === 'card' ? 'card' : 'Seal'}: ${ms(round.ms)}`),
  ].join('\n');
}

function summary(run: Run): string {
  return 'check' in run
    ? `run ${run.number}: ${ms(run.check.totalMs)}, ${run.check.state}`
    : `run ${run.number}: error (${run.error})`;
}

export default function SealSpeedScreen() {
  const [address, setAddress] = useState('');
  const [running, setRunning] = useState(false);
  const [runs, setRuns] = useState<Run[]>([]);
  const [count, setCount] = useState(0);

  const ready = address.trim().length > 0 && !running;
  const last = runs[0];

  async function run() {
    if (!ready) {
      return;
    }
    const number = count + 1;
    setCount(number);
    setRunning(true);
    let next: Run;
    try {
      next = { number, check: await checkWithSeal(address) };
    } catch (error) {
      next = { number, error: error instanceof Error ? error.message : String(error) };
    }
    setRuns((kept) => [next, ...kept].slice(0, KEPT_RUNS));
    setRunning(false);
  }

  return (
    <ScrollView style={styles.page} contentContainerStyle={styles.content} testID="seal-speed-screen">
      <Text accessibilityRole="header" style={styles.title}>
        Seal speed
      </Text>
      <Text style={styles.note} testID="seal-speed-note">
        Times a Check through the Seal relay: authenticate, read the record, signed answer. Fill is not on the relay
        yet, so this times Check only. Target: {TARGET_MS / 1000} s or less.
      </Text>
      <TextInput
        accessibilityLabel="Seal address"
        autoCapitalize="none"
        autoCorrect={false}
        editable={!running}
        keyboardType="url"
        onChangeText={setAddress}
        placeholder="https://seal.example:8443"
        placeholderTextColor="#6A6A7A"
        style={styles.input}
        testID="seal-speed-url"
        value={address}
      />
      <Pressable
        accessibilityRole="button"
        accessibilityState={{ disabled: !ready }}
        disabled={!ready}
        onPress={run}
        style={styles.run}
        testID="seal-speed-run"
      >
        <Text style={styles.text}>{running ? 'Checking…' : 'Run a Check'}</Text>
      </Pressable>
      <Text selectable style={styles.result} testID="seal-speed-result">
        {last === undefined
          ? 'No run yet'
          : 'check' in last
            ? describeCheck(last.check)
            : `error: ${last.error}`}
      </Text>
      <View style={styles.runs}>
        <Text style={styles.text}>Last {KEPT_RUNS} runs (this session only)</Text>
        <Text selectable style={styles.result} testID="seal-speed-runs">
          {runs.length === 0 ? 'none' : runs.map(summary).join('\n')}
        </Text>
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  page: {
    flex: 1,
    backgroundColor: '#0A0A12',
  },
  content: {
    padding: 24,
    paddingTop: 64,
  },
  title: {
    color: '#FFFFFF',
    fontSize: 24,
    fontWeight: '700',
  },
  note: {
    marginTop: 12,
    color: '#C8C8D8',
    fontSize: 14,
  },
  input: {
    marginTop: 16,
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderWidth: 1,
    borderColor: '#3A3A4A',
    color: '#FFFFFF',
    fontFamily: 'Menlo',
    fontSize: 14,
  },
  run: {
    marginTop: 16,
    paddingVertical: 12,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#FFFFFF',
  },
  text: {
    color: '#FFFFFF',
    fontSize: 16,
  },
  result: {
    marginTop: 16,
    color: '#C8C8D8',
    fontFamily: 'Menlo',
    fontSize: 13,
  },
  runs: {
    marginTop: 24,
  },
});
