// Speed test of a Java Card over NFC: taps the probe applet
// (tools/card-probe) and shows each step's time, whether every answer was
// right, whether answers longer than 256 bytes got through, and the Make,
// Check and Open estimates. A bare test screen at /card-probe, opened from
// the bench, not product UI. Runs are kept in memory only.
import { useState } from 'react';
import { Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';

import { describeProbe, probeCardOverNfc, ProbeCancelled, PROBE_AID, type ProbeReport } from '../modules/ghost-nfc/card-probe';

/** How many runs the screen keeps. */
export const KEPT_RUNS = 10;

type Run = { number: number; report: ProbeReport } | { number: number; error: string };

function summary(run: Run): string {
  if (!('report' in run)) {
    return `run ${run.number}: error (${run.error})`;
  }
  const r = run.report;
  const k = Number.isFinite(r.keccakFastMs) ? `Keccak ${Math.round(r.keccakFastMs)} ms` : 'Keccak not measured';
  return `run ${run.number}: ${k}, ${r.problems.length === 0 ? 'every step ran' : `${r.problems.length} problem(s)`}`;
}

export default function CardProbeScreen() {
  const [running, setRunning] = useState(false);
  const [step, setStep] = useState<string | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [count, setCount] = useState(0);
  const last = runs[0];

  async function run() {
    if (running) {
      return;
    }
    const number = count + 1;
    setCount(number);
    setRunning(true);
    setStep(null);
    let next: Run | null;
    try {
      next = { number, report: await probeCardOverNfc(setStep) };
    } catch (error) {
      next = error instanceof ProbeCancelled ? null : { number, error: error instanceof Error ? error.message : String(error) };
    }
    if (next) {
      const kept = next;
      setRuns((previous) => [kept, ...previous].slice(0, KEPT_RUNS));
    }
    setStep(null);
    setRunning(false);
  }

  return (
    <ScrollView style={styles.page} contentContainerStyle={styles.content} testID="card-probe-screen">
      <Text accessibilityRole="header" style={styles.title}>
        Card probe
      </Text>
      <Text style={styles.note} testID="card-probe-note">
        Times the Java Card probe applet ({PROBE_AID}) over NFC. The probe must be installed on the card. Tap Run, hold
        the card flat on the top of the iPhone and keep it still for about 20 seconds.
      </Text>
      <Pressable
        accessibilityRole="button"
        accessibilityState={{ disabled: running }}
        disabled={running}
        onPress={run}
        style={styles.run}
        testID="card-probe-run"
      >
        <Text style={styles.text}>{running ? (step ?? 'Waiting for the card…') : 'Run'}</Text>
      </Pressable>
      <Text selectable style={styles.result} testID="card-probe-result">
        {last === undefined ? 'No run yet' : 'report' in last ? describeProbe(last.report) : `error: ${last.error}`}
      </Text>
      <View style={styles.runs}>
        <Text style={styles.text}>Last {KEPT_RUNS} runs (this session only)</Text>
        <Text selectable style={styles.result} testID="card-probe-runs">
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
