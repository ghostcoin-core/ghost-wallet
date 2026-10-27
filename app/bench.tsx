// Feasibility harness: pick a native benchmark, run it, read the last result.
// A bare test screen at /bench, not product UI.
import { useState } from 'react';
import { Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';

import { listBenchmarks, runBenchmark, type BenchRecord } from '../modules/ghost-bench';

const MIB = 1024 * 1024;

function mib(bytes: number): string {
  return `${(bytes / MIB).toFixed(1)} MiB`;
}

function yesNo(value: boolean): string {
  return value ? 'yes' : 'no';
}

/** The record as plain text lines, in the order the table prints them. */
export function describeRecord(record: BenchRecord): string {
  const { battery, device, memory, thermal } = record;
  const drop = battery.drop === undefined ? 'unknown' : `${(battery.drop * 100).toFixed(1)}%`;
  return [
    `${record.benchmark}: ${record.status}${record.error ? ` (${record.error})` : ''}`,
    `${device.model}, ${device.systemName} ${device.systemVersion}`,
    ...record.stages.map((stage) => `${stage.name}: ${stage.seconds.toFixed(2)} s`),
    `total: ${record.totalSeconds.toFixed(2)} s`,
    `peak resident: ${mib(memory.peakResidentBytes)}`,
    `peak footprint: ${mib(memory.peakFootprintBytes)}`,
    `least available: ${mib(memory.minAvailableBytes)}`,
    `memory warning: ${yesNo(memory.warning)}`,
    `killed: ${yesNo(memory.killed)}`,
    `thermal: start ${thermal.start}, end ${thermal.end}, worst ${thermal.worst}`,
    `battery drop: ${drop}`,
  ].join('\n');
}

function availableBenchmarks(): string[] | null {
  try {
    return listBenchmarks();
  } catch {
    return null;
  }
}

export default function BenchScreen() {
  const [names] = useState(availableBenchmarks);
  const [selected, setSelected] = useState<string | null>(() => names?.[0] ?? null);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  async function run() {
    if (!selected || running) {
      return;
    }
    setRunning(true);
    setResult(null);
    try {
      setResult(describeRecord(await runBenchmark(selected)));
    } catch (error) {
      setResult(`${selected}: error (${error instanceof Error ? error.message : String(error)})`);
    } finally {
      setRunning(false);
    }
  }

  return (
    <ScrollView style={styles.page} contentContainerStyle={styles.content} testID="bench-screen">
      <Text accessibilityRole="header" style={styles.title}>
        Bench
      </Text>
      {names === null ? (
        <Text style={styles.text}>Benchmarks unavailable in this build</Text>
      ) : (
        <View style={styles.names}>
          {names.map((name) => (
            <Pressable
              key={name}
              accessibilityRole="radio"
              accessibilityState={{ selected: name === selected, disabled: running }}
              disabled={running}
              onPress={() => setSelected(name)}
              style={[styles.name, name === selected && styles.nameSelected]}
              testID={`bench-name-${name}`}
            >
              <Text style={styles.text}>{name}</Text>
            </Pressable>
          ))}
        </View>
      )}
      <Pressable
        accessibilityRole="button"
        accessibilityState={{ disabled: running || !selected }}
        disabled={running || !selected}
        onPress={run}
        style={styles.run}
        testID="bench-run"
      >
        <Text style={styles.text}>{running ? 'Running…' : 'Run'}</Text>
      </Pressable>
      <Text selectable style={styles.result} testID="bench-result">
        {result ?? 'No result yet'}
      </Text>
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
  names: {
    marginTop: 16,
  },
  name: {
    paddingVertical: 8,
    paddingHorizontal: 12,
    borderWidth: 1,
    borderColor: '#3A3A4A',
    marginBottom: 8,
  },
  nameSelected: {
    borderColor: '#FFFFFF',
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
    marginTop: 24,
    color: '#C8C8D8',
    fontFamily: 'Menlo',
    fontSize: 13,
  },
});
