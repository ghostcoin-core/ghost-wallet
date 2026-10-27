// The feasibility harness, as the app sees it.
//
// Benchmarks are native functions registered by name in
// ios/BenchmarkRegistry.swift. Running one records its stage times, peak
// memory, memory warnings, heat and battery drop, and appends that record to
// bench-results.json in the app's Documents folder (scripts/pull-results.sh
// copies it off the phone).
import { requireNativeModule } from 'expo';

export type ThermalState = 'nominal' | 'fair' | 'serious' | 'critical' | 'unknown';

export type BenchStage = {
  name: string;
  seconds: number;
};

export type BenchRecord = {
  status: 'ok' | 'failed' | 'killed';
  error?: string;
  benchmark: string;
  startedAt: string;
  device: {
    model: string;
    systemName: string;
    systemVersion: string;
    lowPowerMode: boolean;
  };
  stages: BenchStage[];
  totalSeconds: number;
  memory: {
    peakResidentBytes: number;
    peakFootprintBytes: number;
    minAvailableBytes: number;
    warning: boolean;
    killed: boolean;
  };
  thermal: {
    start: ThermalState;
    end: ThermalState;
    worst: ThermalState;
  };
  battery: {
    startLevel?: number;
    endLevel?: number;
    drop?: number;
    state: string;
  };
  notes: Record<string, string>;
};

type GhostBenchNative = {
  listBenchmarks(): string[];
  resultsPath(): string;
  runBenchmark(name: string): Promise<BenchRecord>;
};

function native(): GhostBenchNative {
  // Looked up lazily so that a build without the module fails here, not at import.
  return requireNativeModule<GhostBenchNative>('GhostBench');
}

/** Names of the registered native benchmarks, sorted. */
export function listBenchmarks(): string[] {
  return native().listBenchmarks();
}

/** Path of bench-results.json on the phone. */
export function resultsPath(): string {
  return native().resultsPath();
}

/** Runs the named benchmark and resolves with the record it appended. */
export function runBenchmark(name: string): Promise<BenchRecord> {
  return native().runBenchmark(name);
}
