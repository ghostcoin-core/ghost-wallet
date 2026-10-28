#!/usr/bin/env node
// Turns bench-results.json (written on the phone by modules/ghost-bench) into
// a markdown go/no-go report: for each phone, the latest run of each Phase 0
// benchmark with its key numbers and a verdict judged against the
// user-facing limits (LIMITS).
//
//   node scripts/feasibility-report.js bench-results.json
//   node scripts/feasibility-report.js < bench-results.json
//
// The verdicts are a starting point for docs/feasibility.md
// (scripts/feasibility-doc.js), not the decision.
'use strict';

const fs = require('fs');

const MIB = 1024 * 1024;

/**
 * The user-facing limits. A run that misses any limit that applies to it, or
 * does not record the number a limit needs, doesn't work. Every limit is a
 * real-device limit: a simulator run never passes one.
 */
const LIMITS = {
  /** Balance on screen from the cache (restore note `balanceFromCacheSeconds`). */
  cachedBalanceSeconds: 2,
  /** Restore to the first balance on screen (restore note `timeToFirstBalanceSeconds`). */
  timeToFirstBalanceSeconds: 10,
  /** The slowest Summon proof of a run (summon notes `proveMillis-<n>`). */
  summonProofSeconds: 10,
  /** Worst thermal states that fail any run. */
  failingThermalStates: ['serious', 'critical'],
  /** Thermal states a run may reach and still pass. */
  passingThermalStates: ['nominal', 'fair'],
};

/** Checks in the notes that are not user-facing limits but still fail a run. */
const THRESHOLDS = {
  /**
   * RandomX caches the worst-case stress run held while it proved, when it
   * synced headers: both keys' caches. The app releases the caches before a
   * proof, so this is a stress case, not a requirement.
   */
  worstCaseCaches: 2,
  /**
   * RandomX caches the worst-case stress run holds while it proves now that
   * it spot checks one header (its runs note `spotCheckCacheSeconds`): the
   * spot check's one cache.
   */
  spotCheckWorstCaseCaches: 1,
};

/**
 * The memory iOS lets a foreground app use before jetsam ends it, per
 * hardware model. Starting values of about half the phone's RAM; replace each
 * with a measured one (a real-device run's peakFootprintBytes plus its
 * minAvailableBytes). A model not listed here can't pass the memory limit.
 */
const JETSAM_LIMIT_BYTES = {
  'iPhone13,1': 2048 * MIB, // iPhone 12 mini, 4 GB
  'iPhone13,2': 2048 * MIB, // iPhone 12, 4 GB
  'iPhone13,3': 3072 * MIB, // iPhone 12 Pro, 6 GB
  'iPhone13,4': 3072 * MIB, // iPhone 12 Pro Max, 6 GB
  'iPhone17,1': 4096 * MIB, // iPhone 16 Pro, 8 GB
  'iPhone17,2': 4096 * MIB, // iPhone 16 Pro Max, 8 GB
  'iPhone17,3': 4096 * MIB, // iPhone 16, 8 GB
  'iPhone17,4': 4096 * MIB, // iPhone 16 Plus, 8 GB
};

/** The slowest phone the app must work on. iPhone 12 until it is decided. */
const MINIMUM_PHONE = { name: 'iPhone 12', models: ['iPhone13,2'] };

/** What uname reports as the model inside the iOS simulator. */
const SIMULATOR_MODELS = ['arm64', 'x86_64', 'i386'];

const DEVICE_KINDS = {
  real: 'real device',
  simulator: 'simulator',
  unknown: 'unknown device kind',
};

/** The Phase 0 benchmarks, in report order. */
const BENCHMARKS = ['summon', 'header-sync', 'restore', 'kill-recovery', 'worst-case'];

/**
 * Benchmarks that measure a stress case the app avoids in its normal path:
 * their row is labelled, and a doesn't-work verdict asks for no PLAN change.
 */
const STRESS_LABEL = 'stress benchmark only';
const STRESS_BENCHMARKS = ['worst-case'];

function benchmarkLabel(benchmark) {
  return STRESS_BENCHMARKS.includes(benchmark) ? `${benchmark} (${STRESS_LABEL})` : benchmark;
}

const VERDICTS = {
  works: 'works',
  limits: 'works with limits',
  doesntWork: "doesn't work",
  notRun: 'not run',
};

const COLUMNS = [
  'Benchmark',
  'Run',
  'Device',
  'Status',
  'Peak footprint',
  'Memory warning',
  'Killed',
  'Worst thermal',
  'Key numbers',
  'Verdict',
  'Why',
];

function mib(bytes) {
  return typeof bytes === 'number' ? `${(bytes / MIB).toFixed(1)} MiB` : '-';
}

function yesNo(value) {
  if (value === undefined || value === null) {
    return '-';
  }
  return value ? 'yes' : 'no';
}

function int(text) {
  if (typeof text !== 'string' || !/^-?\d+$/.test(text.trim())) {
    return null;
  }
  return Number(text.trim());
}

/** A non-negative decimal note, or null. */
function decimal(text) {
  if (typeof text !== 'string' || !/^\d+(\.\d+)?$/.test(text.trim())) {
    return null;
  }
  return Number(text.trim());
}

/** The model, iOS version and kind (simulator or real device) of a run. */
function deviceOf(record) {
  const device = record.device || {};
  const model = typeof device.model === 'string' && device.model !== '' ? device.model : null;
  const systemVersion =
    typeof device.systemVersion === 'string' && device.systemVersion !== '' ? device.systemVersion : null;
  let kind = DEVICE_KINDS.unknown;
  if (typeof device.simulator === 'boolean') {
    kind = device.simulator ? DEVICE_KINDS.simulator : DEVICE_KINDS.real;
  } else if (model && SIMULATOR_MODELS.includes(model)) {
    kind = DEVICE_KINDS.simulator;
  } else if (model && /^iPhone\d+,\d+$/.test(model)) {
    kind = DEVICE_KINDS.real;
  }
  return { model, systemVersion, kind };
}

function deviceText(device) {
  return `${device.model || 'unknown model'}, iOS ${device.systemVersion || '-'}, ${device.kind}`;
}

/** Why a run's device can't pass a real-device limit, if it can't. */
function deviceProblems(device) {
  const reasons = [];
  if (!device.model) {
    reasons.push('no device model recorded');
  }
  if (!device.systemVersion) {
    reasons.push('no iOS version recorded');
  }
  if (device.kind === DEVICE_KINDS.simulator) {
    reasons.push("simulator run: can't pass a real-device limit");
  } else if (device.kind === DEVICE_KINDS.unknown) {
    reasons.push('not recorded whether simulator or real device');
  }
  return reasons;
}

/** The prove times of notes `proveMillis-<n>`, in run order. */
function proveMillis(notes) {
  return Object.keys(notes)
    .filter((key) => /^proveMillis-\d+$/.test(key))
    .sort((a, b) => int(a.split('-')[1]) - int(b.split('-')[1]))
    .map((key) => int(notes[key]))
    .filter((value) => value !== null);
}

function proveSummary(notes) {
  const times = proveMillis(notes);
  if (times.length === 0) {
    return [];
  }
  return [`prove ${Math.min(...times)}-${Math.max(...times)} ms`];
}

/** `killPointsPassed` ("N of M kill points recorded") as numbers, or null. */
function killPoints(notes) {
  const match = /^\s*(\d+) of (\d+)\b/.exec(String(notes.killPointsPassed ?? ''));
  return match ? { passed: Number(match[1]), total: Number(match[2]) } : null;
}

/** A limit on a seconds note: a failure reason, or null when it is met. */
function secondsLimit(label, key, max) {
  return (record) => {
    const notes = record.notes || {};
    const value = decimal(notes[key]);
    if (value === null) {
      return `${label} not measured (no ${key} note)`;
    }
    return value > max ? `${label} ${value} s, over ${max} s` : null;
  };
}

/**
 * The user-facing limits as checks, in report order. `benchmarks` null means
 * every benchmark. Each check returns why the run misses it, or null.
 */
const LIMIT_CHECKS = [
  {
    text: `balance on screen ≤ ${LIMITS.cachedBalanceSeconds} s from cache (restore note \`balanceFromCacheSeconds\`)`,
    benchmarks: ['restore'],
    check: secondsLimit('balance from cache', 'balanceFromCacheSeconds', LIMITS.cachedBalanceSeconds),
  },
  {
    text: `restore time to first balance ≤ ${LIMITS.timeToFirstBalanceSeconds} s (restore note \`timeToFirstBalanceSeconds\`)`,
    benchmarks: ['restore'],
    check: secondsLimit('time to first balance', 'timeToFirstBalanceSeconds', LIMITS.timeToFirstBalanceSeconds),
  },
  {
    text: `every Summon proof ≤ ${LIMITS.summonProofSeconds} s (summon notes \`proveMillis-<n>\`)`,
    benchmarks: ['summon'],
    check: (record) => {
      const times = proveMillis(record.notes || {});
      if (times.length === 0) {
        return 'Summon proof not measured (no proveMillis notes)';
      }
      const slowest = Math.max(...times);
      return slowest > LIMITS.summonProofSeconds * 1000
        ? `Summon proof ${slowest / 1000} s, over ${LIMITS.summonProofSeconds} s`
        : null;
    },
  },
  {
    text: "peak memory under the device's jetsam limit (\`JETSAM_LIMIT_BYTES\`)",
    benchmarks: null,
    check: (record) => {
      const footprint = (record.memory || {}).peakFootprintBytes;
      if (typeof footprint !== 'number') {
        return 'peak memory not measured';
      }
      const { model } = deviceOf(record);
      const limit = model ? JETSAM_LIMIT_BYTES[model] : undefined;
      if (limit === undefined) {
        return `no jetsam limit known for ${model || 'an unknown model'}`;
      }
      return footprint >= limit
        ? `peak footprint ${mib(footprint)}, not under the ${model} jetsam limit ${mib(limit)}`
        : null;
    },
  },
  {
    text: `no thermal state of ${LIMITS.failingThermalStates.join(' or ')}`,
    benchmarks: null,
    check: (record) => {
      const worst = (record.thermal || {}).worst;
      if (LIMITS.failingThermalStates.includes(worst)) {
        return `thermal ${worst}`;
      }
      return LIMITS.passingThermalStates.includes(worst) ? null : 'thermal state not measured';
    },
  },
  {
    text: 'header checks within their budget (header-sync note `headerBudgetOk`)',
    benchmarks: ['header-sync'],
    check: (record) => {
      const value = (record.notes || {}).headerBudgetOk;
      if (value === 'true') {
        return null;
      }
      return value === 'false' ? 'header checks over budget' : 'header budget not measured (no headerBudgetOk note)';
    },
  },
];

/** Why a run misses the user-facing limits that apply to it. */
function limitFailures(record) {
  return LIMIT_CHECKS.filter(({ benchmarks }) => !benchmarks || benchmarks.includes(record.benchmark))
    .map(({ check }) => check(record))
    .filter(Boolean);
}

/** The numbers that matter for each benchmark, from its notes. */
function keyNumbers(benchmark, notes) {
  const parts = [];
  const add = (label, key) => {
    if (notes[key] !== undefined) {
      parts.push(`${label} ${notes[key]}`);
    }
  };
  switch (benchmark) {
    case 'summon':
      if (notes.verifiedCount !== undefined || notes.runs !== undefined) {
        parts.push(`verified ${notes.verifiedCount ?? '-'}/${notes.runs ?? '-'}`);
      }
      parts.push(...proveSummary(notes));
      add('proof bytes', 'proofBytes');
      break;
    case 'header-sync':
      add('cache s', 'spotCheckCacheSeconds');
      add('hash s', 'spotCheckHashSeconds');
      add('headers', 'syncedHeaders');
      add('headers/s', 'headersPerSecond');
      add('max caches', 'maxCacheCount');
      add('resume s', 'resumeSeconds');
      add('budget ok', 'headerBudgetOk');
      break;
    case 'restore':
      if (notes.accountsFound !== undefined || notes.accountsExpected !== undefined) {
        parts.push(`accounts ${notes.accountsFound ?? '-'}/${notes.accountsExpected ?? '-'}`);
      }
      add('scan complete', 'scanComplete');
      add('cached balance s', 'balanceFromCacheSeconds');
      add('first balance s', 'timeToFirstBalanceSeconds');
      add('restore s', 'restoreSeconds');
      break;
    case 'kill-recovery':
      add('kill points', 'killPointsPassed');
      break;
    case 'worst-case':
      add('caches', 'cacheCountBeforeProve');
      if (notes.verifiedCount !== undefined || notes.runs !== undefined) {
        parts.push(`verified ${notes.verifiedCount ?? '-'}/${notes.runs ?? '-'}`);
      }
      parts.push(...proveSummary(notes));
      break;
    default:
      break;
  }
  return parts.length > 0 ? parts.join(', ') : '-';
}

/**
 * The RandomX caches a worst-case run must hold through its proofs: the spot
 * check's one when it spot checked a header, both keys' caches for an older
 * run that synced headers.
 */
function worstCaseCaches(notes) {
  return notes.spotCheckCacheSeconds !== undefined
    ? THRESHOLDS.spotCheckWorstCaseCaches
    : THRESHOLDS.worstCaseCaches;
}

/** Reasons in the notes that a check failed. */
function failedChecks(benchmark, notes) {
  const reasons = [];
  if (benchmark === 'summon' || benchmark === 'worst-case') {
    const verified = int(notes.verifiedCount);
    const runs = int(notes.runs);
    if (verified === null || runs === null) {
      reasons.push('no verifiedCount/runs notes');
    } else if (verified < runs) {
      reasons.push(`only ${verified} of ${runs} proofs verified`);
    }
  }
  if (benchmark === 'restore') {
    const found = int(notes.accountsFound);
    const expected = int(notes.accountsExpected);
    if (found === null || expected === null || found !== expected) {
      reasons.push(`found ${notes.accountsFound ?? '-'} of ${notes.accountsExpected ?? '-'} accounts`);
    }
    if (notes.scanComplete !== 'true') {
      reasons.push('scan not complete');
    }
  }
  if (benchmark === 'kill-recovery') {
    // Every kill point must be covered: "N of M" with N = M.
    const points = killPoints(notes);
    if (!points) {
      reasons.push('kill points not counted (no killPointsPassed note)');
    } else if (points.total === 0 || points.passed !== points.total) {
      reasons.push(`only ${points.passed} of ${points.total} kill points passed`);
    }
  }
  // The header budget (header-sync note `headerBudgetOk`) is a limit in
  // LIMIT_CHECKS.
  if (benchmark === 'worst-case') {
    if (notes.workerStress !== undefined && notes.workerStress !== 'true') {
      reasons.push(`workerStress ${notes.workerStress}: not run as the stress case`);
    }
    const wanted = worstCaseCaches(notes);
    if (int(notes.cacheCountBeforeProve) !== wanted) {
      reasons.push(`${notes.cacheCountBeforeProve ?? 'no'} RandomX caches held, not ${wanted}`);
    }
  }
  // Kill points: every outcome that is not "ok..." lost or repeated a payment.
  for (const key of Object.keys(notes).sort()) {
    if (key.startsWith('killPoint.') && !String(notes[key]).startsWith('ok')) {
      reasons.push(`${key}: ${notes[key]}`);
    }
  }
  return reasons;
}

/** The verdict of one run record, and why. */
function verdictOf(record) {
  const memory = record.memory || {};
  const notes = record.notes || {};

  const fatal = [];
  if (record.status !== 'ok') {
    fatal.push(record.error ? `status ${record.status}: ${record.error}` : `status ${record.status}`);
  }
  if (memory.killed) {
    fatal.push('killed');
  }
  fatal.push(...deviceProblems(deviceOf(record)));
  fatal.push(...failedChecks(record.benchmark, notes));
  fatal.push(...limitFailures(record));
  if (fatal.length > 0) {
    return { verdict: VERDICTS.doesntWork, reasons: fatal };
  }
  if (memory.warning) {
    return { verdict: VERDICTS.limits, reasons: ['memory warning'] };
  }
  return { verdict: VERDICTS.works, reasons: [] };
}

/**
 * A kill-recovery run the benchmark ended on purpose (it notes `killedAt`):
 * its outcome is in the next run's notes, so it is not the run to judge.
 */
function deliberateKill(record) {
  return record.benchmark === 'kill-recovery' && Boolean((record.notes || {}).killedAt);
}

/**
 * Phones (model and device kind) in the order they first appear, each with its
 * latest run per benchmark.
 */
function latestRuns(records) {
  const phones = new Map();
  records.forEach((record, index) => {
    if (!record || !BENCHMARKS.includes(record.benchmark) || deliberateKill(record)) {
      return;
    }
    const device = deviceOf(record);
    const key = `${device.model || 'unknown model'} (${device.kind})`;
    if (!phones.has(key)) {
      phones.set(key, { model: device.model || 'unknown model', kind: device.kind, runs: new Map() });
    }
    const { runs } = phones.get(key);
    const current = runs.get(record.benchmark);
    const newer =
      !current ||
      (record.startedAt || '') > (current.record.startedAt || '') ||
      ((record.startedAt || '') === (current.record.startedAt || '') && index > current.index);
    if (newer) {
      runs.set(record.benchmark, { record, index });
    }
  });
  return phones;
}

function cell(text) {
  return String(text).replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

function tableLine(cells) {
  return `| ${cells.map(cell).join(' | ')} |`;
}

/** The report rows of one phone, as markdown table lines, and its benchmark verdicts. */
function phoneRows(runs) {
  const lines = [];
  const verdicts = [];
  for (const benchmark of BENCHMARKS) {
    const entry = runs.get(benchmark);
    const label = benchmarkLabel(benchmark);
    if (!entry) {
      lines.push(tableLine([label, '-', '-', '-', '-', '-', '-', '-', '-', VERDICTS.notRun, '-']));
      verdicts.push({ benchmark, verdict: VERDICTS.notRun });
      continue;
    }
    const { record } = entry;
    const memory = record.memory || {};
    const { verdict, reasons } = verdictOf(record);
    verdicts.push({ benchmark, verdict });
    lines.push(
      tableLine([
        label,
        record.startedAt || '-',
        deviceText(deviceOf(record)),
        record.status || '-',
        mib(memory.peakFootprintBytes),
        yesNo(memory.warning),
        yesNo(memory.killed),
        (record.thermal && record.thermal.worst) || '-',
        keyNumbers(benchmark, record.notes || {}),
        verdict,
        reasons.length > 0 ? reasons.join('; ') : '-',
      ]),
    );
    if (verdict === VERDICTS.doesntWork && !STRESS_BENCHMARKS.includes(benchmark)) {
      lines.push(
        tableLine(['', '', '', '', '', '', '', '', '', 'PLAN change needed: (fill in)', '']),
      );
    }
  }
  return { lines, verdicts };
}

/** One phone's overall verdict: it passes only when every benchmark but a stress one works. */
function phoneVerdictLine(verdicts) {
  const failing = verdicts.filter(
    ({ benchmark, verdict }) =>
      !STRESS_BENCHMARKS.includes(benchmark) && verdict !== VERDICTS.works && verdict !== VERDICTS.limits,
  );
  if (failing.length === 0) {
    return 'Verdict: passes every user-facing limit.';
  }
  return `Verdict: fails (${failing.map(({ benchmark, verdict }) => `${benchmark} ${verdict}`).join(', ')}).`;
}

/** The limits as markdown, for the report and docs/feasibility.md. */
function limitLines() {
  return [
    'Limits (`LIMITS` in `scripts/feasibility-report.js`). Miss any one, or record no number for it, ' +
      "and the run doesn't work. Every limit is a real-device limit: a simulator run can't pass.",
    '',
    ...LIMIT_CHECKS.map(({ text, benchmarks }) => `- ${text}${benchmarks ? '' : ', every benchmark'}`),
    '- kill recovery covers every kill point (kill-recovery note `killPointsPassed`, "N of M" with N = M)',
    '',
    "Also doesn't work: status not ok, a kill or crash, no device model, iOS version or simulator/real-device " +
      'record, a failed check in the notes (proofs not all verified, accounts not all found, scan not complete, ' +
      `fewer than ${THRESHOLDS.worstCaseCaches} RandomX caches in the worst case, a kill point lost or paid twice). ` +
      'Works with limits: a memory warning. Works: otherwise.',
  ];
}

function minimumPhoneLine() {
  return `Minimum phone: ${MINIMUM_PHONE.name} (${MINIMUM_PHONE.models.join(', ')}), until it is decided.`;
}

/** The phone sections of the report, each heading starting with `heading`. */
function resultLines(records, heading) {
  const phones = latestRuns(records);
  if (phones.size === 0) {
    return ['No Phase 0 benchmark runs recorded.', '', minimumPhoneOwed()];
  }
  const lines = [];
  for (const { model, kind, runs } of phones.values()) {
    const systems = [...new Set([...runs.values()].map(({ record }) => (record.device || {}).systemVersion))]
      .filter(Boolean)
      .sort();
    const about = [systems.length > 0 ? `iOS ${systems.join(', ')}` : 'iOS -', kind].join(', ');
    lines.push(`${heading} ${model} (${about})`, '');
    lines.push(tableLine(COLUMNS), tableLine(COLUMNS.map(() => '---')));
    const { lines: rowLines, verdicts } = phoneRows(runs);
    lines.push(...rowLines, '', phoneVerdictLine(verdicts), '');
  }
  const ranOnMinimum = [...phones.values()].some(
    ({ model, kind }) => kind === DEVICE_KINDS.real && MINIMUM_PHONE.models.includes(model),
  );
  if (!ranOnMinimum) {
    lines.push(minimumPhoneOwed());
  }
  return lines;
}

/** The stress benchmarks, and why their verdict asks for no PLAN change. */
function stressLines() {
  return [
    `- worst-case is a ${STRESS_LABEL}: it holds the spot check's RandomX cache while it proves ` +
      `(${THRESHOLDS.worstCaseCaches} caches in older runs that synced headers), which the app avoids ` +
      'by freeing the cache before a proof; its verdict asks for no PLAN change and does not fail the phone',
  ];
}

function minimumPhoneOwed() {
  return `Minimum-phone (${MINIMUM_PHONE.name}) real-device run still owed.`;
}

function checkRecords(records) {
  if (!Array.isArray(records)) {
    throw new Error('bench results must be a JSON array of run records');
  }
}

/** The markdown report of an array of run records. */
function buildReport(records) {
  checkRecords(records);
  const lines = ['# Feasibility report', '', ...limitLines(), '', ...stressLines(), '', minimumPhoneLine(), ''];
  lines.push(...resultLines(records, '##'));
  return lines.join('\n').trimEnd();
}

/** Parses the text of bench-results.json into run records. */
function parseResults(text) {
  let records;
  try {
    records = JSON.parse(text);
  } catch (error) {
    throw new Error(`bench results are not valid JSON: ${error.message}`);
  }
  checkRecords(records);
  return records;
}

/** Parses the text of bench-results.json and builds the report. */
function buildReportText(text) {
  return buildReport(parseResults(text));
}

function main(argv) {
  const file = argv[2];
  const text = fs.readFileSync(file && file !== '-' ? file : 0, 'utf8');
  process.stdout.write(`${buildReportText(text)}\n`);
}

if (require.main === module) {
  try {
    main(process.argv);
  } catch (error) {
    process.stderr.write(`feasibility-report: ${error.message}\n`);
    process.exit(1);
  }
}

module.exports = {
  buildReport,
  buildReportText,
  parseResults,
  verdictOf,
  deviceOf,
  limitLines,
  minimumPhoneLine,
  resultLines,
  LIMITS,
  THRESHOLDS,
  JETSAM_LIMIT_BYTES,
  MINIMUM_PHONE,
  BENCHMARKS,
  VERDICTS,
  DEVICE_KINDS,
  STRESS_LABEL,
};
