#!/usr/bin/env node
// Turns bench-results.json (written on the phone by modules/ghost-bench) into
// a markdown go/no-go report: for each phone model, the latest run of each
// Phase 0 benchmark with its key numbers and a verdict.
//
//   node scripts/feasibility-report.js bench-results.json
//   node scripts/feasibility-report.js < bench-results.json
//
// The verdicts are a starting point for docs/feasibility.md, not the decision.
'use strict';

const fs = require('fs');

const MIB = 1024 * 1024;
const GIB = 1024 * MIB;

/**
 * Where the verdicts change. PLAN.md names no numbers, so these are the
 * report's own; change them here.
 */
const THRESHOLDS = {
  /** Peak footprint at or above this: doesn't work. */
  doesntWorkFootprintBytes: 2.0 * GIB,
  /** Peak footprint at or above this: works with limits. */
  limitsFootprintBytes: 1.5 * GIB,
  /** Worst thermal states that mean works with limits. */
  limitsThermalStates: ['serious', 'critical'],
  /** RandomX caches the worst-case run must hold while it proves. */
  worstCaseCaches: 2,
};

/** The Phase 0 benchmarks, in report order. */
const BENCHMARKS = ['summon', 'header-sync', 'restore', 'kill-recovery', 'worst-case'];

const VERDICTS = {
  works: 'works',
  limits: 'works with limits',
  doesntWork: "doesn't work",
  notRun: 'not run',
};

const COLUMNS = [
  'Benchmark',
  'Run',
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
      add('headers', 'syncedHeaders');
      add('headers/s', 'headersPerSecond');
      add('max caches', 'maxCacheCount');
      add('resume s', 'resumeSeconds');
      break;
    case 'restore':
      if (notes.accountsFound !== undefined || notes.accountsExpected !== undefined) {
        parts.push(`accounts ${notes.accountsFound ?? '-'}/${notes.accountsExpected ?? '-'}`);
      }
      add('scan complete', 'scanComplete');
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
  if (benchmark === 'worst-case') {
    if (int(notes.cacheCountBeforeProve) !== THRESHOLDS.worstCaseCaches) {
      reasons.push(
        `${notes.cacheCountBeforeProve ?? 'no'} RandomX caches held, not ${THRESHOLDS.worstCaseCaches}`,
      );
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
  const thermal = record.thermal || {};
  const notes = record.notes || {};
  const footprint = memory.peakFootprintBytes;

  const fatal = [];
  if (record.status !== 'ok') {
    fatal.push(record.error ? `status ${record.status}: ${record.error}` : `status ${record.status}`);
  }
  if (memory.killed) {
    fatal.push('killed');
  }
  if (typeof footprint === 'number' && footprint >= THRESHOLDS.doesntWorkFootprintBytes) {
    fatal.push(`peak footprint ${mib(footprint)}`);
  }
  fatal.push(...failedChecks(record.benchmark, notes));
  if (fatal.length > 0) {
    return { verdict: VERDICTS.doesntWork, reasons: fatal };
  }

  const limits = [];
  if (memory.warning) {
    limits.push('memory warning');
  }
  if (THRESHOLDS.limitsThermalStates.includes(thermal.worst)) {
    limits.push(`thermal ${thermal.worst}`);
  }
  if (typeof footprint === 'number' && footprint >= THRESHOLDS.limitsFootprintBytes) {
    limits.push(`peak footprint ${mib(footprint)}`);
  }
  if (limits.length > 0) {
    return { verdict: VERDICTS.limits, reasons: limits };
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

/** Phone models in the order they first appear, each with its latest run per benchmark. */
function latestRuns(records) {
  const phones = new Map();
  records.forEach((record, index) => {
    if (!record || !BENCHMARKS.includes(record.benchmark) || deliberateKill(record)) {
      return;
    }
    const model = (record.device && record.device.model) || 'unknown phone';
    if (!phones.has(model)) {
      phones.set(model, new Map());
    }
    const runs = phones.get(model);
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

/** The report rows of one phone, as markdown table lines. */
function phoneRows(runs) {
  const lines = [];
  for (const benchmark of BENCHMARKS) {
    const entry = runs.get(benchmark);
    if (!entry) {
      lines.push(tableLine([benchmark, '-', '-', '-', '-', '-', '-', '-', VERDICTS.notRun, '-']));
      continue;
    }
    const { record } = entry;
    const memory = record.memory || {};
    const { verdict, reasons } = verdictOf(record);
    lines.push(
      tableLine([
        benchmark,
        record.startedAt || '-',
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
    if (verdict === VERDICTS.doesntWork) {
      lines.push(
        tableLine(['', '', '', '', '', '', '', '', 'PLAN change needed: (fill in)', '']),
      );
    }
  }
  return lines;
}

function thresholdLines() {
  return [
    'Thresholds (THRESHOLDS in scripts/feasibility-report.js):',
    '',
    `- doesn't work: status not ok, a kill or crash, peak footprint ${mib(THRESHOLDS.doesntWorkFootprintBytes)} or more, ` +
      'a failed check in the notes (proofs not all verified, accounts not all found, scan not complete, ' +
      `fewer than ${THRESHOLDS.worstCaseCaches} RandomX caches in the worst case, a kill point lost or paid twice)`,
    `- works with limits: a memory warning, worst thermal ${THRESHOLDS.limitsThermalStates.join(' or ')}, ` +
      `or peak footprint ${mib(THRESHOLDS.limitsFootprintBytes)} or more`,
    '- works: otherwise',
  ];
}

/** The markdown report of an array of run records. */
function buildReport(records) {
  if (!Array.isArray(records)) {
    throw new Error('bench results must be a JSON array of run records');
  }
  const phones = latestRuns(records);
  const lines = ['# Feasibility report', ''];
  if (phones.size === 0) {
    lines.push('No Phase 0 benchmark runs recorded.');
    return lines.join('\n');
  }
  lines.push(...thresholdLines(), '');
  for (const [model, runs] of phones) {
    const systems = [...new Set([...runs.values()].map(({ record }) => (record.device || {}).systemVersion))]
      .filter(Boolean)
      .sort();
    lines.push(`## ${model}${systems.length > 0 ? ` (iOS ${systems.join(', ')})` : ''}`, '');
    lines.push(tableLine(COLUMNS), tableLine(COLUMNS.map(() => '---')));
    lines.push(...phoneRows(runs), '');
  }
  if (phones.size === 1) {
    lines.push('Older-phone run still owed.');
  }
  return lines.join('\n').trimEnd();
}

/** Parses the text of bench-results.json and builds the report. */
function buildReportText(text) {
  let records;
  try {
    records = JSON.parse(text);
  } catch (error) {
    throw new Error(`bench results are not valid JSON: ${error.message}`);
  }
  return buildReport(records);
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

module.exports = { buildReport, buildReportText, verdictOf, THRESHOLDS, BENCHMARKS, VERDICTS };
