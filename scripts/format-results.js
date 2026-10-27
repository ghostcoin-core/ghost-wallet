#!/usr/bin/env node
// Prints bench-results.json (written on the phone by modules/ghost-bench) as a
// table, one row per run.
//
//   node scripts/format-results.js bench-results.json
//   node scripts/format-results.js < bench-results.json
//
// scripts/pull-results.sh copies the file off the iPhone and pipes it here.
'use strict';

const fs = require('fs');

const MIB = 1024 * 1024;

const COLUMNS = [
  'started',
  'device',
  'iOS',
  'benchmark',
  'status',
  'stages',
  'total',
  'peak RSS',
  'peak footprint',
  'least avail',
  'mem warn',
  'killed',
  'thermal (start>end, worst)',
  'battery drop',
];

function seconds(value) {
  return typeof value === 'number' ? `${value.toFixed(2)}s` : '-';
}

function mib(bytes) {
  return typeof bytes === 'number' ? `${(bytes / MIB).toFixed(1)} MiB` : '-';
}

function yesNo(value) {
  if (value === undefined || value === null) {
    return '-';
  }
  return value ? 'yes' : 'no';
}

function percent(fraction) {
  return typeof fraction === 'number' ? `${(fraction * 100).toFixed(1)}%` : '-';
}

/** One table row (an array of cells) for one run record. */
function row(record) {
  const device = record.device || {};
  const memory = record.memory || {};
  const thermal = record.thermal || {};
  const battery = record.battery || {};
  const stages = (record.stages || [])
    .map((stage) => `${stage.name} ${seconds(stage.seconds)}`)
    .join(', ');
  return [
    record.startedAt || '-',
    device.model || '-',
    device.systemVersion || '-',
    record.benchmark || '-',
    record.error ? `${record.status} (${record.error})` : record.status || '-',
    stages || '-',
    seconds(record.totalSeconds),
    mib(memory.peakResidentBytes),
    mib(memory.peakFootprintBytes),
    mib(memory.minAvailableBytes),
    yesNo(memory.warning),
    yesNo(memory.killed),
    `${thermal.start || '-'}>${thermal.end || '-'}, ${thermal.worst || '-'}`,
    percent(battery.drop),
  ];
}

/** The records as an aligned plain-text table, header first. */
function formatResults(records) {
  if (!Array.isArray(records)) {
    throw new Error('bench results must be a JSON array of run records');
  }
  if (records.length === 0) {
    return 'No benchmark runs recorded.';
  }
  const rows = [COLUMNS, ...records.map(row)];
  const widths = COLUMNS.map((_, column) => Math.max(...rows.map((cells) => cells[column].length)));
  const line = (cells) =>
    cells
      .map((cell, column) => cell.padEnd(widths[column]))
      .join(' | ')
      .trimEnd();
  const separator = widths.map((width) => '-'.repeat(width)).join('-+-');
  return [line(rows[0]), separator, ...rows.slice(1).map(line)].join('\n');
}

/** Parses the text of bench-results.json and formats it. */
function formatResultsText(text) {
  let records;
  try {
    records = JSON.parse(text);
  } catch (error) {
    throw new Error(`bench results are not valid JSON: ${error.message}`);
  }
  return formatResults(records);
}

function main(argv) {
  const file = argv[2];
  const text = fs.readFileSync(file && file !== '-' ? file : 0, 'utf8');
  process.stdout.write(`${formatResultsText(text)}\n`);
}

if (require.main === module) {
  try {
    main(process.argv);
  } catch (error) {
    process.stderr.write(`format-results: ${error.message}\n`);
    process.exit(1);
  }
}

module.exports = { formatResults, formatResultsText, row, COLUMNS };
