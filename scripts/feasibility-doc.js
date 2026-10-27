#!/usr/bin/env node
// Writes docs/feasibility.md from docs/feasibility.template.md: the template's
// placeholders are filled with the limits, the minimum phone and the report of
// a bench-results.json (scripts/feasibility-report.js).
//
//   node scripts/feasibility-doc.js                     # no runs yet
//   node scripts/feasibility-doc.js bench-results.json  # with results
//
// Placeholders: {{limits}}, {{minimumPhone}}, {{results}}.
'use strict';

const fs = require('fs');
const path = require('path');

const { limitLines, minimumPhoneLine, parseResults, resultLines } = require('./feasibility-report');

const ROOT = path.join(path.dirname(require.resolve('./feasibility-report')), '..');
const TEMPLATE = path.join(ROOT, 'docs', 'feasibility.template.md');
const OUTPUT = path.join(ROOT, 'docs', 'feasibility.md');

const PLACEHOLDERS = ['limits', 'minimumPhone', 'results'];

/** docs/feasibility.md from the template text and an array of run records. */
function buildDoc(template, records) {
  const values = {
    limits: limitLines().join('\n'),
    minimumPhone: minimumPhoneLine(),
    results: resultLines(records, '###').join('\n').trimEnd(),
  };
  for (const name of PLACEHOLDERS) {
    if (!template.includes(`{{${name}}}`)) {
      throw new Error(`the template has no {{${name}}} placeholder`);
    }
  }
  // The template's leading comment is for whoever edits the template.
  const body = template.replace(/^\s*<!--[\s\S]*?-->\s*/, '');
  const doc = body.replace(/\{\{(\w+)\}\}/g, (match, name) => {
    if (!Object.prototype.hasOwnProperty.call(values, name)) {
      throw new Error(`unknown placeholder ${match} in the template`);
    }
    return values[name];
  });
  return `${doc.trimEnd()}\n`;
}

function main(argv) {
  const file = argv[2];
  const records = file ? parseResults(fs.readFileSync(file, 'utf8')) : [];
  fs.writeFileSync(OUTPUT, buildDoc(fs.readFileSync(TEMPLATE, 'utf8'), records));
  process.stdout.write(`wrote ${path.relative(ROOT, OUTPUT)}\n`);
}

if (require.main === module) {
  try {
    main(process.argv);
  } catch (error) {
    process.stderr.write(`feasibility-doc: ${error.message}\n`);
    process.exit(1);
  }
}

module.exports = { buildDoc, TEMPLATE, OUTPUT };
