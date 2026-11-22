#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const TOLERATED_TYPE_ERROR = /^error TS5097: /;

export function findings(report) {
  const entries = [report.manifest, ...(report.contents ?? [])].filter(Boolean);
  return entries.flatMap(entry => [
    ...(entry.errors ?? []).map(finding => ({ ...finding, level: 'error', file: entry.file, type: entry.type })),
    ...(entry.warnings ?? []).map(finding => ({ ...finding, level: 'warning', file: entry.file, type: entry.type })),
  ]);
}

export function isTolerated(finding) {
  return finding.level === 'warning' && finding.type === 'hooks' && TOLERATED_TYPE_ERROR.test(finding.message ?? '');
}

export function judge(report) {
  if (!report || typeof report !== 'object' || !report.manifest) {
    return { ok: false, blocking: [], tolerated: [], reason: 'the report has no manifest section' };
  }
  const all = findings(report);
  const blocking = all.filter(finding => !isTolerated(finding));
  const tolerated = all.filter(isTolerated);
  if (blocking.length > 0) return { ok: false, blocking, tolerated, reason: `${blocking.length} finding(s) fail --strict` };
  if (report.success === false && tolerated.length === 0) {
    return { ok: false, blocking, tolerated, reason: 'validation failed without a finding this script can read' };
  }
  return { ok: true, blocking, tolerated, reason: '' };
}

function describe(finding) {
  const where = [finding.file, finding.path].filter(Boolean).join(' ');
  return `${finding.level}: ${where}: ${finding.message}`;
}

function main(dir) {
  if (!dir) {
    console.error('usage: node scripts/validate-plugin.mjs <plugin directory>');
    return 2;
  }
  const run = spawnSync('claude', ['plugin', 'validate', '--strict', '--json', dir], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (run.error) {
    console.error(`could not run claude: ${run.error.message}`);
    return 1;
  }
  let report;
  try {
    report = JSON.parse(run.stdout);
  } catch {
    console.error(`claude plugin validate did not print a JSON report (exit ${run.status})`);
    console.error(run.stdout, run.stderr);
    return 1;
  }
  const verdict = judge(report);
  for (const finding of verdict.blocking) console.error(describe(finding));
  if (verdict.tolerated.length > 0) {
    console.log(`Tolerated ${verdict.tolerated.length} TS5097 warning(s): the type check rejects .ts import paths that Claude Code and Node.js both load.`);
  }
  if (!verdict.ok) {
    console.error(`✘ ${dir}: ${verdict.reason}`);
    return 1;
  }
  console.log(`✔ ${dir}: claude plugin validate --strict passed apart from TS5097`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) process.exitCode = main(process.argv[2]);
