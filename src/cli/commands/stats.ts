/* eslint-disable @typescript-eslint/no-explicit-any -- CLI tools process raw JSON log data */
import fs from 'node:fs';
import path from 'node:path';

import chalk from 'chalk';
import { Command } from 'commander';

import { safeParseLogs } from '../utils';

export async function generateStats(raw: string, opts: any = {}) {
  const entries = safeParseLogs(raw);
  const group = opts.groupBy || 'level';

  const agg: Record<string, number> = {};
  let minTime: Date | null = null;
  let maxTime: Date | null = null;

  for (const e of entries) {
    const key = (e[group] || e.level || 'unknown').toString().toUpperCase();
    agg[key] = (agg[key] || 0) + 1;

    // Track time range
    if (e.timestamp) {
      const ts = new Date(e.timestamp);
      if (!minTime || ts < minTime) minTime = ts;
      if (!maxTime || ts > maxTime) maxTime = ts;
    }
  }

  return {
    total: entries.length,
    groupBy: group,
    distribution: agg,
    timeRange: minTime && maxTime ? { start: minTime, end: maxTime } : null,
  };
}

function formatStatsOutput(stats: unknown, filename: string): string {
  const s = stats as Record<string, unknown>;
  const lines: string[] = [];

  lines.push(chalk.bold(`\nLog Statistics for ${path.basename(filename)}`));
  lines.push(chalk.bold('='.repeat(50)));
  lines.push(chalk.cyan(`Total Entries: ${(s['total'] as number).toLocaleString()}`));

  if (s['timeRange']) {
    lines.push(
      chalk.cyan(
        `Time Range: ${((s['timeRange'] as Record<string, Date>)['start'] as Date).toISOString()} - ${((s['timeRange'] as Record<string, Date>)['end'] as Date).toISOString()}`
      )
    );
  }

  lines.push('');
  lines.push(
    chalk.bold(
      `${(s['groupBy'] as string).charAt(0).toUpperCase() + (s['groupBy'] as string).slice(1)} Distribution:`
    )
  );

  // Sort by count descending
  const sorted = Object.entries(s['distribution'] as Record<string, number>).sort(
    ([, a], [, b]) => (b as number) - (a as number)
  );

  for (const [key, count] of sorted) {
    const percentage = (((count as number) / (s['total'] as number)) * 100).toFixed(1);
    const bar = '█'.repeat(Math.floor(((count as number) / (s['total'] as number)) * 30));

    let colorFn = chalk.white;
    if (key === 'ERROR') colorFn = chalk.red;
    else if (key === 'WARN') colorFn = chalk.yellow;
    else if (key === 'INFO') colorFn = chalk.blue;
    else if (key === 'DEBUG') colorFn = chalk.gray;

    lines.push(
      colorFn(
        `  ${key.padEnd(10)} ${String(count).padStart(8)} (${percentage.padStart(5)}%) ${bar}`
      )
    );
  }

  lines.push('');
  return lines.join('\n');
}

export const statsCommand = new Command('stats')
  .description('Show statistics for a log file')
  .argument('<file>', 'Path to log file')
  .option('--group-by <field>', 'Field to group by (default: level)', 'level')
  .option('--format <fmt>', 'Output format (pretty, json)', 'pretty')
  .action(async (file: string, opts: any) => {
    const full = path.resolve(process.cwd(), file);
    if (!fs.existsSync(full)) {
      console.error(`File not found: ${full}`);
      process.exit(2);
    }

    const raw = fs.readFileSync(full, 'utf8');
    const stats = await generateStats(raw, opts);

    if (opts.format === 'json') {
      console.log(JSON.stringify(stats, null, 2));
    } else {
      console.log(formatStatsOutput(stats, file));
    }
  });
