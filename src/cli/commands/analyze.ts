import { Command } from 'commander';
import fs from 'fs';
import path from 'path';
import { formatAsTable, safeParseLogs } from '../utils';

function parseDurationToMs(input?: string) {
  if (!input) return undefined;
  const m = input.match(/^(\d+)([smhd])$/i);
  if (!m) return undefined;
  const n = parseInt(m[1]!, 10);
  const unit = m[2]!.toLowerCase();
  switch (unit) {
    case 's': return n * 1000;
    case 'm': return n * 60 * 1000;
    case 'h': return n * 60 * 60 * 1000;
    case 'd': return n * 24 * 60 * 60 * 1000;
    default: return undefined;
  }
}

export async function analyzeFileContents(raw: string, opts: any = {}) {
  const entries = safeParseLogs(raw);

  let filtered = entries;

  // time window filtering
  const durMs = parseDurationToMs(opts.last);
  if (durMs) {
    const cutoff = Date.now() - durMs;
    filtered = filtered.filter((e: any) => {
      const ts = e.timestamp ? new Date(e.timestamp).getTime() : undefined;
      if (!ts) return false;
      return ts >= cutoff;
    });
  }

  if (opts.level) {
    filtered = filtered.filter((e: any) => (e.level || '').toLowerCase() === opts.level.toLowerCase());
  }

  const byLevel: Record<string, number> = {};
  for (const e of filtered) {
    const l = (e.level || 'info').toUpperCase();
    byLevel[l] = (byLevel[l] || 0) + 1;
  }

  if (opts.format === 'json') {
    return { total: filtered.length, byLevel };
  }

  const rows = Object.keys(byLevel).map(k => ({ level: k, count: byLevel[k] }));
  return formatAsTable(rows, ['level','count']);
}

export const analyzeCommand = new Command('analyze')
  .description('Analyze log files for patterns and insights')
  .argument('<file>','Path to log file')
  .option('--level <level>','Filter by log level')
  .option('--last <range>','Time range (e.g., 24h, 7d)')
  .option('--format <fmt>','Output format (table,json,csv)','table')
  .action(async (file: string, opts: any) => {
    const full = path.resolve(process.cwd(), file);
    if (!fs.existsSync(full)) {
      console.error(`File not found: ${full}`);
      process.exit(2);
    }

    const raw = fs.readFileSync(full, 'utf8');
    const result = await analyzeFileContents(raw, opts);

    if (opts.format === 'json') {
      console.log(JSON.stringify(result, null, 2));
      return;
    }

    console.log(result);
  });