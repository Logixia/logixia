/* eslint-disable @typescript-eslint/no-explicit-any -- CLI tools process raw JSON log data */
import fs from 'node:fs';
import path from 'node:path';

import { Command } from 'commander';
import pc from 'picocolors';

import { formatAsTable, safeParseLogs, sanitizeForTerminal } from '../utils';

interface SearchCriteria {
  field?: string;
  value: string;
}

function parseQuery(query: string): SearchCriteria {
  const match = query.match(/^(\w+):(.+)$/);
  if (match) {
    return { field: match[1]!, value: match[2]! };
  }
  return { value: query };
}

export interface SearchHit {
  /** 1-based index of the entry among parsed log entries. */
  line: number;
  entry: any;
  /** false for surrounding context entries. */
  match: boolean;
}

function entryMatcher(query: string): (entry: unknown) => boolean {
  const criteria = parseQuery(query);
  const needle = criteria.value.toLowerCase();
  return (entry: unknown) => {
    const row = entry as Record<string, unknown>;
    if (criteria.field) {
      const fieldValue = row[criteria.field];
      if (fieldValue === undefined) return false;
      return String(fieldValue).toLowerCase().includes(needle);
    }
    return JSON.stringify(row).toLowerCase().includes(needle);
  };
}

export async function searchLogs(raw: string, opts: any = {}) {
  return safeParseLogs(raw).filter(entryMatcher(opts.query || ''));
}

/** Like grep -C: matches plus `context` entries before and after each, in file order. */
export async function searchLogsWithContext(raw: string, opts: any = {}): Promise<SearchHit[]> {
  const entries = safeParseLogs(raw);
  const isMatch = entryMatcher(opts.query || '');
  const context = Math.max(0, Number.parseInt(String(opts.context ?? 0), 10) || 0);
  const matched = entries.map((e: unknown) => isMatch(e));
  const hits: SearchHit[] = [];
  for (const [i, entry] of entries.entries()) {
    const near =
      matched[i] || matched.slice(Math.max(0, i - context), i + context + 1).includes(true);
    if (near) hits.push({ line: i + 1, entry, match: Boolean(matched[i]) });
  }
  return hits;
}

function formatSearchResults(hits: SearchHit[], format: string): string {
  if (format === 'json') {
    return sanitizeForTerminal(
      JSON.stringify(
        hits.filter((h) => h.match).map((h) => h.entry),
        null,
        2
      )
    );
  }

  if (hits.length === 0) return pc.yellow('No results found');

  if (format === 'table') {
    const results = hits.map((h) => h.entry);
    const displayColumns = Object.keys(results[0] || {}).slice(0, 4);
    return formatAsTable(results, displayColumns);
  }

  const lines: string[] = [];
  let prev = 0;
  for (const h of hits) {
    if (prev > 0 && h.line > prev + 1) lines.push(pc.gray('--'));
    prev = h.line;
    const sep = h.match ? ':' : '-';
    lines.push(`${pc.gray(String(h.line) + sep)} ${sanitizeForTerminal(JSON.stringify(h.entry))}`);
  }
  return lines.join('\n');
}

export const searchCommand = new Command('search')
  .description('Search log files with query patterns')
  .argument('<file>', 'Path to log file')
  .option('--query <query>', 'Search query (e.g., "user_id:123" or "error")', '')
  .option('--format <fmt>', 'Output format (table, json, line)', 'line')
  .option('--context <lines>', 'Entries of context around each match (line/table formats)', '0')
  .action(async (file: string, opts: any) => {
    const full = path.resolve(process.cwd(), file);
    if (!fs.existsSync(full)) {
      console.error(`File not found: ${full}`);
      process.exit(2);
    }

    if (!opts.query) {
      console.error('--query is required');
      process.exit(2);
    }

    const raw = fs.readFileSync(full, 'utf8');
    const hits = await searchLogsWithContext(raw, opts);
    const count = hits.filter((h) => h.match).length;

    // Keep stdout machine-readable for json output; status goes to stderr.
    const status = opts.format === 'json' ? console.error : console.log;
    status(pc.bold(`\nFound ${count} matches`));
    console.log(formatSearchResults(hits, opts.format));
  });
