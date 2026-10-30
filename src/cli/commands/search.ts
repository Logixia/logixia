/* eslint-disable @typescript-eslint/no-explicit-any -- CLI tools process raw JSON log data */
import fs from 'node:fs';
import path from 'node:path';

import { Command } from 'commander';
import pc from 'picocolors';

import { formatAsTable, parseLogLines, safeParseLogs, sanitizeForTerminal } from '../utils';

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
  /** 0-based index among parsed entries. */
  index: number;
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

/**
 * Like grep -C: matches plus `context` parsed entries (blank lines are skipped) before and
 * after each, in file order, tagged with their original file line numbers. Single pass.
 */
export async function searchLogsWithContext(raw: string, opts: any = {}): Promise<SearchHit[]> {
  const parsed = parseLogLines(raw);
  const isMatch = entryMatcher(opts.query || '');
  const context = Math.max(0, Number.parseInt(String(opts.context ?? 0), 10) || 0);
  const matched = parsed.map((p) => isMatch(p.entry));

  // nextMatch[i] = index of the nearest match at or after i
  const nextMatch = Array.from({ length: parsed.length }, () => Number.POSITIVE_INFINITY);
  let next = Number.POSITIVE_INFINITY;
  for (let i = parsed.length - 1; i >= 0; i--) {
    if (matched[i]) next = i;
    nextMatch[i] = next;
  }

  const hits: SearchHit[] = [];
  let lastMatch = Number.NEGATIVE_INFINITY;
  for (const [i, p] of parsed.entries()) {
    if (matched[i]) lastMatch = i;
    if (i - lastMatch <= context || nextMatch[i]! - i <= context) {
      hits.push({ index: i, line: p.line, entry: p.entry, match: Boolean(matched[i]) });
    }
  }
  return hits;
}

function matchedColumns(hits: SearchHit[]): string[] {
  const cols = new Set<string>();
  for (const h of hits) if (h.match) for (const k of Object.keys(h.entry || {})) cols.add(k);
  if (cols.size === 0) {
    for (const h of hits) for (const k of Object.keys(h.entry || {})) cols.add(k);
  }
  return [...cols].slice(0, 4);
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
    const withContext = hits.some((h) => !h.match);
    const rows = hits.map((h) =>
      withContext ? { match: h.match ? '*' : '', ...h.entry } : h.entry
    );
    const columns = matchedColumns(hits);
    return formatAsTable(rows, withContext ? ['match', ...columns] : columns);
  }

  const lines: string[] = [];
  let prev = -1;
  for (const h of hits) {
    if (prev >= 0 && h.index > prev + 1) lines.push(pc.gray('--'));
    prev = h.index;
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
