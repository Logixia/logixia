/* eslint-disable @typescript-eslint/no-explicit-any -- CLI tools process raw JSON log data */
/**
 * logixia CLI — SQL-like log query engine
 *
 * Supports a subset of SQL syntax over NDJSON / JSON log files:
 *
 *   SELECT * FROM logs WHERE level='error' AND duration > 500
 *   SELECT level, message FROM logs WHERE level='warn'
 *   COUNT BY level
 *   AVG(duration) BY endpoint
 *   GROUP BY statusCode
 *
 * Time-range shortcuts (--since / --until):
 *   --since "last 2 hours"
 *   --since "last 30 minutes"
 *   --since "today"
 *   --since "2024-01-15T08:00:00"
 *
 * @example Basic filter
 *   logixia query app.log --sql "SELECT * FROM logs WHERE level='error'"
 *
 * @example Aggregation
 *   logixia query app.log --sql "COUNT BY level"
 *
 * @example Time range + table output
 *   logixia query app.log --since "last 1 hour" --format table
 *
 * @example Live tail with SQL filter
 *   logixia query app.log --follow --sql "WHERE level='error'"
 */
import fs from 'node:fs';
import path from 'node:path';

import { Command } from 'commander';
import pc from 'picocolors';

import { formatAsTable, safeParseLogs } from '../utils';

// ── Time-range parser ─────────────────────────────────────────────────────────

/**
 * Parse a human-friendly time range string into a `Date`.
 * Returns `undefined` when the string is not recognised.
 *
 * Supported formats:
 *  - "last N minutes" / "last N hours" / "last N days"
 *  - "today"  → start of today (00:00:00)
 *  - "yesterday" → start of yesterday
 *  - ISO 8601 or any string parseable by `new Date()`
 */
function parseTimeRange(value: string): Date | undefined {
  const norm = value.trim().toLowerCase();

  // "today"
  if (norm === 'today') {
    const d = new Date();
    d.setHours(0, 0, 0, 0);
    return d;
  }

  // "yesterday"
  if (norm === 'yesterday') {
    const d = new Date();
    d.setDate(d.getDate() - 1);
    d.setHours(0, 0, 0, 0);
    return d;
  }

  // "last N <unit>"
  const relMatch = norm.match(
    /^last\s+(\d+)\s+(minute|minutes|min|hour|hours|day|days|week|weeks)$/
  );
  if (relMatch) {
    const n = Number(relMatch[1]);
    const unit = relMatch[2]!;
    let ms: number;
    if (unit.startsWith('min')) {
      ms = n * 60_000;
    } else if (unit.startsWith('hour')) {
      ms = n * 3_600_000;
    } else if (unit.startsWith('day')) {
      ms = n * 86_400_000;
    } else {
      ms = n * 7 * 86_400_000;
    }
    return new Date(Date.now() - ms);
  }

  // ISO / arbitrary date string
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

// ── SQL parser ────────────────────────────────────────────────────────────────

type Operator = '=' | '!=' | '>' | '>=' | '<' | '<=' | 'LIKE' | 'NOT LIKE' | 'IN' | 'NOT IN';

interface Condition {
  field: string;
  op: Operator;
  value: string | number | string[];
  /** If `true`, the field is matched case-insensitively */
  caseless?: boolean;
}

interface Conjunction {
  type: 'AND' | 'OR';
  conditions: (Condition | Conjunction)[];
}

interface ParsedQuery {
  select: string[] | '*';
  where: Condition[] | null;
  /** Raw WHERE conjunction tree (AND / OR) */
  conjunction: Conjunction | null;
  aggregation: {
    fn: 'COUNT' | 'AVG' | 'SUM' | 'MIN' | 'MAX' | 'GROUP' | null;
    field: string | null;
    groupBy: string | null;
  } | null;
  orderBy: { field: string; dir: 'ASC' | 'DESC' } | null;
  limit: number | null;
}

function parseSQL(sql: string): ParsedQuery {
  const result: ParsedQuery = {
    select: '*',
    where: null,
    conjunction: null,
    aggregation: null,
    orderBy: null,
    limit: null,
  };

  const upper = sql.trim().toUpperCase();

  // ── Aggregation shorthands ─────────────────────────────────────────────────
  // "COUNT BY field"
  {
    const m = /^COUNT\s+BY\s+(\w+)/i.exec(sql.trim());
    if (m) {
      result.aggregation = { fn: 'COUNT', field: null, groupBy: m[1]! };
      return result;
    }
  }

  // "GROUP BY field"
  {
    const m = /^GROUP\s+BY\s+(\w+)/i.exec(sql.trim());
    if (m) {
      result.aggregation = { fn: 'GROUP', field: null, groupBy: m[1]! };
      return result;
    }
  }

  // "AVG(field) BY groupField" or "SUM(field) BY groupField"
  {
    const m = /^(AVG|SUM|MIN|MAX)\((\w+)\)\s+BY\s+(\w+)/i.exec(sql.trim());
    if (m) {
      result.aggregation = {
        fn: m[1]!.toUpperCase() as 'AVG' | 'SUM' | 'MIN' | 'MAX',
        field: m[2]!,
        groupBy: m[3]!,
      };
      return result;
    }
  }

  // ── SELECT ─────────────────────────────────────────────────────────────────
  if (upper.startsWith('SELECT')) {
    const fromIdx = upper.indexOf(' FROM ');
    if (fromIdx !== -1) {
      const selectPart = sql.slice(6, fromIdx + sql.length - upper.length).trim();
      if (selectPart !== '*') {
        result.select = selectPart
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
      }
    }
  }

  // ── WHERE ──────────────────────────────────────────────────────────────────
  // Use indexOf-based extraction to avoid lazy .+? with |$ alternation (ReDoS risk).
  const remainder = sql.trim();
  const upperRemainder = remainder.toUpperCase();
  const whereTokenIdx = upperRemainder.indexOf('WHERE ');
  if (whereTokenIdx !== -1) {
    const afterWhere = remainder.slice(whereTokenIdx + 6).trimStart();
    const upperAfter = afterWhere.toUpperCase();
    const orderIdx = upperAfter.indexOf(' ORDER BY ');
    const limitIdx = upperAfter.indexOf(' LIMIT ');
    const candidates = [orderIdx, limitIdx].filter((i) => i !== -1);
    const endIdx = candidates.length > 0 ? Math.min(...candidates) : afterWhere.length;
    result.where = parseWhereClause(afterWhere.slice(0, endIdx).trim());
  }

  // ── ORDER BY ───────────────────────────────────────────────────────────────
  const orderMatch = /ORDER\s+BY\s+(\w+)(?:\s+(ASC|DESC))?/i.exec(remainder);
  if (orderMatch) {
    result.orderBy = {
      field: orderMatch[1]!,
      dir: (orderMatch[2]?.toUpperCase() as 'ASC' | 'DESC') ?? 'ASC',
    };
  }

  // ── LIMIT ──────────────────────────────────────────────────────────────────
  const limitMatch = /LIMIT\s+(\d+)/i.exec(remainder);
  if (limitMatch) {
    result.limit = Number.parseInt(limitMatch[1]!, 10);
  }

  return result;
}

function parseWhereClause(clause: string): Condition[] {
  // Split on AND using indexOf to avoid regex quantifiers that could cause backtracking.
  // Collapse runs of whitespace first so ' AND ' is a reliable separator.
  const normalized = clause.replace(/\s+/g, ' ').trim();
  const upper = normalized.toUpperCase();
  const parts: string[] = [];
  let start = 0;
  let idx = upper.indexOf(' AND ');
  while (idx !== -1) {
    parts.push(normalized.slice(start, idx).trim());
    start = idx + 5; // ' AND '.length === 5
    idx = upper.indexOf(' AND ', start);
  }
  parts.push(normalized.slice(start).trim());

  const conditions: Condition[] = [];
  for (const part of parts.filter(Boolean)) {
    const cond = parseCondition(part);
    if (cond) conditions.push(cond);
  }
  return conditions;
}

/** Longest operators first so `>=` / `<=` / `!=` are matched before `>` / `<` / `=`. */
const COMPARISON_OPS: ReadonlyArray<Operator> = ['>=', '<=', '!=', '>', '<', '='];

function parseCondition(expr: string): Condition | null {
  const trimmed = expr.trim();

  // Extract the leading field name (word characters only) – simple, no backtracking.
  const fieldMatch = /^(\w+)/.exec(trimmed);
  if (!fieldMatch) return null;
  const field = fieldMatch[1]!;

  // Everything after the field name with leading whitespace stripped.
  const rest = trimmed.slice(field.length).trimStart();

  // Each keyword check below uses a bounded prefix-only regex (no `.+` tail capture).
  // The actual value is recovered with `slice(matchedPrefix.length)` – no backtracking.

  // NOT LIKE
  const notLikePrefix = /^NOT\s+LIKE\s+/i.exec(rest);
  if (notLikePrefix) {
    return {
      field,
      op: 'NOT LIKE',
      value: rest.slice(notLikePrefix[0].length).trim(),
      caseless: true,
    };
  }

  // LIKE
  const likePrefix = /^LIKE\s+/i.exec(rest);
  if (likePrefix) {
    return { field, op: 'LIKE', value: rest.slice(likePrefix[0].length).trim(), caseless: true };
  }

  // NOT IN ( ... )
  const notInPrefix = /^NOT\s+IN\s*\(/i.exec(rest);
  if (notInPrefix) {
    const inner = rest.slice(notInPrefix[0].length, rest.lastIndexOf(')'));
    const values = inner.split(',').map((v) => v.trim().replace(/^'|'$/g, ''));
    return { field, op: 'NOT IN', value: values };
  }

  // IN ( ... )
  const inPrefix = /^IN\s*\(/i.exec(rest);
  if (inPrefix) {
    const inner = rest.slice(inPrefix[0].length, rest.lastIndexOf(')'));
    const values = inner.split(',').map((v) => v.trim().replace(/^'|'$/g, ''));
    return { field, op: 'IN', value: values };
  }

  // Comparison operators – plain startsWith, zero regex.
  for (const op of COMPARISON_OPS) {
    if (rest.startsWith(op)) {
      const rawValue = rest.slice(op.length).trim().replace(/^'|'$/g, '');
      const numValue = Number(rawValue);
      const value = Number.isNaN(numValue) ? rawValue : numValue;
      return { field, op, value };
    }
  }

  return null;
}

// ── Filter evaluation ─────────────────────────────────────────────────────────

function matchesCondition(row: Record<string, any>, cond: Condition): boolean {
  const rawFieldValue = row[cond.field];
  if (rawFieldValue === undefined) return false;

  const fieldStr = String(rawFieldValue).toLowerCase();
  const condStr = cond.caseless ? String(cond.value).toLowerCase() : String(cond.value);

  switch (cond.op) {
    case '=':
      return String(rawFieldValue) === String(cond.value);
    case '!=':
      return String(rawFieldValue) !== String(cond.value);
    case '>':
      return Number(rawFieldValue) > Number(cond.value);
    case '>=':
      return Number(rawFieldValue) >= Number(cond.value);
    case '<':
      return Number(rawFieldValue) < Number(cond.value);
    case '<=':
      return Number(rawFieldValue) <= Number(cond.value);
    case 'LIKE': {
      // SQL LIKE: % = wildcard, _ = single char
      const pattern = condStr.replace(/%/g, '.*').replace(/_/g, '.');
      return new RegExp(`^${pattern}$`, 'i').test(fieldStr);
    }
    case 'NOT LIKE': {
      const pattern = condStr.replace(/%/g, '.*').replace(/_/g, '.');
      return !new RegExp(`^${pattern}$`, 'i').test(fieldStr);
    }
    case 'IN':
      return (cond.value as string[]).some((v) => String(rawFieldValue) === v);
    case 'NOT IN':
      return !(cond.value as string[]).some((v) => String(rawFieldValue) === v);
    default:
      return false;
  }
}

function matchesWhere(row: Record<string, any>, conditions: Condition[] | null): boolean {
  if (!conditions || conditions.length === 0) return true;
  return conditions.every((c) => matchesCondition(row, c));
}

// ── Aggregation engine ────────────────────────────────────────────────────────

function runAggregation(entries: any[], agg: NonNullable<ParsedQuery['aggregation']>): string {
  const { fn, field, groupBy } = agg;

  if (!groupBy) return pc.yellow('Aggregation requires a GROUP BY field');

  // Build groups
  const groups: Record<string, any[]> = {};
  for (const entry of entries) {
    const key = String(entry[groupBy] ?? '(empty)');
    if (!groups[key]) groups[key] = [];
    groups[key].push(entry);
  }

  if (fn === 'COUNT' || fn === 'GROUP') {
    const rows = Object.entries(groups)
      .map(([k, v]) => ({ [groupBy]: k, count: v.length }))
      .sort((a, b) => b.count - a.count);

    return formatAsTable(rows, [groupBy, 'count']);
  }

  // AVG / SUM / MIN / MAX require a numeric field
  if (!field) return pc.yellow('Numeric aggregation requires a field: AVG(field) BY group');

  const rows = Object.entries(groups)
    .map(([k, v]) => {
      const nums = v.map((e) => Number(e[field!])).filter((n) => !Number.isNaN(n));
      let result: number;
      switch (fn) {
        case 'AVG':
          result = nums.length ? nums.reduce((a, b) => a + b, 0) / nums.length : 0;
          break;
        case 'SUM':
          result = nums.reduce((a, b) => a + b, 0);
          break;
        case 'MIN':
          result = nums.length ? Math.min(...nums) : 0;
          break;
        case 'MAX':
          result = nums.length ? Math.max(...nums) : 0;
          break;
        default:
          result = 0;
      }
      return { [groupBy]: k, [`${fn}(${field})`]: Math.round(result * 100) / 100, count: v.length };
    })
    .sort((a, b) => {
      const key = `${fn}(${field})`;
      return (b[key] as number) - (a[key] as number);
    });

  return formatAsTable(rows, [groupBy, `${fn}(${field})`, 'count']);
}

// ── Format results ────────────────────────────────────────────────────────────

function projectRow(row: Record<string, any>, select: string[] | '*'): Record<string, any> {
  if (select === '*') return row;
  const projected: Record<string, any> = {};
  for (const field of select) {
    projected[field] = row[field];
  }
  return projected;
}

function formatResults(results: any[], format: string): string {
  if (results.length === 0) return pc.yellow('No results found');

  if (format === 'json') {
    return JSON.stringify(results, null, 2);
  }

  if (format === 'ndjson') {
    return results.map((r) => JSON.stringify(r)).join('\n');
  }

  if (format === 'table') {
    const columns = Object.keys(results[0] || {}).slice(0, 6);
    return formatAsTable(results, columns);
  }

  // Default: one JSON per line with colored level
  return results
    .map((r) => {
      const level = (r.level || '').toUpperCase();
      const line = JSON.stringify(r);
      if (level === 'ERROR' || level === 'CRITICAL') return pc.red(line);
      if (level === 'WARN') return pc.yellow(line);
      if (level === 'DEBUG' || level === 'VERBOSE') return pc.gray(line);
      return line;
    })
    .join('\n');
}

// ── Execute a query against an array of log entries ───────────────────────────

export function executeQuery(
  entries: any[],
  opts: {
    sql?: string;
    since?: string;
    until?: string;
    limit?: number;
    orderBy?: string;
  }
): { results: any[]; aggregationOutput: string | null } {
  let rows: any[] = entries;

  // ── Time filtering ─────────────────────────────────────────────────────────
  const sinceDate = opts.since ? parseTimeRange(opts.since) : undefined;
  const untilDate = opts.until ? parseTimeRange(opts.until) : undefined;

  if (sinceDate || untilDate) {
    rows = rows.filter((row) => {
      const ts = row.timestamp ? new Date(row.timestamp as string) : null;
      if (!ts || Number.isNaN(ts.getTime())) return true; // keep rows without timestamp
      if (sinceDate && ts < sinceDate) return false;
      if (untilDate && ts > untilDate) return false;
      return true;
    });
  }

  // ── Parse SQL ─────────────────────────────────────────────────────────────
  const query = opts.sql
    ? parseSQL(opts.sql)
    : {
        select: '*' as const,
        where: null,
        conjunction: null,
        aggregation: null,
        orderBy: null,
        limit: null,
      };

  // ── WHERE filter ──────────────────────────────────────────────────────────
  if (query.where) {
    rows = rows.filter((row) => matchesWhere(row, query.where));
  }

  // ── Aggregation ───────────────────────────────────────────────────────────
  if (query.aggregation) {
    return { results: [], aggregationOutput: runAggregation(rows, query.aggregation) };
  }

  // ── SELECT projection ─────────────────────────────────────────────────────
  rows = rows.map((row) => projectRow(row, query.select));

  // ── ORDER BY ──────────────────────────────────────────────────────────────
  const orderField = query.orderBy?.field ?? opts.orderBy;
  if (orderField) {
    const dir = query.orderBy?.dir ?? 'ASC';
    rows.sort((a, b) => {
      const av = a[orderField];
      const bv = b[orderField];
      if (av === undefined && bv === undefined) return 0;
      if (av === undefined) return dir === 'ASC' ? 1 : -1;
      if (bv === undefined) return dir === 'ASC' ? -1 : 1;
      if (typeof av === 'number' && typeof bv === 'number') {
        return dir === 'ASC' ? av - bv : bv - av;
      }
      return dir === 'ASC'
        ? String(av).localeCompare(String(bv))
        : String(bv).localeCompare(String(av));
    });
  }

  // ── LIMIT ─────────────────────────────────────────────────────────────────
  const limitN = query.limit ?? opts.limit;
  if (limitN && limitN > 0) {
    rows = rows.slice(0, limitN);
  }

  return { results: rows, aggregationOutput: null };
}

// ── Commander command ─────────────────────────────────────────────────────────

export const queryCommand = new Command('query')
  .description(
    'Query log files with SQL-like syntax\n\n' +
      '  Examples:\n' +
      '    logixia query app.log --sql "SELECT * FROM logs WHERE level=\'error\'"\n' +
      '    logixia query app.log --sql "COUNT BY level"\n' +
      '    logixia query app.log --sql "AVG(duration) BY endpoint"\n' +
      '    logixia query app.log --since "last 2 hours" --format table\n' +
      '    logixia query app.log --follow --sql "WHERE level=\'error\'"\n'
  )
  .argument('<file>', 'Path to NDJSON or JSON log file')
  .option('--sql <query>', 'SQL-like query string')
  .option('--since <time>', 'Only include entries after this time (e.g. "last 2 hours", "today")')
  .option('--until <time>', 'Only include entries before this time')
  .option('--limit <n>', 'Maximum number of results to return', '0')
  .option('--order-by <field>', 'Sort results by this field')
  .option('--format <fmt>', 'Output format: line, table, json, ndjson', 'line')
  .option('--follow', 'Follow file for new entries matching the query (tail mode)', false)
  .action(async (file: string, opts: any) => {
    const full = path.resolve(process.cwd(), file);
    if (!fs.existsSync(full)) {
      console.error(pc.red(`File not found: ${full}`));
      process.exit(2);
    }

    const raw = fs.readFileSync(full, 'utf8');
    const entries = safeParseLogs(raw);

    const limitN = opts.limit ? Number.parseInt(opts.limit, 10) : 0;

    const { results, aggregationOutput } = executeQuery(entries, {
      sql: opts.sql,
      since: opts.since,
      until: opts.until,
      limit: limitN,
      orderBy: opts.orderBy,
    });

    if (aggregationOutput !== null) {
      console.log(pc.bold('\nAggregation result:'));
      console.log(aggregationOutput);
    } else {
      console.log(
        pc.bold(
          `\nFound ${pc.cyan(String(results.length))} match${results.length === 1 ? '' : 'es'}`
        )
      );
      if (results.length > 0) {
        console.log(formatResults(results, opts.format || 'line'));
      }
    }

    // ── Live tail mode ─────────────────────────────────────────────────────
    if (opts.follow) {
      console.log(pc.dim('\n--- following (ctrl-c to exit) ---'));
      let pos = fs.statSync(full).size;
      let buffer = '';

      fs.watchFile(full, { interval: 300 }, (curr) => {
        if (curr.size <= pos) return;
        const rs = fs.createReadStream(full, { start: pos, end: curr.size, encoding: 'utf8' });
        rs.on('data', (chunk: Buffer | string) => {
          buffer += chunk;
          const lines = buffer.split(/\r?\n/);
          buffer = lines.pop() ?? '';

          for (const line of lines.filter(Boolean)) {
            try {
              const parsed = JSON.parse(line);
              const { results: tailResults } = executeQuery([parsed], {
                sql: opts.sql,
                since: opts.since,
                until: opts.until,
              });
              if (tailResults.length > 0) {
                console.log(formatResults(tailResults, opts.format || 'line'));
              }
            } catch {
              // Not JSON — print raw if no SQL filter
              if (!opts.sql) console.log(line);
            }
          }
        });
        rs.on('end', () => {
          pos = curr.size;
        });
      });
    }
  });
