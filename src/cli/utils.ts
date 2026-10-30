/* eslint-disable @typescript-eslint/no-explicit-any -- CLI tools process raw JSON log data */

export { csvField } from '../utils/csv.utils';

/**
 * Render a single cell value. Uses a null/undefined check rather than `||` so
 * falsy-but-real values (0, false, '') still render — a `count=0` or
 * `statusCode=0` field must not silently display as blank.
 */
function cellText(value: unknown): string {
  return value === null || value === undefined ? '' : sanitizeInline(String(value));
}

// C0 controls (except tab and newline), DEL, C1 controls and the Unicode line/paragraph separators.
// eslint-disable-next-line no-control-regex -- matching control characters is the purpose
const TERMINAL_UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029]/g;

function escapeChar(ch: string): string {
  const code = ch.charCodeAt(0);
  return code <= 0xff
    ? `\\x${code.toString(16).padStart(2, '0')}`
    : `\\u${code.toString(16).padStart(4, '0')}`;
}

/**
 * Make untrusted log text safe to print: control characters (ESC, CR, BEL, C1
 * codes, ...) are replaced by a visible `\xNN` escape. Tabs and newlines are kept
 * so multi-line output the CLI formats itself is unaffected.
 */
export function sanitizeForTerminal(text: string): string {
  return text.replace(TERMINAL_UNSAFE, escapeChar);
}

/** Like {@link sanitizeForTerminal} but also escapes newlines and tabs (single-line cells). */
export function sanitizeInline(text: string): string {
  return sanitizeForTerminal(text).replace(/\n/g, '\\n').replace(/\t/g, '\\t');
}

/** Escape regular-expression metacharacters so `text` matches literally. */
export function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function formatAsTable(rows: any[], columns: string[]) {
  // very small table printer
  const colWidths: number[] = columns.map((c) =>
    Math.max(sanitizeInline(c).length, ...rows.map((r) => cellText(r[c]).length))
  );
  const hdr = columns.map((c, i) => sanitizeInline(c).padEnd(colWidths[i] ?? 0)).join(' | ');
  const sep = colWidths.map((w) => '-'.repeat(w)).join('-|-');
  const body = rows
    .map((r) => columns.map((c, i) => cellText(r[c]).padEnd(colWidths[i] ?? 0)).join(' | '))
    .join('\n');
  return [hdr, sep, body].join('\n');
}

export function safeParseLogs(raw: string) {
  // try JSON lines first, fallback to simple line parser
  const lines = raw.split(/\r?\n/).filter(Boolean);
  const parsed: any[] = [];
  for (const l of lines) {
    try {
      const j = JSON.parse(l);
      parsed.push(j);
      continue;
    } catch {
      // not json
    }
    parsed.push({ message: l });
  }
  return parsed;
}
