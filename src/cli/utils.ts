/* eslint-disable @typescript-eslint/no-explicit-any -- CLI tools process raw JSON log data */

/**
 * Render a single cell value. Uses a null/undefined check rather than `||` so
 * falsy-but-real values (0, false, '') still render — a `count=0` or
 * `statusCode=0` field must not silently display as blank.
 */
function cellText(value: unknown): string {
  return value === null || value === undefined ? '' : String(value);
}

export function formatAsTable(rows: any[], columns: string[]) {
  // very small table printer
  const colWidths: number[] = columns.map((c) =>
    Math.max(c.length, ...rows.map((r) => cellText(r[c]).length))
  );
  const hdr = columns.map((c, i) => c.padEnd(colWidths[i] ?? 0)).join(' | ');
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
