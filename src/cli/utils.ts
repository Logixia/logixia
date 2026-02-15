export function formatAsTable(rows: any[], columns: string[]) {
  // very small table printer
  const colWidths: number[] = columns.map(c => Math.max(c.length, ...rows.map(r => (r[c] || '').toString().length)));
  const hdr = columns.map((c,i) => c.padEnd(colWidths[i] ?? 0)).join(' | ');
  const sep = colWidths.map(w => '-'.repeat(w)).join('-|-');
  const body = rows.map(r => columns.map((c,i) => (r[c] || '').toString().padEnd(colWidths[i] ?? 0)).join(' | ')).join('\n');
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
    } catch (e) {
      // not json
    }
    parsed.push({ message: l });
  }
  return parsed;
}
