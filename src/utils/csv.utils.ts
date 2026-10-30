const CSV_FORMULA_PREFIX = /^[=+\-@\t\r]/;

/**
 * Render one CSV field. String values that a spreadsheet would treat as a
 * formula (leading `=`, `+`, `-`, `@`, tab or CR) are prefixed with `'`.
 * Objects are JSON-encoded. Fields containing a comma, quote, CR or LF are quoted;
 * `alwaysQuote` quotes every field. `null` / `undefined` render as empty.
 */
export function csvField(value: unknown, alwaysQuote = false): string {
  if (value === undefined || value === null) return alwaysQuote ? '""' : '';
  let str: string;
  if (typeof value === 'string') {
    str = CSV_FORMULA_PREFIX.test(value) ? `'${value}` : value;
  } else if (typeof value === 'object') {
    str = JSON.stringify(value);
  } else {
    str = String(value);
  }
  if (alwaysQuote || /[",\r\n]/.test(str)) return `"${str.replace(/"/g, '""')}"`;
  return str;
}
