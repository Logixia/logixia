/**
 * Tests for the CLI table/parse helpers.
 *
 * Key regression: formatAsTable used `(r[c] || '')`, so a falsy-but-real value
 * (0, false, '') rendered as blank — a count=0 / statusCode=0 column silently
 * disappeared. Cells must render real values.
 */

import { formatAsTable, safeParseLogs } from '../utils';

describe('formatAsTable', () => {
  it('renders header, separator, and rows', () => {
    const out = formatAsTable([{ a: '1', b: 'x' }], ['a', 'b']);
    const lines = out.split('\n');
    expect(lines[0]).toContain('a');
    expect(lines[0]).toContain('b');
    expect(lines[2]).toContain('1');
    expect(lines[2]).toContain('x');
  });

  it('renders falsy-but-real values (0, false) instead of blanks', () => {
    const out = formatAsTable([{ count: 0, ok: false }], ['count', 'ok']);
    expect(out).toContain('0');
    expect(out).toContain('false');
  });

  it('does not crash on an empty rows array', () => {
    expect(() => formatAsTable([], ['a', 'b'])).not.toThrow();
    const out = formatAsTable([], ['a', 'b']);
    expect(out).toContain('a');
  });

  it('handles missing fields as empty cells', () => {
    const out = formatAsTable([{ a: 'present' }], ['a', 'missing']);
    expect(out).toContain('present');
  });
});

describe('safeParseLogs', () => {
  it('parses JSON lines into objects', () => {
    const raw = '{"level":"info","message":"a"}\n{"level":"error","message":"b"}';
    const parsed = safeParseLogs(raw);
    expect(parsed).toHaveLength(2);
    expect(parsed[0].level).toBe('info');
    expect(parsed[1].message).toBe('b');
  });

  it('falls back to a message wrapper for non-JSON lines', () => {
    const raw = 'plain text line\n{"message":"json line"}';
    const parsed = safeParseLogs(raw);
    expect(parsed).toHaveLength(2);
    expect(parsed[0]).toEqual({ message: 'plain text line' });
    expect(parsed[1].message).toBe('json line');
  });

  it('ignores blank lines', () => {
    const raw = '{"a":1}\n\n\n{"b":2}\n';
    expect(safeParseLogs(raw)).toHaveLength(2);
  });
});
