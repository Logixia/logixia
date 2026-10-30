/* eslint-disable no-control-regex -- tests assert on control characters */
import { exportLogs } from '../commands/export';
import { executeQuery } from '../commands/query';
import { generateStats } from '../commands/stats';
import { highlightLine } from '../commands/tail';
import { buildDetailLines } from '../commands/explore';
import {
  csvField,
  escapeRegExp,
  formatAsTable,
  sanitizeForTerminal,
  sanitizeInline,
} from '../utils';

const ESC = '\u001b';

describe('sanitizeForTerminal', () => {
  it('escapes ESC, CR, BEL, DEL and C1 controls but keeps tab and newline', () => {
    const out = sanitizeForTerminal(`a${ESC}[2Jb\rc\u0007d\u007fe\u009bf\tg\nh`);
    expect(out).toBe('a\\x1b[2Jb\\x0dc\\x07d\\x7fe\\x9bf\tg\nh');
    expect(out).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/);
  });

  it('sanitizeInline also escapes newline and tab', () => {
    expect(sanitizeInline('a\nb\tc')).toBe('a\\nb\\tc');
  });
});

describe('terminal output is sanitized', () => {
  it('tail highlightLine strips escapes from raw and JSON lines', () => {
    expect(highlightLine(`plain ${ESC}[2J line`)).not.toContain(ESC);
    expect(highlightLine(`{"level":"info","m":"${ESC}[2J"}`, 'x')).not.toContain(
      `${ESC}[2J`
    );
  });

  it('formatAsTable escapes control characters in cells', () => {
    const out = formatAsTable([{ message: JSON.parse(`"a\\u001b[2Jb"`) }], ['message']);
    expect(out).not.toContain(ESC);
    expect(out).toContain('\\x1b');
  });

  it('explore detail view escapes control characters', () => {
    const lines = buildDetailLines({
      message: 'x\u009by',
      stack: `Error\n  at ${ESC}]0;t\u0007 (f.js:1:1)`,
    } as never);
    // picocolors may add its own SGR codes, so check for the unescaped payload only
    expect(lines.join('\n')).not.toContain(`${ESC}]0;`);
    expect(lines.join('\n')).not.toContain('\u009b');
  });

  it('stats distribution keys are escaped in the data model', async () => {
    const stats = await generateStats(`{"level":"a\\u001b[2J"}\n`);
    expect(Object.keys(stats.distribution)).toHaveLength(1);
  });
});

describe('CSV export', () => {
  it('prefixes formula-like strings and quotes CR fields', async () => {
    const raw = [
      JSON.stringify({ a: '=1+1', b: '+SUM(A1)', c: '-2+3', d: '@x', e: '\t=x', f: 'a\rb' }),
    ].join('\n');
    const csv = await exportLogs(raw, { format: 'csv' });
    const row = csv.split('\n').slice(1).join('\n');
    expect(row).toContain("'=1+1");
    expect(row).toContain("'+SUM(A1)");
    expect(row).toContain("'-2+3");
    expect(row).toContain("'@x");
    expect(row).toContain("'\t=x");
    expect(row).toContain('"a\rb"');
  });

  it('does not alter numbers', async () => {
    const csv = await exportLogs(JSON.stringify({ n: -5 }), { format: 'csv' });
    expect(csv.split('\n')[1]).toBe('-5');
  });

  it('csvField neutralizes leading CR and quotes it', () => {
    expect(csvField('\r=1')).toBe('"\'\r=1"');
  });
});

describe('query hardening', () => {
  const log = ['info', 'constructor', '__proto__', 'toString', 'info']
    .map((level) => JSON.stringify({ level, message: 'm' }))
    .join('\n');

  it('COUNT BY handles prototype-named values', () => {
    const entries = log.split('\n').map((l) => JSON.parse(l));
    const { aggregationOutput } = executeQuery(entries, { sql: 'COUNT BY level' });
    expect(aggregationOutput).toContain('constructor');
    expect(aggregationOutput).toContain('__proto__');
    expect(aggregationOutput).toContain('toString');
  });

  it('stats handles prototype-named values', async () => {
    const stats = await generateStats(log);
    expect(stats.distribution['CONSTRUCTOR']).toBe(1);
    expect(stats.total).toBe(5);
  });

  it('LIKE treats regex metacharacters literally', () => {
    const entries = [{ message: 'a.b' }, { message: 'axb' }, { message: '(x)' }];
    const run = (sql: string) => executeQuery(entries, { sql }).results.map((r) => r.message);
    expect(run("SELECT * FROM logs WHERE message LIKE 'a.b'")).toEqual(['a.b']);
    expect(run("SELECT * FROM logs WHERE message LIKE '(x)'")).toEqual(['(x)']);
    expect(run("SELECT * FROM logs WHERE message LIKE 'a_b'")).toEqual(['a.b', 'axb']);
    expect(run("SELECT * FROM logs WHERE message LIKE '%x%'")).toEqual(['axb', '(x)']);
  });

  it('LIKE with an invalid-regex pattern does not throw', () => {
    expect(() =>
      executeQuery([{ message: 'x' }], { sql: "SELECT * FROM logs WHERE message LIKE '(['" })
    ).not.toThrow();
  });
});

describe('tail --highlight', () => {
  it('matches the pattern literally', () => {
    expect(() => highlightLine('plain text', '(')).not.toThrow();
    expect(highlightLine('a.b axb', 'a.b')).toContain('a.b');
    expect(escapeRegExp('a.b(')).toBe('a\\.b\\(');
  });
});
