import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { analyzeFileContents } from '../commands/analyze';
import { executeQuery, queryCommand } from '../commands/query';
import { searchCommand, searchLogsWithContext } from '../commands/search';
import { parseLogLines } from '../utils';

// eslint-disable-next-line no-control-regex -- strip ANSI colors
const strip = (s: string): string => s.replace(/\u001b\[[0-9;]*m/g, '');

describe('parseLogLines', () => {
  it('keeps original file line numbers across blank lines', () => {
    const rows = parseLogLines('{"a":1}\n\n\nplain text\n{"b":2}');
    expect(rows.map((r) => r.line)).toEqual([1, 4, 5]);
    expect(rows[1]!.entry).toEqual({ message: 'plain text' });
  });
});

describe('searchLogsWithContext', () => {
  const raw = [
    '{"message":"a"}',
    '',
    '{"message":"hit"}',
    '',
    '',
    '{"message":"b"}',
    '{"message":"c"}',
    '{"message":"d"}',
    '{"message":"hit2"}',
  ].join('\n');

  it('reports real file line numbers', async () => {
    const hits = await searchLogsWithContext(raw, { query: 'message:hit', context: 1 });
    expect(hits.map((h) => [h.line, h.match])).toEqual([
      [1, false],
      [3, true],
      [6, false],
      [8, false],
      [9, true],
    ]);
  });

  it('handles context larger than the file and adjacent matches', async () => {
    const hits = await searchLogsWithContext(raw, { query: 'message:hit', context: 100 });
    expect(hits).toHaveLength(6);
  });

  it('is linear on large inputs', async () => {
    const big = Array.from({ length: 50_000 }, (_, i) => `{"message":"m${i}"}`).join('\n');
    const t = Date.now();
    const hits = await searchLogsWithContext(big, { query: 'message:m25000', context: 1000 });
    expect(hits.length).toBeGreaterThan(1000);
    expect(Date.now() - t).toBeLessThan(2000);
  });
});

describe('analyze csv sanitizing', () => {
  it('escapes terminal control sequences in level names', async () => {
    const raw = JSON.stringify({ level: '\u001b]0;pwned\u0007x', message: 'm' });
    const out = (await analyzeFileContents(raw, { format: 'csv' })) as string;
    expect(out).not.toContain('\u001b');
    expect(out).not.toContain('\u0007');
    expect(out).toContain('\\x1b');
  });
});

describe('query machine formats', () => {
  const entries = [
    { level: 'info', message: 'a' },
    { level: 'info', message: 'b' },
    { level: 'error', message: 'c' },
  ];

  it('executeQuery exposes structured aggregation rows', () => {
    const r = executeQuery(entries, { sql: 'COUNT BY level' });
    expect(r.aggregationRows).toEqual([
      { level: 'info', count: 2 },
      { level: 'error', count: 1 },
    ]);
  });

  describe('via the command', () => {
    let dir: string;
    let file: string;
    let out: string[];
    let err: string[];

    beforeEach(() => {
      dir = fs.mkdtempSync(path.join(os.tmpdir(), 'logixia-cli-'));
      file = path.join(dir, 'app.log');
      fs.writeFileSync(file, entries.map((e) => JSON.stringify(e)).join('\n'));
      out = [];
      err = [];
      jest
        .spyOn(console, 'log')
        .mockImplementation((...a: unknown[]) => void out.push(a.join(' ')));
      jest
        .spyOn(console, 'error')
        .mockImplementation((...a: unknown[]) => void err.push(a.join(' ')));
    });

    afterEach(() => {
      jest.restoreAllMocks();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    const run = (sql: string, format: string) =>
      queryCommand.parseAsync(['node', 'query', file, '--sql', sql, '--format', format]);

    it('json aggregation is a parseable array', async () => {
      await run('COUNT BY level', 'json');
      expect(JSON.parse(out.join('\n'))).toEqual([
        { level: 'info', count: 2 },
        { level: 'error', count: 1 },
      ]);
      expect(strip(err.join('\n'))).toContain('Aggregation result');
    });

    it('ndjson aggregation is one object per line', async () => {
      await run('COUNT BY level', 'ndjson');
      expect(
        out
          .join('\n')
          .split('\n')
          .map((l) => JSON.parse(l))
      ).toEqual([
        { level: 'info', count: 2 },
        { level: 'error', count: 1 },
      ]);
    });

    it('zero results print [] for json and nothing for ndjson', async () => {
      await run("WHERE level = 'nope'", 'json');
      expect(JSON.parse(out.join('\n'))).toEqual([]);
      out.length = 0;
      await run("WHERE level = 'nope'", 'ndjson');
      expect(out).toEqual([]);
      expect(strip(err.join('\n'))).toContain('Found 0 matches');
    });
  });
});

describe('search table with context', () => {
  let dir: string;
  let out: string[];

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'logixia-cli-'));
    out = [];
    jest.spyOn(console, 'log').mockImplementation((...a: unknown[]) => void out.push(a.join(' ')));
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('marks matches and builds columns from matched rows', async () => {
    const file = path.join(dir, 'app.log');
    fs.writeFileSync(
      file,
      ['{"noise":1}', '{"level":"error","message":"boom"}', '{"noise":2}'].join('\n')
    );
    await searchCommand.parseAsync([
      'node',
      'search',
      file,
      '--query',
      'message:boom',
      '--context',
      '1',
      '--format',
      'table',
    ]);
    const text = strip(out.join('\n'));
    const [header, ...rows] = text
      .split('\n')
      .filter((l) => l.trim() && !/^[-+| ]+$/.test(l) && !l.startsWith('Found'));
    expect(header).toMatch(/match/);
    expect(header).toMatch(/level/);
    expect(header).toMatch(/message/);
    expect(rows.filter((r) => r.includes('*'))).toHaveLength(1);
    expect(rows.find((r) => r.includes('*'))).toContain('boom');
  });
});
