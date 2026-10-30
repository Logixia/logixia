import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { analyzeCommand, analyzeFileContents } from '../commands/analyze';
import { queryCommand } from '../commands/query';
import { searchCommand, searchLogsWithContext } from '../commands/search';

const RAW = [
  { level: 'info', message: 'one' },
  { level: 'info', message: 'two' },
  { level: 'error', message: 'boom' },
  { level: 'info', message: 'four' },
  { level: 'info', message: 'five' },
  { level: 'info', message: 'six' },
  { level: 'info', message: 'seven' },
  { level: 'warn', message: 'boom again' },
]
  .map((e) => JSON.stringify(e))
  .join('\n');

// eslint-disable-next-line no-control-regex -- strip ANSI colors
const strip = (s: string): string => s.replace(/\u001b\[[0-9;]*m/g, '');

describe('analyze --format csv', () => {
  it('renders header and one row per level', async () => {
    const out = await analyzeFileContents(RAW, { format: 'csv' });
    expect(out).toBe('level,count\nINFO,6\nERROR,1\nWARN,1');
  });

  it('renders only the header for empty input', async () => {
    expect(await analyzeFileContents('', { format: 'csv' })).toBe('level,count');
  });
});

describe('searchLogsWithContext', () => {
  it('returns matches only when context is 0', async () => {
    const hits = await searchLogsWithContext(RAW, { query: 'boom' });
    expect(hits.map((h) => [h.line, h.match])).toEqual([
      [3, true],
      [8, true],
    ]);
  });

  it('includes N surrounding entries and flags them as context', async () => {
    const hits = await searchLogsWithContext(RAW, { query: 'message:boom', context: '1' });
    expect(hits.map((h) => [h.line, h.match])).toEqual([
      [2, false],
      [3, true],
      [4, false],
      [7, false],
      [8, true],
    ]);
  });
});

describe('CLI stdout stays machine readable', () => {
  let dir: string;
  let file: string;
  let out: string[];
  let err: string[];

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'logixia-cli-'));
    file = path.join(dir, 'app.log');
    fs.writeFileSync(file, RAW);
    out = [];
    err = [];
    jest.spyOn(console, 'log').mockImplementation((...a: unknown[]) => void out.push(a.join(' ')));
    jest
      .spyOn(console, 'error')
      .mockImplementation((...a: unknown[]) => void err.push(a.join(' ')));
  });

  afterEach(() => {
    jest.restoreAllMocks();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('search --format json prints only JSON on stdout', async () => {
    await searchCommand.parseAsync(['node', 'search', file, '--query', 'boom', '--format', 'json']);
    const parsed = JSON.parse(out.join('\n'));
    expect(parsed).toHaveLength(2);
    expect(strip(err.join('\n'))).toContain('Found 2 matches');
  });

  it('search --context prints grep-style context lines', async () => {
    await searchCommand.parseAsync([
      'node',
      'search',
      file,
      '--query',
      'message:boom',
      '--context',
      '1',
      '--format',
      'line',
    ]);
    const lines = strip(out.join('\n')).split('\n');
    expect(lines.some((l) => l.startsWith('2- '))).toBe(true);
    expect(lines.some((l) => l.startsWith('3: '))).toBe(true);
    expect(lines).toContain('--');
  });

  it('query --format ndjson prints only NDJSON on stdout', async () => {
    await queryCommand.parseAsync([
      'node',
      'query',
      file,
      '--sql',
      "WHERE level = 'info'",
      '--format',
      'ndjson',
    ]);
    const lines = out.join('\n').split('\n').filter(Boolean);
    expect(lines.length).toBeGreaterThan(0);
    for (const l of lines) expect(() => JSON.parse(l)).not.toThrow();
    expect(strip(err.join('\n'))).toMatch(/Found \d+ match/);
  });

  it('analyze --format csv prints CSV through the command', async () => {
    await analyzeCommand.parseAsync(['node', 'analyze', file, '--format', 'csv']);
    expect(out.join('\n')).toBe('level,count\nINFO,6\nERROR,1\nWARN,1');
  });
});
