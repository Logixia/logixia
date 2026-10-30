import { exportLogs } from '../commands/export';
import { searchLogs } from '../commands/search';
import { generateStats } from '../commands/stats';

// safeParseLogs keeps a non-JSON line as `{ message: <line> }` instead of dropping or throwing.
const raw = [
  JSON.stringify({
    timestamp: '2024-01-01T10:00:00.000Z',
    level: 'info',
    message: 'started, ready',
    user_id: '123',
  }),
  'this is not json {',
  JSON.stringify({
    timestamp: '2024-01-01T12:00:00.000Z',
    level: 'error',
    message: 'said "boom"',
    user_id: '456',
  }),
  JSON.stringify({
    timestamp: '2024-01-01T11:00:00.000Z',
    level: 'info',
    message: 'plain',
    user_id: '123',
  }),
].join('\n');

describe('exportLogs', () => {
  it('writes a CSV header and one row per entry (malformed line becomes a message-only row)', async () => {
    const out = await exportLogs(raw, { format: 'csv', fields: 'level,message' });
    const lines = out.split('\n');
    expect(lines[0]).toBe('level,message');
    expect(lines).toHaveLength(5);
    expect(lines[2]).toBe(',this is not json {');
  });

  it('derives CSV columns from the first entry when no fields are given', async () => {
    const out = await exportLogs(raw, { format: 'csv' });
    expect(out.split('\n')[0]).toBe('timestamp,level,message,user_id');
  });

  it('escapes commas and quotes in CSV fields', async () => {
    const out = await exportLogs(raw, { format: 'csv', fields: 'message' });
    const lines = out.split('\n');
    expect(lines[1]).toBe('"started, ready"');
    expect(lines[3]).toBe('"said ""boom"""');
  });

  it('neutralises spreadsheet formulas in CSV cells', async () => {
    const out = await exportLogs(JSON.stringify({ message: '=SUM(A1)' }), {
      format: 'csv',
      fields: 'message',
    });
    expect(out.split('\n')[1]).toBe("'=SUM(A1)");
  });

  it('returns an empty string for CSV of no entries', async () => {
    expect(await exportLogs('', { format: 'csv' })).toBe('');
  });

  it('limits CSV columns with fields (trimming whitespace)', async () => {
    const out = await exportLogs(raw, { format: 'csv', fields: ' level , user_id ' });
    expect(out.split('\n').slice(0, 2)).toEqual(['level,user_id', 'info,123']);
  });

  it('JSON output round-trips to the same entries', async () => {
    const out = await exportLogs(raw, { format: 'json' });
    const parsed = JSON.parse(out);
    expect(parsed).toHaveLength(4);
    expect(parsed[1]).toEqual({ message: 'this is not json {' });
    expect(parsed[2]).toEqual({
      timestamp: '2024-01-01T12:00:00.000Z',
      level: 'error',
      message: 'said "boom"',
      user_id: '456',
    });
  });

  it('JSON output with fields keeps only those fields', async () => {
    const out = await exportLogs(raw, { format: 'json', fields: 'level,missing' });
    expect(JSON.parse(out)).toEqual([{ level: 'info' }, {}, { level: 'error' }, { level: 'info' }]);
  });

  it('defaults to JSON when no format is given', async () => {
    const out = await exportLogs(raw);
    expect(JSON.parse(out)).toHaveLength(4);
  });
});

describe('generateStats', () => {
  it('counts per level (upper-cased) and the total, bucketing malformed lines as UNKNOWN', async () => {
    const stats = await generateStats(raw);
    expect(stats.total).toBe(4);
    expect(stats.groupBy).toBe('level');
    expect({ ...stats.distribution }).toEqual({ INFO: 2, UNKNOWN: 1, ERROR: 1 });
  });

  it('reports the time range', async () => {
    const stats = await generateStats(raw);
    expect(stats.timeRange?.start.toISOString()).toBe('2024-01-01T10:00:00.000Z');
    expect(stats.timeRange?.end.toISOString()).toBe('2024-01-01T12:00:00.000Z');
  });

  it('groups by another field', async () => {
    const stats = await generateStats(raw, { groupBy: 'user_id' });
    expect(stats.groupBy).toBe('user_id');
    expect({ ...stats.distribution }).toEqual({ '123': 2, '456': 1, UNKNOWN: 1 });
  });

  it('handles empty input', async () => {
    const stats = await generateStats('');
    expect(stats.total).toBe(0);
    expect({ ...stats.distribution }).toEqual({});
    expect(stats.timeRange).toBeNull();
  });
});

describe('searchLogs', () => {
  it('matches a plain-text query across all fields, case-insensitively', async () => {
    const results = await searchLogs(raw, { query: 'BOOM' });
    expect(results).toHaveLength(1);
    expect((results[0] as Record<string, unknown>)['user_id']).toBe('456');
  });

  it('supports field:value queries', async () => {
    const results = await searchLogs(raw, { query: 'user_id:123' });
    expect(results).toHaveLength(2);
  });

  it('field:value does not match other fields or missing fields', async () => {
    expect(await searchLogs(raw, { query: 'level:123' })).toHaveLength(0);
    expect(await searchLogs(raw, { query: 'nofield:x' })).toHaveLength(0);
  });

  it('returns an empty array when nothing matches', async () => {
    expect(await searchLogs(raw, { query: 'zzz-no-match' })).toEqual([]);
  });

  it('does not throw on malformed lines (they are searchable as plain messages)', async () => {
    await expect(searchLogs(raw, { query: 'not json' })).resolves.toEqual([
      { message: 'this is not json {' },
    ]);
  });
});
