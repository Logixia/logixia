/**
 * executeQuery tests.
 *
 * Covered: SELECT * / SELECT a,b projection, WHERE with = != > >= < <= LIKE IN,
 * AND / OR, ORDER BY ASC|DESC, LIMIT (SQL and opts), COUNT BY / GROUP BY /
 * AVG|SUM|MIN|MAX(field) BY aggregation, since/until (ISO, "last N unit", "today").
 * Not covered: NOT LIKE / NOT IN, parenthesised WHERE groups, output formatting.
 * The WHERE OR/LIKE regressions live in query-where.test.ts.
 */

import { executeQuery } from '../commands/query';

const T0 = Date.parse('2024-06-01T12:00:00.000Z');
const iso = (offsetMs: number): string => new Date(T0 + offsetMs).toISOString();
const H = 3_600_000;

const entries = [
  { level: 'info', message: 'boot', timestamp: iso(-5 * H), duration: 10, service: 'api' },
  { level: 'error', message: 'db down', timestamp: iso(-4 * H), duration: 500, service: 'api' },
  { level: 'warn', message: 'slow', timestamp: iso(-3 * H), duration: 300, service: 'worker' },
  { level: 'info', message: 'ok', timestamp: iso(-2 * H), duration: 120, service: 'api' },
  {
    level: 'error',
    message: 'timeout',
    timestamp: iso(-90 * 60_000),
    duration: 900,
    service: 'worker',
  },
  { level: 'info', message: 'ok 2', timestamp: iso(-30 * 60_000), duration: 50, service: 'worker' },
  { level: 'debug', message: 'trace', timestamp: iso(-10 * 60_000), duration: 5, service: 'api' },
  { level: 'info', message: 'no duration', timestamp: iso(-5 * 60_000), service: 'api' },
  { level: 'error', message: 'no ts', duration: 200, service: 'api' },
  { level: 'warn', message: 'last', timestamp: iso(0), duration: 101, service: 'worker' },
];

function parseTable(output: string | null): Array<Record<string, string>> {
  const [header, , ...body] = (output ?? '').split('\n');
  const cols = header!.split('|').map((c) => c.trim());
  return body.map((line) => {
    const cells = line.split('|').map((c) => c.trim());
    return Object.fromEntries(cols.map((c, i) => [c, cells[i]!]));
  });
}

const msgs = (rows: Array<Record<string, unknown>>): unknown[] => rows.map((r) => r['message']);

describe('executeQuery', () => {
  it('SELECT * with no WHERE returns everything', () => {
    const { results, aggregationOutput } = executeQuery(entries, { sql: 'SELECT * FROM logs' });
    expect(results).toHaveLength(entries.length);
    expect(aggregationOutput).toBeNull();
  });

  it('returns everything when no sql is given', () => {
    expect(executeQuery(entries, {}).results).toHaveLength(entries.length);
  });

  it("WHERE level = 'error'", () => {
    const { results } = executeQuery(entries, { sql: "WHERE level = 'error'" });
    expect(msgs(results)).toEqual(['db down', 'timeout', 'no ts']);
  });

  it('supports != comparison', () => {
    const { results } = executeQuery(entries, { sql: "WHERE level != 'info'" });
    expect(results).toHaveLength(6);
  });

  it('numeric comparisons', () => {
    expect(msgs(executeQuery(entries, { sql: 'WHERE duration > 300' }).results)).toEqual([
      'db down',
      'timeout',
    ]);
    expect(executeQuery(entries, { sql: 'WHERE duration >= 300' }).results).toHaveLength(3);
    expect(executeQuery(entries, { sql: 'WHERE duration < 10' }).results).toHaveLength(1);
    expect(executeQuery(entries, { sql: 'WHERE duration <= 10' }).results).toHaveLength(2);
  });

  it('rows missing the field never satisfy a numeric comparison', () => {
    const { results } = executeQuery(entries, { sql: 'WHERE duration > 0' });
    expect(msgs(results)).not.toContain('no duration');
  });

  it('AND narrows, OR widens', () => {
    const and = executeQuery(entries, { sql: "WHERE level = 'error' AND duration > 600" });
    expect(msgs(and.results)).toEqual(['timeout']);
    const or = executeQuery(entries, { sql: "WHERE level = 'debug' OR duration > 800" });
    expect(msgs(or.results)).toEqual(['timeout', 'trace']);
  });

  it('IN list', () => {
    const { results } = executeQuery(entries, { sql: "WHERE level IN ('warn', 'debug')" });
    expect(results).toHaveLength(3);
  });

  it('SELECT level, message projects only those fields', () => {
    const { results } = executeQuery(entries, {
      sql: "SELECT level, message FROM logs WHERE level = 'debug'",
    });
    expect(results).toEqual([{ level: 'debug', message: 'trace' }]);
  });

  it('ORDER BY duration DESC with LIMIT 3', () => {
    const { results } = executeQuery(entries, {
      sql: 'SELECT * FROM logs ORDER BY duration DESC LIMIT 3',
    });
    expect(results.map((r) => r['duration'])).toEqual([900, 500, 300]);
  });

  it('ORDER BY places rows missing the field last in both directions', () => {
    const { results } = executeQuery(entries, { sql: 'SELECT * FROM logs ORDER BY duration ASC' });
    expect(results[0]['duration']).toBe(5);
    expect(results[results.length - 1]['message']).toBe('no duration');
    const desc = executeQuery(entries, { sql: 'ORDER BY duration DESC' }).results;
    expect(desc[desc.length - 1]['message']).toBe('no duration');
  });

  it('ORDER BY on strings uses locale comparison', () => {
    const { results } = executeQuery(entries, { sql: 'ORDER BY message ASC LIMIT 2' });
    expect(msgs(results)).toEqual(['boot', 'db down']);
  });

  it('honours opts.orderBy and opts.limit when the SQL has none', () => {
    const { results } = executeQuery(entries, { orderBy: 'duration', limit: 2 });
    expect(results.map((r) => r['duration'])).toEqual([5, 10]);
  });

  describe('ORDER BY / LIMIT edge cases', () => {
    const rows = [
      { id: 'a', score: 2 },
      { id: 'b', score: null },
      { id: 'c', score: 3 },
      { id: 'd' },
      { id: 'e', score: 1 },
    ];
    const ids = (rs: Array<Record<string, unknown>>) => rs.map((r) => r['id']);

    it('sorts null and missing values last under ASC', () => {
      const { results } = executeQuery(rows, { sql: 'ORDER BY score ASC' });
      expect(ids(results)).toEqual(['e', 'a', 'c', 'b', 'd']);
    });

    it('sorts null and missing values last under DESC', () => {
      const { results } = executeQuery(rows, { sql: 'ORDER BY score DESC' });
      expect(ids(results)).toEqual(['c', 'a', 'e', 'b', 'd']);
    });

    it('orders by a field that is not in the SELECT list', () => {
      const { results } = executeQuery(entries, {
        sql: 'SELECT message FROM logs ORDER BY duration DESC LIMIT 2',
      });
      expect(results).toEqual([{ message: 'timeout' }, { message: 'db down' }]);
    });

    it('LIMIT 0 returns no rows (SQL and opts)', () => {
      expect(executeQuery(entries, { sql: 'SELECT * FROM logs LIMIT 0' }).results).toEqual([]);
      expect(executeQuery(entries, { limit: 0 }).results).toEqual([]);
    });

    it('does not treat ORDER BY / LIMIT text inside a quoted WHERE literal as clauses', () => {
      const lit = [
        { id: 1, message: 'order by duration desc', duration: 1 },
        { id: 2, message: 'limit 1', duration: 9 },
        { id: 3, message: 'other', duration: 5 },
      ];
      const a = executeQuery(lit, { sql: "WHERE message != 'order by duration desc'" });
      expect(a.results.map((r) => r['id'])).toEqual([2, 3]);
      const b = executeQuery(lit, { sql: "WHERE message = 'limit 1'" });
      expect(b.results.map((r) => r['id'])).toEqual([2]);
      const c = executeQuery(lit, {
        sql: "WHERE message != 'x limit 1' ORDER BY duration DESC LIMIT 2",
      });
      expect(c.results.map((r) => r['id'])).toEqual([2, 3]);
    });
  });

  it('COUNT BY level returns exact counts per group, highest first, and no rows', () => {
    const { results, aggregationOutput } = executeQuery(entries, { sql: 'COUNT BY level' });
    expect(results).toEqual([]);
    expect(parseTable(aggregationOutput)).toEqual([
      { level: 'info', count: '4' },
      { level: 'error', count: '3' },
      { level: 'warn', count: '2' },
      { level: 'debug', count: '1' },
    ]);
  });

  it('GROUP BY level behaves like a count', () => {
    const { aggregationOutput } = executeQuery(entries, { sql: 'GROUP BY level' });
    expect(parseTable(aggregationOutput)).toEqual([
      { level: 'info', count: '4' },
      { level: 'error', count: '3' },
      { level: 'warn', count: '2' },
      { level: 'debug', count: '1' },
    ]);
  });

  // api durations: 10, 500, 120, 5, 200 (one api row has none); worker: 300, 900, 50, 101
  it.each([
    ['AVG', { api: '167', worker: '337.75' }],
    ['SUM', { api: '835', worker: '1351' }],
    ['MIN', { api: '5', worker: '50' }],
    ['MAX', { api: '500', worker: '900' }],
  ])('%s(duration) BY service computes exact values per group', (fn, expected) => {
    const { aggregationOutput } = executeQuery(entries, { sql: `${fn}(duration) BY service` });
    const rows = parseTable(aggregationOutput);
    expect(Object.keys(rows[0]!)).toEqual(['service', `${fn}(duration)`, 'count']);
    const byService = Object.fromEntries(rows.map((r) => [r['service'], r[`${fn}(duration)`]]));
    expect(byService).toEqual(expected);
    expect(Object.fromEntries(rows.map((r) => [r['service'], r['count']]))).toEqual({
      api: '6',
      worker: '4',
    });
  });

  it('applies time filters before aggregating', () => {
    const { aggregationOutput } = executeQuery(entries, {
      sql: 'COUNT BY message',
      since: iso(-1 * H),
    });
    expect(aggregationOutput).not.toContain('boot');
    expect(aggregationOutput).toContain('trace');
  });

  describe('since / until', () => {
    afterEach(() => {
      jest.useRealTimers();
    });

    it('since with an ISO date drops older rows but keeps rows without a timestamp', () => {
      const { results } = executeQuery(entries, { since: iso(-100 * 60_000) });
      expect(msgs(results)).toEqual(['timeout', 'ok 2', 'trace', 'no duration', 'no ts', 'last']);
    });

    it('until with an ISO date drops newer rows', () => {
      const { results } = executeQuery(entries, { until: iso(-3 * H) });
      expect(msgs(results)).toEqual(['boot', 'db down', 'slow', 'no ts']);
    });

    it('since and until combine into a window', () => {
      const { results } = executeQuery(entries, {
        since: iso(-4 * H),
        until: iso(-2 * H),
        sql: "SELECT * FROM logs WHERE level != 'error'",
      });
      expect(msgs(results)).toEqual(['slow', 'ok']);
    });

    it('relative "last N hours" is evaluated against the current time', () => {
      jest.useFakeTimers({ now: T0 });
      const { results } = executeQuery(entries, { since: 'last 1 hour' });
      expect(msgs(results)).toEqual(['ok 2', 'trace', 'no duration', 'no ts', 'last']);
    });

    it('relative minutes and days units', () => {
      jest.useFakeTimers({ now: T0 });
      expect(executeQuery(entries, { since: 'last 20 minutes' }).results).toHaveLength(4);
      expect(executeQuery(entries, { since: 'last 2 days' }).results).toHaveLength(entries.length);
    });

    it('"today" starts at local midnight', () => {
      jest.useFakeTimers({ now: new Date(2024, 5, 1, 12, 0, 0) });
      const rows = [
        { message: 'yesterday', timestamp: new Date(2024, 4, 31, 23, 0, 0).toISOString() },
        { message: 'today', timestamp: new Date(2024, 5, 1, 1, 0, 0).toISOString() },
      ];
      expect(msgs(executeQuery(rows, { since: 'today' }).results)).toEqual(['today']);
      expect(msgs(executeQuery(rows, { since: 'yesterday' }).results)).toEqual([
        'yesterday',
        'today',
      ]);
    });

    it('ignores an unparseable since value', () => {
      expect(executeQuery(entries, { since: 'whenever' }).results).toHaveLength(entries.length);
    });
  });
});
