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

  it('COUNT BY level puts a table in aggregationOutput and no rows in results', () => {
    const { results, aggregationOutput } = executeQuery(entries, { sql: 'COUNT BY level' });
    expect(results).toEqual([]);
    expect(aggregationOutput).toContain('level');
    expect(aggregationOutput).toContain('count');
    expect(aggregationOutput).toContain('info');
    expect(aggregationOutput).toContain('error');
  });

  it('GROUP BY level behaves like a count', () => {
    const { aggregationOutput } = executeQuery(entries, { sql: 'GROUP BY level' });
    expect(aggregationOutput).toContain('warn');
    expect(aggregationOutput).toContain('debug');
  });

  it('AVG(duration) BY service computes the mean per group', () => {
    const { aggregationOutput } = executeQuery(entries, { sql: 'AVG(duration) BY service' });
    expect(aggregationOutput).toContain('AVG(duration)');
    // api: (10+500+120+5+200)/5 = 167 ; worker: (300+900+50+101)/4 = 337.75
    expect(aggregationOutput).toContain('167');
    expect(aggregationOutput).toContain('337.75');
  });

  it('SUM, MIN and MAX aggregations', () => {
    expect(executeQuery(entries, { sql: 'SUM(duration) BY service' }).aggregationOutput).toContain(
      '1351'
    );
    expect(executeQuery(entries, { sql: 'MIN(duration) BY service' }).aggregationOutput).toContain(
      'MIN(duration)'
    );
    expect(executeQuery(entries, { sql: 'MAX(duration) BY service' }).aggregationOutput).toContain(
      '900'
    );
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
