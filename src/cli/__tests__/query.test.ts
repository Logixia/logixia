/**
 * Tests for `executeQuery` (the pure query engine behind `logixia query`).
 *
 * Covered here:
 *   - `SELECT *` (no WHERE) / `SELECT a, b` projection
 *   - `WHERE` equality (`=`), numeric comparison (`>`), and `AND`
 *   - `ORDER BY <field> ASC|DESC` and `LIMIT n`
 *   - `COUNT BY`, `AVG(x) BY`, `GROUP BY` (populate `aggregationOutput`)
 *   - `--since` / `--until` with ISO dates and relative values (`last N hours`)
 *
 * Not yet covered / known limitations:
 *   - `OR` is parsed into the `conjunction` tree but `matchesWhere` only applies
 *     AND semantics over the flat `where` list.
 *   - `LIKE` / `NOT LIKE` keep the surrounding value quotes (e.g. `LIKE 'db%'`
 *     matches the literal quotes too), so they are not exercised here.
 */
import { executeQuery } from '../commands/query';

interface LogEntry {
  level: string;
  message: string;
  timestamp: string;
  duration: number;
  service: string;
}

const FIXTURE: LogEntry[] = [
  { level: 'info', message: 'user login', timestamp: '2024-01-15T10:00:00Z', duration: 50, service: 'api' },
  { level: 'error', message: 'db timeout', timestamp: '2024-01-15T10:05:00Z', duration: 500, service: 'api' },
  { level: 'warn', message: 'slow query', timestamp: '2024-01-15T10:10:00Z', duration: 200, service: 'worker' },
  { level: 'error', message: 'auth failure', timestamp: '2024-01-15T10:15:00Z', duration: 120, service: 'auth' },
  { level: 'info', message: 'health check', timestamp: '2024-01-15T10:20:00Z', duration: 5, service: 'api' },
  { level: 'debug', message: 'trace span', timestamp: '2024-01-15T10:25:00Z', duration: 1, service: 'api' },
];

describe('executeQuery', () => {
  it('SELECT * with no WHERE returns everything', () => {
    const { results, aggregationOutput } = executeQuery(FIXTURE, {
      sql: 'SELECT * FROM logs',
    });

    expect(results).toHaveLength(FIXTURE.length);
    expect(aggregationOutput).toBeNull();
  });

  it('WHERE level = \'error\' filters by exact value', () => {
    const { results } = executeQuery(FIXTURE, {
      sql: "SELECT * FROM logs WHERE level = 'error'",
    });

    expect(results).toHaveLength(2);
    expect(results.every((r) => r.level === 'error')).toBe(true);
  });

  it('WHERE duration > 100 filters by numeric comparison', () => {
    const { results } = executeQuery(FIXTURE, {
      sql: 'SELECT * FROM logs WHERE duration > 100',
    });

    expect(results.map((r) => r.duration)).toEqual([500, 200, 120]);
  });

  it('WHERE with AND combines conditions', () => {
    const { results } = executeQuery(FIXTURE, {
      sql: "SELECT * FROM logs WHERE level = 'error' AND service = 'api'",
    });

    expect(results).toHaveLength(1);
    expect(results[0].message).toBe('db timeout');
  });

  it('SELECT level, message projects only those fields', () => {
    const { results } = executeQuery(FIXTURE, {
      sql: 'SELECT level, message FROM logs',
    });

    expect(results).toHaveLength(FIXTURE.length);
    for (const row of results) {
      expect(Object.keys(row).sort()).toEqual(['level', 'message']);
    }
  });

  it('ORDER BY duration DESC and LIMIT 3', () => {
    const { results } = executeQuery(FIXTURE, {
      sql: 'SELECT * FROM logs ORDER BY duration DESC LIMIT 3',
    });

    expect(results.map((r) => r.duration)).toEqual([500, 200, 120]);
  });

  it('COUNT BY level puts group counts in aggregationOutput', () => {
    const { results, aggregationOutput } = executeQuery(FIXTURE, {
      sql: 'COUNT BY level',
    });

    expect(results).toEqual([]);
    expect(aggregationOutput).not.toBeNull();
    expect(aggregationOutput).toContain('level');
    expect(aggregationOutput).toContain('error');
    expect(aggregationOutput).toContain('info');
  });

  it('AVG(duration) BY service computes numeric aggregates', () => {
    const { aggregationOutput } = executeQuery(FIXTURE, {
      sql: 'AVG(duration) BY service',
    });

    expect(aggregationOutput).toContain('AVG(duration)');
    // api: (50 + 500 + 5 + 1) / 4 = 139
    expect(aggregationOutput).toContain('139');
  });

  it('GROUP BY service groups rows', () => {
    const { aggregationOutput } = executeQuery(FIXTURE, {
      sql: 'GROUP BY service',
    });

    expect(aggregationOutput).not.toBeNull();
    expect(aggregationOutput).toContain('service');
    expect(aggregationOutput).toContain('api');
  });

  it('since / until with an ISO date', () => {
    const since = executeQuery(FIXTURE, { since: '2024-01-15T10:10:00Z' });
    expect(since.results).toHaveLength(4);

    const until = executeQuery(FIXTURE, { until: '2024-01-15T10:15:00Z' });
    expect(until.results).toHaveLength(4);
  });

  it('since with a relative value (last N hours)', () => {
    jest.useFakeTimers({ now: new Date('2024-01-15T11:00:00Z') });
    try {
      const none = executeQuery(FIXTURE, { since: 'last 30 minutes' });
      expect(none.results).toHaveLength(0);

      const all = executeQuery(FIXTURE, { since: 'last 2 hours' });
      expect(all.results).toHaveLength(FIXTURE.length);
    } finally {
      jest.useRealTimers();
    }
  });
});
