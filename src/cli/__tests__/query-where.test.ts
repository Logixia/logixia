/**
 * Tests for the SQL WHERE parser/evaluator (issue #137).
 *
 * Two defects are covered:
 *  - The WHERE parser built an AND/OR tree but the matcher only applied AND
 *    over the flat condition list, so `... OR ...` returned nothing.
 *  - `LIKE` / `NOT LIKE` kept the surrounding quotes on the value, so
 *    `message LIKE 'db%'` tried to match the literal `'db%'`.
 */

import { executeQuery } from '../commands/query';

const entries = [
  { level: 'error', message: 'db connect failed', service: 'api' },
  { level: 'warn', message: 'retry scheduled', service: 'worker' },
  { level: 'info', message: 'request ok', service: 'api' },
  { level: 'error', message: 'timeout', service: 'worker' },
];

function levels(results: Array<Record<string, unknown>>): string[] {
  return results.map((r) => String(r['level']));
}

describe('executeQuery WHERE evaluation', () => {
  it('matches rows on either side of an OR', () => {
    const { results } = executeQuery(entries, {
      sql: "WHERE level = 'error' OR level = 'warn'",
    });
    expect(levels(results).sort()).toEqual(['error', 'error', 'warn']);
  });

  it('binds AND tighter than OR', () => {
    const { results } = executeQuery(entries, {
      sql: "WHERE level = 'error' AND service = 'api' OR level = 'warn'",
    });
    // (error AND api) → the first row; OR warn → the second row.
    expect(levels(results).sort()).toEqual(['error', 'warn']);
  });

  it('strips quotes from a LIKE value and matches the pattern', () => {
    const { results } = executeQuery(entries, {
      sql: "WHERE message LIKE 'db%'",
    });
    expect(levels(results)).toEqual(['error']);
  });

  it('strips quotes from a NOT LIKE value', () => {
    const { results } = executeQuery(entries, {
      sql: "WHERE message NOT LIKE '%scheduled'",
    });
    expect(levels(results).sort()).toEqual(['error', 'error', 'info']);
  });

  it('still applies a plain AND chain', () => {
    const { results } = executeQuery(entries, {
      sql: "WHERE level = 'error' AND service = 'worker'",
    });
    expect(levels(results)).toEqual(['error']);
  });
});
