import type { LogEntry } from '../../../types';
import { BasicSearchEngine } from '../basic-search-engine';

const NOW = Date.now();
function log(over: Partial<LogEntry>): LogEntry {
  return {
    timestamp: new Date(NOW).toISOString(),
    level: 'info',
    appName: 'app',
    message: 'm',
    ...over,
  };
}

async function messages(
  eng: BasicSearchEngine,
  filters: Parameters<BasicSearchEngine['search']>[1]
): Promise<string[]> {
  return (await eng.search('', filters)).map((r) => r.log.message).sort();
}

describe('BasicSearchEngine filters', () => {
  const eng = new BasicSearchEngine();
  eng.addLogs([
    log({ message: 'a', payload: { userId: 'u1', sessionId: 's1', region: 'eu' } }),
    log({
      message: 'b',
      level: 'error',
      payload: { user_id: 'u2', session_id: 's2', region: 'us' },
    }),
    log({ message: 'c', level: 'warn', payload: { userId: 7 } }),
    log({ message: 'old', timestamp: new Date(NOW - 3 * 3_600_000).toISOString() }),
  ]);

  it('filters by userIds and sessionIds', async () => {
    expect(await messages(eng, { userIds: ['u1', 'u2'] })).toEqual(['a', 'b']);
    expect(await messages(eng, { userIds: ['7'] })).toEqual(['c']);
    expect(await messages(eng, { sessionIds: ['s2'] })).toEqual(['b']);
  });

  it('filters by minSeverity', async () => {
    expect(await messages(eng, { minSeverity: 3 })).toEqual(['b', 'c']);
    expect(await messages(eng, { minSeverity: 4 })).toEqual(['b']);
  });

  it('applies excludePatterns case-insensitively', async () => {
    expect(await messages(eng, { excludePatterns: ['OLD', '"eu"'] })).toEqual(['b', 'c']);
  });

  it('filters by customFields in the payload or on the log', async () => {
    expect(await messages(eng, { customFields: { region: 'us' } })).toEqual(['b']);
    expect(await messages(eng, { customFields: { level: 'warn' } })).toEqual(['c']);
    expect(await messages(eng, { customFields: { 'payload.region': 'eu' } })).toEqual(['a']);
  });

  it('applies TimeRange.relative', async () => {
    const recent = await messages(eng, {
      timeRange: { start: 0, relative: { value: 2, unit: 'hours' } },
    });
    expect(recent).toEqual(['a', 'b', 'c']);
    const wide = await messages(eng, {
      timeRange: { start: NOW, relative: { value: 1, unit: 'days' } },
    });
    expect(wide).toContain('old');
  });
});

describe('BasicSearchEngine natural language', () => {
  it('applies recognized filters and uses an empty text query', async () => {
    const eng = new BasicSearchEngine();
    eng.addLogs([
      log({ message: 'boom', level: 'error' }),
      log({ message: 'fine' }),
      log({
        message: 'ancient',
        level: 'error',
        timestamp: new Date(NOW - 5 * 3_600_000).toISOString(),
      }),
    ]);
    const parsed = await eng.parseNaturalLanguageQuery('show errors in the last 2 hours');
    expect(parsed.textQuery).toBe('');
    expect(parsed.filters.levels).toEqual(['error']);
    expect(parsed.filters.timeRange?.relative).toEqual({ value: 2, unit: 'hours' });

    const results = await eng.naturalLanguageSearch('show errors in the last 2 hours');
    expect(results.map((r) => r.log.message)).toEqual(['boom']);
  });

  it('keeps leftover words as the text query', async () => {
    const eng = new BasicSearchEngine();
    const parsed = await eng.parseNaturalLanguageQuery(
      'find timeout errors from the billing service'
    );
    expect(parsed.textQuery).toBe('timeout');
    expect(parsed.filters.services).toEqual(['billing']);
  });

  it('parses minutes and user ids', async () => {
    const eng = new BasicSearchEngine();
    const parsed = await eng.parseNaturalLanguageQuery('warnings for user u42 last 30 minutes');
    expect(parsed.filters.userIds).toEqual(['u42']);
    expect(parsed.filters.timeRange?.relative).toEqual({ value: 30, unit: 'minutes' });
    expect(parsed.textQuery).toBe('');
  });
});
