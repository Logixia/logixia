import type { LogEntry } from '../../../types';
import { NLPSearchEngine } from '../../engines/nlp-search-engine';
import { BasicSearchEngine } from '../basic-search-engine';
import { extractUserId } from '../user-id';

const log = (over: Partial<LogEntry> & Record<string, unknown>): LogEntry =>
  ({
    timestamp: new Date().toISOString(),
    level: 'info',
    appName: 'app',
    message: 'm',
    ...over,
  }) as LogEntry;

describe('extractUserId', () => {
  it.each([
    ['user u42 failed', 'u42', 'user u42'],
    ['errors where user id is u42', 'u42', 'user id is u42'],
    ['userId: abc', 'abc', 'userId: abc'],
    ['user 7', '7', 'user 7'],
  ])('%s', (q, id, span) => {
    expect(extractUserId(q)).toEqual({ id, span });
  });

  it.each(['what did user do yesterday', 'user logins for me', 'user id is', 'user id of the app'])(
    'ignores %s',
    (q) => {
      expect(extractUserId(q)).toBeUndefined();
    }
  );
});

describe('natural-language parsing edge cases', () => {
  const eng = new BasicSearchEngine();

  it('drops punctuation-only tokens', async () => {
    const p = await eng.parseNaturalLanguageQuery('any errors in the last hour?');
    expect(p.textQuery).toBe('');
  });

  it('trims punctuation around leftover words', async () => {
    const p = await eng.parseNaturalLanguageQuery('timeout, errors!');
    expect(p.textQuery).toBe('timeout');
  });

  it('consumes only the matched user span', async () => {
    const p = await eng.parseNaturalLanguageQuery('user logins for user u42');
    expect(p.filters.userIds).toEqual(['u42']);
    expect(p.textQuery).toBe('user logins');
  });

  it('does not take stopwords after "user id"', async () => {
    const p = await eng.parseNaturalLanguageQuery('errors where user id is u42');
    expect(p.filters.userIds).toEqual(['u42']);
  });

  it('does not filter on "user do"', async () => {
    const p = await eng.parseNaturalLanguageQuery('what did user do yesterday');
    expect(p.filters.userIds).toBeUndefined();
  });

  it('NLPSearchEngine no longer extracts loose user ids', async () => {
    const nlp = new NLPSearchEngine();
    nlp.addLogs([log({ message: 'something' })]);
    const parsed = await nlp.parseNaturalLanguageQuery('what did user do yesterday');
    expect(parsed.filters.userIds).toBeUndefined();
    const ok = await nlp.parseNaturalLanguageQuery('activity for user u42');
    expect(ok.filters.userIds).toEqual(['u42']);
  });
});

describe('robustness and field matching', () => {
  it('minSeverity tolerates missing or non-string levels', async () => {
    const eng = new BasicSearchEngine();
    eng.addLogs([
      log({ message: 'nolevel', level: undefined as unknown as string }),
      log({ message: 'numlevel', level: 3 as unknown as string }),
      log({ message: 'err', level: 'error' }),
    ]);
    const r = await eng.search('', { minSeverity: 2 });
    expect(r.map((x) => x.log.message).sort()).toEqual(['err', 'nolevel', 'numlevel']);
    expect(await eng.search('', { minSeverity: 3 })).toHaveLength(1);
  });

  it('customFields are type-aware', async () => {
    const eng = new BasicSearchEngine();
    eng.addLogs([
      log({ message: 'num', payload: { status: 500 } }),
      log({ message: 'nul', payload: { status: null } }),
      log({ message: 'obj', payload: { status: { code: 1 } } }),
      log({ message: 'none', payload: {} }),
    ]);
    const msgs = async (cf: Record<string, unknown>) =>
      (await eng.search('', { customFields: cf })).map((r) => r.log.message);
    expect(await msgs({ status: '500' })).toEqual(['num']);
    expect(await msgs({ status: 500 })).toEqual(['num']);
    expect(await msgs({ status: 'null' })).toEqual([]);
    expect(await msgs({ status: null })).toEqual(['nul']);
    expect(await msgs({ status: { code: 1 } })).toEqual(['obj']);
    expect(await msgs({ status: { code: 2 } })).toEqual([]);
    expect(await msgs({ status: {} })).toEqual([]);
  });

  it('applies excludePatterns together with the text query', async () => {
    const eng = new BasicSearchEngine();
    eng.addLogs([log({ message: 'login ok' }), log({ message: 'login failed' })]);
    const r = await eng.search('login', { excludePatterns: ['FAILED'] });
    expect(r.map((x) => x.log.message)).toEqual(['login ok']);
  });
});
