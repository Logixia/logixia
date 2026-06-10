/**
 * Tests for BasicSearchEngine.
 *
 * Focus on the two fixed bugs plus core behavior:
 *  - getSearchableText used raw JSON.stringify(payload), which throws on a cyclic
 *    payload and crashes the WHOLE search. It must now be circular-safe.
 *  - addLogs grew this.logs without bound (memory leak) and used push(...logs)
 *    (RangeError risk on huge arrays). It must cap at maxLogs (FIFO).
 */

import type { LogEntry } from '../../../types';
import { BasicSearchEngine } from '../basic-search-engine';

function makeLog(i: number, overrides: Partial<LogEntry> = {}): LogEntry {
  return {
    timestamp: new Date(2026, 0, 1, 0, 0, i).toISOString(),
    level: 'info',
    appName: 'TestApp',
    message: `message ${i}`,
    ...overrides,
  };
}

describe('BasicSearchEngine — search', () => {
  it('returns logs whose searchable text contains the query terms', async () => {
    const eng = new BasicSearchEngine();
    eng.addLogs([makeLog(1, { message: 'user login ok' }), makeLog(2, { message: 'cache miss' })]);

    const results = await eng.search('login');
    expect(results).toHaveLength(1);
    expect(results[0]!.log.message).toBe('user login ok');
  });

  it('does not crash when a stored log has a circular payload', async () => {
    const eng = new BasicSearchEngine();
    const circular: Record<string, unknown> = { a: 1 };
    circular.self = circular;
    eng.addLogs([makeLog(1, { payload: circular }), makeLog(2)]);

    let results: Awaited<ReturnType<typeof eng.search>> = [];
    await expect(
      (async () => {
        results = await eng.search('message');
      })()
    ).resolves.toBeUndefined();
    expect(results.length).toBe(2);
  });

  it('correlates logs by trace id, sorted by timestamp', async () => {
    const eng = new BasicSearchEngine();
    eng.addLogs([
      makeLog(2, { traceId: 't1' }),
      makeLog(1, { traceId: 't1' }),
      makeLog(3, { traceId: 't2' }),
    ]);

    const correlated = await eng.correlateByTraceId('t1');
    expect(correlated.logs).toHaveLength(2);
    // Earliest timestamp first.
    expect(correlated.logs[0]!.message).toBe('message 1');
  });
});

describe('BasicSearchEngine — bounded buffer', () => {
  it('caps the log buffer at maxLogs and keeps the newest entries (FIFO)', () => {
    const eng = new BasicSearchEngine({ maxLogs: 10 });
    const batch: LogEntry[] = [];
    for (let i = 0; i < 25; i += 1) batch.push(makeLog(i));
    eng.addLogs(batch);

    const logs = eng.getLogs();
    expect(logs).toHaveLength(10);
    const messages = logs.map((l) => l.message);
    expect(messages).toContain('message 24');
    expect(messages).not.toContain('message 0');
  });

  it('caps correctly across multiple addLogs calls', () => {
    const eng = new BasicSearchEngine({ maxLogs: 5 });
    for (let i = 0; i < 8; i += 1) eng.addLogs([makeLog(i)]);
    expect(eng.getLogs()).toHaveLength(5);
    expect(eng.getLogs().map((l) => l.message)).toContain('message 7');
  });

  it('clearLogs empties the buffer', () => {
    const eng = new BasicSearchEngine();
    eng.addLogs([makeLog(1), makeLog(2)]);
    eng.clearLogs();
    expect(eng.getLogs()).toHaveLength(0);
  });
});
