/**
 * Tests for BasicLogIndexer.
 *
 * Focus: the index-size accounting. getIndexStats() previously JSON.stringify'd
 * every entry on each call (O(n) — for the default 1M cap that blocks the event
 * loop). Size is now maintained incrementally, so these tests pin that the
 * running total stays consistent across add / remove / clear. Also covers field
 * search and the max-size eviction.
 */

import type { LogEntry } from '../../../types';
import { BasicLogIndexer } from '../basic-log-indexer';

function makeLog(i: number, overrides: Partial<LogEntry> = {}): LogEntry {
  return {
    timestamp: new Date(2026, 0, 1, 0, 0, i).toISOString(),
    level: 'info',
    appName: 'TestApp',
    message: `message-${i}`,
    ...overrides,
  };
}

describe('BasicLogIndexer — size accounting', () => {
  it('reports a positive size after indexing and zero after clear', async () => {
    const ix = new BasicLogIndexer({ autoOptimize: false });
    for (let i = 0; i < 50; i += 1) await ix.indexLog(makeLog(i));

    const stats = await ix.getIndexStats();
    expect(stats.totalDocuments).toBe(50);
    expect(stats.indexSize).toBeGreaterThan(0);

    await ix.clearIndex();
    const after = await ix.getIndexStats();
    expect(after.totalDocuments).toBe(0);
    expect(after.indexSize).toBe(0);
  });

  it('decrements size back to zero when all entries are removed by age', async () => {
    const ix = new BasicLogIndexer({ autoOptimize: false });
    for (let i = 0; i < 30; i += 1) await ix.indexLog(makeLog(i));
    expect((await ix.getIndexStats()).indexSize).toBeGreaterThan(0);

    // Cutoff far in the future → removes everything.
    const removed = await ix.removeOldLogs(new Date(Date.now() + 10_000_000));
    expect(removed).toBe(30);

    const stats = await ix.getIndexStats();
    expect(stats.totalDocuments).toBe(0);
    expect(stats.indexSize).toBe(0);
  });

  it('keeps size non-negative and consistent after partial removal', async () => {
    const ix = new BasicLogIndexer({ autoOptimize: false });
    for (let i = 0; i < 20; i += 1) await ix.indexLog(makeLog(i));
    const full = (await ix.getIndexStats()).indexSize;

    // Remove the first ~10 (their timestamps are earliest).
    const cutoff = new Date(2026, 0, 1, 0, 0, 10).toISOString();
    await ix.removeOldLogs(new Date(cutoff));

    const partial = (await ix.getIndexStats()).indexSize;
    expect(partial).toBeGreaterThan(0);
    expect(partial).toBeLessThan(full);
  });
});

describe('BasicLogIndexer — field search', () => {
  it('finds logs by an indexed field value (case-insensitive)', async () => {
    const ix = new BasicLogIndexer({ autoOptimize: false });
    await ix.indexLog(makeLog(1, { level: 'error', traceId: 'TRACE-1' }));
    await ix.indexLog(makeLog(2, { level: 'info', traceId: 'trace-1' }));

    const byTrace = ix.searchByField('traceId', 'trace-1');
    expect(byTrace).toHaveLength(2);

    const errors = ix.searchByField('level', 'ERROR');
    expect(errors).toHaveLength(1);
  });

  it('returns an empty array for an unknown field or value', async () => {
    const ix = new BasicLogIndexer({ autoOptimize: false });
    await ix.indexLog(makeLog(1));
    expect(ix.searchByField('nope', 'x')).toEqual([]);
    expect(ix.searchByField('level', 'warn')).toEqual([]);
  });
});

describe('BasicLogIndexer — max size eviction', () => {
  it('evicts oldest logs once the index exceeds maxIndexSize', async () => {
    // maxIndexSize 10 → after crossing, removeOldestLogs trims ~10%.
    const ix = new BasicLogIndexer({ autoOptimize: false, maxIndexSize: 10 });
    for (let i = 0; i < 12; i += 1) await ix.indexLog(makeLog(i));

    const stats = await ix.getIndexStats();
    // Never grows unbounded past the cap (eviction kicked in).
    expect(stats.totalDocuments).toBeLessThanOrEqual(11);
    expect(stats.indexSize).toBeGreaterThan(0);
  });
});
