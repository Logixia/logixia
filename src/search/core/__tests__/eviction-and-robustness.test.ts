import type { LogEntry } from '../../../types';
import { BasicLogIndexer } from '../basic-log-indexer';
import { BasicSearchEngine } from '../basic-search-engine';

function log(i: number, extra: Partial<LogEntry> = {}): LogEntry {
  return {
    timestamp: new Date(2026, 0, 1, 0, 0, 0, i).toISOString(),
    level: 'info',
    appName: 'App',
    message: `m${i}`,
    traceId: `trace-${i}`,
    ...extra,
  };
}

describe('BasicLogIndexer eviction', () => {
  it('drops the oldest entries past the cap and removes empty field-index sets', async () => {
    const ix = new BasicLogIndexer({ maxIndexSize: 100, autoOptimize: false });
    for (let i = 0; i < 300; i++) await ix.indexLog(log(i));

    const stats = await ix.getIndexStats();
    expect(stats.totalDocuments).toBeLessThanOrEqual(100);
    expect(ix.searchByField('traceId', 'trace-0')).toEqual([]);
    expect(ix.searchByField('traceId', 'trace-299')).toHaveLength(1);

    const traceIndex = (
      ix as unknown as { fieldIndices: Map<string, Map<string, Set<string>>> }
    ).fieldIndices.get('traceId')!;
    expect(traceIndex.size).toBe(stats.totalDocuments);
    for (const ids of traceIndex.values()) expect(ids.size).toBeGreaterThan(0);
  });

  it('keeps the size accounting consistent after eviction', async () => {
    const ix = new BasicLogIndexer({ maxIndexSize: 50, autoOptimize: false });
    for (let i = 0; i < 200; i++) await ix.indexLog(log(i));
    const before = await ix.getIndexStats();
    await ix.removeOldLogs(new Date(2100, 0, 1));
    const after = await ix.getIndexStats();
    expect(before.indexSize).toBeGreaterThan(0);
    expect(after.totalDocuments).toBe(0);
    expect(after.indexSize).toBe(0);
  });

  it('removeOldLogs also deletes emptied field-index sets', async () => {
    const ix = new BasicLogIndexer({ autoOptimize: false });
    for (let i = 0; i < 10; i++) await ix.indexLog(log(i));
    await ix.removeOldLogs(new Date(2100, 0, 1));
    const fields = (ix as unknown as { fieldIndices: Map<string, Map<string, Set<string>>> })
      .fieldIndices;
    for (const index of fields.values()) expect(index.size).toBe(0);
  });

  it('evicts at cap without a quadratic stall', async () => {
    const ix = new BasicLogIndexer({ maxIndexSize: 20_000, autoOptimize: false });
    let worst = 0;
    for (let i = 0; i < 30_000; i++) {
      const t = Date.now();
      await ix.indexLog(log(i));
      worst = Math.max(worst, Date.now() - t);
    }
    expect(worst).toBeLessThan(1500);
  }, 60_000);

  it('tolerates BigInt and circular values in an entry', async () => {
    const ix = new BasicLogIndexer({ autoOptimize: false });
    const cyclic: Record<string, unknown> = { n: BigInt(5) };
    cyclic['self'] = cyclic;
    await expect(ix.indexLog(log(1, cyclic as Partial<LogEntry>))).resolves.toBeUndefined();
    await expect(ix.indexBatch([log(2, cyclic as Partial<LogEntry>)])).resolves.toBeUndefined();
    expect((await ix.getIndexStats()).totalDocuments).toBe(2);
  });
});

describe('BasicSearchEngine addLogs at cap', () => {
  it('keeps only the newest maxLogs entries, in order', () => {
    const engine = new BasicSearchEngine({ maxLogs: 100 });
    for (let i = 0; i < 1000; i++) engine.addLogs([log(i)]);
    const logs = engine.getLogs();
    expect(logs).toHaveLength(100);
    expect(logs[0]!.message).toBe('m900');
    expect(logs[99]!.message).toBe('m999');
  });

  it('handles bulk adds larger than the cap', () => {
    const engine = new BasicSearchEngine({ maxLogs: 10 });
    engine.addLogs(Array.from({ length: 25 }, (_, i) => log(i)));
    expect(engine.getLogs().map((l) => l.message)).toEqual(
      Array.from({ length: 10 }, (_, i) => `m${i + 15}`)
    );
  });

  it('searches see only live entries and clearLogs resets', async () => {
    const engine = new BasicSearchEngine({ maxLogs: 5 });
    for (let i = 0; i < 12; i++) engine.addLogs([log(i)]);
    expect(await engine.search('m3')).toHaveLength(0);
    expect(await engine.search('m11')).toHaveLength(1);
    engine.clearLogs();
    expect(engine.getLogs()).toEqual([]);
    engine.addLogs([log(1)]);
    expect(engine.getLogs()).toHaveLength(1);
  });

  it('does not slow down per add once at the cap', () => {
    const engine = new BasicSearchEngine({ maxLogs: 100_000 });
    engine.addLogs(Array.from({ length: 100_000 }, (_, i) => log(i)));
    const start = Date.now();
    for (let i = 0; i < 20_000; i++) engine.addLogs([log(i)]);
    expect(Date.now() - start).toBeLessThan(1500);
  });
});
