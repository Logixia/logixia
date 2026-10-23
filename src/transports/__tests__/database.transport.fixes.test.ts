import type { DatabaseTransportConfig, TransportLogEntry } from '../../types/transport.types';
import { DatabaseTransport } from '../database.transport';

function makeEntry(index: number): TransportLogEntry {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    level: 'info',
    message: `db-line-${index}`,
  };
}

function makeTransport(type: string, connection: unknown, batchSize = 1000000) {
  const transport = new DatabaseTransport({
    type,
    database: 'x',
    table: 'logs',
    batchSize,
    flushInterval: 60000,
  } as unknown as DatabaseTransportConfig);
  const internals = transport as unknown as { connection: unknown; isConnected: boolean };
  internals.connection = connection;
  internals.isConnected = true;
  return transport;
}

describe('DatabaseTransport timers', () => {
  it('flush interval does not keep the process alive', async () => {
    const transport = makeTransport('sqlite', { close: async () => {} });
    const timer = (transport as unknown as { flushTimer: NodeJS.Timeout }).flushTimer;
    expect(timer.hasRef()).toBe(false);
    await transport.close();
  });
});

describe('DatabaseTransport close() during a running drain', () => {
  it('waits for the in-flight insert before closing the connection', async () => {
    const events: string[] = [];
    let releaseInsert: () => void = () => {};
    const connection = {
      prepare: async () => ({
        run: () =>
          new Promise<void>((resolve) => {
            releaseInsert = () => {
              events.push('insert-done');
              resolve();
            };
          }),
        finalize: async () => {},
      }),
      exec: async () => {},
      close: async () => {
        events.push('closed');
      },
    };
    const transport = makeTransport('sqlite', connection);
    await transport.write(makeEntry(0));

    const flushing = transport.flush();
    await new Promise((r) => setImmediate(r));
    expect(transport.getBatchInfo().currentBatchLength).toBe(0);

    const closing = transport.close();
    await new Promise((r) => setImmediate(r));
    expect(events).toEqual([]);

    releaseInsert();
    await Promise.all([flushing, closing]);
    expect(events).toEqual(['insert-done', 'closed']);
  });
});

describe('DatabaseTransport sqlite transaction', () => {
  it('rolls back a partially written batch and re-inserts it whole on retry', async () => {
    const committed: string[] = [];
    let pending: string[] = [];
    let failOnce = true;
    const connection = {
      prepare: async () => ({
        run: async (...cols: unknown[]) => {
          if (failOnce && pending.length === 2) {
            failOnce = false;
            throw new Error('disk full');
          }
          pending.push(String(cols[2]));
        },
        finalize: async () => {},
      }),
      exec: async (sql: string) => {
        if (sql === 'BEGIN') pending = [];
        if (sql === 'COMMIT') committed.push(...pending);
        if (sql === 'ROLLBACK') pending = [];
      },
      close: async () => {},
    };
    const transport = makeTransport('sqlite', connection);
    for (let i = 0; i < 4; i += 1) await transport.write(makeEntry(i));

    await expect(transport.flush()).rejects.toThrow('disk full');
    expect(committed).toEqual([]);

    await transport.flush();
    expect(committed).toEqual(['db-line-0', 'db-line-1', 'db-line-2', 'db-line-3']);
    await transport.close();
  });
});

describe('DatabaseTransport postgres chunking', () => {
  it('keeps every insert under the 65535 parameter limit and wraps chunks in a transaction', async () => {
    const calls: Array<{ sql: string; params: number }> = [];
    const connection = {
      query: async (sql: string, params?: unknown[]) => {
        calls.push({ sql: sql.trim().split('\n')[0] ?? '', params: params?.length ?? 0 });
        return { rows: [] };
      },
      end: async () => {},
    };
    const transport = makeTransport('postgresql', connection);
    const total = 20000;
    for (let i = 0; i < total; i += 1) transport.addToBatch(makeEntry(i));

    await transport.flush();

    const inserts = calls.filter((c) => c.sql.startsWith('INSERT'));
    expect(inserts.length).toBeGreaterThan(1);
    expect(Math.max(...inserts.map((c) => c.params))).toBeLessThanOrEqual(65535);
    expect(inserts.reduce((sum, c) => sum + c.params, 0)).toBe(total * 8);
    expect(calls[0]?.sql).toBe('BEGIN');
    expect(calls[calls.length - 1]?.sql).toBe('COMMIT');
    await transport.close();
  });

  it('rolls back when a later chunk fails', async () => {
    const statements: string[] = [];
    let inserts = 0;
    const connection = {
      query: async (sql: string) => {
        const head = sql.trim().split('\n')[0] ?? '';
        statements.push(head);
        if (head.startsWith('INSERT') && ++inserts === 2) throw new Error('boom');
        return { rows: [] };
      },
      end: async () => {},
    };
    const transport = makeTransport('postgresql', connection);
    for (let i = 0; i < 20000; i += 1) transport.addToBatch(makeEntry(i));

    await expect(transport.flush()).rejects.toThrow('boom');
    expect(statements).toContain('ROLLBACK');
    expect(statements).not.toContain('COMMIT');
    expect(transport.getBatchInfo().currentBatchLength).toBe(20000);
  });
});

describe('DatabaseTransport mysql chunking', () => {
  it('splits large batches into chunks inside a transaction', async () => {
    const rowsPerCall: number[] = [];
    const steps: string[] = [];
    const connection = {
      beginTransaction: async () => void steps.push('begin'),
      commit: async () => void steps.push('commit'),
      rollback: async () => void steps.push('rollback'),
      query: async (_sql: string, args: unknown[][][]) => {
        rowsPerCall.push(args[0]?.length ?? 0);
        return [[], []];
      },
      end: async () => {},
    };
    const transport = makeTransport('mysql', connection);
    for (let i = 0; i < 12000; i += 1) transport.addToBatch(makeEntry(i));

    await transport.flush();

    expect(rowsPerCall).toEqual([5000, 5000, 2000]);
    expect(steps).toEqual(['begin', 'commit']);
    await transport.close();
  });
});

describe('DatabaseTransport getLogCount', () => {
  it('reads the count from sqlite via get()', async () => {
    const transport = makeTransport('sqlite', {
      get: async () => ({ count: 7 }),
      close: async () => {},
    });
    expect(await transport.getLogCount()).toBe(7);
    await transport.close();
  });

  it('reads the count from the [rows, fields] tuple mysql2 returns', async () => {
    const transport = makeTransport('mysql', {
      query: async () => [[{ count: '42' }], []],
      end: async () => {},
    });
    expect(await transport.getLogCount()).toBe(42);
    await transport.close();
  });

  it('reads the count from postgres rows', async () => {
    const transport = makeTransport('postgresql', {
      query: async () => ({ rows: [{ count: '5' }] }),
      end: async () => {},
    });
    expect(await transport.getLogCount()).toBe(5);
    await transport.close();
  });
});
