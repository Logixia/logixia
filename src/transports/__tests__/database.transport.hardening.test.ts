import type { DatabaseTransportConfig, TransportLogEntry } from '../../types/transport.types';
import { DatabaseTransport } from '../database.transport';

function makeEntry(index: number, overrides: Partial<TransportLogEntry> = {}): TransportLogEntry {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    level: 'info',
    message: `db-line-${index}`,
    ...overrides,
  };
}

function inject(transport: DatabaseTransport, connection: unknown): void {
  const internals = transport as unknown as { connection: unknown; isConnected: boolean };
  internals.connection = connection;
  internals.isConnected = true;
}

function makeSqlite(
  extra: Partial<DatabaseTransportConfig>,
  reject: (message: string) => boolean = () => false
) {
  const written: string[] = [];
  let pending: string[] = [];
  const connection = {
    prepare: async () => ({
      run: async (...cols: unknown[]) => {
        if (reject(String(cols[2]))) throw new Error('poison row');
        pending.push(String(cols[2]));
      },
      finalize: async () => {},
    }),
    exec: async (sql: string) => {
      if (sql === 'BEGIN' || sql === 'ROLLBACK') pending = [];
      if (sql === 'COMMIT') written.push(...pending);
    },
    close: async () => {},
  };
  const transport = new DatabaseTransport({
    type: 'sqlite',
    database: 'x',
    batchSize: 1_000_000,
    flushInterval: 60000,
    ...extra,
  } as unknown as DatabaseTransportConfig);
  inject(transport, connection);
  return { transport, written };
}

describe('DatabaseTransport buffer cap', () => {
  it('drops the oldest entries past maxBufferSize', () => {
    const { transport } = makeSqlite({ maxBufferSize: 5 });
    for (let i = 0; i < 12; i += 1) transport.addToBatch(makeEntry(i));
    expect(transport.getBatchInfo().currentBatchLength).toBe(5);
  });

  it('keeps the newest entries when it drops', async () => {
    const { transport, written } = makeSqlite({ maxBufferSize: 3 });
    for (let i = 0; i < 6; i += 1) transport.addToBatch(makeEntry(i));
    await transport.flush();
    expect(written).toEqual(['db-line-3', 'db-line-4', 'db-line-5']);
  });
});

describe('DatabaseTransport poison batches', () => {
  it('retries a failing batch maxRetries times before isolating it', async () => {
    const { transport, written } = makeSqlite({ maxRetries: 3 }, (m) => m === 'db-line-2');
    for (let i = 0; i < 5; i += 1) transport.addToBatch(makeEntry(i));

    await expect(transport.flush()).rejects.toThrow('poison row');
    await expect(transport.flush()).rejects.toThrow('poison row');
    expect(transport.getBatchInfo().currentBatchLength).toBe(5);

    await transport.flush();
    expect(transport.getBatchInfo().currentBatchLength).toBe(0);
    expect([...written].sort()).toEqual(['db-line-0', 'db-line-1', 'db-line-3', 'db-line-4']);
  });

  it('keeps a lone failing entry buffered because nothing proves the database is up', async () => {
    const { transport, written } = makeSqlite({ maxRetries: 2 }, () => true);
    transport.addToBatch(makeEntry(0));
    await expect(transport.flush()).rejects.toThrow('poison row');
    await expect(transport.flush()).rejects.toThrow('poison row');
    expect(transport.getBatchInfo().currentBatchLength).toBe(1);
    expect(written).toEqual([]);
  });

  it('keeps every entry during an outage, up to maxBufferSize, and recovers', async () => {
    let down = true;
    const { transport, written } = makeSqlite({ maxRetries: 2, maxBufferSize: 6 }, () => down);
    for (let i = 0; i < 9; i += 1) transport.addToBatch(makeEntry(i));
    for (let round = 0; round < 4; round += 1) {
      await expect(transport.flush()).rejects.toThrow('poison row');
    }
    expect(transport.getBatchInfo().currentBatchLength).toBe(6);

    down = false;
    await transport.flush();
    expect(written).toEqual([
      'db-line-3',
      'db-line-4',
      'db-line-5',
      'db-line-6',
      'db-line-7',
      'db-line-8',
    ]);
  });

  it('does not grow the buffer while the database keeps failing', async () => {
    const { transport } = makeSqlite({ maxBufferSize: 10, maxRetries: 100 }, () => true);
    for (let round = 0; round < 5; round += 1) {
      for (let i = 0; i < 8; i += 1) transport.addToBatch(makeEntry(i));
      await transport.flush().catch(() => {});
    }
    expect(transport.getBatchInfo().currentBatchLength).toBeLessThanOrEqual(10);
  });
});

describe('DatabaseTransport postgres NUL handling', () => {
  it('strips NUL and its JSON escape before insert', async () => {
    const params: unknown[][] = [];
    const connection = {
      query: async (_sql: string, p?: unknown[]) => {
        if (p) params.push(p);
        return { rows: [] };
      },
      end: async () => {},
    };
    const transport = new DatabaseTransport({
      type: 'postgresql',
      database: 'x',
      batchSize: 1000,
      flushInterval: 60000,
    } as unknown as DatabaseTransportConfig);
    inject(transport, connection);

    transport.addToBatch(
      makeEntry(0, {
        message: 'bad\u0000msg',
        context: 'ctx\u0000',
        data: { key: 'va\u0000lue', literal: 'a\\u0000b' },
      })
    );
    await transport.flush();

    const row = params[0] as string[];
    expect(row[2]).toBe('badmsg');
    expect(row[4]).toBe('ctx');
    expect(JSON.parse(row[3] as string)).toEqual({ key: 'value', literal: 'a\\u0000b' });
  });
});
