import type { DatabaseTransportConfig, TransportLogEntry } from '../../types/transport.types';
import { DatabaseTransport, isDataError } from '../database.transport';

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

const dataError = (): Error =>
  Object.assign(new Error('constraint failed'), { code: 'SQLITE_CONSTRAINT' });
const transientError = (): Error => Object.assign(new Error('timed out'), { code: 'ETIMEDOUT' });

type Failure = (message: string) => Error | undefined;

function makeSqlite(extra: Partial<DatabaseTransportConfig>, failure: Failure = () => {}) {
  const written: string[] = [];
  let pending: string[] = [];
  let transactions = 0;
  const connection = {
    prepare: async () => ({
      run: async (...cols: unknown[]) => {
        const error = failure(String(cols[2]));
        if (error) throw error;
        pending.push(String(cols[2]));
      },
      finalize: async () => {},
    }),
    exec: async (sql: string) => {
      if (sql === 'BEGIN') {
        transactions += 1;
        pending = [];
      }
      if (sql === 'ROLLBACK') pending = [];
      if (sql === 'COMMIT') written.push(...pending);
    },
    close: async () => {},
  };
  const transport = new DatabaseTransport({
    type: 'sqlite',
    database: 'x',
    batchSize: 100,
    flushInterval: 60000,
    ...extra,
  } as unknown as DatabaseTransportConfig);
  inject(transport, connection);
  return { transport, written, writes: () => transactions };
}

const buffered = (t: DatabaseTransport): number => t.getBatchInfo().currentBatchLength;

describe('isDataError', () => {
  it.each([
    ['postgresql', { code: '22021' }, true],
    ['postgresql', { code: '23505' }, true],
    ['postgresql', { code: '54000' }, true],
    ['postgresql', { code: '08006' }, false],
    ['postgresql', { code: '57P01' }, false],
    ['postgresql', { code: 'ECONNREFUSED' }, false],
    ['mysql', { code: 'ER_DATA_TOO_LONG' }, true],
    ['mysql', { errno: 1048 }, true],
    ['mysql', { code: 'ER_ACCESS_DENIED_ERROR' }, false],
    ['mysql', { code: 'PROTOCOL_CONNECTION_LOST' }, false],
    ['sqlite', { code: 'SQLITE_CONSTRAINT' }, true],
    ['sqlite', { code: 'SQLITE_TOOBIG' }, true],
    ['sqlite', { code: 'SQLITE_MISMATCH' }, true],
    ['sqlite', { code: 'SQLITE_BUSY' }, false],
    ['mongodb', { code: 10334 }, true],
    ['mongodb', { name: 'BSONObjectTooLarge' }, true],
    ['mongodb', { code: 91 }, false],
    ['mongodb', { name: 'MongoNetworkError' }, false],
  ])('%s %j -> %s', (type, error, expected) => {
    expect(isDataError(type, error)).toBe(expected);
  });

  it('looks through a wrapped cause and ignores non-objects', () => {
    expect(isDataError('postgresql', new Error('x', { cause: { code: '22P02' } }))).toBe(true);
    expect(isDataError('postgresql', 'boom')).toBe(false);
    expect(isDataError('postgresql')).toBe(false);
  });
});

describe('DatabaseTransport buffer cap', () => {
  it('drops the oldest entries past maxBufferSize', () => {
    const { transport } = makeSqlite({ maxBufferSize: 5, batchSize: 5 });
    for (let i = 0; i < 12; i += 1) transport.addToBatch(makeEntry(i));
    expect(buffered(transport)).toBe(5);
  });

  it('raises maxBufferSize to batchSize', () => {
    const { transport } = makeSqlite({ maxBufferSize: 2, batchSize: 5 });
    for (let i = 0; i < 12; i += 1) transport.addToBatch(makeEntry(i));
    expect(buffered(transport)).toBe(5);
  });

  it('keeps the newest entries when it drops', async () => {
    const { transport, written } = makeSqlite({ maxBufferSize: 3, batchSize: 3 });
    for (let i = 0; i < 6; i += 1) transport.addToBatch(makeEntry(i));
    await transport.flush();
    expect(written).toEqual(['db-line-3', 'db-line-4', 'db-line-5']);
  });
});

describe('DatabaseTransport data errors', () => {
  it('drops only the refused entry and writes the rest', async () => {
    const { transport, written } = makeSqlite({}, (m) =>
      m === 'db-line-2' ? dataError() : undefined
    );
    for (let i = 0; i < 5; i += 1) transport.addToBatch(makeEntry(i));

    await transport.flush();

    expect(buffered(transport)).toBe(0);
    expect([...written].sort()).toEqual(['db-line-0', 'db-line-1', 'db-line-3', 'db-line-4']);
  });

  it('drops a lone refused entry', async () => {
    const { transport, written } = makeSqlite({}, () => dataError());
    transport.addToBatch(makeEntry(0));
    await transport.flush();
    expect(buffered(transport)).toBe(0);
    expect(written).toEqual([]);
  });

  it('stops isolating on a transient error and keeps the unwritten entries', async () => {
    const { transport, written } = makeSqlite({}, (m) => {
      if (m === 'db-line-2') return dataError();
      return m === 'db-line-3' ? transientError() : undefined;
    });
    for (let i = 0; i < 5; i += 1) transport.addToBatch(makeEntry(i));

    await expect(transport.flush()).rejects.toThrow('timed out');

    expect([...written].sort()).toEqual(['db-line-0', 'db-line-1']);
    expect(buffered(transport)).toBe(2);
  });

  it('caps the writes spent isolating one flush at twice the batch size', async () => {
    const { transport, writes } = makeSqlite({ batchSize: 8 }, () => dataError());
    for (let i = 0; i < 8; i += 1) transport.addToBatch(makeEntry(i));
    await transport.flush();
    expect(writes()).toBeLessThanOrEqual(1 + 16);
    expect(buffered(transport)).toBe(0);
  });

  it('only splits the failing batch, not the rest of the buffer', async () => {
    const { transport, writes } = makeSqlite({ batchSize: 4 }, (m) =>
      m === 'db-line-0' ? dataError() : undefined
    );
    for (let i = 0; i < 20; i += 1) transport.addToBatch(makeEntry(i));
    await transport.flush();
    // 5 batches, one extra write per bisect level of the first batch.
    expect(writes()).toBeLessThanOrEqual(5 + 4);
    expect(buffered(transport)).toBe(0);
  });
});

describe('DatabaseTransport outage', () => {
  it('writes once per flush, drops nothing, and keeps entries up to maxBufferSize', async () => {
    let down = true;
    const { transport, written, writes } = makeSqlite({ batchSize: 5, maxBufferSize: 6 }, () =>
      down ? transientError() : undefined
    );
    for (let i = 0; i < 9; i += 1) transport.addToBatch(makeEntry(i));
    expect(buffered(transport)).toBe(6);

    for (let round = 0; round < 4; round += 1) {
      await expect(transport.flush()).rejects.toThrow('timed out');
    }
    expect(writes()).toBe(4);
    expect(buffered(transport)).toBe(6);

    down = false;
    await transport.flush();
    expect(written).toEqual([3, 4, 5, 6, 7, 8].map((i) => `db-line-${i}`));
  });

  it('does not touch the whole buffer when the database is down', async () => {
    const { transport, writes } = makeSqlite({ batchSize: 10, maxBufferSize: 5000 }, () =>
      transientError()
    );
    for (let i = 0; i < 1000; i += 1) transport.addToBatch(makeEntry(i));
    await expect(transport.flush()).rejects.toThrow('timed out');
    expect(writes()).toBe(1);
    expect(buffered(transport)).toBe(1000);
  });
});

describe('DatabaseTransport mongodb', () => {
  function makeMongo(insertMany: jest.Mock) {
    const transport = new DatabaseTransport({
      type: 'mongodb',
      database: 'x',
      batchSize: 10,
      flushInterval: 60000,
    } as unknown as DatabaseTransportConfig);
    inject(transport, {
      db: () => ({ collection: () => ({ insertMany }) }),
      close: async () => {},
    });
    return transport;
  }

  it('inserts unordered', async () => {
    const insertMany = jest.fn(async () => ({}));
    const transport = makeMongo(insertMany);
    transport.addToBatch(makeEntry(0));
    await transport.flush();
    expect(insertMany).toHaveBeenCalledWith(expect.any(Array), { ordered: false });
  });

  it('drops refused documents, keeps transient failures, never re-inserts stored ones', async () => {
    const insertMany = jest
      .fn()
      .mockRejectedValueOnce(
        Object.assign(new Error('bulk'), {
          writeErrors: [
            { index: 1, code: 121 },
            { index: 3, code: 91 },
          ],
        })
      )
      .mockResolvedValue({});
    const transport = makeMongo(insertMany);
    for (let i = 0; i < 5; i += 1) transport.addToBatch(makeEntry(i));

    await expect(transport.flush()).rejects.toThrow('bulk');
    expect(buffered(transport)).toBe(1);

    await transport.flush();
    const retried = (insertMany.mock.calls[1] as unknown[][])[0] as Array<{ message: string }>;
    expect(retried.map((d) => d.message)).toEqual(['db-line-3']);
    expect(buffered(transport)).toBe(0);
  });

  it('rethrows an error without per-document details as transient', async () => {
    const insertMany = jest
      .fn()
      .mockRejectedValueOnce(new Error('network down'))
      .mockResolvedValue({});
    const transport = makeMongo(insertMany);
    for (let i = 0; i < 3; i += 1) transport.addToBatch(makeEntry(i));
    await expect(transport.flush()).rejects.toThrow('network down');
    expect(buffered(transport)).toBe(3);
  });
});

describe('DatabaseTransport postgres NUL handling', () => {
  it('strips NUL everywhere and the JSON escape only from the payload column', async () => {
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
        message: 'bad\u0000msg literal \\u0000 text',
        context: 'ctx\u0000',
        data: { key: 'va\u0000lue', literal: 'a\\u0000b' },
      })
    );
    await transport.flush();

    const row = params[0] as string[];
    expect(row[2]).toBe('badmsg literal \\u0000 text');
    expect(row[4]).toBe('ctx');
    expect(JSON.parse(row[3] as string)).toEqual({ key: 'value', literal: 'a\\u0000b' });
  });
});
