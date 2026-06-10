/**
 * Tests for DatabaseTransport batching + flush correctness.
 *
 * Two regression guarantees, both reproductions of real production incidents:
 *
 *  1. NO DUPLICATION — write() fires flush() un-awaited once the batch crosses
 *     batchSize, and the interval timer fires it too, so a synchronous burst can
 *     trigger many overlapping flushes. Before the fix each overlapping flush
 *     snapshotted the not-yet-cleared batch and wrote it again (the same class of
 *     bug that turned ~120 NestJS bootstrap logs into 11k file lines). The fix
 *     serializes flushes through a single shared drain promise and detaches the
 *     batch synchronously before awaiting.
 *
 *  2. NO LOG LOSS — a failed flush must re-buffer its entries, and close() must
 *     drain everything (retrying transient failures) before dropping the
 *     connection, so the "last N seconds of logs lost on deploy" problem can't
 *     happen.
 */

import type { DatabaseTransportConfig, TransportLogEntry } from '../../types/transport.types';
import { DatabaseTransport } from '../database.transport';

function makeEntry(index: number): TransportLogEntry {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    level: 'info',
    message: `db-line-${index}`,
  };
}

/**
 * A fake SQLite-style connection that records every row handed to it. We use the
 * sqlite path because flushToSQLite drives the connection through prepare()/run()
 * which is trivial to stub, and the batching/flush logic under test is shared
 * across all DB types.
 */
function makeFakeSqliteTransport(opts: {
  batchSize?: number;
  flushInterval?: number;
  failTimes?: number; // number of run() calls that should throw before succeeding
}) {
  const written: string[] = [];
  let runCalls = 0;
  const failTimes = opts.failTimes ?? 0;

  const stmt = {
    run: async (...cols: unknown[]) => {
      runCalls += 1;
      if (runCalls <= failTimes) {
        throw new Error('simulated DB write failure');
      }
      // cols[2] is the message column (timestamp, level, message, ...)
      written.push(String(cols[2]));
    },
    finalize: async () => {},
  };

  const connection = {
    prepare: async () => stmt,
    exec: async () => {},
    close: async () => {},
  };

  const config = {
    type: 'sqlite',
    database: ':memory:',
    table: 'logs',
    batchSize: opts.batchSize ?? 100,
    flushInterval: opts.flushInterval ?? 5000,
  } as unknown as DatabaseTransportConfig;

  const transport = new DatabaseTransport(config);
  // Inject the fake connection and mark connected so write() skips the real connect().
  const internals = transport as unknown as { connection: unknown; isConnected: boolean };
  internals.connection = connection;
  internals.isConnected = true;

  return { transport, written, getRunCalls: () => runCalls };
}

describe('DatabaseTransport — batch flush', () => {
  it('writes each entry exactly once on a synchronous un-awaited burst far larger than batchSize', async () => {
    const { transport, written } = makeFakeSqliteTransport({ batchSize: 100 });

    const total = 500;
    const writes: Array<Promise<void>> = [];
    for (let index = 0; index < total; index += 1) {
      writes.push(transport.write(makeEntry(index)));
    }
    await Promise.allSettled(writes);
    await transport.flush();

    expect(written).toHaveLength(total);
    expect(new Set(written).size).toBe(total);
    await transport.close();
  });

  it('does not re-write entries when flush() is called concurrently', async () => {
    const { transport, written } = makeFakeSqliteTransport({ batchSize: 1000 });

    const writes: Array<Promise<void>> = [];
    for (let index = 0; index < 50; index += 1) {
      writes.push(transport.write(makeEntry(index)));
    }
    await Promise.allSettled(writes);

    await Promise.all([transport.flush(), transport.flush(), transport.flush()]);
    await transport.flush();

    expect(written).toHaveLength(50);
    expect(new Set(written).size).toBe(50);
    await transport.close();
  });

  it('re-buffers entries when a flush fails so no logs are lost', async () => {
    // First run() throws; the entry must survive and be written on the next flush.
    const { transport, written } = makeFakeSqliteTransport({ batchSize: 1, failTimes: 1 });

    // batchSize 1 → write() triggers a flush that fails; write() rejects but the
    // entry stays buffered.
    await expect(transport.write(makeEntry(0))).rejects.toThrow(/simulated DB write failure/);
    expect(written).toHaveLength(0);

    // Next flush succeeds and drains the re-buffered entry exactly once.
    await transport.flush();
    expect(written).toEqual(['db-line-0']);
    await transport.close();
  });

  it('close() drains all buffered entries (retrying a transient failure) with no loss', async () => {
    const { transport, written } = makeFakeSqliteTransport({
      batchSize: 1000, // never auto-flushes; everything is still buffered at close()
      failTimes: 1, // first close() flush attempt fails, second succeeds
    });

    for (let index = 0; index < 10; index += 1) {
      await transport.write(makeEntry(index));
    }
    // Nothing flushed yet (batch below threshold).
    expect(written).toHaveLength(0);

    await transport.close();

    // All 10 entries landed exactly once despite the first flush attempt failing.
    expect(written).toHaveLength(10);
    expect(new Set(written).size).toBe(10);
  });
});
