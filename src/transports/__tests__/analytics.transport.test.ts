/**
 * Tests for the AnalyticsTransport base class batching + flush correctness.
 *
 * AnalyticsTransport is the shared base for Mixpanel, DataDog, Segment, and
 * Google Analytics, so a flush bug here is a bug in all four. addToBatch() fires
 * flush() un-awaited on every Nth entry, so a synchronous burst can trigger many
 * overlapping flushes. Before the fix each overlapping flush snapshotted the
 * not-yet-cleared batch and sent it again — the same N² duplication that turned
 * ~120 logs into thousands of delivered events. The fix serializes flushes
 * through a single shared drain promise and detaches the batch synchronously.
 *
 * Also covers: failed sendBatch() re-buffers entries (no loss), and close()
 * drains everything through a transient failure.
 */

import type { AnalyticsTransportConfig, TransportLogEntry } from '../../types/transport.types';
import { AnalyticsTransport } from '../analytics.transport';

function makeEntry(index: number): TransportLogEntry {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    level: 'info',
    message: `analytics-line-${index}`,
  };
}

/** Concrete test subclass that records every batch it is asked to send. */
class TestAnalyticsTransport extends AnalyticsTransport {
  public readonly sent: string[] = [];
  private failTimes: number;
  private sendCalls = 0;

  constructor(config: AnalyticsTransportConfig, failTimes = 0) {
    super('test-analytics', config);
    this.failTimes = failTimes;
    this.isReady = true; // skip the async init wait
  }

  protected initialize(): void {
    this.isReady = true;
  }

  protected async sendEntry(entry: TransportLogEntry): Promise<void> {
    this.sent.push(entry.message);
  }

  protected async sendBatch(entries: TransportLogEntry[]): Promise<void> {
    this.sendCalls += 1;
    if (this.sendCalls <= this.failTimes) {
      throw new Error('simulated analytics send failure');
    }
    for (const entry of entries) this.sent.push(entry.message);
  }

  protected cleanup(): void {
    /* no-op */
  }
}

describe('AnalyticsTransport — batch flush', () => {
  it('sends each entry exactly once on a synchronous un-awaited burst far larger than batchSize', async () => {
    const transport = new TestAnalyticsTransport({ batchSize: 50, flushInterval: 0 });

    const total = 500;
    const writes: Array<Promise<void>> = [];
    for (let index = 0; index < total; index += 1) {
      writes.push(transport.write(makeEntry(index)));
    }
    await Promise.allSettled(writes);
    await transport.flush();

    expect(transport.sent).toHaveLength(total);
    expect(new Set(transport.sent).size).toBe(total);
    await transport.close();
  });

  it('does not re-send entries when flush() is called concurrently', async () => {
    const transport = new TestAnalyticsTransport({ batchSize: 1000, flushInterval: 0 });

    const writes: Array<Promise<void>> = [];
    for (let index = 0; index < 50; index += 1) {
      writes.push(transport.write(makeEntry(index)));
    }
    await Promise.allSettled(writes);

    await Promise.all([transport.flush(), transport.flush(), transport.flush()]);
    await transport.flush();

    expect(transport.sent).toHaveLength(50);
    expect(new Set(transport.sent).size).toBe(50);
    await transport.close();
  });

  it('re-buffers entries when a send fails so no logs are lost', async () => {
    const transport = new TestAnalyticsTransport({ batchSize: 1000, flushInterval: 0 }, 1);

    for (let index = 0; index < 5; index += 1) {
      await transport.write(makeEntry(index));
    }

    // First flush fails internally (error is swallowed by drain → re-buffered).
    await transport.flush();
    expect(transport.sent).toHaveLength(0);

    // Second flush succeeds and delivers all 5 exactly once.
    await transport.flush();
    expect(transport.sent).toHaveLength(5);
    expect(new Set(transport.sent).size).toBe(5);
    await transport.close();
  });

  it('close() drains all buffered entries through a transient failure with no loss', async () => {
    const transport = new TestAnalyticsTransport({ batchSize: 1000, flushInterval: 0 }, 1);

    for (let index = 0; index < 10; index += 1) {
      await transport.write(makeEntry(index));
    }
    expect(transport.sent).toHaveLength(0);

    await transport.close();

    expect(transport.sent).toHaveLength(10);
    expect(new Set(transport.sent).size).toBe(10);
  });
});
