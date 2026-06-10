/**
 * Verification example for the overlapping-batch-flush fix.
 *
 * Reproduces the production incident where a synchronous burst of logs (e.g. a
 * NestJS app replaying buffered bootstrap logs) caused a batching transport to
 * write the SAME entries many times — ~120 logs became thousands of lines.
 *
 * This drives the AnalyticsTransport batching path (shared by Mixpanel/DataDog/
 * Segment/Google Analytics) with a fake provider that just counts what it
 * receives, then asserts:
 *   - every entry is delivered EXACTLY once  (no N² duplication)
 *   - a failed batch is re-buffered and re-sent (no log loss)
 *   - close() drains everything on shutdown    (no loss on deploy)
 *
 * Run: npx ts-node examples/verify-flush-no-duplication.ts
 */

import { AnalyticsTransport } from '../src/transports/analytics.transport';
import { CloudWatchTransport } from '../src/transports/cloudwatch.transport';
import type { AnalyticsTransportConfig, TransportLogEntry } from '../src/types/transport.types';

class FakeProviderTransport extends AnalyticsTransport {
  public readonly received: string[] = [];
  public sendBatchCalls = 0;
  private failFirst: boolean;

  constructor(config: AnalyticsTransportConfig, failFirst = false) {
    super('fake-provider', config);
    this.failFirst = failFirst;
    this.isReady = true;
  }

  protected initialize(): void {
    this.isReady = true;
  }
  protected async sendEntry(entry: TransportLogEntry): Promise<void> {
    this.received.push(entry.message);
  }
  protected async sendBatch(entries: TransportLogEntry[]): Promise<void> {
    this.sendBatchCalls += 1;
    // Simulate network latency so concurrent flushes actually overlap.
    await new Promise((r) => setTimeout(r, 5));
    if (this.failFirst && this.sendBatchCalls === 1) {
      throw new Error('simulated provider outage');
    }
    for (const e of entries) this.received.push(e.message);
  }
  protected cleanup(): void {
    /* no-op */
  }
}

function entry(i: number): TransportLogEntry {
  return { timestamp: new Date(), level: 'info', message: `event-${i}` };
}

async function main() {
  let allPassed = true;
  const check = (name: string, cond: boolean, detail: string) => {
    console.log(`${cond ? '✅ PASS' : '❌ FAIL'}  ${name} — ${detail}`);
    if (!cond) allPassed = false;
  };

  // ── Scenario 1: synchronous burst, un-awaited writes ───────────────────────
  {
    const t = new FakeProviderTransport({ apiKey: 'test', batchSize: 50, flushInterval: 0 });
    const TOTAL = 600;
    const writes: Array<Promise<void>> = [];
    for (let i = 0; i < TOTAL; i++) writes.push(t.write(entry(i)));
    await Promise.allSettled(writes);
    await t.flush();
    check(
      'burst of 600 logs delivered exactly once',
      t.received.length === TOTAL && new Set(t.received).size === TOTAL,
      `delivered=${t.received.length}, unique=${new Set(t.received).size}, expected=${TOTAL}`
    );
    await t.close();
  }

  // ── Scenario 2: concurrent flush() calls collapse to one drain ─────────────
  {
    const t = new FakeProviderTransport({ apiKey: 'test', batchSize: 1000, flushInterval: 0 });
    for (let i = 0; i < 100; i++) await t.write(entry(i));
    await Promise.all([t.flush(), t.flush(), t.flush(), t.flush()]);
    check(
      '4 concurrent flushes do not duplicate',
      t.received.length === 100 && new Set(t.received).size === 100,
      `delivered=${t.received.length}, sendBatchCalls=${t.sendBatchCalls}`
    );
    await t.close();
  }

  // ── Scenario 3: failed batch is re-buffered, then close() drains it ────────
  {
    const t = new FakeProviderTransport({ apiKey: 'test', batchSize: 1000, flushInterval: 0 }, true);
    for (let i = 0; i < 10; i++) await t.write(entry(i));
    await t.flush(); // first attempt fails inside drain → re-buffered
    const afterFail = t.received.length;
    await t.close(); // retries and drains everything
    check(
      'no log loss when provider fails then recovers on close',
      afterFail === 0 && t.received.length === 10 && new Set(t.received).size === 10,
      `afterFailedFlush=${afterFail}, afterClose=${t.received.length}`
    );
  }

  // ── Scenario 4: cloud transport drains its whole batch + close() on shutdown ─
  {
    const t = new CloudWatchTransport({
      logGroupName: '/verify',
      batchSize: 10,
      flushIntervalMs: 999_999,
    });
    const recorded: unknown[] = [];
    // Stub the private network call so no real AWS request is made.
    (t as unknown as { putLogEvents: (e: unknown[]) => Promise<void> }).putLogEvents = async (
      events
    ) => {
      recorded.push(...events);
    };
    for (let i = 0; i < 95; i++) t.write(entry(i)); // 95 > batchSize → tail would be left by old flush()
    await t.close(); // must drain ALL 95, not just one chunk, then stop the timer
    check(
      'cloud transport close() drains the whole batch on shutdown',
      recorded.length === 95,
      `delivered=${recorded.length}, expected=95`
    );
  }

  console.log(`\n${allPassed ? '🎉 ALL CHECKS PASSED' : '🔥 SOME CHECKS FAILED'}`);
  process.exit(allPassed ? 0 : 1);
}

main().catch((err) => {
  console.error('Example crashed:', err);
  process.exit(1);
});
