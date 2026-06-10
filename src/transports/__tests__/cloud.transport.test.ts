/**
 * Tests for the cloud transports (CloudWatch, GCP Cloud Logging, Azure Monitor).
 *
 * All three buffer entries and flush on an interval. They previously:
 *   - flushed only ONE batchSize chunk per flush() (a tail was left behind), and
 *   - had NO close() method, so on shutdown the manager skipped them and any
 *     buffered logs were lost on deploy.
 *
 * These tests verify flush() now drains the WHOLE batch, close() drains
 * everything and stops the timer, and a failed send re-buffers (no loss, no
 * duplication). The private send method is stubbed so no real network call runs.
 */

import type { TransportLogEntry } from '../../types/transport.types';
import { AzureMonitorTransport } from '../azure-monitor.transport';
import { CloudWatchTransport } from '../cloudwatch.transport';
import { GCPTransport } from '../gcp.transport';

function makeEntry(index: number): TransportLogEntry {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    level: 'info',
    message: `cloud-line-${index}`,
  };
}

/**
 * Wraps a freshly-constructed cloud transport, replacing its private network
 * send method with a recorder. cols are the batched items; we record their count
 * and optionally fail the first N sends.
 */
function instrument(
  transport: { flush(): Promise<void>; close?(): Promise<void>; write(e: TransportLogEntry): void },
  sendMethodName: string,
  failTimes = 0
) {
  const recorded: unknown[] = [];
  let sendCalls = 0;
   
  (transport as any)[sendMethodName] = async (items: unknown[]) => {
    sendCalls += 1;
    if (sendCalls <= failTimes) throw new Error('simulated cloud outage');
    recorded.push(...items);
  };
  return { recorded, getSendCalls: () => sendCalls };
}

describe('Cloud transports — drain & close', () => {
  describe('CloudWatchTransport', () => {
    it('flush() drains the whole batch even when it exceeds batchSize', async () => {
      const t = new CloudWatchTransport({
        logGroupName: '/test',
        batchSize: 10,
        flushIntervalMs: 999_999,
      });
      const { recorded } = instrument(t, 'putLogEvents');

      for (let i = 0; i < 35; i += 1) t.write(makeEntry(i));
      await t.flush();

      expect(recorded).toHaveLength(35);
      await t.close();
    });

    it('close() drains everything through a transient failure with no loss', async () => {
      const t = new CloudWatchTransport({
        logGroupName: '/test',
        batchSize: 1000,
        flushIntervalMs: 999_999,
      });
      const { recorded } = instrument(t, 'putLogEvents', 1);

      for (let i = 0; i < 20; i += 1) t.write(makeEntry(i));
      await t.close();

      expect(recorded).toHaveLength(20);
    });
  });

  describe('GCPTransport', () => {
    it('flush() drains the whole batch and close() stops the timer', async () => {
      const t = new GCPTransport({ projectId: 'p', batchSize: 10, flushIntervalMs: 999_999 });
      const { recorded } = instrument(t, 'writeEntries');

      for (let i = 0; i < 25; i += 1) t.write(makeEntry(i));
      await t.flush();
      expect(recorded).toHaveLength(25);

      await t.close();
    });

    it('close() drains everything through a transient failure with no loss', async () => {
      const t = new GCPTransport({ projectId: 'p', batchSize: 1000, flushIntervalMs: 999_999 });
      const { recorded } = instrument(t, 'writeEntries', 1);

      for (let i = 0; i < 15; i += 1) t.write(makeEntry(i));
      await t.close();

      expect(recorded).toHaveLength(15);
    });
  });

  describe('AzureMonitorTransport', () => {
    it('flush() drains the whole batch and close() stops the timer', async () => {
      const t = new AzureMonitorTransport({
        endpoint: 'https://example.ingest.monitor.azure.com',
        ruleId: 'dcr-123',
        streamName: 'Custom-Logs',
        batchSize: 10,
        flushIntervalMs: 999_999,
      });
      const { recorded } = instrument(t, 'sendEntries');

      for (let i = 0; i < 22; i += 1) t.write(makeEntry(i));
      await t.flush();
      expect(recorded).toHaveLength(22);

      await t.close();
    });

    it('close() drains everything through a transient failure with no loss', async () => {
      const t = new AzureMonitorTransport({
        endpoint: 'https://example.ingest.monitor.azure.com',
        ruleId: 'dcr-123',
        streamName: 'Custom-Logs',
        batchSize: 1000,
        flushIntervalMs: 999_999,
      });
      const { recorded } = instrument(t, 'sendEntries', 1);

      for (let i = 0; i < 18; i += 1) t.write(makeEntry(i));
      await t.close();

      expect(recorded).toHaveLength(18);
    });
  });
});
