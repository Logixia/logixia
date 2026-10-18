/**
 * Guards issue #35: the legacy 'logitron' name must not leak into the payloads
 * DataDog receives. The default service, logger name, metric tags and
 * source_type_name are all user-visible data, so a regression here silently
 * mislabels every application's log stream.
 *
 * The payload builder is exercised directly on a prototype instance: the
 * transport's own constructor kicks off an async initialize() that needs a live
 * provider, which is not what this unit test is about.
 */
import type { TransportLogEntry } from '../../types/transport.types';
import { DataDogTransport } from '../datadog.transport';

function makeEntry(): TransportLogEntry {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    level: 'info',
    message: 'hello from the test suite',
  };
}

interface DataDogLogPayload {
  logs: Array<{ service: string; logger: { name: string } }>;
}

interface DataDogInternals {
  config: Record<string, unknown>;
  datadogConfig: { apiKey: string; service?: string; env?: string; version?: string };
  sendLogBatch: (entries: TransportLogEntry[]) => Promise<void>;
  makeLogsRequest: (endpoint: string, payload: unknown) => Promise<void>;
}

function makeTransport(): { transport: DataDogInternals; sent: unknown[] } {
  const sent: unknown[] = [];
  const transport = Object.create(DataDogTransport.prototype) as unknown as DataDogInternals;
  transport.config = {};
  transport.datadogConfig = { apiKey: 'test-key', env: 'production' };
  transport.makeLogsRequest = (_endpoint, payload) => {
    sent.push(payload);
    return Promise.resolve();
  };
  return { transport, sent };
}

describe('DataDogTransport — outgoing payload branding', () => {
  it('labels the log payload with the logixia service and logger, not logitron', async () => {
    const { transport, sent } = makeTransport();

    await transport.sendLogBatch([makeEntry()]);

    expect(sent).toHaveLength(1);
    const payload = sent[0] as DataDogLogPayload;
    expect(payload.logs[0]?.service).toBe('logixia');
    expect(payload.logs[0]?.logger.name).toBe('logixia');
    expect(JSON.stringify(payload)).not.toContain('logitron');
  });
});
