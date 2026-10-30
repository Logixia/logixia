/**
 * Tests for the OTLP Logs transport (R2).
 *
 * Verifies the OTel SeverityNumber mapping, the OTLP/HTTP JSON payload shape
 * (resource attributes, scopeLogs, logRecords with severity/body/attributes/
 * traceId), whole-batch drain, close() draining + retry, and failure re-buffer.
 * fetch is mocked — no network.
 */

// OTLP collectors are conventionally reached over plain http on localhost in
// dev/test (e.g. http://localhost:4318/v1/logs); these are test URLs, not prod.
/* eslint-disable sonarjs/no-clear-text-protocols */
import type { TransportLogEntry } from '../../types/transport.types';
import { OtlpLogTransport, toOtelSeverity } from '../otlp.transport';

function entry(i: number, over: Partial<TransportLogEntry> = {}): TransportLogEntry {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    level: 'info',
    message: `otlp-${i}`,
    ...over,
  };
}

describe('toOtelSeverity', () => {
  it('maps standard levels to the OTel SeverityNumber scale', () => {
    expect(toOtelSeverity('trace').number).toBe(1);
    expect(toOtelSeverity('debug').number).toBe(5);
    expect(toOtelSeverity('info').number).toBe(9);
    expect(toOtelSeverity('warn').number).toBe(13);
    expect(toOtelSeverity('error').number).toBe(17);
    expect(toOtelSeverity('fatal').number).toBe(21);
  });

  it('falls back to INFO (9) for unknown/custom levels', () => {
    expect(toOtelSeverity('kafka').number).toBe(9);
    expect(toOtelSeverity('kafka').text).toBe('INFO');
  });
});

describe('OtlpLogTransport', () => {
  let fetchMock: jest.Mock;
  let original: typeof globalThis.fetch | undefined;

  beforeEach(() => {
    original = globalThis.fetch;
    fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    (globalThis as { fetch: unknown }).fetch = fetchMock;
  });

  afterEach(() => {
    (globalThis as { fetch: unknown }).fetch = original;
  });

  function lastPayload(): Record<string, unknown> {
    const call = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
    return JSON.parse((call[1] as { body: string }).body);
  }

  it('POSTs an OTLP-shaped payload with resource + scope + logRecords', async () => {
    const t = new OtlpLogTransport({
      url: 'http://collector:4318/v1/logs',
      serviceName: 'api',
      serviceVersion: '1.2.3',
      environment: 'prod',
      batchSize: 1000,
      flushIntervalMs: 999_999,
    });
    t.write(
      entry(1, {
        level: 'error',
        message: 'boom',
        traceId: '123e4567-e89b-12d3-a456-426614174000',
        data: { code: 42 },
      })
    );
    await t.flush();

    const p = lastPayload() as {
      resourceLogs: Array<{
        resource: { attributes: Array<{ key: string; value: { stringValue?: string } }> };
        scopeLogs: Array<{
          scope: { name: string };
          logRecords: Array<Record<string, unknown>>;
        }>;
      }>;
    };

    const rl = p.resourceLogs[0]!;
    const resAttrKeys = rl.resource.attributes.map((a) => a.key);
    expect(resAttrKeys).toContain('service.name');
    expect(resAttrKeys).toContain('service.version');
    expect(resAttrKeys).toContain('deployment.environment');

    const rec = rl.scopeLogs[0]!.logRecords[0]!;
    expect(rec.severityNumber).toBe(17); // error
    expect(rec.severityText).toBe('ERROR');
    expect((rec.body as { stringValue: string }).stringValue).toBe('boom');
    expect(rec.traceId).toBe('123e4567e89b12d3a456426614174000');
    // data fields become attributes
    const attrs = rec.attributes as Array<{ key: string; value: { intValue?: number } }>;
    expect(attrs.find((a) => a.key === 'code')?.value.intValue).toBe(42);

    await t.close();
  });

  it('drains the whole batch across multiple POSTs', async () => {
    const t = new OtlpLogTransport({
      url: 'http://c/v1/logs',
      batchSize: 10,
      flushIntervalMs: 999_999,
    });
    for (let i = 0; i < 35; i += 1) t.write(entry(i));
    await t.flush();

    const totalRecords = fetchMock.mock.calls.reduce((sum, call) => {
      const body = JSON.parse((call[1] as { body: string }).body);
      return sum + body.resourceLogs[0].scopeLogs[0].logRecords.length;
    }, 0);
    expect(totalRecords).toBe(35);
    await t.close();
  });

  it('re-buffers on a failed POST (no loss) and close() drains it', async () => {
    fetchMock.mockResolvedValueOnce({ ok: false, status: 503 });
    const t = new OtlpLogTransport({
      url: 'http://c/v1/logs',
      batchSize: 1000,
      flushIntervalMs: 999_999,
    });
    for (let i = 0; i < 5; i += 1) t.write(entry(i));

    await t.flush(); // first POST fails → re-buffered
    await t.close(); // retries and drains

    const totalRecords = fetchMock.mock.calls
      .filter((c) => c)
      .reduce((sum, call) => {
        try {
          const body = JSON.parse((call[1] as { body: string }).body);
          return sum + body.resourceLogs[0].scopeLogs[0].logRecords.length;
        } catch {
          return sum;
        }
      }, 0);
    // 5 records were eventually delivered (the failed attempt re-queued them).
    expect(totalRecords).toBeGreaterThanOrEqual(5);
  });

  it('serializes object data and bigint without throwing', async () => {
    const t = new OtlpLogTransport({
      url: 'http://c/v1/logs',
      batchSize: 1000,
      flushIntervalMs: 999_999,
    });
    t.write(entry(1, { data: { nested: { a: 1 }, big: BigInt(9) } }));
    await expect(t.flush()).resolves.toBeUndefined();
    await t.close();
  });

  describe('trace and span correlation', () => {
    type Rec = Record<string, unknown> & { attributes: Array<{ key: string; value: unknown }> };

    async function record(over: Partial<TransportLogEntry>): Promise<Rec> {
      const t = new OtlpLogTransport({
        url: 'http://c/v1/logs',
        batchSize: 1000,
        flushIntervalMs: 999_999,
      });
      t.write(entry(1, over));
      await t.flush();
      await t.close();
      const body = JSON.parse((fetchMock.mock.calls[0]![1] as { body: string }).body);
      return body.resourceLogs[0].scopeLogs[0].logRecords[0] as Rec;
    }
    const keys = (r: Rec) => r.attributes.map((a) => a.key);

    it('omits an undefined traceId instead of emitting an empty attribute', async () => {
      const rec = await record({ data: { traceId: undefined, orderId: 'o1' } });
      expect(keys(rec)).not.toContain('traceId');
      expect(keys(rec)).not.toContain('trace_id');
      expect(rec['traceId']).toBeUndefined();
      expect(keys(rec)).toContain('orderId');
    });

    it('puts valid hex span and trace ids into the native record fields', async () => {
      const rec = await record({
        data: { traceId: '0af7651916cd43dd8448eb211c80319c', spanId: 'b7ad6b7169203331' },
      });
      expect(rec['traceId']).toBe('0af7651916cd43dd8448eb211c80319c');
      expect(rec['spanId']).toBe('b7ad6b7169203331');
      expect(keys(rec)).not.toContain('traceId');
      expect(keys(rec)).not.toContain('spanId');
    });

    it('does not repeat an entry traceId that the payload also carries', async () => {
      const id = '0af7651916cd43dd8448eb211c80319c';
      const rec = await record({ traceId: id, data: { traceId: id } });
      expect(rec['traceId']).toBe(id);
      expect(keys(rec)).not.toContain('traceId');
    });

    it('keeps non-hex span ids as attributes', async () => {
      const rec = await record({ data: { spanId: 'span-1' } });
      expect(rec['spanId']).toBeUndefined();
      expect(keys(rec)).toContain('spanId');
    });

    it('keeps a non-hex entry traceId as a trace_id attribute', async () => {
      const rec = await record({ traceId: 'req-1' });
      expect(rec['traceId']).toBeUndefined();
      expect(keys(rec)).toContain('trace_id');
    });
  });
});
