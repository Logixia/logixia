import { gunzipSync } from 'node:zlib';

import type { DataDogTransportConfig, TransportLogEntry } from '../../types/transport.types';
import { DataDogTransport } from '../datadog.transport';

type Log = Record<string, any>;

const fetchMock = jest.fn();

function makeEntry(overrides: Partial<TransportLogEntry> = {}): TransportLogEntry {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    level: 'info',
    message: 'hello from the test suite',
    ...overrides,
  };
}

function makeTransport(config: Partial<DataDogTransportConfig> = {}): DataDogTransport {
  return new DataDogTransport({ apiKey: 'secret-key', batchSize: 1, ...config });
}

function callBody(index = 0): any {
  const body = fetchMock.mock.calls[index][1].body;
  return JSON.parse(typeof body === 'string' ? body : gunzipSync(body).toString());
}

function callUrl(index = 0): string {
  return fetchMock.mock.calls[index][0] as string;
}

beforeEach(() => {
  fetchMock.mockReset();
  fetchMock.mockResolvedValue({ ok: true, status: 200, statusText: 'OK' });
  global.fetch = fetchMock as unknown as typeof fetch;
});

describe('DataDogTransport logs intake', () => {
  it('posts a top-level array to /api/v2/logs with the API key in a header only', async () => {
    await makeTransport().write(makeEntry());

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://http-intake.logs.datadoghq.com/api/v2/logs');
    expect(url).not.toContain('secret-key');
    expect(init.method).toBe('POST');
    expect(init.headers['DD-API-KEY']).toBe('secret-key');
    expect(init.headers['Content-Type']).toBe('application/json');
    expect(Array.isArray(callBody())).toBe(true);
  });

  it.each([
    'datadoghq.com',
    'datadoghq.eu',
    'us3.datadoghq.com',
    'us5.datadoghq.com',
    'ap1.datadoghq.com',
    'ddog-gov.com',
  ] as const)('routes site %s to its own intake host', async (site) => {
    await makeTransport({ site }).write(makeEntry());
    expect(callUrl()).toBe(`https://http-intake.logs.${site}/api/v2/logs`);
  });

  it('changes the metrics host with the site too', async () => {
    await makeTransport({ site: 'datadoghq.eu', enableLogs: false, enableMetrics: true }).write(
      makeEntry()
    );
    expect(callUrl()).toBe('https://api.datadoghq.eu/api/v1/series');
  });

  it('builds the Datadog log object', async () => {
    await makeTransport({ service: 'api', env: 'staging', version: '1.2.3' }).write(
      makeEntry({ context: 'Auth', data: { userId: 7 } })
    );

    const [log] = callBody() as Log[];
    expect(log).toMatchObject({
      ddsource: 'nodejs',
      ddtags: 'env:staging,service:api,version:1.2.3',
      service: 'api',
      status: 'info',
      message: 'hello from the test suite',
      env: 'staging',
      version: '1.2.3',
      timestamp: '2026-01-01T00:00:00.000Z',
      context: 'Auth',
      userId: 7,
    });
    expect(typeof log['hostname']).toBe('string');
  });

  it('defaults service and env and omits the version tag', async () => {
    await makeTransport().write(makeEntry());
    const [log] = callBody() as Log[];
    expect(log['service']).toBe('logixia');
    expect(log['ddtags']).toBe('env:production,service:logixia');
    expect(JSON.stringify(log)).not.toContain('logitron');
  });

  it.each([
    ['error', 'error'],
    ['warn', 'warn'],
    ['warning', 'warn'],
    ['info', 'info'],
    ['verbose', 'debug'],
    ['fatal', 'critical'],
    ['WARN', 'warn'],
    ['custom-level', 'info'],
  ])('maps level %s to status %s', async (level, status) => {
    await makeTransport().write(makeEntry({ level }));
    expect((callBody() as Log[])[0]?.['status']).toBe(status);
  });

  it('skips debug and trace entries', async () => {
    const transport = makeTransport();
    await transport.write(makeEntry({ level: 'debug' }));
    await transport.write(makeEntry({ level: 'trace' }));
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('keeps core fields authoritative over payload keys', async () => {
    await makeTransport({ service: 'api' }).write(
      makeEntry({
        data: { service: 'evil', status: 'ok', ddtags: 'x:y', ddsource: 'z', hostname: 'h' },
      })
    );
    const [log] = callBody() as Log[];
    expect(log['service']).toBe('api');
    expect(log['status']).toBe('info');
    expect(log['ddsource']).toBe('nodejs');
    expect(log['ddtags']).toBe('env:production,service:api');
    expect(log['hostname']).not.toBe('h');
    expect(log['data_service']).toBe('evil');
    expect(log['data_status']).toBe('ok');
  });

  it('applies custom properties', async () => {
    await makeTransport({ customProperties: { team: 'core' } }).write(makeEntry());
    expect((callBody() as Log[])[0]?.['team']).toBe('core');
  });

  describe('trace correlation', () => {
    it('sends the low 64 bits of a W3C trace id as a decimal dd.trace_id', async () => {
      await makeTransport().write(
        makeEntry({
          traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
          data: { spanId: '00f067aa0ba902b7' },
        })
      );
      const [log] = callBody() as Log[];
      expect(log['dd.trace_id']).toBe(BigInt('0xa3ce929d0e0e4736').toString());
      expect(log['dd.span_id']).toBe(BigInt('0x00f067aa0ba902b7').toString());
    });

    it('omits dd.span_id when there is no active span', async () => {
      await makeTransport().write(makeEntry({ traceId: '1234abcd1234abcd' }));
      const [log] = callBody() as Log[];
      expect(log['dd.trace_id']).toBe(BigInt('0x1234abcd1234abcd').toString());
      expect(log).not.toHaveProperty('dd.span_id');
    });

    it('omits both ids without a trace id and never invents a span id', async () => {
      await makeTransport().write(makeEntry());
      const [log] = callBody() as Log[];
      expect(log).not.toHaveProperty('dd.trace_id');
      expect(log).not.toHaveProperty('dd.span_id');
    });

    it('passes a non-hex trace id through unchanged', async () => {
      await makeTransport().write(makeEntry({ traceId: 'req-123' }));
      expect((callBody() as Log[])[0]?.['dd.trace_id']).toBe('req-123');
    });

    it('does not let a payload override dd.trace_id', async () => {
      await makeTransport().write(
        makeEntry({ traceId: '1234abcd1234abcd', data: { 'dd.trace_id': 'forged' } })
      );
      const [log] = callBody() as Log[];
      expect(log['dd.trace_id']).toBe(BigInt('0x1234abcd1234abcd').toString());
      expect(log['data_dd.trace_id']).toBe('forged');
    });

    it('posts a traced entry once when logs and traces are both on', async () => {
      await makeTransport({ enableTraces: true }).write(makeEntry({ traceId: 'abcdef12' }));
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
  });

  describe('batch limits', () => {
    it('sends a small batch as one request', async () => {
      const transport = makeTransport() as any;
      await transport.sendBatch([makeEntry(), makeEntry({ level: 'error' })]);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(callBody()).toHaveLength(2);
    });

    it('splits more than 1000 entries into several requests', async () => {
      const transport = makeTransport() as any;
      await transport.sendBatch(Array.from({ length: 2500 }, () => makeEntry()));
      expect(fetchMock.mock.calls.map((_, i) => callBody(i).length)).toEqual([1000, 1000, 500]);
    });

    it('splits a batch that would pass 5MB', async () => {
      const transport = makeTransport() as any;
      const big = 'x'.repeat(900_000);
      await transport.sendBatch(Array.from({ length: 8 }, () => makeEntry({ message: big })));
      expect(fetchMock.mock.calls.length).toBeGreaterThan(1);
      for (let i = 0; i < fetchMock.mock.calls.length; i += 1) {
        expect(Buffer.byteLength(fetchMock.mock.calls[i][1].body)).toBeLessThanOrEqual(5_000_000);
      }
      const total = fetchMock.mock.calls.reduce((n, _c, i) => n + callBody(i).length, 0);
      expect(total).toBe(8);
    });

    it('truncates a single log over 1MB', async () => {
      const transport = makeTransport() as any;
      await transport.sendBatch([makeEntry({ message: 'y'.repeat(1_500_000) })]);
      const [log] = callBody() as Log[];
      expect(log['truncated']).toBe(true);
      expect(log['message'].length).toBeLessThan(1_000_000);
      expect(Buffer.byteLength(fetchMock.mock.calls[0][1].body)).toBeLessThan(1_000_000);
      expect(log['service']).toBe('logixia');
    });

    it('flushes buffered entries through the batch path', async () => {
      const transport = makeTransport({ batchSize: 100, flushInterval: 60_000 });
      await transport.write(makeEntry());
      await transport.write(makeEntry());
      expect(fetchMock).not.toHaveBeenCalled();
      await transport.close();
      expect(callBody()).toHaveLength(2);
    });
  });

  it('gzips the body when compress is on', async () => {
    await makeTransport({ compress: true }).write(makeEntry());
    const init = fetchMock.mock.calls[0][1];
    expect(init.headers['Content-Encoding']).toBe('gzip');
    expect(Array.isArray(callBody())).toBe(true);
  });

  it('sends no Content-Encoding by default', async () => {
    await makeTransport().write(makeEntry());
    expect(fetchMock.mock.calls[0][1].headers).not.toHaveProperty('Content-Encoding');
  });

  it('sends no logs request when enableLogs is false', async () => {
    await makeTransport({ enableLogs: false }).write(makeEntry());
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('DataDogTransport errors', () => {
  it('rejects sendBatch with the status on a non-2xx response', async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 403, statusText: 'Forbidden' });
    const transport = makeTransport() as any;
    await expect(transport.sendBatch([makeEntry()])).rejects.toThrow(/403/);
  });

  it('wraps network failures without leaking the API key', async () => {
    fetchMock.mockRejectedValue(new Error('socket hang up'));
    const transport = makeTransport() as any;
    const error = await transport.sendBatch([makeEntry()]).catch((e: Error) => e);
    expect(error.message).toContain('Failed to send logs to DataDog');
    expect(error.message).not.toContain('secret-key');
  });

  it('keeps entries for the next flush when the request fails', async () => {
    fetchMock.mockResolvedValueOnce({ ok: false, status: 500, statusText: 'Server Error' });
    const transport = makeTransport({ batchSize: 100, flushInterval: 60_000 });
    await transport.write(makeEntry());
    await transport.flush();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await transport.flush();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(callBody(1)).toHaveLength(1);
  });

  it('fails writes when the API key is missing', async () => {
    const transport = new DataDogTransport({ apiKey: '', batchSize: 1 });
    await expect(transport.write(makeEntry())).rejects.toThrow('API key is required');
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('DataDogTransport metrics and events', () => {
  it('posts a count metric to /api/v1/series', async () => {
    await makeTransport({ enableLogs: false, enableMetrics: true, service: 'api' }).write(
      makeEntry({ level: 'error', context: 'Db', appName: 'web' })
    );
    expect(callUrl()).toBe('https://api.datadoghq.com/api/v1/series');
    expect(fetchMock.mock.calls[0][1].headers['DD-API-KEY']).toBe('secret-key');
    const [series] = callBody().series;
    expect(series).toMatchObject({
      metric: 'logitron.logs.error',
      type: 'count',
      points: [[1767225600, 1]],
    });
    expect(series.tags).toEqual(
      expect.arrayContaining([
        'level:error',
        'service:api',
        'env:production',
        'context:Db',
        'app:web',
      ])
    );
  });

  it('sends logs and metrics together when both are enabled', async () => {
    await makeTransport({ enableMetrics: true }).write(makeEntry());
    expect(fetchMock.mock.calls.map((c) => c[0]).sort()).toEqual([
      'https://api.datadoghq.com/api/v1/series',
      'https://http-intake.logs.datadoghq.com/api/v2/logs',
    ]);
  });

  it('sends custom gauge metrics', async () => {
    await makeTransport().sendCustomMetric({
      name: 'queue.depth',
      value: 4,
      tags: { q: 'a' },
      timestamp: new Date('2026-01-01T00:00:00.000Z'),
    });
    expect(callUrl()).toBe('https://api.datadoghq.com/api/v1/series');
    expect(callBody().series[0]).toMatchObject({
      metric: 'queue.depth',
      type: 'gauge',
      points: [[1767225600, 4]],
      tags: ['q:a'],
    });
  });

  it('posts events to /api/v1/events', async () => {
    await makeTransport({ service: 'api' }).sendEvent('Deploy', 'done', ['team:core']);
    expect(callUrl()).toBe('https://api.datadoghq.com/api/v1/events');
    expect(callBody()).toMatchObject({
      title: 'Deploy',
      text: 'done',
      source_type_name: 'logixia',
      tags: ['service:api', 'env:production', 'team:core'],
    });
  });

  it('rejects events and metrics on non-2xx responses', async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 429, statusText: 'Too Many' });
    const transport = makeTransport();
    await expect(transport.sendEvent('t', 'x')).rejects.toThrow(/429/);
    await expect(transport.sendCustomMetric({ name: 'm', value: 1 })).rejects.toThrow(/429/);
  });
});
