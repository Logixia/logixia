/**
 * Flush behaviour of the network transports against a real local HTTP server:
 * serialized sends, close() waiting for in-flight requests, ordered re-queue,
 * buffer cap, 4xx drop, and request timeout.
 */

import * as http from 'node:http';
import type { AddressInfo, Socket } from 'node:net';

import type { TransportLogEntry } from '../../types/transport.types';
import { AzureMonitorTransport } from '../azure-monitor.transport';
import { BatchBuffer, HttpError, httpRequest } from '../batch-buffer';
import { CloudWatchTransport } from '../cloudwatch.transport';
import { GCPTransport } from '../gcp.transport';
import { OtlpLogTransport, toOtlpTraceId } from '../otlp.transport';

process.env['LOGIXIA_SILENT_INTERNAL'] = '1';

type Handler = (req: http.IncomingMessage, res: http.ServerResponse, body: string) => void;

interface TestServer {
  url: string;
  received: string[][];
  setHandler(h: Handler): void;
  close(): Promise<void>;
}

async function startServer(initial: Handler): Promise<TestServer> {
  let handler = initial;
  const received: string[][] = [];
  const sockets = new Set<Socket>();
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c: Buffer) => (body += c.toString()));
    req.on('end', () => {
      try {
        const parsed = JSON.parse(body) as {
          resourceLogs: Array<{
            scopeLogs: Array<{ logRecords: Array<{ body: { stringValue: string } }> }>;
          }>;
        };
        received.push(
          parsed.resourceLogs[0]!.scopeLogs[0]!.logRecords.map((r) => r.body.stringValue)
        );
      } catch {
        received.push([]);
      }
      handler(req, res, body);
    });
  });
  server.on('connection', (s) => {
    sockets.add(s);
    s.on('close', () => sockets.delete(s));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}/v1/logs`,
    received,
    setHandler: (h) => {
      handler = h;
    },
    close: () =>
      new Promise<void>((r) => {
        for (const s of sockets) s.destroy();
        server.close(() => r());
      }),
  };
}

const ok = (_req: http.IncomingMessage, res: http.ServerResponse): void => {
  res.statusCode = 200;
  res.end('{}');
};

function entry(i: number): TransportLogEntry {
  return { timestamp: new Date('2026-01-01T00:00:00.000Z'), level: 'info', message: `m${i}` };
}

const names = (n: number, from = 0): string[] =>
  Array.from({ length: n }, (_, i) => `m${from + i}`);

describe('network transports against a local server', () => {
  let server: TestServer;

  afterEach(async () => {
    await server.close();
  });

  it('close() waits for a slow in-flight request started by a threshold flush', async () => {
    server = await startServer((_req, res) => setTimeout(() => ok(_req, res), 300));
    const t = new OtlpLogTransport({ url: server.url, batchSize: 3, flushIntervalMs: 999_999 });
    for (let i = 0; i < 3; i += 1) t.write(entry(i));

    const started = Date.now();
    await t.close();

    expect(Date.now() - started).toBeGreaterThanOrEqual(250);
    expect(server.received.flat()).toEqual(names(3));
  });

  it('overlapping flush() calls share one send instead of duplicating entries', async () => {
    server = await startServer((_req, res) => setTimeout(() => ok(_req, res), 100));
    const t = new OtlpLogTransport({ url: server.url, batchSize: 100, flushIntervalMs: 999_999 });
    for (let i = 0; i < 5; i += 1) t.write(entry(i));

    await Promise.all([t.flush(), t.flush(), t.flush()]);
    await t.close();

    expect(server.received).toHaveLength(1);
    expect(server.received[0]).toEqual(names(5));
  });

  it('keeps order across failed sends and delivers everything once the server recovers', async () => {
    server = await startServer((_req, res) => {
      res.statusCode = 500;
      res.end('down');
    });
    const t = new OtlpLogTransport({ url: server.url, batchSize: 3, flushIntervalMs: 999_999 });
    for (let i = 0; i < 12; i += 1) t.write(entry(i));

    await t.flush();
    await t.flush();
    server.setHandler((req, res) => ok(req, res));
    server.received.length = 0;
    await t.close();

    expect(server.received.flat()).toEqual(names(12));
  });

  it('caps the buffer and drops the oldest entries while the endpoint is down', async () => {
    server = await startServer((_req, res) => {
      res.statusCode = 503;
      res.end();
    });
    const t = new OtlpLogTransport({
      url: server.url,
      batchSize: 100,
      maxBufferSize: 5,
      flushIntervalMs: 999_999,
    });
    for (let i = 0; i < 12; i += 1) t.write(entry(i));
    await t.flush();

    server.setHandler((req, res) => ok(req, res));
    server.received.length = 0;
    await t.close();

    expect(server.received.flat()).toEqual(names(5, 7));
  });

  it('drops a batch the server rejects with 400 instead of retrying it', async () => {
    server = await startServer((_req, res) => {
      res.statusCode = 400;
      res.end('bad');
    });
    const t = new OtlpLogTransport({ url: server.url, batchSize: 100, flushIntervalMs: 999_999 });
    for (let i = 0; i < 4; i += 1) t.write(entry(i));

    await t.flush();
    await t.flush();
    await t.close();

    expect(server.received).toHaveLength(1);
  });

  it('retries on 429', async () => {
    let hits = 0;
    server = await startServer((_req, res) => {
      hits += 1;
      res.statusCode = hits === 1 ? 429 : 200;
      res.end('{}');
    });
    const t = new OtlpLogTransport({ url: server.url, batchSize: 100, flushIntervalMs: 999_999 });
    t.write(entry(0));

    await t.flush();
    await t.flush();

    expect(server.received).toEqual([['m0'], ['m0']]);
    await t.close();
  });

  it('times out a hanging server and keeps the entries buffered', async () => {
    server = await startServer(() => {
      /* never respond */
    });
    const t = new OtlpLogTransport({
      url: server.url,
      batchSize: 100,
      requestTimeoutMs: 100,
      flushIntervalMs: 999_999,
    });
    t.write(entry(0));

    const started = Date.now();
    await t.flush();
    expect(Date.now() - started).toBeLessThan(2000);

    server.setHandler((req, res) => ok(req, res));
    server.received.length = 0;
    await t.close();
    expect(server.received.flat()).toEqual(['m0']);
  });

  it('httpRequest times out and reports HttpError for non-2xx', async () => {
    server = await startServer(() => {
      /* never respond */
    });
    await expect(
      httpRequest({ url: new URL(server.url), body: '{}', timeoutMs: 80, label: 'hang' })
    ).rejects.toThrow(/timed out/);

    server.setHandler((_req, res) => {
      res.statusCode = 403;
      res.end('nope');
    });
    await expect(
      httpRequest({ url: new URL(server.url), body: '{}', timeoutMs: 1000, label: 'x' })
    ).rejects.toMatchObject({ status: 403, body: 'nope' });
  });
});

describe('BatchBuffer', () => {
  it('stops the drain loop on failure and restores the batch at the front', async () => {
    const sent: number[][] = [];
    let fail = true;
    const buf = new BatchBuffer<number>({
      name: 't',
      batchSize: 2,
      send: async (items) => {
        if (fail) throw new Error('boom');
        sent.push(items);
      },
    });
    for (let i = 0; i < 5; i += 1) buf.push(i);
    await buf.flush();
    expect(buf).toHaveLength(5);
    fail = false;
    await buf.flush();
    expect(sent).toEqual([[0, 1], [2, 3], [4]]);
  });

  it('drops on a 4xx HttpError and continues with the next batch', async () => {
    const sent: number[][] = [];
    const buf = new BatchBuffer<number>({
      name: 't',
      batchSize: 2,
      send: async (items) => {
        if (items[0] === 0) throw new HttpError(400, 'bad', 'x');
        sent.push(items);
      },
    });
    for (let i = 0; i < 4; i += 1) buf.push(i);
    await buf.flush();
    expect(sent).toEqual([[2, 3]]);
    expect(buf).toHaveLength(0);
  });

  it('does not start threshold flushes while backing off after a failure', async () => {
    const send = jest.fn().mockRejectedValue(new Error('down'));
    const buf = new BatchBuffer<number>({ name: 't', batchSize: 1, send });
    buf.push(1);
    buf.flushIfFull();
    await buf.flush().catch(() => {});
    const calls = send.mock.calls.length;
    buf.push(2);
    buf.flushIfFull();
    buf.flushIfFull();
    expect(send.mock.calls).toHaveLength(calls);
  });
});

describe('toOtlpTraceId', () => {
  it('strips dashes from UUIDs and lowercases', () => {
    expect(toOtlpTraceId('0AF7651916CD43DD8448EB211C80319C')).toBe(
      '0af7651916cd43dd8448eb211c80319c'
    );
    expect(toOtlpTraceId('123e4567-e89b-12d3-a456-426614174000')).toBe(
      '123e4567e89b12d3a456426614174000'
    );
  });

  it('rejects ids that are not 32 hex characters', () => {
    expect(toOtlpTraceId('req-abc')).toBeUndefined();
    expect(toOtlpTraceId('0'.repeat(32))).toBeUndefined();
  });
});

describe('cloud transports flush serialization and token failure', () => {
  it('CloudWatch close() waits for a send started by a threshold flush', async () => {
    const t = new CloudWatchTransport({
      logGroupName: '/t',
      batchSize: 2,
      flushIntervalMs: 999_999,
    });
    let finished = false;
    (t as any).putLogEvents = async () => {
      await new Promise((r) => setTimeout(r, 150));
      finished = true;
    };
    t.write(entry(0));
    t.write(entry(1));
    await t.close();
    expect(finished).toBe(true);
  });

  it('GCP re-buffers instead of dropping when no token is available', async () => {
    const t = new GCPTransport({ projectId: 'p', batchSize: 100, flushIntervalMs: 999_999 });
    (t as any).getAccessToken = async () => null;
    for (let i = 0; i < 4; i += 1) t.write(entry(i));
    await t.flush();

    const delivered: unknown[] = [];
    (t as any).writeEntries = async (items: unknown[]) => {
      delivered.push(...items);
    };
    await t.close();
    expect(delivered).toHaveLength(4);
  });

  it('Azure re-buffers instead of dropping when no token is available', async () => {
    const t = new AzureMonitorTransport({
      endpoint: 'https://x.ingest.monitor.azure.com',
      ruleId: 'dcr-1',
      streamName: 'Custom-L',
      batchSize: 100,
      flushIntervalMs: 999_999,
    });
    (t as any).getAccessToken = async () => null;
    for (let i = 0; i < 4; i += 1) t.write(entry(i));
    await t.flush();

    const delivered: unknown[] = [];
    (t as any).sendEntries = async (items: unknown[]) => {
      delivered.push(...items);
    };
    await t.close();
    expect(delivered).toHaveLength(4);
  });
});
