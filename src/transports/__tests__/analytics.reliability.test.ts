import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import * as net from 'node:net';

import { fetchWithTimeout } from '../fetch-timeout';
import { SegmentTransport } from '../segment.transport';

const entry = (i: number) => ({ timestamp: new Date(), level: 'info', message: `m${i}` });

describe('fetchWithTimeout', () => {
  it('rejects instead of hanging on an endpoint that never answers', async () => {
    const sockets: net.Socket[] = [];
    const server = net.createServer((s) => {
      sockets.push(s);
      s.on('data', () => {});
    });
    await new Promise<void>((r) => server.listen(0, r));
    const port = (server.address() as AddressInfo).port;
    await expect(
      fetchWithTimeout(`http://127.0.0.1:${port}/`, { method: 'POST', body: 'x' }, 100)
    ).rejects.toThrow(/timed out after 100ms/);
    for (const s of sockets) s.destroy();
    await new Promise((r) => server.close(r));
  });
});

describe('analytics transport retry backoff', () => {
  it('does not re-send a failing batch on every log once the batch is full', async () => {
    let requests = 0;
    const server = http.createServer((req, res) => {
      requests++;
      req.resume();
      req.on('end', () => {
        res.statusCode = 500;
        res.end('down');
      });
    });
    await new Promise<void>((r) => server.listen(0, r));
    const port = (server.address() as AddressInfo).port;
    process.env['LOGIXIA_SILENT_INTERNAL'] = '1';
    const transport = new SegmentTransport({
      writeKey: 'k',
      dataPlaneUrl: `http://127.0.0.1:${port}`,
      batchSize: 5,
      flushInterval: 60000,
    });
    for (let i = 0; i < 200; i++) {
      await transport.write(entry(i));
      await new Promise((r) => setImmediate(r));
    }
    await new Promise((r) => setTimeout(r, 100));
    expect(requests).toBeLessThanOrEqual(2);
    expect(transport.batch).toHaveLength(200);
    transport.batch = [];
    await transport.close();
    await new Promise((r) => server.close(r));
  });
});
