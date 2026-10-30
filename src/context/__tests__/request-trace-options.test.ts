import type { AddressInfo } from 'node:net';

import express from 'express';
import Fastify from 'fastify';

import { createLogger } from '../../core/logitron-logger';
import { createFastifyPlugin } from '../../middleware/http-logger';
import type { ITransport, TransportLogEntry } from '../../types/transport.types';
import { getCurrentTraceId, runWithTraceId } from '../../utils/trace.utils';
import {
  createExpressContextMiddleware,
  createFastifyContextHook,
  LogixiaContext,
} from '../async-context';

function setup() {
  const entries: TransportLogEntry[] = [];
  const transport: ITransport = { name: 'capture', write: (e) => void entries.push(e) };
  const logger = createLogger({
    appName: 'opts',
    environment: 'test',
    traceId: true,
    silent: false,
    transports: { custom: [transport] },
  });
  return { logger, entries };
}

const TP = '4bf92f3577b34da6a3ce929d0e0e4736';

describe('context helpers: single source of truth and options', () => {
  it('getCurrentTraceId() sees the request id inside Express and Fastify helpers', async () => {
    const seen: Array<string | undefined> = [];
    const exp = express().disable('x-powered-by');
    exp.use(createExpressContextMiddleware({ responseHeader: 'x-trace-id' }));
    exp.get('/', (_req, res) => {
      seen.push(getCurrentTraceId());
      res.send('ok');
    });
    const server = exp.listen(0);
    let echoed: string | null;
    try {
      const { port } = server.address() as AddressInfo;
      const r = await fetch(`http://127.0.0.1:${port}/`, {
        headers: { traceparent: `00-${TP}-00f067aa0ba902b7-01` },
      });
      echoed = r.headers.get('x-trace-id');
    } finally {
      server.close();
    }
    expect(seen).toEqual([TP]);
    expect(echoed).toBe(TP);

    const app = Fastify();
    app.addHook('onRequest', createFastifyContextHook({ responseHeader: 'x-trace-id' }));
    app.get('/', async () => getCurrentTraceId());
    const res = await app.inject({ method: 'GET', url: '/', headers: { 'x-request-id': 'rid-1' } });
    await app.close();
    expect(res.body).toBe('rid-1');
    expect(res.headers['x-trace-id']).toBe('rid-1');
  });

  it('does not set a response header by default', async () => {
    const app = Fastify();
    app.addHook('onRequest', createFastifyContextHook());
    app.get('/', async () => 'ok');
    const res = await app.inject({ method: 'GET', url: '/', headers: { 'x-trace-id': 'abc' } });
    await app.close();
    expect(res.headers['x-trace-id']).toBeUndefined();
  });

  it('innermost scope wins in both nesting orders', async () => {
    const { logger, entries } = setup();
    await runWithTraceId('outer-trace', () =>
      LogixiaContext.run({ traceId: 'inner-ctx' }, () => logger.info('a'))
    );
    await LogixiaContext.run({ traceId: 'outer-ctx' }, () =>
      runWithTraceId('inner-trace', () => logger.info('b'))
    );
    await LogixiaContext.run({ traceId: 'p' }, () =>
      LogixiaContext.run({ userId: 'u' }, () => logger.info('c'))
    );
    const id = (m: string) => entries.find((e) => e.message === m)?.traceId;
    expect(id('a')).toBe('inner-ctx');
    expect(id('b')).toBe('inner-trace');
    expect(id('c')).toBe('p');
  });

  it('honours each helper own traceIdHeader', async () => {
    const { logger, entries } = setup();
    const app = Fastify();
    await app.register(createFastifyPlugin(logger, { requestLevel: 'info', traceIdHeader: 'x-a' }));
    app.addHook('onRequest', createFastifyContextHook({ traceIdHeader: ['x-b'] }));
    app.get('/', async () => {
      await logger.info('handled');
      return 'ok';
    });
    await app.inject({ method: 'GET', url: '/', headers: { 'x-a': 'from-a', 'x-b': 'from-b' } });
    await app.close();
    expect(entries.find((e) => e.message === 'handled')?.traceId).toBe('from-b');
    expect(entries.find((e) => e.message === 'request started')?.data?.['traceId']).toBe('from-a');
  });

  it('never uses fastify default counter ids; falls back to a full UUID', async () => {
    const app = Fastify();
    let id: string | undefined;
    app.addHook('onRequest', createFastifyContextHook());
    app.get('/', async () => {
      id = getCurrentTraceId();
      return 'ok';
    });
    await app.inject({ method: 'GET', url: '/' });
    await app.close();
    expect(id).toMatch(/^[\da-f]{8}-[\da-f]{4}-4[\da-f]{3}-[\da-f]{4}-[\da-f]{12}$/);
  });

  it('uses a non-counter request.id (custom genReqId)', async () => {
    const app = Fastify({ genReqId: () => 'custom-id-1' });
    let id: string | undefined;
    app.addHook('onRequest', createFastifyContextHook());
    app.get('/', async () => {
      id = getCurrentTraceId();
      return 'ok';
    });
    await app.inject({ method: 'GET', url: '/' });
    await app.close();
    expect(id).toBe('custom-id-1');
  });

  it('enrich cannot replace the resolved traceId; indexable req compiles under strict', async () => {
    const hook = createFastifyContextHook({
      enrich: (req) => ({ userId: req['user'] as string, traceId: '' }),
    });
    const ctx = await new Promise<ReturnType<typeof LogixiaContext.get>>((resolve) => {
      hook({ headers: { 'x-trace-id': 'real' }, user: 'u1' }, {}, () =>
        resolve(LogixiaContext.get())
      );
    });
    expect(ctx).toMatchObject({ traceId: 'real', userId: 'u1' });
  });
});
