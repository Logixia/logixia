import type { AddressInfo } from 'node:net';

import express from 'express';
import Fastify from 'fastify';

import { createLogger } from '../../core/logitron-logger';
import { createExpressMiddleware, createFastifyPlugin } from '../../middleware/http-logger';
import type { ITransport, TransportLogEntry } from '../../types/transport.types';
import { runWithTraceId } from '../../utils/trace.utils';
import {
  createExpressContextMiddleware,
  createFastifyContextHook,
  LogixiaContext,
} from '../async-context';

function setup() {
  const entries: TransportLogEntry[] = [];
  const transport: ITransport = { name: 'capture', write: (e) => void entries.push(e) };
  const logger = createLogger({
    appName: 'unify',
    environment: 'test',
    traceId: true,
    silent: false,
    transports: { custom: [transport] },
  });
  return { logger, entries };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('LogContext traceId reaches the logger top-level traceId', () => {
  it('express: concurrent requests log their own x-trace-id', async () => {
    const { logger, entries } = setup();
    const app = express().disable('x-powered-by');
    app.use(createExpressContextMiddleware());
    app.get('/', async (req, res) => {
      await sleep(req.headers['x-trace-id'] === 'trace-a' ? 30 : 5);
      await logger.info('handled');
      res.send('ok');
    });
    const server = app.listen(0);
    try {
      const { port } = server.address() as AddressInfo;
      await Promise.all(
        ['trace-a', 'trace-b'].map((id) =>
          fetch(`http://127.0.0.1:${port}/`, { headers: { 'x-trace-id': id } })
        )
      );
    } finally {
      server.close();
    }
    const ids = entries.filter((e) => e.message === 'handled').map((e) => e.traceId);
    expect(ids.sort()).toEqual(['trace-a', 'trace-b']);
  });

  it('fastify: concurrent requests log their own x-trace-id; hook is typed for addHook', async () => {
    const { logger, entries } = setup();
    const app = Fastify();
    app.addHook('onRequest', createFastifyContextHook());
    app.get('/', async (request) => {
      await sleep(request.headers['x-trace-id'] === 'trace-a' ? 30 : 5);
      await logger.info('handled');
      return { ok: true };
    });
    await Promise.all(
      ['trace-a', 'trace-b'].map((id) =>
        app.inject({ method: 'GET', url: '/', headers: { 'x-trace-id': id } })
      )
    );
    await app.close();
    const ids = entries.filter((e) => e.message === 'handled').map((e) => e.traceId);
    expect(ids.sort()).toEqual(['trace-a', 'trace-b']);
  });

  it('TraceContext still takes precedence over a LogixiaContext traceId', async () => {
    const { logger, entries } = setup();
    await LogixiaContext.run({ traceId: 'ctx' }, () =>
      runWithTraceId('trace-ctx', () => logger.info('both'))
    );
    expect(entries.find((e) => e.message === 'both')?.traceId).toBe('trace-ctx');
  });

  it('fastify: plugin and context hook share one fallback id in either order', async () => {
    for (const pluginFirst of [true, false]) {
      const { logger, entries } = setup();
      const app = Fastify();
      const register = async () => {
        await app.register(createFastifyPlugin(logger, { requestLevel: 'info' }));
      };
      if (pluginFirst) await register();
      app.addHook('onRequest', createFastifyContextHook());
      if (!pluginFirst) await register();
      app.get('/', async () => {
        await logger.info('handled');
        return 'ok';
      });
      await app.inject({ method: 'GET', url: '/' });
      await app.close();
      const ctxId = entries.find((e) => e.message === 'handled')?.traceId;
      const started = entries.find((e) => e.message === 'request started');
      expect(ctxId).toBeDefined();
      expect(started?.data?.['traceId']).toBe(ctxId);
    }
  });

  it('express: http logger and context middleware share one fallback id', async () => {
    const { logger, entries } = setup();
    const app = express().disable('x-powered-by');
    app.use(createExpressMiddleware(logger, { requestLevel: 'info' }));
    app.use(createExpressContextMiddleware());
    app.get('/', async (_req, res) => {
      await logger.info('handled');
      res.send('ok');
    });
    const server = app.listen(0);
    try {
      const { port } = server.address() as AddressInfo;
      await fetch(`http://127.0.0.1:${port}/`);
    } finally {
      server.close();
    }
    const started = entries.find((e) => e.message === 'request started');
    expect(started?.data?.['traceId']).toBe(entries.find((e) => e.message === 'handled')?.traceId);
  });
});
