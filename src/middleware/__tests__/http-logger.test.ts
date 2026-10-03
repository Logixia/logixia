/**
 * Tests for the HTTP logger middleware (Morgan replacement).
 *
 * Key regression: a normal response emits BOTH 'finish' and 'close' events, and
 * the middleware registered onFinish on both. Without a guard that double-logged
 * the "request completed" entry (and the slow-request warning). These tests pin
 * single-logging plus the request-start / skip / status-level behavior.
 */

import Fastify, { type FastifyInstance, type FastifyPluginCallback } from 'fastify';

import type { IBaseLogger } from '../../types';
import {
  createExpressMiddleware,
  createFastifyPlugin,
  type HttpLoggerOptions,
  type IncomingRequest,
  type OutgoingResponse,
} from '../http-logger';

interface LogCall {
  level: string;
  message: string;
  data?: Record<string, unknown>;
}

function makeLogger(): { logger: IBaseLogger; calls: LogCall[] } {
  const calls: LogCall[] = [];
  const logger = {
    logLevel: (level: string, message: string, data?: Record<string, unknown>) => {
      calls.push({ level, message, data });
      return Promise.resolve();
    },
    warn: (message: string, data?: Record<string, unknown>) => {
      calls.push({ level: 'warn', message, data });
      return Promise.resolve();
    },
  } as unknown as IBaseLogger;
  return { logger, calls };
}

/** A fake response that lets the test fire 'finish' / 'close' events. */
function makeRes(statusCode = 200): OutgoingResponse & { fire(event: string): void } {
  const handlers: Record<string, Array<() => void>> = {};
  return {
    statusCode,
    once(event: string, cb: () => void) {
      if (!handlers[event]) handlers[event] = [];
      handlers[event]!.push(cb);
    },
    fire(event: string) {
      for (const cb of handlers[event] ?? []) cb();
    },
  } as OutgoingResponse & { fire(event: string): void };
}

describe('createExpressMiddleware', () => {
  it('logs "request completed" only once when both finish and close fire', () => {
    const { logger, calls } = makeLogger();
    const mw = createExpressMiddleware(logger, { requestLevel: 'silent' });
    const req: IncomingRequest = { method: 'GET', url: '/x', headers: {} };
    const res = makeRes(200);

    mw(req, res, () => {});
    res.fire('finish');
    res.fire('close'); // must NOT log a second completion

    const completions = calls.filter((c) => c.message === 'request completed');
    expect(completions).toHaveLength(1);
  });

  it('logs a request-start entry at the configured level', () => {
    const { logger, calls } = makeLogger();
    const mw = createExpressMiddleware(logger, { requestLevel: 'debug' });
    const req: IncomingRequest = { method: 'POST', url: '/y', headers: {} };
    const res = makeRes(201);

    mw(req, res, () => {});
    const start = calls.find((c) => c.message === 'request started');
    expect(start?.level).toBe('debug');
  });

  it('uses the error level for a 5xx response', () => {
    const { logger, calls } = makeLogger();
    const mw = createExpressMiddleware(logger, { requestLevel: 'silent', errorLevel: 'error' });
    const req: IncomingRequest = { method: 'GET', url: '/z', headers: {} };
    const res = makeRes(500);

    mw(req, res, () => {});
    res.fire('finish');

    const completion = calls.find((c) => c.message === 'request completed');
    expect(completion?.level).toBe('error');
    expect(completion?.data?.statusCode).toBe(500);
  });

  it('redacts sensitive headers in the logged fields', () => {
    const { logger, calls } = makeLogger();
    const mw = createExpressMiddleware(logger, { requestLevel: 'info' });
    const req: IncomingRequest = {
      method: 'GET',
      url: '/a',
      headers: { authorization: 'Bearer secret', 'x-custom': 'visible' },
    };
    const res = makeRes(200);

    mw(req, res, () => {});
    const start = calls.find((c) => c.message === 'request started');
    const headers = start?.data?.headers as Record<string, unknown>;
    expect(headers.authorization).toBe('[REDACTED]');
    expect(headers['x-custom']).toBe('visible');
  });

  it('skips logging when the skip predicate returns true', () => {
    const { logger, calls } = makeLogger();
    const mw = createExpressMiddleware(logger, { skip: (req) => req.url === '/health' });
    let nextCalled = false;

    mw({ method: 'GET', url: '/health', headers: {} }, makeRes(200), () => {
      nextCalled = true;
    });

    expect(nextCalled).toBe(true);
    expect(calls).toHaveLength(0);
  });
});

/** A real Fastify instance with the logixia plugin registered. */
function makeFastifyApp(logger: IBaseLogger, options: HttpLoggerOptions = {}): FastifyInstance {
  const app = Fastify();
  // The source keeps a minimal structural `FastifyInstance` type so the published
  // package doesn't depend on fastify's types. Bridge to fastify's callback type
  // here so `register` type-checks.
  app.register(createFastifyPlugin(logger, options) as unknown as FastifyPluginCallback);
  return app;
}

describe('createFastifyPlugin', () => {
  it('logs "request completed" for routes registered on the root instance', async () => {
    const { logger, calls } = makeLogger();
    const app = makeFastifyApp(logger, { requestLevel: 'silent' });
    app.get('/orders', async () => ({ ok: true }));

    const res = await app.inject({ method: 'GET', url: '/orders' });

    expect(res.statusCode).toBe(200);
    const completion = calls.find((c) => c.message === 'request completed');
    expect(completion).toBeDefined();
    expect(completion?.data?.statusCode).toBe(200);
    expect(typeof completion?.data?.duration).toBe('number');
    await app.close();
  });

  it('honors the skip predicate', async () => {
    const { logger, calls } = makeLogger();
    const app = makeFastifyApp(logger, { skip: (req) => req.url === '/health' });
    app.get('/health', async () => ({ ok: true }));

    const res = await app.inject({ method: 'GET', url: '/health' });

    expect(res.statusCode).toBe(200);
    expect(calls).toHaveLength(0);
    await app.close();
  });

  it('uses the error level for a 5xx response', async () => {
    const { logger, calls } = makeLogger();
    const app = makeFastifyApp(logger, { requestLevel: 'silent', errorLevel: 'error' });
    app.get('/boom', async () => {
      throw new Error('boom');
    });

    const res = await app.inject({ method: 'GET', url: '/boom' });

    expect(res.statusCode).toBe(500);
    const completion = calls.find((c) => c.message === 'request completed');
    expect(completion?.level).toBe('error');
    expect(completion?.data?.statusCode).toBe(500);
    await app.close();
  });

  it('warns on slow requests when slowRequestThresholdMs is 0', async () => {
    const { logger, calls } = makeLogger();
    const app = makeFastifyApp(logger, { requestLevel: 'silent', slowRequestThresholdMs: 0 });
    app.get('/slow', async () => {
      await new Promise((resolve) => setTimeout(resolve, 5));
      return { ok: true };
    });

    const res = await app.inject({ method: 'GET', url: '/slow' });

    expect(res.statusCode).toBe(200);
    const warn = calls.find((c) => c.message === 'slow request detected');
    expect(warn).toBeDefined();
    await app.close();
  });
});
