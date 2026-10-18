/**
 * Tests for the HTTP logger middleware (Morgan replacement).
 *
 * Key regression: a normal response emits BOTH 'finish' and 'close' events, and
 * the middleware registered onFinish on both. Without a guard that double-logged
 * the "request completed" entry (and the slow-request warning). These tests pin
 * single-logging plus the request-start / skip / status-level behavior.
 */

import type { FastifyInstance as FastifyApp } from 'fastify';
import Fastify from 'fastify';

import type { IBaseLogger } from '../../types';
import {
  createExpressMiddleware,
  createFastifyPlugin,
  type IncomingRequest,
  type OutgoingResponse,
} from '../http-logger';

interface LogCall {
  level: string;
  message: string;
  data?: Record<string, unknown> | undefined;
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

describe('createFastifyPlugin', () => {
  let app: FastifyApp;

  beforeEach(() => {
    app = Fastify();
  });

  afterEach(async () => {
    await app.close();
    jest.restoreAllMocks();
  });

  it('logs a root route registered after the plugin', async () => {
    const { logger, calls } = makeLogger();
    await app.register(createFastifyPlugin(logger));
    app.get('/orders', async () => ({ orders: [] }));

    const response = await app.inject({
      method: 'GET',
      url: '/orders',
      headers: {
        'x-trace-id': 'orders-trace',
        authorization: 'Bearer test-secret',
        'x-visible': 'kept',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ orders: [] });
    const starts = calls.filter((call) => call.message === 'request started');
    const completions = calls.filter((call) => call.message === 'request completed');
    expect(starts).toHaveLength(1);
    expect(starts[0]?.level).toBe('debug');
    expect(completions).toHaveLength(1);
    expect(completions[0]?.level).toBe('info');
    expect(completions[0]?.data).toEqual(
      expect.objectContaining({
        traceId: 'orders-trace',
        method: 'GET',
        url: '/orders',
        statusCode: 200,
        duration: expect.any(Number),
        headers: expect.objectContaining({
          authorization: '[REDACTED]',
          'x-visible': 'kept',
        }),
      })
    );
    expect(completions[0]?.data?.duration).toBeGreaterThanOrEqual(0);
  });

  it('logs routes registered in a later child plugin', async () => {
    const { logger, calls } = makeLogger();
    await app.register(createFastifyPlugin(logger));
    app.register(async (child) => {
      child.get('/nested', async () => ({ ok: true }));
    });

    const response = await app.inject('/nested');

    expect(response.statusCode).toBe(200);
    const completions = calls.filter((call) => call.message === 'request completed');
    expect(completions).toHaveLength(1);
    expect(completions[0]?.data?.url).toBe('/nested');
  });

  it('does not log skipped requests in either hook', async () => {
    const { logger, calls } = makeLogger();
    await app.register(
      createFastifyPlugin(logger, {
        skip: (request) => request.url === '/health',
        slowRequestThresholdMs: 0,
      })
    );
    app.get('/health', async () => ({ ok: true }));

    const response = await app.inject('/health');

    expect(response.statusCode).toBe(200);
    expect(calls).toHaveLength(0);
  });

  it('uses the configured error level for a server error', async () => {
    const { logger, calls } = makeLogger();
    await app.register(createFastifyPlugin(logger, { errorLevel: 'fatal' }));
    app.get('/unavailable', async (_request, reply) => {
      return reply.code(503).send({ error: 'unavailable' });
    });

    const response = await app.inject('/unavailable');

    expect(response.statusCode).toBe(503);
    const completion = calls.find((call) => call.message === 'request completed');
    expect(completion?.level).toBe('fatal');
    expect(completion?.data?.statusCode).toBe(503);
  });

  it('warns when a request exceeds the slow request threshold', async () => {
    let now = 1000;
    jest.spyOn(Date, 'now').mockImplementation(() => now);
    const { logger, calls } = makeLogger();
    await app.register(createFastifyPlugin(logger, { slowRequestThresholdMs: 0 }));
    app.get('/slow', async () => {
      now += 5;
      return { ok: true };
    });

    const response = await app.inject({
      method: 'GET',
      url: '/slow',
      headers: { 'x-trace-id': 'slow-trace' },
    });

    expect(response.statusCode).toBe(200);
    const warnings = calls.filter((call) => call.message === 'slow request detected');
    expect(warnings).toHaveLength(1);
    expect(warnings[0]?.level).toBe('warn');
    expect(warnings[0]?.data).toEqual({
      traceId: 'slow-trace',
      url: '/slow',
      method: 'GET',
      duration: 5,
      threshold: 0,
    });
  });

  it('logs completion when request start logging is silent', async () => {
    const { logger, calls } = makeLogger();
    await app.register(createFastifyPlugin(logger, { requestLevel: 'silent' }));
    app.get('/silent', async () => ({ ok: true }));

    const response = await app.inject('/silent');

    expect(response.statusCode).toBe(200);
    expect(calls.filter((call) => call.message === 'request started')).toHaveLength(0);
    expect(calls.filter((call) => call.message === 'request completed')).toHaveLength(1);
  });
});
