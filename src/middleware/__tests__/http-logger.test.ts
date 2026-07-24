/**
 * Tests for the HTTP logger middleware (Morgan replacement).
 *
 * Key regression: a normal response emits BOTH 'finish' and 'close' events, and
 * the middleware registered onFinish on both. Without a guard that double-logged
 * the "request completed" entry (and the slow-request warning). These tests pin
 * single-logging plus the request-start / skip / status-level behavior.
 */

import type { IBaseLogger } from '../../types';
import {
  createExpressMiddleware,
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
