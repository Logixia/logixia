/**
 * LogixiaContext — Zero-boilerplate AsyncLocalStorage context propagation.
 *
 * Lets every `logger.info()` call inside a context automatically pick up stored
 * fields (requestId, userId, tenantId, …) without passing them through every function.
 *
 * Works across `Promise.all`, `setTimeout`, and event emitters — anything that
 * inherits the async execution context.
 *
 * @example
 * ```ts
 * import { LogixiaContext } from 'logixia';
 *
 * // Wrap a request handler:
 * app.use((req, res, next) => {
 *   LogixiaContext.run({ requestId: req.id, userId: req.user?.id }, next);
 * });
 *
 * // Anywhere deeper in the call tree:
 * async function processOrder(orderId: string) {
 *   const ctx = LogixiaContext.get();  // { requestId, userId, orderId }
 *   logger.info('Processing order', { orderId, ...ctx });
 * }
 * ```
 */

import { AsyncLocalStorage } from 'node:async_hooks';

import { resolveRequestTraceId } from '../utils/trace.utils';

export interface LogContext {
  traceId?: string;
  spanId?: string;
  userId?: string;
  tenantId?: string;
  sessionId?: string;
  [key: string]: unknown;
}

// Module-level singleton so all loggers share the same ALS store.
const _storage = new AsyncLocalStorage<LogContext>();

export const LogixiaContext = {
  /**
   * Run `callback` inside an async context that carries `store` fields.
   * All loggers queried within `callback` (and its async descendants) will
   * automatically see these fields.
   *
   * @example
   * ```ts
   * LogixiaContext.run({ requestId: 'abc', userId: '42' }, async () => {
   *   await processOrder();   // sees requestId + userId in every log
   * });
   * ```
   */
  run<T>(store: LogContext, callback: () => T): T {
    const parent = _storage.getStore() ?? {};
    return _storage.run({ ...parent, ...store }, callback);
  },

  /**
   * Return the context fields active in the current async scope.
   * Returns `undefined` when called outside any `LogixiaContext.run()`.
   */
  get(): LogContext | undefined {
    return _storage.getStore();
  },

  /**
   * Merge `fields` into the **existing** context for the current scope.
   * If called outside a `run()` context this is a no-op (logs a dev warning).
   */
  set(fields: Partial<LogContext>): void {
    const store = _storage.getStore();
    if (!store) {
      // Silently ignore — avoids crashing in code that may call setContext
      // before a request context is established (e.g. background jobs).
      return;
    }
    for (const key of Object.keys(fields)) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
      store[key] = fields[key];
    }
  },

  /**
   * Retrieve the underlying `AsyncLocalStorage` instance.
   * Useful for advanced use-cases like custom middleware.
   */
  getStorage(): AsyncLocalStorage<LogContext> {
    return _storage;
  },
};

/** Minimal structural request shape; Express and Fastify requests satisfy it. */
export interface ContextRequestLike {
  headers?: Record<string, string | string[] | undefined>;
  id?: unknown;
}

/**
 * Create an Express/Connect-compatible middleware that wraps each request in
 * a `LogixiaContext.run()` scope populated with common request fields.
 *
 * The logger reads the scope's `traceId`, so every log line in the request
 * carries it as its top-level trace ID.
 *
 * @example
 * ```ts
 * import { createExpressContextMiddleware } from 'logixia';
 * app.use(createExpressContextMiddleware());
 * ```
 */
export function createExpressContextMiddleware<Req extends ContextRequestLike = ContextRequestLike>(
  options: {
    /** Extract additional fields from the request. */
    enrich?: (req: Req) => Partial<LogContext>;
    /** Header to read the traceId from. Default: 'x-trace-id'. */
    traceIdHeader?: string;
  } = {}
) {
  const { enrich, traceIdHeader = 'x-trace-id' } = options;

  return function logixiaContextMiddleware(req: Req, _res: unknown, next: () => void): void {
    const traceId = resolveRequestTraceId(req, traceIdHeader);
    LogixiaContext.run({ traceId, ...(enrich ? enrich(req) : {}) }, next);
  };
}

/**
 * Create a Fastify lifecycle hook that wraps each request in a context scope.
 *
 * Register with `fastify.addHook('onRequest', createFastifyContextHook())`.
 * Shares the per-request trace ID with `createFastifyPlugin()` from
 * `logixia/middleware`, so both log the same ID regardless of registration order.
 */
export function createFastifyContextHook<Req extends ContextRequestLike = ContextRequestLike>(
  options: {
    enrich?: (request: Req) => Partial<LogContext>;
    traceIdHeader?: string;
  } = {}
) {
  const { enrich, traceIdHeader = 'x-trace-id' } = options;

  return function logixiaFastifyHook(request: Req, _reply: unknown, done: () => void): void {
    const traceId = resolveRequestTraceId(request, traceIdHeader);
    LogixiaContext.run({ traceId, ...(enrich ? enrich(request) : {}) }, done);
  };
}
