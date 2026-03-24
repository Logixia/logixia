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
import { randomUUID } from 'node:crypto';

/** Short request-scoped ID — uses Node's built-in crypto, never the global. */
function randomShortId(): string {
  return randomUUID().slice(0, 8);
}

export interface LogContext {
  requestId?: string;
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
    Object.assign(store, fields);
  },

  /**
   * Retrieve the underlying `AsyncLocalStorage` instance.
   * Useful for advanced use-cases like custom middleware.
   */
  getStorage(): AsyncLocalStorage<LogContext> {
    return _storage;
  },
};

/**
 * Create an Express/Connect-compatible middleware that wraps each request in
 * a `LogixiaContext.run()` scope populated with common request fields.
 *
 * @example
 * ```ts
 * import { createExpressContextMiddleware } from 'logixia';
 * app.use(createExpressContextMiddleware());
 * ```
 */
export function createExpressContextMiddleware(
  options: {
    /** Extract additional fields from the request. */
    enrich?: (req: Record<string, unknown>) => Partial<LogContext>;
    /** Header to read the requestId from. Default: 'x-request-id'. */
    requestIdHeader?: string;
    /** Header to read the traceId from. Default: 'x-trace-id'. */
    traceIdHeader?: string;
  } = {}
) {
  const { enrich, requestIdHeader = 'x-request-id', traceIdHeader = 'x-trace-id' } = options;

  return function logixiaContextMiddleware(
    req: Record<string, unknown>,
    _res: unknown,
    next: () => void
  ): void {
    const headers = (req['headers'] ?? {}) as Record<string, string | undefined>;
    const traceId = headers[traceIdHeader];
    const base: LogContext = {
      requestId: (headers[requestIdHeader] as string | undefined) ?? randomShortId(),
      ...(traceId !== undefined ? { traceId } : {}),
    };
    LogixiaContext.run({ ...base, ...(enrich ? enrich(req) : {}) }, next);
  };
}

/**
 * Create a Fastify lifecycle hook that wraps each request in a context scope.
 *
 * Register with `fastify.addHook('onRequest', createFastifyContextHook())`.
 */
export function createFastifyContextHook(
  options: {
    enrich?: (request: Record<string, unknown>) => Partial<LogContext>;
    requestIdHeader?: string;
    traceIdHeader?: string;
  } = {}
) {
  const { enrich, requestIdHeader = 'x-request-id', traceIdHeader = 'x-trace-id' } = options;

  return function logixiaFastifyHook(
    request: Record<string, unknown>,
    _reply: unknown,
    done: () => void
  ): void {
    const headers = (request['headers'] ?? {}) as Record<string, string | undefined>;
    const traceId = headers[traceIdHeader];
    const base: LogContext = {
      requestId:
        (headers[requestIdHeader] as string | undefined) ??
        (request['id'] as string | undefined) ??
        randomShortId(),
      ...(traceId !== undefined ? { traceId } : {}),
    };
    LogixiaContext.run({ ...base, ...(enrich ? enrich(request) : {}) }, done);
  };
}
