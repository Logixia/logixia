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

import { assignOwn } from '../utils/own-property';
import {
  type ContextRequestLike,
  resolveRequestTraceId,
  resolveTraceHeaders,
  type TraceHeaderOption,
} from '../utils/request-trace';
import { TraceContext } from '../utils/trace.utils';

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
    const scoped = (): T => _storage.run({ ...parent, ...store }, callback);
    const traceId = store.traceId;
    if (typeof traceId !== 'string' || traceId === '') return scoped();
    // An explicit traceId also becomes the TraceContext ID, so getCurrentTraceId(),
    // the logger, outbound propagation and the OTel bridge all see the same value.
    const trace = TraceContext.instance;
    return trace.storage.run({ ...trace.storage.getStore(), [trace.contextKey]: traceId }, scoped);
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
      assignOwn(store, key, fields[key]);
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

export type { ContextRequestLike };

interface ContextHelperOptions<Req extends ContextRequestLike> {
  /**
   * Extract additional fields from the request. A `traceId` returned here is ignored:
   * the resolved request trace ID always wins.
   */
  enrich?: (request: Req & Record<string, unknown>) => Partial<LogContext>;
  /**
   * Header name, or list of names tried in order, to read the trace ID from.
   * Default: `DEFAULT_TRACE_HEADERS` (traceparent is parsed to its 32-hex trace id).
   */
  traceIdHeader?: TraceHeaderOption;
  /**
   * Echo the resolved trace ID on the response under this header name.
   * Default: `false` (no response header is set).
   */
  responseHeader?: string | false;
}

function buildScope<Req extends ContextRequestLike>(
  request: Req,
  options: ContextHelperOptions<Req>,
  headers: readonly string[]
): LogContext {
  const extra = options.enrich ? options.enrich(request as Req & Record<string, unknown>) : {};
  return { ...extra, traceId: resolveRequestTraceId(request, headers) };
}

/**
 * Create an Express/Connect-compatible middleware that wraps each request in
 * a `LogixiaContext.run()` scope populated with common request fields.
 *
 * Trace ID: the first present header of `traceIdHeader` (default
 * `DEFAULT_TRACE_HEADERS`, `traceparent` parsed), else `request.id`, else a
 * generated UUID. It is available via `getCurrentTraceId()` and is the logger's
 * top-level `traceId` inside the request. No response header is set unless
 * `responseHeader` is given.
 *
 * @example
 * ```ts
 * import { createExpressContextMiddleware } from 'logixia';
 * app.use(createExpressContextMiddleware({ responseHeader: 'x-trace-id' }));
 * ```
 */
export function createExpressContextMiddleware<Req extends ContextRequestLike = ContextRequestLike>(
  options: ContextHelperOptions<Req> = {}
) {
  const headers = resolveTraceHeaders(options.traceIdHeader);

  return function logixiaContextMiddleware(
    req: Req,
    res: { setHeader?: (name: string, value: string) => unknown },
    next: () => void
  ): void {
    const scope = buildScope(req, options, headers);
    if (options.responseHeader) res.setHeader?.(options.responseHeader, scope.traceId as string);
    LogixiaContext.run(scope, next);
  };
}

/**
 * Create a Fastify lifecycle hook that wraps each request in a context scope.
 *
 * Register with `fastify.addHook('onRequest', createFastifyContextHook())`.
 * Resolves the trace ID exactly like {@link createExpressContextMiddleware} and
 * shares it with `createFastifyPlugin()` from `logixia/middleware`. Fastify's
 * default counter `request.id` (`req-1`, ...) is never used as a trace ID.
 */
export function createFastifyContextHook<Req extends ContextRequestLike = ContextRequestLike>(
  options: ContextHelperOptions<Req> = {}
) {
  const headers = resolveTraceHeaders(options.traceIdHeader);

  return function logixiaFastifyHook(
    request: Req,
    reply: { header?: (name: string, value: string) => unknown },
    done: () => void
  ): void {
    const scope = buildScope(request, options, headers);
    if (options.responseHeader) reply.header?.(options.responseHeader, scope.traceId as string);
    LogixiaContext.run(scope, done);
  };
}
