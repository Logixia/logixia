/**
 * Hono request logging middleware: trace ID, response header and a completion entry.
 *
 * Only structural types are used, so it works with any Hono version and runs on Node,
 * Bun and Cloudflare Workers (`nodejs_compat`, for `AsyncLocalStorage`).
 *
 * @example
 * ```ts
 * import { Hono } from 'hono';
 * import { createHonoMiddleware } from 'logixia/hono';
 *
 * const app = new Hono();
 * app.use(createHonoMiddleware(logger));
 * ```
 */

import { serializeError } from '../utils/error.utils';
import { internalError } from '../utils/internal-log';
import { resolveTraceHeaders } from '../utils/request-trace';
import {
  buildNameSet,
  DEFAULT_REDACT_QUERY_PARAMS,
  redactUrlQuery,
} from '../utils/sensitive-names';
import { extractTraceId, generateTraceId, runWithTraceId } from '../utils/trace.utils';

// ── Structural types ─────────────────────────────────────────────────────────

type LogFn = (message: string, data?: Record<string, unknown>) => unknown;

/** The logger methods used: logixia's `Logger` and `createBrowserLogger()` both fit. */
export interface HonoLoggerLike {
  info: LogFn;
  warn: LogFn;
  error: LogFn;
}

/** The slice of Hono's `Context` the middleware reads and writes. */
export interface HonoContextLike {
  req: { method: string; url: string; header(name: string): string | undefined };
  res: Response;
  error?: Error | undefined;
  header(name: string, value: string): unknown;
  set(key: 'traceId', value: string): void;
}

export type HonoNext = () => Promise<void>;

export interface HonoMiddlewareOptions {
  /** Skip logging and tracing for a request, for example health checks. */
  skip?: (c: HonoContextLike) => boolean;
  /**
   * Header name, or list of names tried in order, to read the trace ID from.
   * Default: `DEFAULT_TRACE_HEADERS` (traceparent, x-trace-id, x-request-id,
   * x-correlation-id, trace-id). A generated UUID is used when none is present.
   */
  traceIdHeader?: string | readonly string[];
  /** Response header that carries the trace ID. Default: `'x-trace-id'`. `false` sets none. */
  responseHeader?: string | false;
  /**
   * Extra query-string parameter names redacted from the logged path, merged with the
   * defaults (token, access_token, refresh_token, code, password, secret, api_key, ...).
   */
  redactQueryParams?: string[];
  /** Fields added to every entry. */
  extraFields?: (c: HonoContextLike) => Record<string, unknown>;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Fire-and-forget: a failing log call must never fail the request. */
function emit(logger: HonoLoggerLike, level: keyof HonoLoggerLike, message: string, data: object) {
  try {
    const result = logger[level](message, data as Record<string, unknown>);
    if (result && typeof (result as Promise<unknown>).catch === 'function') {
      (result as Promise<unknown>).catch((error: unknown) =>
        internalError('hono middleware: log call failed', error)
      );
    }
  } catch (error) {
    internalError('hono middleware: log call failed', error);
  }
}

/** Pathname plus the query string with secret parameters redacted, from an absolute or relative URL. */
function loggedPath(url: string, params: ReadonlySet<string>): string {
  const schemeEnd = url.indexOf('://');
  const pathStart = schemeEnd === -1 ? 0 : url.indexOf('/', schemeEnd + 3);
  return pathStart === -1 ? '/' : redactUrlQuery(url.slice(pathStart), params);
}

function ensureHeader(c: HonoContextLike, name: string, value: string): void {
  try {
    if (c.res.headers.get(name) === value) return;
    c.res.headers.set(name, value);
  } catch {
    // Immutable headers (a proxied fetch() response): rebuild the response with a mutable copy.
    const copy = new Response(c.res.body, c.res);
    copy.headers.set(name, value);
    c.res = copy;
  }
}

/**
 * Create a Hono middleware (`app.use(...)`).
 *
 * Per request it resolves the trace ID from headers, sets it on the response and on
 * `c.var.traceId`, runs the rest of the request inside {@link runWithTraceId} and logs
 * one entry when the request completes: `method`, `path` (query secrets redacted),
 * `status`, `duration` in ms and `traceId`. Responses with status 500 and above, and
 * errors thrown by handlers, are logged at `error`; other thrown errors at `warn`.
 */
export function createHonoMiddleware(
  logger: HonoLoggerLike,
  options: HonoMiddlewareOptions = {}
): (c: HonoContextLike, next: HonoNext) => Promise<void> {
  const { skip, extraFields, responseHeader = 'x-trace-id' } = options;
  const traceHeaders = resolveTraceHeaders(options.traceIdHeader);
  const params = buildNameSet(DEFAULT_REDACT_QUERY_PARAMS, options.redactQueryParams);

  return async function logixiaHonoMiddleware(c, next) {
    if (skip?.(c)) return next();

    const headers: Record<string, string | undefined> = {};
    for (const name of traceHeaders) {
      const key = name.toLowerCase();
      headers[key] = c.req.header(key);
    }
    const traceId = extractTraceId({ headers }, { header: [...traceHeaders] }) ?? generateTraceId();
    const start = Date.now();
    c.set('traceId', traceId);
    if (responseHeader) c.header(responseHeader, traceId);

    await runWithTraceId(traceId, async () => {
      let thrown: unknown;
      try {
        await next();
      } catch (error) {
        thrown = error;
      }
      // Hono hands a handler's error to onError and resolves next(); c.error is how it shows up here.
      const failure = thrown ?? c.error;
      if (responseHeader && thrown === undefined) ensureHeader(c, responseHeader, traceId);

      const status = thrown === undefined ? c.res.status : 500;
      const entry = {
        traceId,
        method: c.req.method,
        path: loggedPath(c.req.url, params),
        status,
        duration: Date.now() - start,
        ...(failure === undefined ? {} : { error: serializeError(toError(failure)) }),
        ...extraFields?.(c),
      };
      if (failure !== undefined) {
        emit(logger, status >= 500 ? 'error' : 'warn', 'request failed', entry);
      } else {
        emit(logger, status >= 500 ? 'error' : 'info', 'request completed', entry);
      }
      if (thrown !== undefined) throw thrown;
    });
  };
}

function toError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}
