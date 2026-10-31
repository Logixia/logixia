/**
 * HTTP request/response logging middleware — Morgan replacement.
 *
 * Fixes every documented Morgan bug:
 *  - statusCode always captured correctly, even for requests > 20 s
 *  - Logs request START (with traceId) and response FINISH (with duration)
 *  - Captures errors before and after response
 *  - Auto-redacts Authorization / Cookie / Set-Cookie headers
 *  - Slow-request warnings
 *  - Skip predicates for health-check routes / static assets
 *
 * @example Express
 * ```ts
 * import { createExpressMiddleware } from 'logixia/middleware';
 * app.use(createExpressMiddleware(logger));
 * ```
 *
 * @example Fastify
 * ```ts
 * import { createFastifyPlugin } from 'logixia/middleware';
 * await fastify.register(createFastifyPlugin(logger));
 * ```
 */

import type { IBaseLogger } from '../types';
import type { HttpRequestShape, HttpResponseShape } from '../types/http-shapes';
import { internalError } from '../utils/internal-log';
import { setOwnProperty } from '../utils/own-property';
import { resolveRequestTraceId, resolveTraceHeaders } from '../utils/request-trace';
import { stringifyForLog } from '../utils/safe-stringify';
import {
  buildNameSet,
  DEFAULT_REDACT_HEADERS,
  DEFAULT_REDACT_QUERY_PARAMS,
  redactUrlQuery as sanitizeUrl,
} from '../utils/sensitive-names';

// ── Shared types ─────────────────────────────────────────────────────────────

export interface HttpLoggerOptions {
  /**
   * Skip logging for a request. Called before any I/O.
   * @example `skip: (req) => req.url === '/health'`
   */
  skip?: (req: IncomingRequest) => boolean;
  /**
   * Log request body (POST/PUT/PATCH). Capped at `bodyMaxBytes` (default: 4096).
   * Redaction still applies to the captured body.
   * Default: false.
   */
  logBody?: boolean;
  /** Max bytes of body to capture. Default: 4096. */
  bodyMaxBytes?: number;
  /**
   * Emit a WARN log when a request duration exceeds this threshold (ms).
   * Default: 1000.
   */
  slowRequestThresholdMs?: number;
  /**
   * Additional fields to include in every log entry.
   * @example `extraFields: (req) => ({ tenantId: req.headers['x-tenant-id'] })`
   */
  extraFields?: (req: IncomingRequest) => Record<string, unknown>;
  /**
   * Header name, or list of names tried in order, to read the trace ID from.
   * Default: the library-wide list (`DEFAULT_TRACE_HEADERS`: traceparent,
   * x-trace-id, x-request-id, x-correlation-id, trace-id).
   * If none is present, `request.id` is used when it is not a framework counter,
   * otherwise a UUID is generated and shared with the logixia context helpers.
   */
  traceIdHeader?: string | readonly string[];
  /**
   * Additional headers to redact from logged output. Merged with the defaults
   * (authorization, cookie, set-cookie, x-api-key, proxy-authorization,
   * x-auth-token, x-access-token, x-csrf-token, x-amz-security-token).
   */
  redactHeaders?: string[];
  /**
   * Additional query-string parameter names whose values are redacted from the
   * logged URL. Merged with the defaults (token, access_token, refresh_token,
   * code, password, secret, api_key, apikey, key, signature, sig, auth).
   */
  redactQueryParams?: string[];
  /**
   * Log level for request-start entries. Default: 'debug'.
   * Set to 'silent' to suppress request-start logs entirely.
   */
  requestLevel?: string;
  /** Log level for successful response entries. Default: 'info'. */
  responseLevel?: string;
  /** Log level for error responses (status ≥ 500). Default: 'error'. */
  errorLevel?: string;
}

// Minimal structural types so we don't need @types/express / fastify in core
export type IncomingRequest = HttpRequestShape;
export type OutgoingResponse = HttpResponseShape;

// ── Helpers ───────────────────────────────────────────────────────────────────

function sanitizeHeaders(
  headers: Record<string, string | string[] | undefined> | undefined,
  redactSet: Set<string>
): Record<string, unknown> {
  if (!headers) return {};
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    out[k] = redactSet.has(k.toLowerCase()) ? '[REDACTED]' : v;
  }
  return out;
}

/** Fire-and-forget a logger call; a failing log must never become an unhandled rejection. */
function fire(result: unknown): void {
  if (result && typeof (result as Promise<unknown>).catch === 'function') {
    (result as Promise<unknown>).catch((error: unknown) =>
      internalError('http-logger: log call failed', error)
    );
  }
}

interface NameSets {
  headers: Set<string>;
  queryParams: Set<string>;
}

function resolveNameSets(options: HttpLoggerOptions): NameSets {
  return {
    headers: buildNameSet(DEFAULT_REDACT_HEADERS, options.redactHeaders),
    queryParams: buildNameSet(DEFAULT_REDACT_QUERY_PARAMS, options.redactQueryParams),
  };
}

function buildBaseFields(
  req: IncomingRequest,
  traceId: string,
  options: HttpLoggerOptions,
  { headers: redactSet, queryParams: paramSet }: NameSets
): Record<string, unknown> {
  const fields: Record<string, unknown> = {
    traceId,
    method: req.method?.toUpperCase() ?? 'UNKNOWN',
    url: sanitizeUrl(req.url ?? '/', paramSet),
    ip: req.ip ?? req.socket?.remoteAddress ?? 'unknown',
    headers: sanitizeHeaders(req.headers, redactSet),
  };

  if (options.extraFields) {
    Object.assign(fields, options.extraFields(req));
  }

  return fields;
}

// ── Express middleware ────────────────────────────────────────────────────────

/**
 * Create an Express / Connect compatible middleware that replaces Morgan.
 */
export function createExpressMiddleware(
  logger: IBaseLogger,
  options: HttpLoggerOptions = {}
): (req: IncomingRequest, res: OutgoingResponse, next: () => void) => void {
  const {
    skip,
    logBody,
    bodyMaxBytes,
    traceIdHeader,
    requestLevel = 'debug',
    responseLevel = 'info',
    errorLevel = 'error',
    slowRequestThresholdMs = 1000,
  } = options;
  const nameSets = resolveNameSets(options);
  const traceHeaders = resolveTraceHeaders(traceIdHeader);

  return function logixiaHttpMiddleware(
    req: IncomingRequest,
    res: OutgoingResponse,
    next: () => void
  ): void {
    if (skip?.(req)) {
      next();
      return;
    }

    const traceId = resolveRequestTraceId(req, traceHeaders);
    const startMs = Date.now();
    const baseFields = buildBaseFields(req, traceId, options, nameSets);

    // Log request start
    if (requestLevel !== 'silent') {
      fire(
        logger.logLevel(requestLevel, 'request started', {
          ...baseFields,
          ...(logBody && req.body ? { body: truncateBody(req.body, bodyMaxBytes) } : {}),
        })
      );
    }

    // Hook into the response 'finish' event — fires after headers + body are sent.
    // This is what Morgan gets wrong for slow requests (it uses 'close' which may
    // fire before the status code is set on some Node versions).
    //
    // BOTH 'finish' and 'close' fire on a normal response, so guard against
    // logging the completion twice (which would duplicate the completed entry and
    // the slow-request warning).
    let completed = false;
    const onFinish = (): void => {
      if (completed) return;
      completed = true;

      const duration = Date.now() - startMs;
      const status = res.statusCode ?? 0;
      const level = status >= 500 ? errorLevel : responseLevel;

      fire(
        logger.logLevel(level, 'request completed', {
          ...baseFields,
          statusCode: status,
          duration,
        })
      );

      if (duration > slowRequestThresholdMs) {
        fire(
          logger.warn('slow request detected', {
            ...baseFields,
            statusCode: status,
            duration,
            threshold: slowRequestThresholdMs,
          })
        );
      }
    };

    res.once?.('finish', onFinish);
    // Fallback: also covers a client that disconnects before 'finish' fires. The
    // `completed` guard ensures a normal finish+close pair logs only once.
    res.once?.('close', onFinish);

    next();
  };
}

// ── Fastify plugin ─────────────────────────────────────────────────────────────

export interface FastifyInstance {
  addHook: (name: string, fn: (req: unknown, reply: unknown, done: () => void) => void) => void;
}

/**
 * Create a Fastify plugin (a function you pass to `fastify.register()`).
 *
 * @example
 * ```ts
 * await fastify.register(createFastifyPlugin(logger, { slowRequestThresholdMs: 500 }));
 * ```
 */
export function createFastifyPlugin(logger: IBaseLogger, options: HttpLoggerOptions = {}) {
  const {
    skip,
    traceIdHeader,
    requestLevel = 'debug',
    responseLevel = 'info',
    errorLevel = 'error',
    slowRequestThresholdMs = 1000,
  } = options;
  const nameSets = resolveNameSets(options);
  const traceHeaders = resolveTraceHeaders(traceIdHeader);

  function logixiaFastifyPlugin(fastify: FastifyInstance, _opts: unknown, done: () => void): void {
    fastify.addHook('onRequest', (request: unknown, _reply: unknown, hookDone: () => void) => {
      const req = request as IncomingRequest & { _logixiaStart?: number };
      if (skip?.(req)) {
        hookDone();
        return;
      }

      const traceId = resolveRequestTraceId(req, traceHeaders);
      req._logixiaStart = Date.now();

      if (requestLevel !== 'silent') {
        fire(
          logger.logLevel(
            requestLevel,
            'request started',
            buildBaseFields(req, traceId, options, nameSets)
          )
        );
      }
      hookDone();
    });

    fastify.addHook('onResponse', (request: unknown, reply: unknown, hookDone: () => void) => {
      const req = request as IncomingRequest & { _logixiaStart?: number };
      if (req._logixiaStart === undefined) {
        hookDone();
        return;
      }

      const rep = reply as { statusCode?: number };
      const duration = Date.now() - req._logixiaStart;
      const status = rep.statusCode ?? 0;
      const traceId = resolveRequestTraceId(req, traceHeaders);
      const level = status >= 500 ? errorLevel : responseLevel;
      const baseFields = buildBaseFields(req, traceId, options, nameSets);

      fire(
        logger.logLevel(level, 'request completed', {
          ...baseFields,
          statusCode: status,
          duration,
        })
      );

      if (duration > slowRequestThresholdMs) {
        fire(
          logger.warn('slow request detected', {
            traceId,
            url: baseFields.url,
            method: req.method,
            duration,
            threshold: slowRequestThresholdMs,
          })
        );
      }

      hookDone();
    });

    done();
  }

  return Object.assign(logixiaFastifyPlugin, {
    [Symbol.for('skip-override')]: true,
    [Symbol.for('fastify.display-name')]: 'logixia',
  });
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/**
 * Bound the captured body without turning it into a string, so the logger's
 * path-based redaction still sees the original keys. Oversized structures are
 * pruned (extra keys/items dropped, long strings cut) rather than serialized.
 */
function truncateBody(body: unknown, maxBytes = 4096): unknown {
  if (typeof body === 'string') {
    return body.length > maxBytes ? body.slice(0, maxBytes) + '…[truncated]' : body;
  }
  if (body && typeof body === 'object') {
    const str = stringifyForLog(body);
    if (str.length <= maxBytes) return body;
    return pruneValue(body, { left: maxBytes }, 0, new Set());
  }
  return body;
}

const TRUNCATED = '…[truncated]';
const MAX_PRUNE_DEPTH = 8;

function pruneValue(
  value: unknown,
  budget: { left: number },
  depth: number,
  ancestors: Set<object>
): unknown {
  if (typeof value === 'string') {
    const cut = value.slice(0, Math.max(0, budget.left));
    budget.left -= cut.length;
    return cut.length < value.length ? cut + TRUNCATED : cut;
  }
  if (value === null || typeof value !== 'object') {
    budget.left -= 8;
    return value;
  }
  if (value instanceof Date) {
    budget.left -= 24;
    return Number.isNaN(value.getTime()) ? 'Invalid Date' : value.toISOString();
  }
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    budget.left -= 16;
    return `[Buffer ${value.byteLength} bytes]`;
  }
  if (value instanceof Error) return value;
  if (ancestors.has(value) || depth >= MAX_PRUNE_DEPTH) return TRUNCATED;
  ancestors.add(value);
  try {
    if (Array.isArray(value) || value instanceof Set || value instanceof Map) {
      const items: unknown[] = [];
      for (const item of value instanceof Map ? value.entries() : value) {
        if (budget.left <= 0) {
          items.push(TRUNCATED);
          break;
        }
        items.push(pruneValue(item, budget, depth + 1, ancestors));
      }
      return items;
    }
    const toJSON = (value as { toJSON?: unknown }).toJSON;
    if (typeof toJSON === 'function') {
      const json: unknown = toJSON.call(value);
      if (json !== value) return pruneValue(json, budget, depth + 1, ancestors);
    }
    const record: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
      if (budget.left <= 0) {
        record['…'] = TRUNCATED;
        break;
      }
      budget.left -= k.length;
      setOwnProperty(record, k, pruneValue(v, budget, depth + 1, ancestors));
    }
    return record;
  } catch {
    return TRUNCATED;
  } finally {
    ancestors.delete(value);
  }
}
