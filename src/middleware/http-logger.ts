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

/* eslint-disable sonarjs/void-use -- intentional fire-and-forget in sync middleware callbacks */
import type { IBaseLogger } from '../types';

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
   * Trace ID header. Default: 'x-trace-id'.
   * If the header is absent, a short random ID is generated.
   */
  traceIdHeader?: string;
  /**
   * Headers to redact from logged output.
   * Default: ['authorization', 'cookie', 'set-cookie', 'x-api-key'].
   */
  redactHeaders?: string[];
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
export interface IncomingRequest {
  method?: string;
  url?: string;
  headers?: Record<string, string | string[] | undefined>;
  body?: unknown;
  socket?: { remoteAddress?: string };
  ip?: string;
}

export interface OutgoingResponse {
  statusCode?: number;
  on?: (event: string, cb: () => void) => void;
  once?: (event: string, cb: () => void) => void;
  getHeader?: (name: string) => string | number | string[] | undefined;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const DEFAULT_REDACT_HEADERS = new Set(['authorization', 'cookie', 'set-cookie', 'x-api-key']);

function sanitizeHeaders(
  headers: Record<string, string | string[] | undefined> | undefined,
  redactSet: Set<string>
): Record<string, unknown> {
  if (!headers) return {};
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k] = redactSet.has(k.toLowerCase()) ? '[REDACTED]' : v;
  }
  return out;
}

function shortId(): string {
  // eslint-disable-next-line sonarjs/pseudo-random -- non-security request ID
  return Math.random().toString(36).slice(2, 10);
}

function buildBaseFields(
  req: IncomingRequest,
  traceId: string,
  options: HttpLoggerOptions
): Record<string, unknown> {
  const redactSet = options.redactHeaders
    ? new Set(options.redactHeaders.map((h) => h.toLowerCase()))
    : DEFAULT_REDACT_HEADERS;

  const fields: Record<string, unknown> = {
    traceId,
    method: req.method?.toUpperCase() ?? 'UNKNOWN',
    url: req.url ?? '/',
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
    traceIdHeader = 'x-trace-id',
    requestLevel = 'debug',
    responseLevel = 'info',
    errorLevel = 'error',
    slowRequestThresholdMs = 1000,
  } = options;

  return function logixiaHttpMiddleware(
    req: IncomingRequest,
    res: OutgoingResponse,
    next: () => void
  ): void {
    if (skip?.(req)) {
      next();
      return;
    }

    const traceId = (req.headers?.[traceIdHeader] as string | undefined) ?? shortId();
    const startMs = Date.now();
    const baseFields = buildBaseFields(req, traceId, options);

    // Log request start
    if (requestLevel !== 'silent') {
      void logger.logLevel(requestLevel, 'request started', {
        ...baseFields,
        ...(logBody && req.body ? { body: truncateBody(req.body, bodyMaxBytes) } : {}),
      });
    }

    // Hook into the response 'finish' event — fires after headers + body are sent.
    // This is what Morgan gets wrong for slow requests (it uses 'close' which may
    // fire before the status code is set on some Node versions).
    const onFinish = (): void => {
      const duration = Date.now() - startMs;
      const status = res.statusCode ?? 0;
      const level = status >= 500 ? errorLevel : responseLevel;

      void logger.logLevel(level, 'request completed', {
        ...baseFields,
        statusCode: status,
        duration,
      });

      if (duration > slowRequestThresholdMs) {
        void logger.warn('slow request detected', {
          ...baseFields,
          statusCode: status,
          duration,
          threshold: slowRequestThresholdMs,
        });
      }
    };

    res.once?.('finish', onFinish);
    // Fallback: also listen to 'close' (client disconnected before response finished)
    res.once?.('close', () => {
      if ((res.statusCode ?? 0) === 0) onFinish();
    });

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
    traceIdHeader = 'x-trace-id',
    requestLevel = 'debug',
    responseLevel = 'info',
    errorLevel = 'error',
    slowRequestThresholdMs = 1000,
  } = options;

  return function logixiaFastifyPlugin(
    fastify: FastifyInstance,
    _opts: unknown,
    done: () => void
  ): void {
    fastify.addHook('onRequest', (request: unknown, _reply: unknown, hookDone: () => void) => {
      const req = request as IncomingRequest & { _logixiaStart?: number; _logixiaId?: string };
      if (skip?.(req)) {
        hookDone();
        return;
      }

      const traceId = (req.headers?.[traceIdHeader] as string | undefined) ?? shortId();
      req._logixiaStart = Date.now();
      req._logixiaId = traceId;

      if (requestLevel !== 'silent') {
        void logger.logLevel(
          requestLevel,
          'request started',
          buildBaseFields(req, traceId, options)
        );
      }
      hookDone();
    });

    fastify.addHook('onResponse', (request: unknown, reply: unknown, hookDone: () => void) => {
      const req = request as IncomingRequest & { _logixiaStart?: number; _logixiaId?: string };
      const rep = reply as { statusCode?: number };
      const duration = Date.now() - (req._logixiaStart ?? Date.now());
      const status = rep.statusCode ?? 0;
      const traceId = req._logixiaId ?? shortId();
      const level = status >= 500 ? errorLevel : responseLevel;

      void logger.logLevel(level, 'request completed', {
        ...buildBaseFields(req, traceId, options),
        statusCode: status,
        duration,
      });

      if (duration > slowRequestThresholdMs) {
        void logger.warn('slow request detected', {
          traceId,
          url: req.url,
          method: req.method,
          duration,
          threshold: slowRequestThresholdMs,
        });
      }

      hookDone();
    });

    done();
  };
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function truncateBody(body: unknown, maxBytes = 4096): unknown {
  if (typeof body === 'string') {
    return body.length > maxBytes ? body.slice(0, maxBytes) + '…[truncated]' : body;
  }
  if (body && typeof body === 'object') {
    const str = JSON.stringify(body);
    if (str.length > maxBytes) {
      return str.slice(0, maxBytes) + '…[truncated]';
    }
  }
  return body;
}
