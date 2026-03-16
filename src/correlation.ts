/**
 * logixia — Microservices Correlation ID Propagation
 *
 * Provides zero-boilerplate correlation ID generation and propagation for
 * distributed systems. A single correlation ID travels through every service
 * in a request fan-out, making it trivial to join logs across services.
 *
 * Features:
 *  - UUID v4 correlation ID generation (via `crypto.randomUUID()`)
 *  - Express / Fastify / NestJS incoming-request middleware
 *  - `correlationFetch()` — wraps global `fetch`, auto-injects `X-Correlation-ID`
 *  - `createCorrelationAxiosInterceptor()` — axios request interceptor
 *  - `childFromRequest(req, logger)` — child logger with all request identifiers
 *  - Kafka / SQS / RabbitMQ message context helpers
 *  - Integration with `LogixiaContext` (AsyncLocalStorage) so every `logger.info()`
 *    call automatically includes the correlationId without per-call passing.
 *
 * @example Express middleware
 * ```ts
 * import { correlationMiddleware } from 'logixia/correlation';
 * import { logger } from 'logixia';
 *
 * app.use(correlationMiddleware());
 *
 * app.get('/orders', (req, res) => {
 *   // correlationId is automatically in every log inside this request
 *   logger.info('Listing orders');
 *   res.json({ ok: true });
 * });
 * ```
 *
 * @example Outbound fetch with correlation
 * ```ts
 * import { correlationFetch } from 'logixia/correlation';
 *
 * // Reads correlationId from current LogixiaContext and injects it as header
 * const data = await correlationFetch('https://payments.internal/charge', {
 *   method: 'POST',
 *   body: JSON.stringify({ amount: 100 }),
 * });
 * ```
 *
 * @example Manual correlation context
 * ```ts
 * import { withCorrelationId } from 'logixia/correlation';
 *
 * await withCorrelationId('trace-abc-123', async () => {
 *   // All logs and outbound fetch calls in here carry 'trace-abc-123'
 *   await processOrder();
 * });
 * ```
 */

import { LogixiaContext } from './context/async-context';

// ── Types ─────────────────────────────────────────────────────────────────────

/** Fields injected into the log context by the correlation middleware. */
export interface CorrelationContext {
  correlationId: string;
  requestId?: string;
  traceId?: string;
  /** Service that originated the request (from `X-Origin-Service` header). */
  originService?: string;
  /** Index signature so CorrelationContext is assignable to LogContext. */
  [key: string]: unknown;
}

export interface CorrelationMiddlewareOptions {
  /**
   * HTTP header to read/write the correlation ID from/to.
   * @default 'x-correlation-id'
   */
  header?: string;
  /**
   * HTTP header for request ID (a per-hop identifier, different from correlationId).
   * @default 'x-request-id'
   */
  requestIdHeader?: string;
  /**
   * HTTP header for the originating service name.
   * @default 'x-origin-service'
   */
  originServiceHeader?: string;
  /**
   * Function to generate a new correlation ID when none is present in the request.
   * @default () => crypto.randomUUID()
   */
  generate?: () => string;
  /**
   * When `true`, the response will include the correlation ID header so
   * clients can log it client-side.
   * @default true
   */
  setResponseHeader?: boolean;
}

// ── ID generation ─────────────────────────────────────────────────────────────

/**
 * Generate a new correlation ID using `crypto.randomUUID()` (available in
 * Node.js 14.17+, all modern browsers, and Edge runtimes).
 */
export function generateCorrelationId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  // Fallback for very old Node.js builds (pseudo-random is acceptable for a correlation ID)
  // eslint-disable-next-line sonarjs/pseudo-random
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 11)}`;
}

// ── Context helpers ───────────────────────────────────────────────────────────

/**
 * Return the correlation ID from the current `LogixiaContext`, or `undefined`
 * when called outside any context scope.
 */
export function getCurrentCorrelationId(): string | undefined {
  const ctx = LogixiaContext.get();
  return ctx?.correlationId as string | undefined;
}

/**
 * Run `callback` inside a correlation context scope.
 *
 * If a correlation ID is not provided, a new UUID is generated.
 *
 * @example
 * ```ts
 * await withCorrelationId('cid-abc', async () => {
 *   logger.info('Processing message'); // → { correlationId: 'cid-abc', ... }
 *   await callDownstream();            // correlationFetch() picks up cid-abc
 * });
 * ```
 */
export function withCorrelationId<T>(correlationId: string | undefined, callback: () => T): T {
  const id = correlationId ?? generateCorrelationId();
  return LogixiaContext.run({ correlationId: id }, callback);
}

// ── Express / Connect middleware ──────────────────────────────────────────────

/**
 * Express-compatible middleware that:
 * 1. Reads `X-Correlation-ID` from the incoming request (or generates a new one)
 * 2. Wraps the request in a `LogixiaContext` so all loggers in the handler
 *    automatically include `correlationId`
 * 3. Writes the correlation ID back to the response header (opt-out via options)
 *
 * @example
 * ```ts
 * import { correlationMiddleware } from 'logixia/correlation';
 * app.use(correlationMiddleware());
 * ```
 */
export function correlationMiddleware(options: CorrelationMiddlewareOptions = {}) {
  const {
    header = 'x-correlation-id',
    requestIdHeader = 'x-request-id',
    originServiceHeader = 'x-origin-service',
    generate = generateCorrelationId,
    setResponseHeader = true,
  } = options;

  return function logixiaCorrelationMiddleware(
    req: Record<string, unknown>,
    res: Record<string, unknown>,
    next: () => void
  ): void {
    const headers = (req['headers'] ?? {}) as Record<string, string | undefined>;

    const correlationId = headers[header] ?? generate();
    const requestId = headers[requestIdHeader] ?? generate();
    const originService = headers[originServiceHeader];

    if (setResponseHeader) {
      const setHeader = res['setHeader'] as ((name: string, value: string) => void) | undefined;
      if (typeof setHeader === 'function') {
        setHeader.call(res, header, correlationId);
      }
    }

    const ctx: CorrelationContext = {
      correlationId,
      requestId,
      ...(originService !== undefined ? { originService } : {}),
    };

    LogixiaContext.run(ctx, next);
  };
}

// ── Fastify hook ──────────────────────────────────────────────────────────────

/**
 * Fastify `onRequest` lifecycle hook — same functionality as `correlationMiddleware`
 * but adapted to Fastify's hook API.
 *
 * @example
 * ```ts
 * import { correlationFastifyHook } from 'logixia/correlation';
 * fastify.addHook('onRequest', correlationFastifyHook());
 * ```
 */
export function correlationFastifyHook(options: CorrelationMiddlewareOptions = {}) {
  const {
    header = 'x-correlation-id',
    requestIdHeader = 'x-request-id',
    originServiceHeader = 'x-origin-service',
    generate = generateCorrelationId,
    setResponseHeader = true,
  } = options;

  return function logixiaCorrelationFastifyHook(
    request: Record<string, unknown>,
    reply: Record<string, unknown>,
    done: () => void
  ): void {
    const headers = (request['headers'] ?? {}) as Record<string, string | undefined>;

    const correlationId = headers[header] ?? generate();
    const requestId =
      headers[requestIdHeader] ?? (request['id'] as string | undefined) ?? generate();
    const originService = headers[originServiceHeader];

    if (setResponseHeader) {
      const replyHeader = reply['header'] as ((name: string, value: string) => void) | undefined;
      if (typeof replyHeader === 'function') {
        replyHeader.call(reply, header, correlationId);
      }
    }

    const ctx: CorrelationContext = {
      correlationId,
      requestId,
      ...(originService !== undefined ? { originService } : {}),
    };

    LogixiaContext.run(ctx, done);
  };
}

// ── Outbound fetch wrapper ────────────────────────────────────────────────────

/**
 * A drop-in replacement for `fetch` that automatically injects the current
 * `correlationId` from `LogixiaContext` as an `X-Correlation-ID` request header.
 *
 * Falls back to the global `fetch` when no correlation context is active.
 *
 * @example
 * ```ts
 * import { correlationFetch } from 'logixia/correlation';
 *
 * // Inside a request handler with correlationMiddleware active:
 * const response = await correlationFetch('https://payments.internal/v1/charge', {
 *   method: 'POST',
 *   body: JSON.stringify({ amount: 100 }),
 * });
 * ```
 */
export async function correlationFetch(
  input: string | URL,
  init: Record<string, unknown> = {},
  options: { header?: string } = {}
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): Promise<any> {
  const header = options.header ?? 'x-correlation-id';
  const correlationId = getCurrentCorrelationId();

  // Build merged headers as a plain object
  const existingHeaders: Record<string, string> =
    init['headers'] && typeof init['headers'] === 'object'
      ? (init['headers'] as Record<string, string>)
      : {};

  const headers: Record<string, string> = { ...existingHeaders };
  if (correlationId && !headers[header]) {
    headers[header] = correlationId;
  }

  // Propagate request-id as well
  const ctx = LogixiaContext.get();
  if (ctx?.requestId && !headers['x-request-id']) {
    headers['x-request-id'] = ctx.requestId as string;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (globalThis as any)['fetch'](input, { ...init, headers });
}

// ── Axios interceptor factory ─────────────────────────────────────────────────

/**
 * Returns an axios request interceptor that automatically injects the current
 * correlation ID into outgoing axios requests.
 *
 * @example
 * ```ts
 * import axios from 'axios';
 * import { createCorrelationAxiosInterceptor } from 'logixia/correlation';
 *
 * axios.interceptors.request.use(createCorrelationAxiosInterceptor());
 * ```
 */
export function createCorrelationAxiosInterceptor(
  options: { header?: string } = {}
): (config: Record<string, unknown>) => Record<string, unknown> {
  const header = options.header ?? 'x-correlation-id';

  return function correlationAxiosInterceptor(
    config: Record<string, unknown>
  ): Record<string, unknown> {
    const correlationId = getCurrentCorrelationId();
    if (!correlationId) return config;

    const headers = (config['headers'] ?? {}) as Record<string, unknown>;
    if (!headers[header]) {
      headers[header] = correlationId;
    }

    const ctx = LogixiaContext.get();
    if (ctx?.requestId && !headers['x-request-id']) {
      headers['x-request-id'] = ctx.requestId;
    }

    return { ...config, headers };
  };
}

// ── Child logger from request ─────────────────────────────────────────────────

/**
 * Create a child logger enriched with all correlation-relevant identifiers
 * extracted from the incoming HTTP request.
 *
 * The child logger's every call automatically includes:
 * `correlationId`, `requestId`, `method`, `url`, `userAgent`, `ip`
 *
 * @example
 * ```ts
 * import { childFromRequest } from 'logixia/correlation';
 * import { logger } from 'logixia';
 *
 * app.use((req, res, next) => {
 *   req.logger = childFromRequest(req, logger);
 *   next();
 * });
 *
 * app.get('/orders', (req, res) => {
 *   req.logger.info('Listing orders');  // → correlationId, requestId, method, url ...
 * });
 * ```
 */
export function childFromRequest<TLogger extends { child(ctx: Record<string, unknown>): TLogger }>(
  req: Record<string, unknown>,
  logger: TLogger,
  options: { correlationHeader?: string; requestIdHeader?: string } = {}
): TLogger {
  const correlationHeader = options.correlationHeader ?? 'x-correlation-id';
  const requestIdHeader = options.requestIdHeader ?? 'x-request-id';

  const headers = (req['headers'] ?? {}) as Record<string, string | undefined>;
  const correlationId =
    headers[correlationHeader] ?? getCurrentCorrelationId() ?? generateCorrelationId();
  const requestId = headers[requestIdHeader] ?? generateCorrelationId();

  const method = req['method'] as string | undefined;
  const url = (req['url'] as string | undefined) ?? (req['originalUrl'] as string | undefined);
  const userAgent = headers['user-agent'];
  const ip =
    (headers['x-forwarded-for'] as string | undefined)?.split(',')[0]?.trim() ??
    ((req['socket'] as Record<string, unknown> | undefined)?.['remoteAddress'] as
      | string
      | undefined);

  return logger.child({
    correlationId,
    requestId,
    ...(method !== undefined ? { method } : {}),
    ...(url !== undefined ? { url } : {}),
    ...(userAgent !== undefined ? { userAgent } : {}),
    ...(ip !== undefined ? { ip } : {}),
  });
}

// ── Message queue helpers ─────────────────────────────────────────────────────

/**
 * Extract a correlation context from a Kafka / RabbitMQ / SQS message object.
 *
 * Looks for `correlationId`, `correlation_id`, or `x-correlation-id` in
 * `message.headers` (Kafka) or `message.MessageAttributes` (SQS).
 *
 * @example Kafka consumer
 * ```ts
 * import { extractMessageCorrelationId, withCorrelationId } from 'logixia/correlation';
 *
 * consumer.run({
 *   eachMessage: async ({ message }) => {
 *     const correlationId = extractMessageCorrelationId(message);
 *     await withCorrelationId(correlationId, () => processMessage(message));
 *   },
 * });
 * ```
 */
export function extractMessageCorrelationId(message: Record<string, unknown>): string | undefined {
  // Kafka: message.headers is Record<string, Buffer | string>
  const kafkaHeaders = message['headers'] as Record<string, Buffer | string> | undefined;
  if (kafkaHeaders) {
    const raw =
      kafkaHeaders['x-correlation-id'] ??
      kafkaHeaders['correlationId'] ??
      kafkaHeaders['correlation_id'];
    if (raw !== undefined) {
      return Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw);
    }
  }

  // SQS: message.MessageAttributes
  const sqsAttrs = message['MessageAttributes'] as
    | Record<string, { StringValue?: string }>
    | undefined;
  if (sqsAttrs) {
    return (
      sqsAttrs['x-correlation-id']?.StringValue ??
      sqsAttrs['correlationId']?.StringValue ??
      sqsAttrs['correlation_id']?.StringValue
    );
  }

  // AMQP / generic envelope
  return (
    (message['correlationId'] as string | undefined) ??
    (message['correlation_id'] as string | undefined)
  );
}

/**
 * Build Kafka message headers containing the current correlation context.
 *
 * @example
 * ```ts
 * import { buildKafkaCorrelationHeaders } from 'logixia/correlation';
 *
 * await producer.send({
 *   topic: 'orders',
 *   messages: [{ value: JSON.stringify(order), headers: buildKafkaCorrelationHeaders() }],
 * });
 * ```
 */
export function buildKafkaCorrelationHeaders(): Record<string, string> {
  const ctx = LogixiaContext.get();
  const headers: Record<string, string> = {};

  const correlationId = ctx?.correlationId as string | undefined;
  if (correlationId) headers['x-correlation-id'] = correlationId;

  const requestId = ctx?.requestId as string | undefined;
  if (requestId) headers['x-request-id'] = requestId;

  const traceId = ctx?.traceId as string | undefined;
  if (traceId) headers['x-trace-id'] = traceId;

  return headers;
}
