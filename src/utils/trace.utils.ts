/**
 * Trace ID utilities for Logitron
 */

import { AsyncLocalStorage } from 'node:async_hooks';

import { v4 as uuidv4 } from 'uuid';

import type { TraceIdConfig, TraceIdExtractorConfig } from '../types';

// Async local storage for trace context
export const traceStorage = new AsyncLocalStorage<{
  traceId: string;
  [key: string]: unknown;
}>();

/**
 * Default trace ID generator using UUID v4
 */
export function generateTraceId(): string {
  return uuidv4();
}

/**
 * Get current trace ID from async context
 */
export function getCurrentTraceId(): string | undefined {
  const store = traceStorage.getStore();
  return store?.traceId;
}

/**
 * Set trace ID in the CURRENT async context without starting a new one.
 *
 * ⚠️  Uses `enterWith()` which mutates the context for the current async
 * execution and ALL futures spawned from it. Prefer `runWithTraceId()` when
 * you can wrap the operation in a callback, as it creates a properly-scoped
 * child context. Use `setTraceId()` only when you cannot use `runWithTraceId()`
 * (e.g., inside a class constructor or a non-callback async entry point).
 */
export function setTraceId(traceId: string, data?: Record<string, unknown>): void {
  const currentStore = traceStorage.getStore() ?? {};
  traceStorage.enterWith({ ...currentStore, traceId, ...data });
}

/**
 * Run function with trace ID context
 */
export function runWithTraceId<T>(traceId: string, fn: () => T, data?: Record<string, unknown>): T {
  return traceStorage.run({ traceId, ...data }, fn);
}

/** Shape that extractTraceId accepts (Express-compatible) */
interface RequestLike {
  headers?: Record<string, string | string[] | undefined>;
  query?: Record<string, string | string[] | undefined>;
  body?: Record<string, string | undefined>;
  params?: Record<string, string | undefined>;
}

/**
 * Extract trace ID from request using configuration
 */
export function extractTraceId(
  request: unknown,
  config: TraceIdExtractorConfig
): string | undefined {
  const req = request as RequestLike;
  // Try headers first
  if (config.header) {
    const headers = Array.isArray(config.header) ? config.header : [config.header];
    for (const header of headers) {
      const value = req.headers?.[header.toLowerCase()];
      if (value) {
        return Array.isArray(value) ? value[0] : value;
      }
    }
  }

  // Try query parameters
  if (config.query) {
    const queries = Array.isArray(config.query) ? config.query : [config.query];
    for (const query of queries) {
      const value = req.query?.[query];
      if (value) {
        return Array.isArray(value) ? value[0] : value;
      }
    }
  }

  // Try body parameters
  if (config.body) {
    const bodyFields = Array.isArray(config.body) ? config.body : [config.body];
    for (const field of bodyFields) {
      const value = req.body?.[field];
      if (value) {
        return value;
      }
    }
  }

  // Try route parameters
  if (config.params) {
    const paramFields = Array.isArray(config.params) ? config.params : [config.params];
    for (const param of paramFields) {
      const value = req.params?.[param];
      if (value) {
        return value;
      }
    }
  }

  return undefined;
}

/**
 * Default headers checked for incoming trace ID propagation, in priority order:
 *   traceparent (W3C/OTel) → x-trace-id → x-request-id → x-correlation-id → trace-id
 */
export const DEFAULT_TRACE_HEADERS = [
  'traceparent',
  'x-trace-id',
  'x-request-id',
  'x-correlation-id',
  'trace-id',
];

/**
 * Create trace ID middleware for Express/NestJS
 */
export function createTraceMiddleware(config: TraceIdConfig) {
  const resolvedConfig: TraceIdConfig = {
    extractor: {
      header: DEFAULT_TRACE_HEADERS,
      query: ['traceId', 'trace_id'],
    },
    ...config,
  };

  return (req: unknown, res: unknown, next: () => void) => {
    let traceId: string | undefined;

    // Try to extract existing trace ID from incoming request
    if (resolvedConfig.extractor) {
      traceId = extractTraceId(req, resolvedConfig.extractor);
    }

    // Generate new trace ID if none was provided by the caller
    if (!traceId) {
      traceId = resolvedConfig.generator ? resolvedConfig.generator() : generateTraceId();
    }

    // Set trace ID on the request object and propagate back in response header
    (req as Record<string, unknown>).traceId = traceId;
    (res as { setHeader: (k: string, v: string) => void }).setHeader('X-Trace-Id', traceId);

    // Run the rest of the middleware/handler chain inside the trace context.
    // AsyncLocalStorage.run() propagates the context through all awaited async
    // operations spawned within the callback, so every logger.log() call
    // will find the same traceId via getCurrentTraceId().
    runWithTraceId(
      traceId,
      () => {
        next();
      },
      {
        requestId:
          ((req as Record<string, unknown>)['id'] as string) ||
          ((req as Record<string, unknown>)['requestId'] as string) ||
          generateTraceId(),
      }
    );
  };
}
