/**
 * Trace ID utilities for Logitron
 */

import { v4 as uuidv4 } from "uuid";
import { AsyncLocalStorage } from "async_hooks";
import { TraceIdConfig, TraceIdExtractorConfig } from "../types";

// Async local storage for trace context
export const traceStorage = new AsyncLocalStorage<{
  traceId: string;
  [key: string]: any;
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
export function setTraceId(traceId: string, data?: Record<string, any>): void {
  const currentStore = traceStorage.getStore() ?? {};
  traceStorage.enterWith({ ...currentStore, traceId, ...data });
}

/**
 * Run function with trace ID context
 */
export function runWithTraceId<T>(
  traceId: string,
  fn: () => T,
  data?: Record<string, any>,
): T {
  return traceStorage.run({ traceId, ...data }, fn);
}

/**
 * Extract trace ID from request using configuration
 */
export function extractTraceId(
  request: any,
  config: TraceIdExtractorConfig,
): string | undefined {
  // Try headers first
  if (config.header) {
    const headers = Array.isArray(config.header)
      ? config.header
      : [config.header];
    for (const header of headers) {
      const value = request.headers?.[header.toLowerCase()];
      if (value) {
        return Array.isArray(value) ? value[0] : value;
      }
    }
  }

  // Try query parameters
  if (config.query) {
    const queries = Array.isArray(config.query) ? config.query : [config.query];
    for (const query of queries) {
      const value = request.query?.[query];
      if (value) {
        return Array.isArray(value) ? value[0] : value;
      }
    }
  }

  // Try body parameters
  if (config.body) {
    const bodyFields = Array.isArray(config.body) ? config.body : [config.body];
    for (const field of bodyFields) {
      const value = request.body?.[field];
      if (value) {
        return value;
      }
    }
  }

  // Try route parameters
  if (config.params) {
    const paramFields = Array.isArray(config.params)
      ? config.params
      : [config.params];
    for (const param of paramFields) {
      const value = request.params?.[param];
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
  "traceparent",
  "x-trace-id",
  "x-request-id",
  "x-correlation-id",
  "trace-id",
];

/**
 * Create trace ID middleware for Express/NestJS
 */
export function createTraceMiddleware(config: TraceIdConfig) {
  const resolvedConfig: TraceIdConfig = {
    extractor: {
      header: DEFAULT_TRACE_HEADERS,
      query: ["traceId", "trace_id"],
    },
    ...config,
  };

  return (req: any, res: any, next: any) => {
    let traceId: string | undefined;

    // Try to extract existing trace ID from incoming request
    if (resolvedConfig.extractor) {
      traceId = extractTraceId(req, resolvedConfig.extractor);
    }

    // Generate new trace ID if none was provided by the caller
    if (!traceId) {
      traceId = resolvedConfig.generator
        ? resolvedConfig.generator()
        : generateTraceId();
    }

    // Set trace ID on the request object and propagate back in response header
    req.traceId = traceId;
    res.setHeader("X-Trace-Id", traceId);

    // Run the rest of the middleware/handler chain inside the trace context.
    // AsyncLocalStorage.run() propagates the context through all awaited async
    // operations spawned within the callback, so every logger.log() call
    // will find the same traceId via getCurrentTraceId().
    runWithTraceId(
      traceId,
      () => {
        next();
      },
      { requestId: req.id || req.requestId || generateTraceId() },
    );
  };
}
