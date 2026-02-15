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
 * Set trace ID in async context
 */
export function setTraceId(traceId: string, data?: Record<string, any>): void {
  const currentStore = traceStorage.getStore() || {};
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
 * Create trace ID middleware for Express/NestJS
 */
export function createTraceMiddleware(config: TraceIdConfig) {
  return (req: any, res: any, next: any) => {
    let traceId: string | undefined;

    // Try to extract existing trace ID
    if (config.extractor) {
      traceId = extractTraceId(req, config.extractor);
    }

    // Generate new trace ID if not found
    if (!traceId) {
      traceId = config.generator ? config.generator() : generateTraceId();
    }

    // Set trace ID in request
    req.traceId = traceId;

    // Set response header
    res.setHeader("X-Trace-Id", traceId);

    // Run with trace context
    runWithTraceId(
      traceId,
      () => {
        next();
      },
      { requestId: req.id || generateTraceId() },
    );
  };
}
