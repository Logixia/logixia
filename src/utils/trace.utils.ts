/**
 * Trace ID utilities for Logitron
 */

import { AsyncLocalStorage } from 'node:async_hooks';

import { v4 as uuidv4 } from 'uuid';

import type { TraceIdConfig, TraceIdExtractorConfig } from '../types';

/** Default key used to store the trace ID in AsyncLocalStorage. */
export const TRACE_CONTEXT_KEY = 'traceId' as const;

// ── TraceContext class ────────────────────────────────────────────────────────

/**
 * Singleton that owns the AsyncLocalStorage and the active contextKey.
 *
 * Why a class instead of bare module-level variables?
 *  - The contextKey is user-configurable; encapsulating it here means there is
 *    exactly one place that reads and writes it.
 *  - All helpers (getCurrentTraceId, runWithTraceId, etc.) delegate to this
 *    instance, so the key is always in sync without hidden global state.
 *  - Easier to test: you can reset the singleton between test cases.
 *
 * Usage (advanced):
 *   import { TraceContext } from 'logixia';
 *   TraceContext.instance.contextKey          // → 'traceId' (or custom)
 *   TraceContext.instance.getCurrentTraceId() // same as standalone fn
 */
export class TraceContext {
  private static _instance: TraceContext | null = null;

  readonly storage = new AsyncLocalStorage<Record<string, unknown>>();
  private _contextKey: string = TRACE_CONTEXT_KEY;

  private constructor() {}

  /** The process-wide singleton. */
  static get instance(): TraceContext {
    if (!TraceContext._instance) {
      TraceContext._instance = new TraceContext();
    }
    return TraceContext._instance;
  }

  /** @internal Reset the singleton (useful in tests). */
  static _reset(): void {
    TraceContext._instance = null;
  }

  // ── Key management ──────────────────────────────────────────────────────────

  /** The AsyncLocalStorage key that holds the trace ID value. */
  get contextKey(): string {
    return this._contextKey;
  }

  /** @internal Called by TraceMiddleware when it boots to register the user's key. */
  setContextKey(key: string): void {
    this._contextKey = key;
  }

  // ── Core operations ─────────────────────────────────────────────────────────

  /** UUID v4 generator (default). */
  generate(): string {
    return uuidv4();
  }

  /** Read the trace ID from the current async context. */
  getCurrentTraceId(): string | undefined {
    return this.storage.getStore()?.[this._contextKey] as string | undefined;
  }

  /**
   * Mutate the CURRENT async context in-place.
   *
   * ⚠️  DEPRECATED — unsafe for concurrent requests.
   *
   * Uses `AsyncLocalStorage.enterWith()`, which mutates the current async
   * execution context and every Promise chain spawned from it. In a server
   * processing overlapping requests this can cause a trace ID set for one
   * request to bleed into *other* in-flight requests that share the same
   * async parent (e.g. a module-level setup function or a cached handler).
   *
   * Use {@link run} instead — it scopes the context to a callback so there
   * is no risk of cross-request leakage.
   *
   * @deprecated Use `TraceContext.instance.run(traceId, fn)` — do not call
   *             `setTraceId` from request-handling code.
   */
  setTraceId(traceId: string, data?: Record<string, unknown>): void {
    const current = this.storage.getStore() ?? {};
    this.storage.enterWith({ ...current, [this._contextKey]: traceId, ...data });
  }

  /** Run `fn` inside a new async context that carries `traceId`. */
  run<T>(traceId: string, fn: () => T, data?: Record<string, unknown>): T {
    return this.storage.run({ [this._contextKey]: traceId, ...data }, fn);
  }
}

// ── Module-level aliases (backwards-compatible public API) ────────────────────

/**
 * The shared AsyncLocalStorage instance.
 * @deprecated Prefer `TraceContext.instance.storage` for new code.
 */
export const traceStorage = TraceContext.instance.storage;

/** Returns the key currently used to store the trace ID in AsyncLocalStorage. */
export function getTraceContextKey(): string {
  return TraceContext.instance.contextKey;
}

/** @internal Called by TraceMiddleware / traceMiddleware() when they boot. */
export function _setActiveContextKey(key: string): void {
  TraceContext.instance.setContextKey(key);
}

/** Generate a UUID v4 trace ID. */
export function generateTraceId(): string {
  return TraceContext.instance.generate();
}

/**
 * Get the current trace ID from async context.
 * Returns `undefined` when called outside a traced request.
 */
export function getCurrentTraceId(): string | undefined {
  return TraceContext.instance.getCurrentTraceId();
}

/**
 * Set trace ID in the CURRENT async context without starting a new one.
 *
 * ⚠️  DEPRECATED — unsafe for concurrent requests.
 *
 * Uses `AsyncLocalStorage.enterWith()`, which mutates the current async
 * execution context and every Promise chain spawned from it. Under load this
 * can cause a trace ID from one request to bleed into others sharing the same
 * async parent.
 *
 * Use {@link runWithTraceId} instead:
 *
 * ```ts
 * await runWithTraceId(traceId, async () => {
 *   // everything here is scoped to this traceId only
 * });
 * ```
 *
 * @deprecated Use `runWithTraceId(traceId, fn)` — do not call `setTraceId`
 *             from request-handling code.
 */
export function setTraceId(traceId: string, data?: Record<string, unknown>): void {
  TraceContext.instance.setTraceId(traceId, data);
}

/** Run `fn` inside a new async context carrying `traceId`. */
export function runWithTraceId<T>(traceId: string, fn: () => T, data?: Record<string, unknown>): T {
  return TraceContext.instance.run(traceId, fn, data);
}

// ── Request extraction ────────────────────────────────────────────────────────

/** Shape that extractTraceId accepts (Express-compatible) */
interface RequestLike {
  headers?: Record<string, string | string[] | undefined>;
  query?: Record<string, string | string[] | undefined>;
  body?: Record<string, string | undefined>;
  params?: Record<string, string | undefined>;
}

/**
 * Coerce an arbitrary value to a non-empty trace ID string, or `undefined`.
 * Rejects empty/whitespace-only strings, non-strings, and non-first array elements.
 */
function toValidTraceId(value: unknown): string | undefined {
  const first = Array.isArray(value) ? value[0] : value;
  if (typeof first !== 'string') return undefined;
  const trimmed = first.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/** Extract trace ID from request using configuration (header → query → body → params). */
export function extractTraceId(
  request: unknown,
  config: TraceIdExtractorConfig
): string | undefined {
  const req = request as RequestLike;

  if (config.header) {
    const headers = Array.isArray(config.header) ? config.header : [config.header];
    for (const header of headers) {
      const value = toValidTraceId(req.headers?.[header.toLowerCase()]);
      if (value) return value;
    }
  }

  if (config.query) {
    const queries = Array.isArray(config.query) ? config.query : [config.query];
    for (const query of queries) {
      const value = toValidTraceId(req.query?.[query]);
      if (value) return value;
    }
  }

  if (config.body) {
    const bodyFields = Array.isArray(config.body) ? config.body : [config.body];
    for (const field of bodyFields) {
      const value = toValidTraceId(req.body?.[field]);
      if (value) return value;
    }
  }

  if (config.params) {
    const paramFields = Array.isArray(config.params) ? config.params : [config.params];
    for (const param of paramFields) {
      const value = toValidTraceId(req.params?.[param]);
      if (value) return value;
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
  const defaultExtractor = {
    header: DEFAULT_TRACE_HEADERS,
    query: ['traceId', 'trace_id'],
  };
  const resolvedConfig: TraceIdConfig = {
    ...config,
    extractor: config?.extractor ? { ...defaultExtractor, ...config.extractor } : defaultExtractor,
  };

  _setActiveContextKey(resolvedConfig.contextKey ?? TRACE_CONTEXT_KEY);

  return (req: unknown, res: unknown, next: () => void) => {
    let traceId: string | undefined;

    if (resolvedConfig.extractor) {
      traceId = extractTraceId(req, resolvedConfig.extractor);
    }

    if (!traceId) {
      traceId = resolvedConfig.generator ? resolvedConfig.generator() : generateTraceId();
    }

    (req as Record<string, unknown>).traceId = traceId;
    (res as { setHeader: (k: string, v: string) => void }).setHeader('X-Trace-Id', traceId);

    runWithTraceId(traceId, () => next());
  };
}
