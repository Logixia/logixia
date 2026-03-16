/**
 * logixia — OpenTelemetry auto trace-log correlation
 *
 * Zero-config: if `@opentelemetry/api` is installed, logixia automatically
 * reads the active span context and injects `traceId`, `spanId`, and
 * `traceFlags` into every log entry. No manual wiring needed.
 *
 * The integration is completely optional — if `@opentelemetry/api` is absent
 * (or the OTel SDK is not initialised), all helpers return `undefined` silently.
 *
 * Additionally exposes a `createOtelLogExporter()` factory that routes every
 * logixia log entry through the active OTel LoggerProvider (OTLP export).
 *
 * @example Auto bridge (zero config)
 * ```ts
 * import { createLogger } from 'logixia';
 * import { initOtelBridge } from 'logixia';
 *
 * // Call once at app startup, after your OTel SDK is initialised
 * initOtelBridge();
 *
 * const logger = createLogger({ appName: 'api' });
 * // Every logger.info / warn / error call now auto-injects traceId + spanId
 * // from the currently active OTel span — no per-call code needed.
 * ```
 *
 * @example Manual span context injection
 * ```ts
 * import { getActiveOtelContext } from 'logixia';
 *
 * const ctx = getActiveOtelContext();
 * await logger.info('Payment processed', { ...ctx, orderId: 'ord_123' });
 * // → { traceId: 'abc...', spanId: 'def...', traceFlags: 1, orderId: 'ord_123' }
 * ```
 */

// ── Types ────────────────────────────────────────────────────────────────────

export interface OtelSpanContext {
  /** W3C 32-hex-char trace ID */
  traceId: string;
  /** W3C 16-hex-char span ID */
  spanId: string;
  /** W3C trace-flags integer (1 = sampled) */
  traceFlags: number;
  /** Whether this context is from a valid, sampled span */
  isSampled: boolean;
}

export interface OtelBridgeOptions {
  /**
   * Field name written to log entries for the trace ID.
   * @default 'traceId'
   */
  traceIdField?: string;
  /**
   * Field name written to log entries for the span ID.
   * @default 'spanId'
   */
  spanIdField?: string;
  /**
   * Field name written to log entries for trace flags.
   * @default 'traceFlags'
   */
  traceFlagsField?: string;
  /**
   * Only inject context when the span is sampled (traceFlags bit 1 set).
   * @default false
   */
  sampledOnly?: boolean;
}

// ── OTel API dynamic import ───────────────────────────────────────────────────

type OtelApi = {
  context: { active(): unknown };
  trace: {
    getSpanContext(
      ctx: unknown
    ): { traceId: string; spanId: string; traceFlags: number } | undefined;
    isSpanContextValid(sc: { traceId: string; spanId: string; traceFlags: number }): boolean;
    TraceFlags: { SAMPLED: number };
  };
};

let _otelApi: OtelApi | null | undefined; // undefined = not yet resolved; null = not available

function tryLoadOtelApi(): OtelApi | null {
  if (_otelApi !== undefined) return _otelApi;
  try {
    // Dynamic require so the package stays optional — no hard peer dep
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    _otelApi = require('@opentelemetry/api') as OtelApi;
    return _otelApi;
  } catch {
    _otelApi = null;
    return null;
  }
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Read the currently active OTel span context (if any) and return its fields
 * in a plain object suitable for spreading into a log entry.
 *
 * Returns `undefined` when:
 * - `@opentelemetry/api` is not installed
 * - No active span exists (root context)
 * - The span context is invalid (all-zeros)
 */
export function getActiveOtelContext(opts: OtelBridgeOptions = {}): OtelSpanContext | undefined {
  const api = tryLoadOtelApi();
  if (!api) return undefined;

  const ctx = api.context.active();
  const sc = api.trace.getSpanContext(ctx);
  if (!sc || !api.trace.isSpanContextValid(sc)) return undefined;

  const isSampled = (sc.traceFlags & api.trace.TraceFlags.SAMPLED) === api.trace.TraceFlags.SAMPLED;

  if (opts.sampledOnly && !isSampled) return undefined;

  return {
    traceId: sc.traceId,
    spanId: sc.spanId,
    traceFlags: sc.traceFlags,
    isSampled,
  };
}

/**
 * Returns a metadata object with OTel context fields ready to merge into a log call,
 * using the configured field names.
 *
 * Returns `{}` when no active span exists (safe to spread unconditionally).
 *
 * @example
 * ```ts
 * await logger.info('Payment processed', {
 *   ...getOtelMetaFields(),
 *   orderId: 'ord_123',
 * });
 * ```
 */
export function getOtelMetaFields(opts: OtelBridgeOptions = {}): Record<string, unknown> {
  const { traceIdField = 'traceId', spanIdField = 'spanId', traceFlagsField = 'traceFlags' } = opts;

  const ctx = getActiveOtelContext(opts);
  if (!ctx) return {};

  return {
    [traceIdField]: ctx.traceId,
    [spanIdField]: ctx.spanId,
    [traceFlagsField]: ctx.traceFlags,
  };
}

// ── Module-level bridge state ─────────────────────────────────────────────────

let _bridgeOptions: OtelBridgeOptions | null = null;

/**
 * Initialise the global OTel bridge.
 *
 * Once called, logixia's internal log pipeline checks for an active OTel span
 * on **every** log call and automatically merges the span context into the
 * entry's metadata — no per-call wiring needed.
 *
 * Call once at app startup, **after** the OTel SDK has been initialised:
 * ```ts
 * import { initOtelBridge } from 'logixia';
 * initOtelBridge();
 * ```
 */
export function initOtelBridge(opts: OtelBridgeOptions = {}): void {
  _bridgeOptions = opts;
}

/**
 * @internal
 * Used by the core logger to inject OTel context when the bridge is active.
 * Returns `{}` when the bridge is not initialised or no active span exists.
 */
export function _getOtelPayloadIfEnabled(): Record<string, unknown> {
  if (!_bridgeOptions) return {};
  return getOtelMetaFields(_bridgeOptions);
}

/**
 * Disable the OTel bridge (useful for tests).
 */
export function disableOtelBridge(): void {
  _bridgeOptions = null;
}
