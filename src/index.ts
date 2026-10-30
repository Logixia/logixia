/**
 * Logixia - Advanced TypeScript Logger
 *
 * A comprehensive logging library with support for:
 * - Multiple output formats (console, file, JSON)
 * - Trace ID tracking
 * - Performance monitoring
 * - NestJS integration
 * - Customizable log levels and colors
 * - Intelligent log search and aggregation
 * - Natural language query processing
 * - Pattern recognition and anomaly detection
 */

import { DEFAULT_CONFIG } from './core/default-config';
import { createLogger as createLoggerFromCore, LogixiaLogger } from './core/logitron-logger';

// Type exports
export * from './formatters';
export * from './types';
export type { ITransport, TransportConfig, TransportLogEntry } from './types/transport.types';
export * from './utils/error.utils';
export type { OtelBridgeOptions, OtelSpanContext } from './utils/otel';
export {
  disableOtelBridge,
  getActiveOtelContext,
  getOtelMetaFields,
  initOtelBridge,
} from './utils/otel';
export { applyRedaction, redactObject } from './utils/redact.utils';
export type { LevelSignalOptions, ReconfigurableLogger } from './utils/runtime-control';
export { createLevelControlHandler, registerLevelSignal } from './utils/runtime-control';
export type { SafeStringifyOptions } from './utils/safe-stringify';
export { decycleValue, retrocycle, safeStringify, stringifyForLog } from './utils/safe-stringify';
export * from './utils/shutdown.utils';
export * from './utils/trace.utils';
export type {
  CompiledSchema,
  LogFieldDef,
  LogFieldType,
  LoggerLike,
  LogSchema,
  TypedLogger,
} from './utils/typed-logger';
export { createTypedLogger, defineLogSchema } from './utils/typed-logger';
export type {
  WideEventFields,
  WideEventLogger,
  WideEventMiddlewareOptions,
  WideEventOptions,
} from './wide-events';
export {
  addEventFields,
  getEventFields,
  setEventField,
  wideEventMiddleware,
  withWideEvent,
} from './wide-events';

// OTLP logs export transport (OpenTelemetry-native log emission)
export type { OtlpLogTransportConfig } from './transports/otlp.transport';
export { OtlpLogTransport, toOtelSeverity } from './transports/otlp.transport';

// Chat webhook transports
export type { DiscordEmbed, DiscordTransportConfig } from './transports/discord.transport';
export { DiscordTransport } from './transports/discord.transport';
export type { SlackMessage, SlackTransportConfig } from './transports/slack.transport';
export { SlackTransport } from './transports/slack.transport';

// Search module exports
export * from './search';

// Context propagation (AsyncLocalStorage)
export type { LogContext } from './context/async-context';
export {
  createExpressContextMiddleware,
  createFastifyContextHook,
  LogixiaContext,
} from './context/async-context';

// Sampling stats (SamplingConfig is already exported via ./types)
export type { SamplingStats } from './utils/sampling.utils';

// Plugin API (Feature 20)
export type { LogixiaPlugin } from './plugin';
export { globalPluginRegistry, PluginRegistry, usePlugin } from './plugin';

// Exception system — typed LogixiaException + unified error response format
export type {
  BuildParams,
  ErrorDetail,
  LogixiaErrorResponse,
  LogixiaExceptionOptions,
} from './exceptions';
export {
  ErrorResponseBuilder,
  generateRequestId,
  generateTraceId,
  isLogixiaException,
  LogixiaException,
} from './exceptions';

// Metrics extraction → Prometheus (Feature 21)
export type {
  CounterConfig,
  GaugeConfig,
  HistogramConfig,
  MetricConfig,
  MetricsMap,
} from './metrics';
export type { MetricsPluginOptions } from './metrics';
export { createMetricsPlugin, MetricsPlugin, OVERFLOW_LABEL_VALUE } from './metrics';

// Core exports
export { DEFAULT_CONFIG, LogixiaLogger };

/**
 * Create a new Logixia logger instance with TypeScript support for custom levels
 * @param config - Logger configuration
 * @returns Typed logger instance
 */
export const createLogger = createLoggerFromCore;

/**
 * Default logger instance
 */
export const logger = new LogixiaLogger(DEFAULT_CONFIG);

/**
 * Export default configuration for reference
 */
