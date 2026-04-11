/**
 * Core type definitions for Logitron Logger
 */

import type { HttpRequest, HttpResponse } from './http.types';
import type { TransportConfig } from './transport.types';

// Log levels const object for better flexibility
export const LogLevel = {
  ERROR: 'error',
  WARN: 'warn',
  INFO: 'info',
  DEBUG: 'debug',
  TRACE: 'trace',
  VERBOSE: 'verbose',
} as const;

export type LogLevel = (typeof LogLevel)[keyof typeof LogLevel];
export type LogLevelString = LogLevel | (string & {});

// Predefined color types
export type LogColor =
  | 'black'
  | 'red'
  | 'green'
  | 'yellow'
  | 'blue'
  | 'magenta'
  | 'cyan'
  | 'white'
  | 'gray'
  | 'grey'
  | 'brightRed'
  | 'brightGreen'
  | 'brightYellow'
  | 'brightBlue'
  | 'brightMagenta'
  | 'brightCyan'
  | 'brightWhite';

// Predefined field keys that can be enabled/disabled
export type LogFieldKey =
  | 'timestamp'
  | 'level'
  | 'appName'
  | 'service'
  | 'traceId'
  | 'message'
  | 'payload'
  | 'timeTaken'
  | 'context'
  | 'userId'
  | 'sessionId'
  | 'environment';

// Environment types
export type Environment = 'development' | 'production';

// Trace ID configuration
export interface TraceIdExtractorConfig {
  header?: string | string[];
  query?: string | string[];
  body?: string | string[];
  params?: string | string[];
}

export interface TraceIdConfig {
  enabled: boolean;
  generator?: () => string;
  contextKey?: string;
  extractor?: TraceIdExtractorConfig;
  /**
   * Name of the response header the middleware writes the resolved traceId
   * into (and that the exception filter echoes back on error responses).
   *
   * Defaults to `'X-Trace-Id'`. Set to `false` to suppress the response
   * header entirely (useful when the caller already supplies one and you
   * don't want to echo it back).
   *
   * @default 'X-Trace-Id'
   */
  responseHeader?: string | false;
}

// ── Redaction ──────────────────────────────────────────────────────────────────
export interface RedactConfig {
  /**
   * Dot-notation field paths to redact. Supports `*` (one segment) and `**` (any depth).
   * @example `['req.headers.authorization', '*.password', 'user.creditCard']`
   */
  paths?: string[];
  /**
   * Regex patterns applied to string values — replaces matches with the censor string.
   * @example `[/Bearer\s+\S+/gi, /sk-[a-z0-9]{32,}/gi]`
   */
  patterns?: RegExp[];
  /** Replacement value for redacted content. Default: `"[REDACTED]"` */
  censor?: string;
  /**
   * Auto-detect and redact common PII and secret patterns without manual configuration.
   *
   * - `true` / `'conservative'` — JWT tokens, Bearer/API-key strings, common secret field names
   *   (`password`, `token`, `secret`, `apiKey`, `authorization`, `credentials`)
   * - `'aggressive'` — everything above **plus** email addresses, credit-card numbers,
   *   US SSNs, phone numbers, and IP addresses
   *
   * Auto-detected patterns are applied **in addition to** any explicit `paths` / `patterns`.
   *
   * @example
   * ```ts
   * const logger = createLogger({ redact: { autoDetect: 'aggressive' } });
   * await logger.info('user signed up', { email: 'alice@example.com', password: 'hunter2' });
   * // → email: '[REDACTED]', password: '[REDACTED]'
   * ```
   */
  autoDetect?: boolean | 'conservative' | 'aggressive';
}

// ── Log Sampling ───────────────────────────────────────────────────────────────
/**
 * Built-in log sampling / rate limiting.
 *
 * @example
 * ```ts
 * sampling: {
 *   rate: 0.1,                       // log 10% of all entries
 *   perLevel: { debug: 0.01 },       // override: debug at 1%
 *   maxLogsPerSecond: 500,           // hard cap — extras dropped
 *   traceConsistent: true,           // if a traceId is sampled, keep all logs for that trace
 * }
 * ```
 */
export interface SamplingConfig {
  /**
   * Global sample rate for all log levels: 0.0 (drop all) → 1.0 (keep all).
   * Default: 1.0 (no sampling).
   */
  rate?: number;
  /**
   * Per-level rate overrides. Unmentioned levels fall back to `rate`.
   * ERROR and WARN default to 1.0 even when a lower global rate is set,
   * unless you explicitly override them here.
   * @example `{ debug: 0.05, info: 0.5 }`
   */
  perLevel?: Partial<Record<string, number>>;
  /**
   * Hard cap on logs emitted per second across all levels.
   * Excess entries are silently dropped and counted in the sampling stats.
   * Default: unlimited.
   */
  maxLogsPerSecond?: number;
  /**
   * When true, all log entries sharing a traceId are either all kept or all
   * dropped — preventing a sampled trace from having missing log entries.
   * Default: false.
   */
  traceConsistent?: boolean;
  /**
   * Emit a periodic sampling stats entry at this interval (ms).
   * Stats include: sampled, dropped, and rate per level over the window.
   * Set to 0 to disable. Default: 60_000 (60 s).
   */
  statsIntervalMs?: number;
}

// ── Namespace Levels ───────────────────────────────────────────────────────────
/**
 * Per-namespace log level overrides.
 * Keys are namespace patterns (dot-separated, `*` wildcard); values are log levels.
 *
 * @example
 * ```ts
 * namespaceLevels: {
 *   'db.*':    'debug',   // all db.* namespaces → DEBUG
 *   'http.*':  'warn',    // all http.* → WARN only
 *   'payment': 'trace',   // payment namespace → TRACE
 * }
 * ```
 * ENV overrides: `LOGIXIA_LEVEL_DB=debug` maps to namespace `db`.
 */
export type NamespaceLevels = Record<string, LogLevelString>;

// ── Graceful Shutdown ──────────────────────────────────────────────────────────
export interface GracefulShutdownConfig {
  /** Auto-register SIGTERM/SIGINT handlers to flush this logger on exit. Default: false */
  enabled: boolean;
  /** Max ms to wait for transports to flush. Default: 5000 */
  timeout?: number;
  /** Signals to listen on. Default: ['SIGTERM', 'SIGINT'] */
  signals?: NodeJS.Signals[];
}

export interface LoggerConfig<TLevels extends Record<string, number> = Record<string, number>> {
  appName?: string;
  environment?: Environment;
  traceId?: boolean | TraceIdConfig;
  format?: {
    timestamp?: boolean;
    colorize?: boolean;
    json?: boolean;
  };
  silent?: boolean;
  levelOptions?:
    | {
        level?: keyof TLevels | LogLevelString;
        levels?: TLevels;
        colors?: Partial<Record<keyof TLevels | LogLevel, LogColor>>;
      }
    | undefined;
  fields?: Partial<Record<LogFieldKey, string | boolean>>;
  /**
   * Built-in log redaction — masks sensitive fields before they reach any transport.
   * @see RedactConfig
   */
  redact?: RedactConfig;
  /**
   * Per-namespace log level overrides.
   * A child logger's context is used as its namespace for matching.
   * ENV vars `LOGIXIA_LEVEL_<NS>=<level>` also apply.
   */
  namespaceLevels?: NamespaceLevels;
  /**
   * Automatically register SIGTERM/SIGINT handlers that flush all transports
   * before the process exits — prevents losing the last N seconds of logs on
   * deployments / restarts.
   */
  gracefulShutdown?: boolean | GracefulShutdownConfig;
  /**
   * Built-in log sampling & rate limiting.
   * Completely missing from all existing loggers — eliminates the need to
   * implement sampling logic in application code.
   */
  sampling?: SamplingConfig;
  /** Transport configuration — console, file, database, analytics, etc. */
  transports?: TransportConfig;
  [key: string]: unknown;
}

// Base logger interface with standard methods
export interface IBaseLogger {
  error(message: string, data?: Record<string, unknown>): Promise<void>;
  error(error: Error, data?: Record<string, unknown>): Promise<void>;
  warn(message: string, data?: Record<string, unknown>): Promise<void>;
  info(message: string, data?: Record<string, unknown>): Promise<void>;
  debug(message: string, data?: Record<string, unknown>): Promise<void>;
  trace(message: string, data?: Record<string, unknown>): Promise<void>;
  verbose(message: string, data?: Record<string, unknown>): Promise<void>;
  logLevel(level: string, message: string, data?: Record<string, unknown>): Promise<void>;

  time(label: string): void;
  timeEnd(label: string): Promise<number | undefined>;
  timeAsync<T>(label: string, fn: () => Promise<T>): Promise<T>;

  setLevel(level: LogLevel | string): void;
  getLevel(): string;
  setContext(context: string): void;
  getContext(): string | undefined;

  // Field Management Methods
  enableField(fieldName: string): void;
  disableField(fieldName: string): void;
  isFieldEnabled(fieldName: string): boolean;
  getFieldState(): Record<string, boolean>;
  resetFieldState(): void;

  // Transport Level Management Methods
  enableTransportLevelPrompting(): void;
  disableTransportLevelPrompting(): void;
  setTransportLevels(transportId: string, levels: string[]): void;
  getTransportLevels(transportId: string): string[] | undefined;
  clearTransportLevelPreferences(): void;
  getAvailableTransports(): string[];

  child(context: string, data?: Record<string, unknown>): ILogger;
  close(): Promise<void>;

  // Plugin API (Feature 20)
  // Typed as unknown to avoid a circular import between types/index.ts and plugin.ts.
  // The concrete LogixiaLogger class constrains this to LogixiaPlugin.
  use(plugin: { name: string }): this;
  unuse(pluginName: string): this;
}

// Type for custom level methods based on config
export type CustomLevelMethods<T extends Record<string, number>> = {
  [K in keyof T]: (message: string, data?: Record<string, unknown>) => Promise<void>;
};

// Generic logger type that combines base logger with custom level methods
// eslint-disable-next-line @typescript-eslint/no-empty-object-type -- empty default is intentional for optional generic
export type ILogger<TLevels extends Record<string, number> = {}> = IBaseLogger &
  CustomLevelMethods<TLevels>;

// Default logger interface for backward compatibility
// eslint-disable-next-line @typescript-eslint/no-empty-object-type -- marker interface for backward compat
export interface ILoggerDefault extends IBaseLogger {}

// Helper type to create logger with specific custom levels
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- generic type needs any to accept all LoggerConfig shapes
export type LoggerWithLevels<T extends LoggerConfig<any>> = T['levelOptions'] extends {
  levels: infer L;
}
  ? L extends Record<string, number>
    ? ILogger<L>
    : ILoggerDefault
  : ILoggerDefault;

// Helper type to extract levels from config for IntelliSense
export type ExtractLevels<T> = T extends LoggerConfig<infer L> ? L : Record<string, number>;

// Log entry interface
export interface LogEntry {
  timestamp: string;
  level: string;
  appName: string;
  environment?: string;
  traceId?: string;
  message: string;
  payload?: Record<string, unknown>;
  context?: string;
  error?: Error;
}

// Error serialization options
export interface ErrorSerializationOptions {
  includeStack?: boolean;
  maxDepth?: number;
  excludeFields?: string[];
}

// Timing entry interface
export interface TimingEntry {
  label: string;
  startTime: number;
  endTime?: number;
  duration?: number;
}

// Context data interface
export interface ContextData {
  [key: string]: unknown;
}

// Log formatter interface
export interface ILogFormatter {
  format(entry: LogEntry): string;
}

// Request context interface for tracking request lifecycle
export interface RequestContext {
  traceId: string;
  startTime: number;
  endTime?: number;
  duration?: number;
  request: HttpRequest;
  response?: HttpResponse;
  error?: Error;
  userId?: string;
  sessionId?: string;
  userAgent?: string;
  ip?: string;
}

// Default log levels with colors
export const DEFAULT_LOG_LEVELS = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3,
  trace: 4,
  verbose: 5,
};

export const DEFAULT_LOG_COLORS = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  debug: 'blue',
  trace: 'magenta',
  verbose: 'cyan',
};

// Additional exports for compatibility
export type { LoggerConfig as LoggerConfigInterface };

// Export all HTTP types
export * from './http.types';
