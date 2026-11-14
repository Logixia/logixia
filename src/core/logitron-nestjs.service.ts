/**
 * NestJS Service integration for Logixia Logger
 *
 * Implements NestJS's `LoggerService` interface for framework compat, while
 * simultaneously exposing native async overloads that accept structured data:
 *
 *   // NestJS compat — void, string context
 *   logger.warn('message', 'AuthService');
 *
 *   // Native async — Promise<void>, structured metadata
 *   await logger.warn('message', { userId: 'u_abc', action: 'login' });
 *
 * TypeScript resolves the correct overload automatically based on the type of
 * the second argument:
 *   - second arg is `Record<string, unknown>`  → native path  (returns Promise<void>)
 *   - second arg is `string | undefined`       → NestJS compat (returns void)
 *
 * No wrapper, no casting required on the calling side.
 */

import type { LoggerService } from '@nestjs/common';
import { Injectable, Scope } from '@nestjs/common';

import type { LoggerConfig, LogLevelString } from '../types';
import { LogLevel } from '../types';

// ── Custom-level IntelliSense helpers ─────────────────────────────────────────

/**
 * Level names that already have proper typed implementations on LogixiaLoggerService.
 * These are excluded from the auto-generated method type so we don't produce
 * duplicate / conflicting signatures.
 */
type _ServiceBuiltinLevels =
  'error' | 'warn' | 'info' | 'debug' | 'verbose' | 'trace' | 'log' | 'fatal' | 'logLevel';

/**
 * Mapped type that adds one method per *custom* level (i.e. every key in TLevels
 * that is not already a built-in method on LogixiaLoggerService).
 *
 * @example
 * ServiceCustomLevelMethods<{ kafka: 3; mysql: 4; payment: 5 }>
 * // → { kafka(msg, data?): Promise<void>; mysql(...): …; payment(...): … }
 */
type ServiceCustomLevelMethods<TLevels extends Record<string, number>> = {
  readonly [K in keyof TLevels as K extends _ServiceBuiltinLevels ? never : K & string]: (
    message: string,
    data?: Record<string, unknown>
  ) => Promise<void>;
};

/**
 * The return type of `LogixiaLoggerService.create<T>(config)`.
 *
 * When `T` carries `levelOptions.levels`, this type intersects
 * `LogixiaLoggerService` with a method for every *custom* level so the IDE
 * suggests `service.kafka(...)`, `service.payment(...)`, etc.
 */
export type LogixiaServiceWithLevels<T extends LoggerConfig<Record<string, number>>> =
  T['levelOptions'] extends { levels: infer L }
    ? L extends Record<string, number>
      ? LogixiaLoggerService & ServiceCustomLevelMethods<L>
      : LogixiaLoggerService
    : LogixiaLoggerService;

/**
 * Helper — extracts custom level names from a config object's `levelOptions.levels`.
 */
type _ExtractCustomLevelNames<T> = T extends { levelOptions?: { levels?: infer L } }
  ? L extends Record<string, number>
    ? Exclude<keyof L & string, _ServiceBuiltinLevels>
    : never
  : never;

/**
 * Typed `LogixiaLoggerService` with autocomplete for custom levels.
 *
 * Accepts either:
 *   - **string union** of custom level names: `LogixiaServiceWith<'kafka' | 'payment'>`
 *   - **config object type** (via `typeof`): `LogixiaServiceWith<typeof logixiaConfig>`
 *
 * Define your config with `as const` once, derive the type everywhere:
 *
 * @example
 * ```ts
 * // logger.config.ts — define once
 * export const logixiaConfig = {
 *   levelOptions: {
 *     levels: { error: 0, warn: 1, info: 2, debug: 3, verbose: 4, kafka: 5, payment: 6 },
 *   },
 * } as const;
 * export type AppLogger = LogixiaServiceWith<typeof logixiaConfig>;
 *
 * // any.controller.ts — use everywhere, no casting
 * constructor(private readonly logger: AppLogger) {}
 * // this.logger.kafka('msg')  ← fully typed
 * // this.logger.payment('msg') ← fully typed
 * ```
 *
 * @example
 * ```ts
 * // Or use string union directly:
 * type AppLogger = LogixiaServiceWith<'kafka' | 'payment'>;
 * ```
 */
export type LogixiaServiceWith<T extends string | Record<string, unknown>> =
  LogixiaLoggerService & {
    readonly [
      K in T extends string ? Exclude<T, _ServiceBuiltinLevels> : _ExtractCustomLevelNames<T>
    ]: (message: string, data?: Record<string, unknown>) => Promise<void>;
  };
import { protectSecrets } from '../transports/secret-config';
import { safeToString } from '../utils/coerce.utils';
import { internalError } from '../utils/internal-log';
import { getTraceContextKey, TraceContext } from '../utils/trace.utils';
import { LogixiaLogger } from './logitron-logger';

// A trailing string param is a stack trace only when it looks like one.
const looksLikeStack = (value: string): boolean => value.includes('\n    at ');

// NestJS `LogLevel` names -> logixia levels (`verbose()` logs at `trace`), and logixia levels least to most verbose.
const NEST_LEVEL_TO_LOGIXIA: Record<string, LogLevelString> = {
  fatal: LogLevel.ERROR,
  error: LogLevel.ERROR,
  warn: LogLevel.WARN,
  log: LogLevel.INFO,
  debug: LogLevel.DEBUG,
  verbose: LogLevel.TRACE,
};
const LEVEL_VERBOSITY: readonly string[] = [
  LogLevel.ERROR,
  LogLevel.WARN,
  LogLevel.INFO,
  LogLevel.DEBUG,
  LogLevel.TRACE,
];

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null) return false;
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function describeObject(value: object): string {
  return Array.isArray(value) ? safeToString(value) : `[${value.constructor?.name ?? 'Object'}]`;
}

@Injectable({ scope: Scope.TRANSIENT })
export class LogixiaLoggerService implements LoggerService {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- index signature required for dynamic custom-level methods
  [K: string]: any;

  private logger!: LogixiaLogger;
  private context?: string;
  private _mergedConfig!: LoggerConfig;

  constructor(config?: LoggerConfig) {
    const defaultConfig: LoggerConfig = {
      appName: 'NestJS-App',
      environment: 'development',
      traceId: true,
      format: {
        timestamp: true,
        colorize: true,
        json: false,
      },
      silent: false,
      levelOptions: {
        level: LogLevel.INFO,
        levels: {
          error: 0,
          warn: 1,
          log: 2,
          debug: 3,
          verbose: 4,
        },
        colors: {
          error: 'red',
          warn: 'yellow',
          log: 'green',
          debug: 'blue',
          verbose: 'cyan',
        },
      },
      fields: {
        timestamp: '[yyyy-mm-dd HH:MM:ss.MS]',
        level: '[log_level]',
        appName: '[app_name]',
        traceId: '[trace_id]',
        message: '[message]',
        payload: '[payload]',
        timeTaken: '[time_taken_MS]',
      },
    };

    const mergedConfig = { ...defaultConfig, ...config };
    this._attach(mergedConfig, new LogixiaLogger(mergedConfig));
  }

  // Shared by the constructor and child(): wraps `logger` without building a root of its own.
  private _attach(mergedConfig: LoggerConfig, logger: LogixiaLogger): void {
    protectSecrets(this, ['_mergedConfig']);
    this._mergedConfig = mergedConfig;
    this.logger = logger;
    this._createCustomLevelMethods();
  }

  // Dynamically adds a proxy method for every custom level defined in levelOptions.levels
  // so that `service.payment('msg')` works the same as `service.logLevel('payment', 'msg')`.
  private _createCustomLevelMethods(): void {
    const levels = this._mergedConfig.levelOptions?.levels;
    if (!levels) return;
    const self = this as Record<string, unknown>;
    const define = (method: string, levelName: string): void => {
      // Skip levels that already have a built-in implementation on this class
      if (typeof self[method] !== 'undefined') return;
      self[method] = async (message: string, data?: Record<string, unknown>): Promise<void> =>
        this.logger.logLevel(levelName, message, data);
    };
    const names = Object.keys(levels);
    // Exact names first, so a lowercase alias never takes the slot of a level that is really named that.
    for (const levelName of names) define(levelName, levelName);
    // Lowercase alias kept for callers that used it; it logs at the exact level.
    for (const levelName of names) define(levelName.toLowerCase(), levelName);
  }

  // ── log / info ──────────────────────────────────────────────────────────────

  /**
   * NestJS `LoggerService.log` — void. Maps internally to `info`.
   * A trailing string is the context for this call only; object params are merged into the payload.
   *
   * @example `logger.log('User signed up', 'AuthService')`
   * @example `logger.log('User signed up', { userId: 'u_abc' }, 'AuthService')`
   */
  log(message: unknown, ...optionalParams: unknown[]): void {
    const { context, data } = this.parseParams(optionalParams);
    this.reportFailure(
      'log',
      this.withContext(context, () => this.logger.info(this.formatMessage(message), data))
    );
  }

  /**
   * Native async `info` — structured data, returns `Promise<void>`.
   *
   * @example `await logger.info('User signed up', { userId: 'u_abc' })`
   */
  async info(message: string, data?: Record<string, unknown>): Promise<void> {
    return this.logger.info(message, data);
  }

  // ── error ──────────────────────────────────────────────────────────────────

  /**
   * Native async overload — structured metadata, returns `Promise<void>`.
   *
   * @example `await logger.error(new Error('DB timeout'), { requestId: 'req_abc' })`
   * @example `await logger.error('Login failed', { userId: 'u_abc' })`
   */
  error(message: string | Error, data: Record<string, unknown>): Promise<void>;

  /**
   * NestJS compat overload — optional stack trace, then an optional context
   * that applies to this call only, returns `void`.
   *
   * @example `logger.error('Something failed', err.stack, 'AuthService')`
   */
  error(message: unknown, ...optionalParams: unknown[]): void;

  error(message: unknown, ...optionalParams: unknown[]): void | Promise<void> {
    // ── Native path: a single structured-data object ─────────────────────────
    const only = optionalParams[0];
    if (optionalParams.length === 1 && typeof only === 'object' && only !== null) {
      const data = only as Record<string, unknown>;
      return message instanceof Error
        ? this.logger.error(message, data)
        : this.logger.error(this.formatMessage(message), data);
    }

    // ── NestJS compat path ───────────────────────────────────────────────────
    const { context, data } = this.parseParams(optionalParams, true);
    this.reportFailure(
      'error',
      this.withContext(context, () =>
        message instanceof Error
          ? this.logger.error(message, data)
          : this.logger.error(this.formatMessage(message), data)
      )
    );
  }

  // ── fatal ──────────────────────────────────────────────────────────────────

  /**
   * NestJS `LoggerService.fatal`. logixia has no level above `error`, so this logs
   * at `error` with `fatal: true` in the payload, or at a custom `fatal` level when
   * one is configured.
   *
   * @example `logger.fatal('Cannot reach the database, shutting down', 'Bootstrap')`
   */
  fatal(message: unknown, ...optionalParams: unknown[]): void {
    const { context, data } = this.parseParams(optionalParams, true);
    const text = this.formatMessage(message);
    const hasFatalLevel = this._mergedConfig.levelOptions?.levels?.['fatal'] !== undefined;
    this.reportFailure(
      'fatal',
      this.withContext(context, () =>
        hasFatalLevel
          ? this.logger.logLevel('fatal', text, data)
          : this.logger.error(text, { ...data, fatal: true })
      )
    );
  }

  // ── warn ───────────────────────────────────────────────────────────────────

  /**
   * Native async overload — structured metadata, returns `Promise<void>`.
   *
   * @example `await logger.warn('Rate limit approaching', { userId: 'u_abc', count: 90 })`
   */
  warn(message: string, data: Record<string, unknown>): Promise<void>;

  /**
   * NestJS compat overload — optional context for this call only, plus object
   * params merged into the payload, returns `void`.
   *
   * @example `logger.warn('Deprecated API used', 'PaymentService')`
   */
  warn(message: unknown, ...optionalParams: unknown[]): void;

  warn(message: unknown, ...optionalParams: unknown[]): void | Promise<void> {
    const only = optionalParams[0];
    if (optionalParams.length === 1 && typeof only === 'object' && only !== null) {
      return this.logger.warn(this.formatMessage(message), only as Record<string, unknown>);
    }
    const { context, data } = this.parseParams(optionalParams);
    this.reportFailure(
      'warn',
      this.withContext(context, () => this.logger.warn(this.formatMessage(message), data))
    );
  }

  // ── debug ──────────────────────────────────────────────────────────────────

  /**
   * Native async overload — structured metadata, returns `Promise<void>`.
   *
   * @example `await logger.debug('Cache miss', { key: 'user:abc', ttl: 300 })`
   */
  debug(message: string, data: Record<string, unknown>): Promise<void>;

  /**
   * NestJS compat overload — optional context for this call only, plus object
   * params merged into the payload, returns `void`.
   *
   * @example `logger.debug('Processing request', 'OrderService')`
   */
  debug(message: unknown, ...optionalParams: unknown[]): void;

  debug(message: unknown, ...optionalParams: unknown[]): void | Promise<void> {
    const only = optionalParams[0];
    if (optionalParams.length === 1 && typeof only === 'object' && only !== null) {
      return this.logger.debug(this.formatMessage(message), only as Record<string, unknown>);
    }
    const { context, data } = this.parseParams(optionalParams);
    this.reportFailure(
      'debug',
      this.withContext(context, () => this.logger.debug(this.formatMessage(message), data))
    );
  }

  // ── verbose ────────────────────────────────────────────────────────────────

  /**
   * Native async overload — structured metadata, returns `Promise<void>`.
   * Maps to `trace` level internally.
   *
   * @example `await logger.verbose('Socket message received', { event: 'ping', size: 42 })`
   */
  verbose(message: string, data: Record<string, unknown>): Promise<void>;

  /**
   * NestJS compat overload — optional context for this call only, plus object
   * params merged into the payload, returns `void`.
   *
   * @example `logger.verbose('Connection established', 'WebSocketGateway')`
   */
  verbose(message: unknown, ...optionalParams: unknown[]): void;

  verbose(message: unknown, ...optionalParams: unknown[]): void | Promise<void> {
    const only = optionalParams[0];
    if (optionalParams.length === 1 && typeof only === 'object' && only !== null) {
      return this.logger.trace(this.formatMessage(message), only as Record<string, unknown>);
    }
    const { context, data } = this.parseParams(optionalParams);
    this.reportFailure(
      'verbose',
      this.withContext(context, () => this.logger.trace(this.formatMessage(message), data))
    );
  }

  // ── trace / logLevel ───────────────────────────────────────────────────────

  /**
   * Native async `trace` — lowest verbosity level, structured data.
   */
  async trace(message: string, data?: Record<string, unknown>): Promise<void> {
    return this.logger.trace(message, data);
  }

  /**
   * Log at any named level with structured data.
   */
  logLevel(level: string, message: string, data?: Record<string, unknown>): Promise<void> {
    return this.logger.logLevel(level, message, data);
  }

  // ── Timing ─────────────────────────────────────────────────────────────────

  time(label: string): void {
    this.logger.time(label);
  }

  async timeEnd(label: string): Promise<number | undefined> {
    return this.logger.timeEnd(label);
  }

  async timeAsync<T>(label: string, fn: () => Promise<T>): Promise<T> {
    return this.logger.timeAsync(label, fn);
  }

  // ── Context / level management ─────────────────────────────────────────────

  setContext(context: string): void {
    const coerced = typeof context === 'string' ? context : safeToString(context);
    this.context = coerced;
    this.logger.setContext(coerced);
  }

  getContext(): string | undefined {
    return this.context;
  }

  setLevel(level: LogLevelString): void {
    this.logger.setLevel(level);
  }

  getLevel(): LogLevelString {
    return this.logger.getLevel();
  }

  /**
   * NestJS `LoggerService.setLogLevels`. logixia filters by a minimum level, not a
   * set, so the most verbose of `levels` becomes the threshold and everything more
   * severe stays on (`['log', 'error']` also enables `warn`). Unknown names are
   * ignored, and an empty list is ignored too: use `silent` to turn logging off.
   *
   * @example `logger.setLogLevels(['error', 'warn'])`
   */
  setLogLevels(levels: readonly string[]): void {
    let threshold: LogLevelString | undefined;
    let verbosity = -1;
    for (const name of levels) {
      const level = NEST_LEVEL_TO_LOGIXIA[name];
      const rank = level === undefined ? -1 : LEVEL_VERBOSITY.indexOf(level);
      if (rank > verbosity) {
        verbosity = rank;
        threshold = level;
      }
    }
    if (threshold !== undefined) this.setLevel(threshold);
  }

  // ── Child logger ───────────────────────────────────────────────────────────

  child(context: string, data?: Record<string, unknown>): LogixiaLoggerService {
    // Wrap the core child directly: running the constructor would build a second
    // root logger with its own transports, timers and shutdown registration.
    const childService = Object.create(LogixiaLoggerService.prototype) as LogixiaLoggerService;
    childService._attach(this._mergedConfig, this.logger.child(context, data) as LogixiaLogger);
    childService.context = context;
    return childService;
  }

  // ── Misc ───────────────────────────────────────────────────────────────────

  getCurrentTraceId(): string | undefined {
    return TraceContext.instance.getCurrentTraceId();
  }

  /** Returns the AsyncLocalStorage key currently used to store the trace ID. */
  get traceContextKey(): string {
    return getTraceContextKey();
  }

  async close(): Promise<void> {
    return this.logger.close();
  }

  static create<T extends LoggerConfig<Record<string, number>>>(
    config?: T
  ): LogixiaServiceWithLevels<T> {
    return new LogixiaLoggerService(config) as unknown as LogixiaServiceWithLevels<T>;
  }

  getLogger(): LogixiaLogger {
    return this.logger;
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  // Runs `fn` with `context` as the logger's context, then restores it. The log call builds its
  // entry synchronously, so the swap is invisible to other calls and instance state is untouched.
  private withContext<T>(context: string | undefined, fn: () => T): T {
    if (context === undefined || context === this.logger.getContext()) return fn();
    const previous = this.logger.getContext() ?? '';
    this.logger.setContext(context);
    try {
      return fn();
    } finally {
      this.logger.setContext(previous);
    }
  }

  /**
   * Split NestJS `...optionalParams` into a per-call context and a payload.
   * A trailing string is the context; plain objects are merged into the payload and
   * an Error goes under `error`. For `error()` (`withStack`), a leading string is the stack
   * trace, and a lone string is the stack only if it looks like one, since Nest's own
   * `Logger` appends the context as the last param. Anything else is listed under `params`.
   */
  private parseParams(
    params: unknown[],
    withStack = false
  ): { context?: string | undefined; data?: Record<string, unknown> | undefined } {
    if (params.length === 0) return {};
    let rest = params;
    let context: string | undefined;
    const last = params[params.length - 1];
    if (typeof last === 'string' && !(withStack && params.length === 1 && looksLikeStack(last))) {
      // NestJS also passes non-string values (ExecutionContext etc.) in this slot; those
      // are not strings and fall through to the payload handling below.
      context = last.length > 0 ? last : undefined;
      rest = params.slice(0, -1);
    }
    let data: Record<string, unknown> | undefined;
    const extras: unknown[] = [];
    for (const param of rest) {
      if (withStack && typeof param === 'string' && data?.['stack'] === undefined) {
        data = { ...data, stack: param };
      } else if (param instanceof Error) {
        data = { ...data, error: param };
      } else if (isPlainObject(param)) {
        data = { ...data, ...param };
      } else if (param !== undefined) {
        extras.push(typeof param === 'object' && param !== null ? describeObject(param) : param);
      }
    }
    if (extras.length > 0) data = { ...data, params: extras };
    return context === undefined ? { data } : { context, data };
  }

  private reportFailure(method: string, result: Promise<void>): void {
    result.catch((err: unknown) => internalError(`LogixiaLoggerService.${method} failed`, err));
  }

  private formatMessage(message: unknown): string {
    if (typeof message === 'string') return message;
    // The core logger redacts an object message by key and path before turning it
    // into a string. Stringifying here first would leave it only the patterns.
    if (message !== null && typeof message === 'object') return message as unknown as string;
    // Use safeToString rather than raw JSON.stringify: NestJS passes arbitrary
    // values here, and JSON.stringify both THROWS on circular structures (which
    // would crash the log call) and RETURNS undefined for some inputs (e.g. a
    // toJSON returning undefined). safeToString handles both safely.
    return safeToString(message);
  }
}
