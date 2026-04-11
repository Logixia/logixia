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
  | 'error'
  | 'warn'
  | 'info'
  | 'debug'
  | 'verbose'
  | 'trace'
  | 'log'
  | 'logLevel';

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
    readonly [K in T extends string
      ? Exclude<T, _ServiceBuiltinLevels>
      : _ExtractCustomLevelNames<T>]: (
      message: string,
      data?: Record<string, unknown>
    ) => Promise<void>;
  };
import { internalError } from '../utils/internal-log';
import { getTraceContextKey, TraceContext } from '../utils/trace.utils';
import { LogixiaLogger } from './logitron-logger';

@Injectable({ scope: Scope.TRANSIENT })
export class LogixiaLoggerService implements LoggerService {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- index signature required for dynamic custom-level methods
  [K: string]: any;

  private logger: LogixiaLogger;
  private context?: string;
  private _mergedConfig: LoggerConfig;

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

    this._mergedConfig = { ...defaultConfig, ...config };
    this.logger = new LogixiaLogger(this._mergedConfig);
    this._createCustomLevelMethods();
  }

  // Dynamically adds a proxy method for every custom level defined in levelOptions.levels
  // so that `service.payment('msg')` works the same as `service.logLevel('payment', 'msg')`.
  private _createCustomLevelMethods(): void {
    const levels = this._mergedConfig.levelOptions?.levels;
    if (!levels) return;
    for (const levelName of Object.keys(levels)) {
      const lower = levelName.toLowerCase();
      // Skip levels that already have a built-in implementation on this class
      if (typeof (this as Record<string, unknown>)[lower] !== 'undefined') continue;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (this as any)[lower] = async (
        message: string,
        data?: Record<string, unknown>
      ): Promise<void> => {
        return this.logger.logLevel(lower, message, data);
      };
    }
  }

  // ── log / info ──────────────────────────────────────────────────────────────

  /**
   * NestJS `LoggerService.log` — void, string context.
   * Maps internally to `info`.
   *
   * @example `logger.log('User signed up', 'AuthService')`
   */
  log(message: unknown, context?: string): void {
    this.setContextIfProvided(context);
    this.logger
      .info(this.formatMessage(message))
      .catch((err: unknown) => internalError('LogixiaLoggerService.log failed', err));
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
   * NestJS compat overload — string trace + optional context, returns `void`.
   *
   * @example `logger.error('Something failed', err.stack, 'AuthService')`
   */
  error(message: unknown, trace?: string, context?: string): void;

  error(
    message: unknown,
    dataOrTrace?: Record<string, unknown> | string,
    context?: string
  ): void | Promise<void> {
    // ── Native path: second arg is a structured-data object ──────────────────
    if (typeof dataOrTrace === 'object' && dataOrTrace !== null) {
      return message instanceof Error
        ? this.logger.error(message, dataOrTrace)
        : this.logger.error(this.formatMessage(message), dataOrTrace);
    }

    // ── NestJS compat path: second arg is trace string or undefined ──────────
    this.setContextIfProvided(context);
    const errorData: Record<string, string> = {};
    if (typeof dataOrTrace === 'string' && dataOrTrace) {
      errorData.stack = dataOrTrace;
    }

    const logPromise =
      message instanceof Error
        ? this.logger.error(message, errorData)
        : this.logger.error(this.formatMessage(message), errorData);

    logPromise.catch((err: unknown) => internalError('LogixiaLoggerService.error failed', err));
  }

  // ── warn ───────────────────────────────────────────────────────────────────

  /**
   * Native async overload — structured metadata, returns `Promise<void>`.
   *
   * @example `await logger.warn('Rate limit approaching', { userId: 'u_abc', count: 90 })`
   */
  warn(message: string, data: Record<string, unknown>): Promise<void>;

  /**
   * NestJS compat overload — optional context string, returns `void`.
   *
   * @example `logger.warn('Deprecated API used', 'PaymentService')`
   */
  warn(message: unknown, context?: string): void;

  warn(message: unknown, dataOrContext?: Record<string, unknown> | string): void | Promise<void> {
    if (typeof dataOrContext === 'object' && dataOrContext !== null) {
      return this.logger.warn(this.formatMessage(message), dataOrContext);
    }
    this.setContextIfProvided(typeof dataOrContext === 'string' ? dataOrContext : undefined);
    this.logger
      .warn(this.formatMessage(message))
      .catch((err: unknown) => internalError('LogixiaLoggerService.warn failed', err));
  }

  // ── debug ──────────────────────────────────────────────────────────────────

  /**
   * Native async overload — structured metadata, returns `Promise<void>`.
   *
   * @example `await logger.debug('Cache miss', { key: 'user:abc', ttl: 300 })`
   */
  debug(message: string, data: Record<string, unknown>): Promise<void>;

  /**
   * NestJS compat overload — optional context string, returns `void`.
   *
   * @example `logger.debug('Processing request', 'OrderService')`
   */
  debug(message: unknown, context?: string): void;

  debug(message: unknown, dataOrContext?: Record<string, unknown> | string): void | Promise<void> {
    if (typeof dataOrContext === 'object' && dataOrContext !== null) {
      return this.logger.debug(this.formatMessage(message), dataOrContext);
    }
    this.setContextIfProvided(typeof dataOrContext === 'string' ? dataOrContext : undefined);
    this.logger
      .debug(this.formatMessage(message))
      .catch((err: unknown) => internalError('LogixiaLoggerService.debug failed', err));
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
   * NestJS compat overload — optional context string, returns `void`.
   *
   * @example `logger.verbose('Connection established', 'WebSocketGateway')`
   */
  verbose(message: unknown, context?: string): void;

  verbose(
    message: unknown,
    dataOrContext?: Record<string, unknown> | string
  ): void | Promise<void> {
    if (typeof dataOrContext === 'object' && dataOrContext !== null) {
      return this.logger.trace(this.formatMessage(message), dataOrContext);
    }
    this.setContextIfProvided(typeof dataOrContext === 'string' ? dataOrContext : undefined);
    this.logger
      .trace(this.formatMessage(message))
      .catch((err: unknown) => internalError('LogixiaLoggerService.verbose failed', err));
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
    this.context = context;
    this.logger.setContext(context);
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

  // ── Child logger ───────────────────────────────────────────────────────────

  child(context: string, data?: Record<string, unknown>): LogixiaLoggerService {
    const childService = new LogixiaLoggerService(this._mergedConfig);
    childService.logger = this.logger.child(context, data) as LogixiaLogger;
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

  private setContextIfProvided(context?: string): void {
    if (context && context !== this.context) {
      this.setContext(context);
    }
  }

  private formatMessage(message: unknown): string {
    if (typeof message === 'string') return message;
    if (typeof message === 'object') return JSON.stringify(message);
    return String(message);
  }
}
