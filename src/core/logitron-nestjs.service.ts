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
import { internalError } from '../utils/internal-log';
import { getCurrentTraceId } from '../utils/trace.utils';
import { LogixiaLogger } from './logitron-logger';

@Injectable({ scope: Scope.TRANSIENT })
export class LogixiaLoggerService implements LoggerService {
  private logger: LogixiaLogger;
  private context?: string;

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

    this.logger = new LogixiaLogger({ ...defaultConfig, ...config });
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
    const childService = new LogixiaLoggerService();
    childService.logger = this.logger.child(context, data) as LogixiaLogger;
    childService.context = context;
    return childService;
  }

  // ── Misc ───────────────────────────────────────────────────────────────────

  getCurrentTraceId(): string | undefined {
    return getCurrentTraceId();
  }

  async close(): Promise<void> {
    return this.logger.close();
  }

  static create(config?: LoggerConfig): LogixiaLoggerService {
    return new LogixiaLoggerService(config);
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
