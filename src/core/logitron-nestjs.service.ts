/**
 * NestJS Service integration for Logitron Logger
 */

import type { LoggerService} from "@nestjs/common";
import { Injectable, Scope } from "@nestjs/common";

import type { LoggerConfig , LogLevelString } from "../types";
import { LogLevel } from "../types";
import { internalError } from "../utils/internal-log";
import { getCurrentTraceId } from "../utils/trace.utils";
import { LogixiaLogger } from "./logitron-logger";

@Injectable({ scope: Scope.TRANSIENT })
export class LogixiaLoggerService implements LoggerService {
  private logger: LogixiaLogger;
  private context?: string;

  constructor(config?: LoggerConfig) {
    const defaultConfig: LoggerConfig = {
      appName: "NestJS-App",
      environment: "development",
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
          error: "red",
          warn: "yellow",
          log: "green",
          debug: "blue",
          verbose: "cyan",
        },
      },
      fields: {
        timestamp: "[yyyy-mm-dd HH:MM:ss.MS]",
        level: "[log_level]",
        appName: "[app_name]",
        traceId: "[trace_id]",
        message: "[message]",
        payload: "[payload]",
        timeTaken: "[time_taken_MS]",
      },
    };

    this.logger = new LogixiaLogger({ ...defaultConfig, ...config });
  }

  /**
   * NestJS LoggerService interface implementation
   */
  log(message: unknown, context?: string): void {
    this.setContextIfProvided(context);
    this.logger
      .info(this.formatMessage(message))
      .catch((err: unknown) => internalError("LogixiaLoggerService.log failed", err));
  }

  error(message: unknown, trace?: string, context?: string): void {
    this.setContextIfProvided(context);
    const errorData: Record<string, string> = {};

    if (trace) {
      errorData.stack = trace;
    }

    const logPromise =
      typeof message === "object" && message instanceof Error
        ? this.logger.error(message, errorData)
        : this.logger.error(this.formatMessage(message), errorData);

    logPromise.catch((err: unknown) =>
      internalError("LogixiaLoggerService.error failed", err),
    );
  }

  warn(message: unknown, context?: string): void {
    this.setContextIfProvided(context);
    this.logger
      .warn(this.formatMessage(message))
      .catch((err: unknown) => internalError("LogixiaLoggerService.warn failed", err));
  }

  debug(message: unknown, context?: string): void {
    this.setContextIfProvided(context);
    this.logger
      .debug(this.formatMessage(message))
      .catch((err: unknown) => internalError("LogixiaLoggerService.debug failed", err));
  }

  verbose(message: unknown, context?: string): void {
    this.setContextIfProvided(context);
    this.logger
      .trace(this.formatMessage(message))
      .catch((err: unknown) => internalError("LogixiaLoggerService.verbose failed", err));
  }

  /**
   * Extended Logitron methods
   */
  async info(message: string, data?: Record<string, unknown>): Promise<void> {
    return this.logger.info(message, data);
  }

  async trace(message: string, data?: Record<string, unknown>): Promise<void> {
    return this.logger.trace(message, data);
  }

  logLevel(
    level: string,
    message: string,
    data?: Record<string, unknown>,
  ): Promise<void> {
    return this.logger.logLevel(level, message, data);
  }

  /**
   * Timing methods
   */
  time(label: string): void {
    this.logger.time(label);
  }

  async timeEnd(label: string): Promise<number | undefined> {
    return this.logger.timeEnd(label);
  }

  async timeAsync<T>(label: string, fn: () => Promise<T>): Promise<T> {
    return this.logger.timeAsync(label, fn);
  }

  /**
   * Context and level management
   */
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

  /**
   * Create child logger
   */
  child(context: string, data?: Record<string, unknown>): LogixiaLoggerService {
    const childService = new LogixiaLoggerService();
    childService.logger = this.logger.child(context, data) as LogixiaLogger;
    childService.context = context;
    return childService;
  }

  /**
   * Get current trace ID
   */
  getCurrentTraceId(): string | undefined {
    return getCurrentTraceId();
  }

  /**
   * Close logger
   */
  async close(): Promise<void> {
    return this.logger.close();
  }

  /**
   * Private helper methods
   */
  private setContextIfProvided(context?: string): void {
    if (context && context !== this.context) {
      this.setContext(context);
    }
  }

  private formatMessage(message: unknown): string {
    if (typeof message === "string") {
      return message;
    }

    if (typeof message === "object") {
      return JSON.stringify(message);
    }

    return String(message);
  }

  /**
   * Static factory method for easy instantiation
   */
  static create(config?: LoggerConfig): LogixiaLoggerService {
    return new LogixiaLoggerService(config);
  }

  /**
   * Get the underlying Logitron logger instance
   */
  getLogger(): LogixiaLogger {
    return this.logger;
  }
}
