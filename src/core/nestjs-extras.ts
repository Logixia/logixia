/**
 * logixia — NestJS extras: @InjectLogger, @LogMethod, LogixiaExceptionFilter
 *
 * Completes the NestJS deep integration story:
 *   - @InjectLogger() — inject the logger via NestJS DI without typing LOGIXIA_TOKEN manually
 *   - @LogMethod()    — auto-log method entry / exit with args and return value
 *   - LogixiaExceptionFilter — catch-all exception filter that logs unhandled errors
 *                              with full request context before re-throwing
 *
 * @example Full setup
 * ```ts
 * // app.module.ts
 * import { LogixiaModule } from 'logixia';
 * @Module({ imports: [LogixiaModule.forRoot({ appName: 'api' })] })
 * export class AppModule {}
 *
 * // order.service.ts
 * import { Injectable } from '@nestjs/common';
 * import { InjectLogger, LogMethod, LogixiaLoggerService } from 'logixia';
 *
 * @Injectable()
 * export class OrderService {
 *   constructor(@InjectLogger() private readonly logger: LogixiaLoggerService) {}
 *
 *   @LogMethod()
 *   async createOrder(dto: CreateOrderDto) { … }
 * }
 *
 * // main.ts
 * import { LogixiaExceptionFilter } from 'logixia';
 * app.useGlobalFilters(new LogixiaExceptionFilter(logger));
 * ```
 */

import type { ArgumentsHost, ExceptionFilter } from '@nestjs/common';
import { Catch, Inject, Optional } from '@nestjs/common';

import { ErrorResponseBuilder } from '../exceptions/builder';
import { isLogixiaException } from '../exceptions/exception';
import type { LoggerConfig, LogLevelString, TraceIdConfig } from '../types';
import { TraceContext } from '../utils/trace.utils';
import {
  LOGIXIA_LOGGER_CONFIG,
  LOGIXIA_LOGGER_PREFIX,
  LogixiaLoggerModule,
} from './logitron-logger.module';
import type { LogixiaLoggerService } from './logitron-nestjs.service';
import { resolveResponseHeader } from './trace.middleware';

// ── @InjectLogger() ──────────────────────────────────────────────────────────

/**
 * Inject the Logixia logger registered in the current NestJS DI container.
 *
 * Equivalent to `@Inject(LOGIXIA_LOGGER_TOKEN)` but without needing to import
 * the internal token constant yourself.
 *
 * @example
 * ```ts
 * constructor(@InjectLogger() private readonly logger: LogixiaLoggerService) {}
 * ```
 */
export const InjectLogger = (): ParameterDecorator => Inject(`${LOGIXIA_LOGGER_PREFIX}SERVICE`);

// ── @LogMethod() ─────────────────────────────────────────────────────────────

export interface LogMethodOptions {
  /**
   * Log level to use for entry / exit messages.
   * @default 'debug'
   */
  level?: LogLevelString;
  /**
   * Whether to log the arguments passed to the method.
   * Disable for high-throughput hot paths.
   * @default true
   */
  logArgs?: boolean;
  /**
   * Whether to log the return value of the method.
   * @default false
   */
  logResult?: boolean;
  /**
   * Whether to log error stack traces for thrown errors.
   * @default true
   */
  logErrors?: boolean;
  /**
   * Custom label used in log messages instead of the auto-detected class.method name.
   */
  label?: string;
}

/**
 * Method decorator that auto-logs entry, exit, duration, and errors.
 *
 * Works on both async and sync methods. Attaches to the logger found on the
 * class instance via a `logger` property (the conventional NestJS name).
 *
 * @example
 * ```ts
 * @LogMethod({ level: 'info', logArgs: true })
 * async processPayment(orderId: string): Promise<void> { … }
 * ```
 */
export function LogMethod(options: LogMethodOptions = {}): MethodDecorator {
  const { level = 'debug', logArgs = true, logResult = false, logErrors = true } = options;

  // Use PropertyDescriptor (not generic TypedPropertyDescriptor<T>) to avoid
  // strict generic inference issues with exactOptionalPropertyTypes.
  return function (
    target: object,
    propertyKey: string | symbol,
    descriptor: PropertyDescriptor
  ): PropertyDescriptor {
    const originalMethod = descriptor.value as ((...args: unknown[]) => unknown) | undefined;
    if (typeof originalMethod !== 'function') return descriptor;

    const methodName = String(propertyKey);
    const className =
      (target as { constructor?: { name?: string } }).constructor?.name ?? 'Unknown';
    const label = options.label ?? `${className}.${methodName}`;

    let _warnedNoLogger = false;

    descriptor.value = async function (
      this: { logger?: LogixiaLoggerService },
      ...args: unknown[]
    ) {
      // Prefer the instance's own logger; fall back to the global module logger.
      const logger: LogixiaLoggerService | undefined =
        this.logger ?? LogixiaLoggerModule._globalLogger ?? undefined;

      if (!logger && !_warnedNoLogger) {
        _warnedNoLogger = true;
        // eslint-disable-next-line no-console
        console.warn(
          `[logixia] @LogMethod on ${label}: no logger available. ` +
            `Either inject LogixiaLoggerService as this.logger or ensure LogixiaLoggerModule is initialised.`
        );
      }

      const start = Date.now();

      const entry: Record<string, unknown> = { method: label };
      if (logArgs && args.length > 0) {
        entry['args'] = args;
      }

      // Surface logger failures on stderr instead of silently swallowing them —
      // a broken transport is an operator problem that must be observable.
      // Uses a flat 2-arg helper (avoids curried `(phase) => (err) =>` nesting
      // which trips the sonarjs no-nested-functions depth rule).
      const reportLogFailure = (phase: string, err: unknown): void => {
        process.stderr.write(
          `[logixia] @LogMethod(${label}) ${phase} log failed: ${String(err)}\n`
        );
      };

      if (logger) {
        // Use logLevel (extended method) rather than the NestJS interface debug/info
        // which only accepts (message: unknown, context?: string)
        const logFnRaw = (
          logger as unknown as Record<
            string,
            (msg: string, data?: Record<string, unknown>) => Promise<void>
          >
        )[level];
        const logFn = (typeof logFnRaw === 'function' ? logFnRaw : logger.debug).bind(logger);
        const entryPromise = (
          logFn as (msg: string, data?: Record<string, unknown>) => Promise<void>
        )(`→ ${label}`, entry);
        await entryPromise.catch((e: unknown) => reportLogFailure('entry', e));
      }

      try {
        const result = await (originalMethod.apply(this, args) as Promise<unknown>);

        const exit: Record<string, unknown> = {
          method: label,
          durationMs: Date.now() - start,
        };
        if (logResult) exit['result'] = result;

        if (logger) {
          const logFnRaw = (
            logger as unknown as Record<
              string,
              (msg: string, data?: Record<string, unknown>) => Promise<void>
            >
          )[level];
          const logFn = (typeof logFnRaw === 'function' ? logFnRaw : logger.debug).bind(logger);
          const exitPromise = (
            logFn as (msg: string, data?: Record<string, unknown>) => Promise<void>
          )(`← ${label}`, exit);
          await exitPromise.catch((e: unknown) => reportLogFailure('exit', e));
        }

        return result;
      } catch (error) {
        if (logger && logErrors) {
          const err = error instanceof Error ? error : new Error(String(error));
          // Use the structured overload (Record<string, unknown>) so we get
          // Promise<void> back and can attach a stderr fallback for transport
          // failures — otherwise they'd become unhandled rejections.
          const errLog: unknown = logger.error(err, {
            method: label,
            durationMs: Date.now() - start,
          });
          if (
            errLog !== undefined &&
            errLog !== null &&
            typeof (errLog as Promise<void>).catch === 'function'
          ) {
            (errLog as Promise<void>).catch((e: unknown) => reportLogFailure('error', e));
          }
        }
        throw error;
      }
    };

    return descriptor;
  };
}

// ── LogixiaExceptionFilter ───────────────────────────────────────────────────

/**
 * Global NestJS exception filter that converts any exception into the standard
 * `LogixiaErrorResponse` wire format and logs it with full request context.
 *
 * Handles three exception types in priority order:
 *  1. `LogixiaException`     — typed fields used directly
 *  2. NestJS `HttpException` — status + message extracted
 *  3. Unknown / plain Error  — falls back to 500 `server_error`
 *
 * **Debug stripping in production:**
 * The `debug` block is automatically stripped when `NODE_ENV === 'production'`.
 *
 * **Trace ID headers:**
 * `X-Trace-ID` and `X-Request-ID` are echoed back on every error response so
 * clients can correlate with server logs.
 *
 * **Retry-After header:**
 * Automatically added for `429` responses (`Retry-After: 60`).
 *
 * Register in `main.ts`:
 * ```ts
 * const logger = app.get(LogixiaLoggerService);
 * app.useGlobalFilters(new LogixiaExceptionFilter(logger));
 * ```
 */
@Catch()
export class LogixiaExceptionFilter implements ExceptionFilter {
  private readonly _logger: LogixiaLoggerService | undefined;
  private readonly _traceConfig: TraceIdConfig | undefined;

  constructor(
    @Optional()
    @Inject(`${LOGIXIA_LOGGER_PREFIX}SERVICE`)
    logger?: LogixiaLoggerService,
    @Optional()
    @Inject(LOGIXIA_LOGGER_CONFIG)
    loggerConfig?: Partial<LoggerConfig>
  ) {
    // Prefer the injected logger; fall back to the global module logger so
    // `new LogixiaExceptionFilter()` (registered in main.ts before DI resolves)
    // still logs without needing an explicit logger argument.
    this._logger = logger ?? LogixiaLoggerModule._globalLogger ?? undefined;
    // Pick up the user-configured trace settings (response header name, etc.)
    // so the filter echoes the same header the middleware writes.
    this._traceConfig =
      typeof loggerConfig?.traceId === 'object' ? loggerConfig.traceId : undefined;
  }

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();

    const request = ctx.getRequest<{
      method?: string;
      url?: string;
      id?: string;
      startTime?: number;
      headers?: Record<string, string | string[] | undefined>;
    }>();

    interface MinimalResponse {
      status(code: number): MinimalResponse;
      json(body: unknown): void;
      setHeader(name: string, value: string): void;
    }
    const response = ctx.getResponse<MinimalResponse>();

    // ALS is the single source of truth (set by TraceMiddleware).
    // Fall back to header/request.id only if ALS has nothing (e.g. traceId disabled).
    const traceId =
      TraceContext.instance.getCurrentTraceId() ??
      (request.headers?.['x-trace-id'] as string | undefined) ??
      request.id ??
      undefined;

    const { response: errorResponse, httpStatus } = ErrorResponseBuilder.build({
      exception,
      traceId,
      path: request.url ?? '/',
      startTime: request.startTime,
    });

    // ── Logging ──────────────────────────────────────────────────────────────
    if (this._logger) {
      const requestMeta: Record<string, unknown> = {
        method: request.method ?? '',
        url: request.url ?? '',
        status: httpStatus,
        // Only include trace_id when it exists — keeps log records honest when
        // tracing is disabled (instead of writing `trace_id: undefined`).
        ...(errorResponse.meta.trace_id !== undefined
          ? { trace_id: errorResponse.meta.trace_id }
          : {}),
      };

      // `error()` / `warn()` return Promise<void> for the structured overload.
      // We cannot await inside a synchronous ExceptionFilter.catch(), so attach
      // a `.catch()` to prevent unhandledRejection if a transport fails — and
      // fall back to stderr so the error is never silently swallowed.
      const onLogFailure = (err: unknown): void => {
        process.stderr.write(
          `[logixia] ExceptionFilter failed to write log entry: ${String(err)}\n`
        );
      };

      let logPromise: Promise<void> | void;
      if (httpStatus >= 500) {
        const err = exception instanceof Error ? exception : new Error(String(exception));
        logPromise = this._logger.error(err, requestMeta);
      } else if (isLogixiaException(exception)) {
        logPromise = this._logger.warn(
          `[${errorResponse.error.code}] ${errorResponse.error.message}`,
          requestMeta
        );
      } else {
        logPromise = this._logger.warn(
          `[${httpStatus}] ${errorResponse.error.message}`,
          requestMeta
        );
      }

      if (logPromise && typeof (logPromise as Promise<void>).catch === 'function') {
        (logPromise as Promise<void>).catch(onLogFailure);
      }
    }

    // ── Strip debug in production ─────────────────────────────────────────
    if (process.env['NODE_ENV'] === 'production') {
      delete errorResponse.debug;
    }

    // ── Response headers ──────────────────────────────────────────────────
    if (errorResponse.meta.trace_id) {
      const traceHeader = resolveResponseHeader(this._traceConfig);
      if (traceHeader) {
        response.setHeader(traceHeader, errorResponse.meta.trace_id);
      }
    }
    if (httpStatus === 429) {
      response.setHeader('Retry-After', '60');
    }

    response.status(httpStatus).json(errorResponse);
  }
}
