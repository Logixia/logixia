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

import { ErrorResponseBuilder } from '../exceptions/builder.js';
import { isLogixiaException } from '../exceptions/exception.js';
import { LOGIXIA_LOGGER_PREFIX } from './logitron-logger.module';
import type { LogixiaLoggerService } from './logitron-nestjs.service';

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
  level?: 'debug' | 'info' | 'verbose';
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

    descriptor.value = async function (
      this: { logger?: LogixiaLoggerService },
      ...args: unknown[]
    ) {
      const logger = this.logger;
      const start = Date.now();

      const entry: Record<string, unknown> = { method: label };
      if (logArgs && args.length > 0) {
        entry['args'] = args;
      }

      if (logger) {
        // Use logLevel (extended method) rather than the NestJS interface debug/info
        // which only accepts (message: unknown, context?: string)
        const logFn =
          (
            logger as unknown as Record<
              string,
              (msg: string, data?: Record<string, unknown>) => Promise<void>
            >
          )[level] ?? logger.debug.bind(logger);
        if (typeof logFn === 'function') {
          await (logFn as (msg: string, data?: Record<string, unknown>) => Promise<void>)(
            `→ ${label}`,
            entry
          ).catch(() => void 0);
        }
      }

      try {
        const result = await (originalMethod.apply(this, args) as Promise<unknown>);

        const exit: Record<string, unknown> = {
          method: label,
          durationMs: Date.now() - start,
        };
        if (logResult) exit['result'] = result;

        if (logger) {
          const logFn =
            (
              logger as unknown as Record<
                string,
                (msg: string, data?: Record<string, unknown>) => Promise<void>
              >
            )[level] ?? logger.debug.bind(logger);
          if (typeof logFn === 'function') {
            await (logFn as (msg: string, data?: Record<string, unknown>) => Promise<void>)(
              `← ${label}`,
              exit
            ).catch(() => void 0);
          }
        }

        return result;
      } catch (error) {
        if (logger && logErrors) {
          const err = error instanceof Error ? error : new Error(String(error));
          logger.error(err, `${label} durationMs=${Date.now() - start}`);
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
  constructor(
    @Optional()
    @Inject(`${LOGIXIA_LOGGER_PREFIX}SERVICE`)
    private readonly logger?: LogixiaLoggerService
  ) {}

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

    // Prefer x-trace-id (set by RequestIdMiddleware) → request.id → auto-generate
    const requestId =
      (request.headers?.['x-trace-id'] as string | undefined) ?? request.id ?? undefined;

    const { response: errorResponse, httpStatus } = ErrorResponseBuilder.build({
      exception,
      requestId,
      path: request.url ?? '/',
      startTime: request.startTime,
    });

    // ── Logging ──────────────────────────────────────────────────────────────
    if (this.logger) {
      const contextStr = [
        `method=${String(request.method ?? '')}`,
        `url=${String(request.url ?? '')}`,
        `status=${httpStatus}`,
        `request_id=${errorResponse.meta.request_id}`,
      ].join(' ');

      if (httpStatus >= 500) {
        const err = exception instanceof Error ? exception : new Error(String(exception));
        // fire-and-forget — cannot await inside a synchronous ExceptionFilter.catch
        this.logger.error(err, undefined, contextStr);
      } else if (isLogixiaException(exception)) {
        this.logger.warn(
          `[${errorResponse.error.code}] ${errorResponse.error.message}`,
          contextStr
        );
      } else {
        this.logger.warn(`[${httpStatus}] ${errorResponse.error.message}`, contextStr);
      }
    }

    // ── Strip debug in production ─────────────────────────────────────────
    if (process.env['NODE_ENV'] === 'production') {
      delete errorResponse.debug;
    }

    // ── Response headers ──────────────────────────────────────────────────
    response.setHeader('X-Trace-ID', errorResponse.meta.request_id);
    response.setHeader('X-Request-ID', errorResponse.meta.request_id);
    if (httpStatus === 429) {
      response.setHeader('Retry-After', '60');
    }

    response.status(httpStatus).json(errorResponse);
  }
}
