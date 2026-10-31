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
 * import { LogixiaLoggerModule } from 'logixia/nest';
 * @Module({ imports: [LogixiaLoggerModule.forRoot({ service: 'api' })] })
 * export class AppModule {}
 *
 * // order.service.ts
 * import { Injectable } from '@nestjs/common';
 * import { InjectLogger, LogMethod, LogixiaLoggerService } from 'logixia/nest';
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
 * import { LogixiaExceptionFilter } from 'logixia/nest';
 * app.useGlobalFilters(new LogixiaExceptionFilter(logger));
 * ```
 */

import type { ArgumentsHost, ExceptionFilter } from '@nestjs/common';
import { Catch, Inject, Optional } from '@nestjs/common';

import { ErrorResponseBuilder } from '../exceptions/builder';
import { isLogixiaException } from '../exceptions/exception';
import type { LogixiaErrorResponse } from '../exceptions/types';
import type { LoggerConfig, LogLevelString, TraceIdConfig } from '../types';
import { serializeError } from '../utils/error.utils';
import { internalError, internalWarn } from '../utils/internal-log';
import { assignOwn } from '../utils/own-property';
import {
  buildNameSet,
  DEFAULT_REDACT_QUERY_PARAMS,
  redactUrlQuery,
  sanitizeText,
  sensitiveQueryValues,
} from '../utils/sensitive-names';
import { sanitizeIncomingId, TraceContext } from '../utils/trace.utils';
import {
  LOGIXIA_LOGGER_CONFIG,
  LOGIXIA_LOGGER_PREFIX,
  LogixiaLoggerModule,
} from './logitron-logger.module';
import { LogixiaLoggerService } from './logitron-nestjs.service';
import { resolveResponseHeader } from './trace.middleware';

// ── @InjectLogger() ──────────────────────────────────────────────────────────

/**
 * Inject the Logixia logger registered in the current NestJS DI container.
 *
 * With no argument it injects the root `LogixiaLoggerService` provided by
 * `LogixiaLoggerModule.forRoot[Async]()`. With a `context` it injects the child
 * logger that `LogixiaLoggerModule.forFeature(context)` provides for that context
 * (the feature module must be imported where it is used).
 *
 * @example
 * ```ts
 * constructor(@InjectLogger() private readonly logger: LogixiaLoggerService) {}
 *
 * // with LogixiaLoggerModule.forFeature('orders') imported:
 * constructor(@InjectLogger('orders') private readonly logger: LogixiaLoggerService) {}
 * ```
 */
export const InjectLogger = (context?: string): ParameterDecorator =>
  context === undefined
    ? Inject(LogixiaLoggerService)
    : Inject(`${LOGIXIA_LOGGER_PREFIX}${context.toUpperCase()}`);

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
 * Preserves the original method's sync/async contract: a synchronous method
 * stays synchronous (returns its value directly, with logs emitted
 * fire-and-forget), and an async method is awaited so exit/error logs reflect
 * the resolved result. Attaches to the logger found on the class instance via a
 * `logger` property (the conventional NestJS name).
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

    // Surface logger failures on stderr instead of silently swallowing them.
    const reportLogFailure = (phase: string, err: unknown): void => {
      internalError(`@LogMethod(${label}) ${phase} log failed: ${String(err)}`);
    };

    // Emit a log line fire-and-forget, routing transport failures to stderr.
    const emit = (
      logger: LogixiaLoggerService,
      phase: string,
      message: string,
      data: Record<string, unknown>
    ): void => {
      const logFnRaw = (
        logger as unknown as Record<
          string,
          (msg: string, data?: Record<string, unknown>) => Promise<void>
        >
      )[level];
      const logFn = (typeof logFnRaw === 'function' ? logFnRaw : logger.debug).bind(logger);
      const p = logFn(message, data);
      if (p && typeof (p as Promise<void>).catch === 'function') {
        (p as Promise<void>).catch((e: unknown) => reportLogFailure(phase, e));
      }
    };

    const emitError = (logger: LogixiaLoggerService, error: unknown, start: number): void => {
      const err = error instanceof Error ? error : new Error(String(error));
      const errLog: unknown = logger.error(err, { method: label, durationMs: Date.now() - start });
      if (errLog && typeof (errLog as Promise<void>).catch === 'function') {
        (errLog as Promise<void>).catch((e: unknown) => reportLogFailure('error', e));
      }
    };

    descriptor.value = function (this: { logger?: LogixiaLoggerService }, ...args: unknown[]) {
      // Prefer the instance's own logger; fall back to the global module logger.
      const logger: LogixiaLoggerService | undefined =
        this.logger ?? LogixiaLoggerModule._globalLogger ?? undefined;

      if (!logger && !_warnedNoLogger) {
        _warnedNoLogger = true;
        internalWarn(
          `@LogMethod on ${label}: no logger available. ` +
            `Either inject LogixiaLoggerService as this.logger or ensure LogixiaLoggerModule is initialised.`
        );
      }

      const start = Date.now();
      const entry: Record<string, unknown> = { method: label };
      if (logArgs && args.length > 0) entry['args'] = args;
      // Entry log is fire-and-forget so a SYNC method is not forced to become
      // async just to await it.
      if (logger) emit(logger, 'entry', `→ ${label}`, entry);

      const buildExit = (result: unknown): Record<string, unknown> => {
        const exit: Record<string, unknown> = { method: label, durationMs: Date.now() - start };
        if (logResult) exit['result'] = result;
        return exit;
      };

      let result: unknown;
      try {
        result = originalMethod.apply(this, args);
      } catch (error) {
        // Synchronous throw.
        if (logger && logErrors) emitError(logger, error, start);
        throw error;
      }

      // Async method → await via the returned thenable so exit/error reflect the
      // resolved outcome, and preserve the Promise return type.
      if (result && typeof (result as PromiseLike<unknown>).then === 'function') {
        return (result as Promise<unknown>).then(
          (resolved) => {
            if (logger) emit(logger, 'exit', `← ${label}`, buildExit(resolved));
            return resolved;
          },
          (error: unknown) => {
            if (logger && logErrors) emitError(logger, error, start);
            throw error;
          }
        );
      }

      // Synchronous method → log exit fire-and-forget and return the value as-is,
      // preserving the original synchronous contract.
      if (logger) emit(logger, 'exit', `← ${label}`, buildExit(result));
      return result;
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
 * **Debug block (off by default):**
 * Responses never include the `debug` block (stack trace, service, duration)
 * unless `exposeDebug: true` is passed in the filter options. The underlying
 * `cause` is only added when `exposeCause: true` is also set. Enable explicitly
 * for local development only, e.g.
 * `new LogixiaExceptionFilter(logger, undefined, { exposeDebug: process.env.NODE_ENV === 'development' })`.
 *
 * **Trace ID headers:**
 * The request's trace ID is written to one response header — `X-Trace-ID` by
 * default, or the name set via `traceId.responseHeader` (`false` disables it) — so
 * clients can correlate with server logs. The filter does not write
 * `X-Request-ID`.
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
export interface LogixiaExceptionFilterOptions {
  /**
   * Include the `debug` block (stack trace, service, duration) in error responses.
   * @default false
   */
  exposeDebug?: boolean;
  /**
   * Include `debug.cause` as well. Requires `exposeDebug`.
   * @default false
   */
  exposeCause?: boolean;
  /**
   * Extra query parameter names whose values are replaced with `[REDACTED]` in the
   * logged `url`, the response `path`, and any copy of those values inside the error
   * message, stack or details. Merged with the defaults (`token`, `code`, `password`,
   * `api_key`, …) and `LoggerConfig.redact.queryParams`.
   */
  redactQueryParams?: readonly string[];
}

/** Injection token for {@link LogixiaExceptionFilterOptions}. */
export const LOGIXIA_EXCEPTION_FILTER_OPTIONS = 'LOGIXIA_EXCEPTION_FILTER_OPTIONS';

const MAX_SCRUB_DEPTH = 8;

/** Copy `value` with every string passed through `clean`; the input is never modified. */
function cleanDeep(value: unknown, clean: (text: string) => string, depth = 0): unknown {
  if (typeof value === 'string') return clean(value);
  if (value === null || typeof value !== 'object' || depth >= MAX_SCRUB_DEPTH) return value;
  if (Array.isArray(value)) return value.map((item) => cleanDeep(item, clean, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) out[key] = cleanDeep(item, clean, depth + 1);
  return out;
}

function scrubErrorResponse(
  response: LogixiaErrorResponse,
  clean: (text: string) => string
): LogixiaErrorResponse {
  const { error, debug } = response;
  return {
    ...response,
    error: cleanDeep(error, clean) as LogixiaErrorResponse['error'],
    ...(debug !== undefined ? { debug: cleanDeep(debug, clean) as typeof debug } : {}),
  };
}

const MAX_ERROR_DEPTH = 6;

/** Scrub string VALUES of an already serialized tree; keys stay so key-based redaction still applies. */
function scrubSerialized(
  value: unknown,
  clean: (text: string) => string,
  depth: number,
  seen: WeakSet<object>
): unknown {
  if (typeof value === 'string') return clean(value);
  if (value === null || typeof value !== 'object') {
    return typeof value === 'function' || typeof value === 'symbol' ? '[Unserializable]' : value;
  }
  if (seen.has(value)) return '[Circular]';
  if (depth >= MAX_ERROR_DEPTH) return '[MaxDepth]';
  seen.add(value);
  try {
    if (Array.isArray(value))
      return value.map((item) => scrubSerialized(item, clean, depth + 1, seen));
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      assignOwn(out, key, scrubSerialized(item, clean, depth + 1, seen));
    }
    return out;
  } finally {
    seen.delete(value);
  }
}

/** Minimal copy used when the full sanitize step fails; never throws. */
function fallbackError(exception: unknown, clean: (text: string) => string): Error {
  let name = 'Error';
  let message = '[Unserializable]';
  try {
    if (exception instanceof Error) {
      name = exception.name;
      message = clean(exception.message);
    }
  } catch {
    /* hostile getter or revoked proxy: keep the placeholders */
  }
  const copy = new Error(message);
  copy.name = name;
  assignOwn(copy, 'serialization', '[Unserializable]');
  return copy;
}

/**
 * A fresh Error safe to log. Built from `serializeError` (class instances walked by key,
 * so the logger's key-based redaction still sees `authorization`, `x-api-key`, ...), with
 * string values scrubbed. Keeps name, message, stack, cause and custom properties.
 * The original is untouched and this never throws.
 */
function sanitizedError(exception: unknown, clean: (text: string) => string): Error {
  try {
    if (!(exception instanceof Error)) return new Error(clean(String(exception)));
    const serialized = serializeError(exception);
    const scrubbed = scrubSerialized(serialized, clean, 0, new WeakSet()) as Record<
      string,
      unknown
    >;
    const copy = new Error(String(scrubbed['message'] ?? ''));
    for (const [key, value] of Object.entries(scrubbed)) {
      if (key === 'message') continue;
      if (key === 'stack' || key === 'name') {
        Object.defineProperty(copy, key, { value, writable: true, configurable: true });
      } else {
        assignOwn(copy, key, value);
      }
    }
    return copy;
  } catch {
    return fallbackError(exception, clean);
  }
}

@Catch()
export class LogixiaExceptionFilter implements ExceptionFilter {
  private readonly _logger: LogixiaLoggerService | undefined;
  private readonly _traceConfig: TraceIdConfig | undefined;
  private readonly _options: LogixiaExceptionFilterOptions;
  private readonly _redactParams: ReadonlySet<string>;

  constructor(
    @Optional()
    @Inject(LogixiaLoggerService)
    logger?: LogixiaLoggerService,
    @Optional()
    @Inject(LOGIXIA_LOGGER_CONFIG)
    loggerConfig?: Partial<LoggerConfig>,
    @Optional()
    @Inject(LOGIXIA_EXCEPTION_FILTER_OPTIONS)
    options?: LogixiaExceptionFilterOptions
  ) {
    this._options = options ?? {};
    this._redactParams = buildNameSet(DEFAULT_REDACT_QUERY_PARAMS, [
      ...(loggerConfig?.redact?.queryParams ?? []),
      ...(this._options.redactQueryParams ?? []),
    ]);
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
      originalUrl?: string;
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
      sanitizeIncomingId(request.headers?.['x-trace-id']) ??
      sanitizeIncomingId(request.id) ??
      undefined;

    // Query values like ?token=… must not reach logs or the echoed response path.
    // `originalUrl` keeps mount prefixes and matches the HTTP logger / wide events.
    const rawUrl = request.originalUrl ?? request.url ?? '';
    const url = redactUrlQuery(rawUrl, this._redactParams);
    // Nest's own 404 puts the full URL in the message, so scrub it from every text field.
    const secrets = sensitiveQueryValues(rawUrl, this._redactParams);
    const clean = (text: string): string => sanitizeText(text, this._redactParams, secrets);

    const buildFor = (input: unknown) => {
      const { response: built, httpStatus: status } = ErrorResponseBuilder.build({
        exception: input,
        traceId,
        path: url || '/',
        startTime: request.startTime,
        exposeDebug: this._options.exposeDebug === true,
        exposeCause: this._options.exposeCause === true,
      });
      return { errorResponse: scrubErrorResponse(built, clean), httpStatus: status };
    };
    // A hostile exception (throwing getter, revoked proxy) must never lose the response.
    let result: ReturnType<typeof buildFor>;
    try {
      result = buildFor(exception);
    } catch {
      result = buildFor(fallbackError(exception, clean));
    }
    const { errorResponse, httpStatus } = result;
    let logixiaException = false;
    try {
      logixiaException = isLogixiaException(exception);
    } catch {
      /* not inspectable: treat as a plain error */
    }

    // ── Logging ──────────────────────────────────────────────────────────────
    if (this._logger) {
      const requestMeta: Record<string, unknown> = {
        method: request.method ?? '',
        url,
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
        internalError(`ExceptionFilter failed to write log entry: ${String(err)}`);
      };

      let logPromise: Promise<void> | void;
      if (httpStatus >= 500) {
        logPromise = this._logger.error(sanitizedError(exception, clean), requestMeta);
      } else if (logixiaException) {
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

    // ── Response headers ──────────────────────────────────────────────────
    if (errorResponse.meta.trace_id) {
      const traceHeader = resolveResponseHeader(this._traceConfig);
      if (traceHeader) {
        try {
          response.setHeader(traceHeader, errorResponse.meta.trace_id);
        } catch {
          /* headers already sent or invalid — the body still carries the trace id */
        }
      }
    }
    if (httpStatus === 429) {
      try {
        response.setHeader('Retry-After', '60');
      } catch {
        /* headers already sent */
      }
    }

    response.status(httpStatus).json(errorResponse);
  }
}
