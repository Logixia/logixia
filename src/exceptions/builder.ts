/**
 * ErrorResponseBuilder — turns any exception into a `LogixiaErrorResponse`.
 *
 * Priority order:
 *  1. `LogixiaException`      — typed fields used directly
 *  2. NestJS `HttpException`  — duck-typed; status + message extracted
 *  3. Plain `Error` / unknown — falls back to 500 `server_error`
 *
 * The builder **always** populates `debug` when possible.
 * Your exception filter is responsible for stripping it in production:
 * ```ts
 * if (process.env.NODE_ENV === 'production') delete response.debug;
 * ```
 */

import { randomUUID } from 'node:crypto';

import { isLogixiaException } from './exception.js';
import type { LogixiaErrorResponse } from './types.js';

// ── Types ─────────────────────────────────────────────────────────────────────

/** Input parameters for `ErrorResponseBuilder.build`. */
export interface BuildParams {
  /** The caught exception — any type. */
  exception: unknown;
  /**
   * Trace ID to embed in `meta.trace_id`.
   * If omitted a UUID-based ID is auto-generated.
   */
  traceId?: string | undefined;
  /** Request path. e.g. `'/api/v1/auth/login'` */
  path: string;
  /**
   * Originating service name for `debug.service`.
   * e.g. `process.env.SERVICE_NAME` → `'gatekeeper'`
   */
  service?: string | undefined;
  /**
   * `Date.now()` captured at the start of the request.
   * When present, `debug.duration_ms` is computed automatically.
   */
  startTime?: number | undefined;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Generates a trace ID using Node's built-in `crypto.randomUUID`.
 * No extra dependencies required.
 *
 * @example `'550e8400-e29b-41d4-a716-446655440000'`
 */
export function generateTraceId(): string {
  return randomUUID();
}

/** @deprecated Use `generateTraceId` instead. */
export const generateRequestId = generateTraceId;

/**
 * Maps an HTTP status code to a human-friendly error type string.
 * Used as a fallback when the exception is a generic `HttpException`.
 */
function httpStatusToType(status: number): string {
  if (status === 400) return 'api_error';
  if (status === 401) return 'authentication_error';
  if (status === 402) return 'payment_error';
  if (status === 403) return 'authorization_error';
  if (status === 404) return 'not_found_error';
  if (status === 408) return 'timeout_error';
  if (status === 409) return 'conflict_error';
  if (status === 422) return 'validation_error';
  if (status === 429) return 'rate_limit_error';
  if (status >= 500) return 'server_error';
  if (status >= 400) return 'api_error';
  return 'server_error';
}

/**
 * Duck-type check for NestJS `HttpException`.
 * Avoids a hard import on `@nestjs/common` so the builder is usable outside NestJS.
 */
function isHttpException(
  value: unknown
): value is { getStatus(): number; getResponse(): unknown; message: string } {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as Record<string, unknown>)['getStatus'] === 'function' &&
    typeof (value as Record<string, unknown>)['getResponse'] === 'function'
  );
}

/**
 * Builds the optional `debug` block from an error.
 * Returns `undefined` when there is nothing useful to include.
 */
function buildDebug(
  error: unknown,
  service: string | undefined,
  durationMs: number | undefined
): LogixiaErrorResponse['debug'] {
  const stack = error instanceof Error ? error.stack : undefined;

  const causeRaw =
    error instanceof Error ? (error as Error & { cause?: unknown }).cause : undefined;
  let cause: string | undefined;
  if (causeRaw instanceof Error) {
    cause = causeRaw.message;
  } else if (causeRaw !== undefined && causeRaw !== null) {
    cause = String(causeRaw);
  }

  if (!stack && !cause && !service && durationMs === undefined) return undefined;

  return {
    ...(stack !== undefined ? { stack } : {}),
    ...(cause !== undefined ? { cause } : {}),
    ...(service !== undefined ? { service } : {}),
    ...(durationMs !== undefined ? { duration_ms: durationMs } : {}),
  };
}

// ── Builder ───────────────────────────────────────────────────────────────────

export class ErrorResponseBuilder {
  /**
   * Build a `LogixiaErrorResponse` from any thrown value.
   *
   * @param params - See `BuildParams`.
   * @returns The unified error response and the HTTP status code to send.
   *
   * @example In a NestJS exception filter
   * ```ts
   * const { response, httpStatus } = ErrorResponseBuilder.build<AppCode, AppType>({
   *   exception,
   *   traceId: request.headers['x-trace-id'] as string | undefined,
   *   path:    request.url,
   *   service: process.env.SERVICE_NAME,
   *   startTime: request.startTime,
   * });
   *
   * if (process.env.NODE_ENV === 'production') delete response.debug;
   * response.setHeader('X-Trace-ID', response.meta.trace_id);
   * response.status(httpStatus).json(response);
   * ```
   */
  static build<TCode extends string = string, TType extends string = string>(
    params: BuildParams
  ): { response: LogixiaErrorResponse<TCode, TType>; httpStatus: number } {
    const { exception, path, service, startTime, traceId: rawTraceId } = params;
    const traceId = rawTraceId ?? generateTraceId();
    const timestamp = new Date().toISOString();
    const durationMs = startTime !== undefined ? Date.now() - startTime : undefined;

    // ── 1. LogixiaException ────────────────────────────────────────────────
    if (isLogixiaException<TCode, TType>(exception)) {
      const debug = buildDebug(exception, service, durationMs);

      const errorBlock: LogixiaErrorResponse<TCode, TType>['error'] = {
        type: exception.errorType,
        code: exception.errorCode,
        message: exception.message,
      };
      if (exception.param !== undefined) errorBlock.param = exception.param;
      if (exception.details !== undefined && exception.details.length > 0) {
        errorBlock.details = exception.details;
      }
      if (exception.docUrl !== undefined) errorBlock.doc_url = exception.docUrl;

      const response: LogixiaErrorResponse<TCode, TType> = {
        success: false,
        error: errorBlock,
        meta: {
          trace_id: traceId,
          timestamp,
          path,
          status: exception.httpStatus,
        },
        ...(debug !== undefined ? { debug } : {}),
      };

      return { response, httpStatus: exception.httpStatus };
    }

    // ── 2. NestJS HttpException (duck-typed) ──────────────────────────────
    if (isHttpException(exception)) {
      const status = exception.getStatus();
      const exResponse = exception.getResponse();

      // NestJS nests the message: { statusCode, message, error } or a plain string
      let message: string;
      if (typeof exResponse === 'string') {
        message = exResponse;
      } else if (typeof exResponse === 'object' && exResponse !== null && 'message' in exResponse) {
        const raw = (exResponse as { message: unknown }).message;
        message = Array.isArray(raw) ? raw.join(', ') : String(raw);
      } else {
        message = exception.message;
      }

      const type = httpStatusToType(status) as TType;
      const code = `HTTP_${status}` as TCode;
      const debug = buildDebug(exception, service, durationMs);

      const response: LogixiaErrorResponse<TCode, TType> = {
        success: false,
        error: { type, code, message },
        meta: { trace_id: traceId, timestamp, path, status },
        ...(debug !== undefined ? { debug } : {}),
      };

      return { response, httpStatus: status };
    }

    // ── 3. Unknown / plain Error ──────────────────────────────────────────
    const err = exception instanceof Error ? exception : new Error(String(exception));
    const debug = buildDebug(err, service, durationMs);

    const response: LogixiaErrorResponse<TCode, TType> = {
      success: false,
      error: {
        type: 'server_error' as TType,
        code: 'INTERNAL_SERVER_ERROR' as TCode,
        message: 'An unexpected error occurred.',
      },
      meta: { trace_id: traceId, timestamp, path, status: 500 },
      ...(debug !== undefined ? { debug } : {}),
    };

    return { response, httpStatus: 500 };
  }
}
