/**
 * LogixiaException — a strictly typed, framework-agnostic exception class.
 *
 * You bring your own error codes and types; logixia enforces the shape.
 * The `ErrorResponseBuilder` knows how to turn a `LogixiaException` into the
 * standard `LogixiaErrorResponse` wire format.
 *
 * @template TCode - Your error code union. e.g. `'PE-AUTH-001' | 'PE-USR-001'`
 * @template TType - Your error type union. e.g. `'authentication_error' | 'validation_error'`
 *
 * @example Basic throw
 * ```ts
 * throw new LogixiaException({
 *   code:       'PE-AUTH-001',
 *   type:       'authentication_error',
 *   httpStatus: 401,
 *   message:    'Invalid email or password.',
 * });
 * ```
 *
 * @example Fully typed with your own code/type unions
 * ```ts
 * type AppCode = 'PE-AUTH-001' | 'PE-VAL-001';
 * type AppType = 'authentication_error' | 'validation_error';
 *
 * throw new LogixiaException<AppCode, AppType>({
 *   code:       'PE-VAL-001',
 *   type:       'validation_error',
 *   httpStatus: 400,
 *   message:    'Validation failed.',
 *   details: [
 *     { field: 'email', message: 'must be a valid email', code: 'invalid_format' },
 *   ],
 * });
 * ```
 *
 * @example With field pointer (Stripe param pattern)
 * ```ts
 * throw new LogixiaException({
 *   code:       'PE-USR-002',
 *   type:       'conflict_error',
 *   httpStatus: 409,
 *   message:    'This email is already in use.',
 *   param:      'email',
 * });
 * ```
 *
 * @example With cause chain (ES 2022)
 * ```ts
 * try {
 *   await db.save(user);
 * } catch (err) {
 *   throw new LogixiaException({
 *     code:       'PE-DB-001',
 *     type:       'server_error',
 *     httpStatus: 409,
 *     message:    'Duplicate record.',
 *     cause:      err instanceof Error ? err : undefined,
 *   });
 * }
 * ```
 */

import type { ErrorDetail } from './types.js';

// ── Options ───────────────────────────────────────────────────────────────────

/**
 * Constructor options for `LogixiaException`.
 *
 * All user-supplied fields — logixia only owns the wire format.
 */
export interface LogixiaExceptionOptions<
  TCode extends string = string,
  TType extends string = string,
> {
  /**
   * Machine-readable, stable error code.
   * e.g. `'PE-AUTH-001'`
   */
  code: TCode;

  /**
   * Broad error type category.
   * e.g. `'authentication_error'` | `'validation_error'` | `'rate_limit_error'`
   */
  type: TType;

  /**
   * HTTP status code to send on the wire.
   * e.g. `401` | `400` | `429` | `500`
   */
  httpStatus: number;

  /**
   * Human-readable message for the end-user.
   * This IS sent in the response body — keep it safe (no internal paths, etc.).
   */
  message: string;

  /**
   * The specific request field that caused this error (Stripe pattern).
   * e.g. `'email'` | `'metadata.name'`
   */
  param?: string;

  /**
   * Array of per-field validation errors (GitHub pattern).
   * Typically used for `400` / `422` validation failures.
   */
  details?: ErrorDetail[];

  /**
   * Documentation URL for this error (Twilio pattern).
   * e.g. `'https://docs.example.com/errors/PE-AUTH-001'`
   */
  docUrl?: string;

  /**
   * Original error for ES 2022 cause chaining.
   * Serialised into `debug.cause` by the `ErrorResponseBuilder`.
   * Never sent to the client in production.
   */
  cause?: Error;

  /**
   * Arbitrary metadata for logging purposes only.
   * This is **never** included in the HTTP response — it is passed to your
   * logger / monitoring integrations through the exception object.
   *
   * @example
   * ```ts
   * metadata: { userId: 'u_abc', attemptCount: 3 }
   * ```
   */
  metadata?: Record<string, unknown>;
}

// ── Exception class ───────────────────────────────────────────────────────────

export class LogixiaException<
  TCode extends string = string,
  TType extends string = string,
> extends Error {
  /** @readonly The machine-readable error code supplied by the caller. */
  public readonly errorCode: TCode;
  /** @readonly The error type category supplied by the caller. */
  public readonly errorType: TType;
  /** @readonly HTTP status code to respond with. */
  public readonly httpStatus: number;
  /** @readonly Field pointer that caused this error (Stripe pattern). */
  public readonly param: string | undefined;
  /** @readonly Field-level validation errors (GitHub pattern). */
  public readonly details: ErrorDetail[] | undefined;
  /** @readonly Documentation URL for this error (Twilio pattern). */
  public readonly docUrl: string | undefined;
  /**
   * @readonly Extra context for your logger — never serialised into the HTTP response.
   */
  public readonly metadata: Record<string, unknown> | undefined;

  constructor(options: LogixiaExceptionOptions<TCode, TType>) {
    // Pass `cause` through the standard ES 2022 Error options so native
    // tooling (Node.js, Sentry, etc.) can walk the full error chain.
    super(options.message, { cause: options.cause });

    this.name = 'LogixiaException';
    this.errorCode = options.code;
    this.errorType = options.type;
    this.httpStatus = options.httpStatus;
    this.param = options.param;
    this.details = options.details;
    this.docUrl = options.docUrl;
    this.metadata = options.metadata;

    // Restore the correct prototype chain when compiling to ES5.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ── Type guard ────────────────────────────────────────────────────────────────

/**
 * Returns `true` when `value` is a `LogixiaException` instance.
 *
 * Useful in exception filters or middleware that need to distinguish a
 * `LogixiaException` from a plain `Error` or a framework `HttpException`.
 *
 * @example
 * ```ts
 * if (isLogixiaException(err)) {
 *   console.log(err.errorCode, err.httpStatus);
 * }
 * ```
 */
export function isLogixiaException<TCode extends string = string, TType extends string = string>(
  value?: unknown
): value is LogixiaException<TCode, TType> {
  return value instanceof LogixiaException;
}
