/**
 * Unified error response shape for logixia.
 *
 * Design-inspired by Stripe (`type` + `code` + `param`), GitHub (`details[]`),
 * Twilio (`doc_url`), and Cloudflare (`success: false` envelope).
 *
 * The shape is intentionally framework-agnostic — it works for HTTP, WebSocket,
 * Queue/RPC, and any other transport. Your exception filter is responsible for
 * serialising it onto the wire.
 *
 * @template TCode - Union of valid error code strings you define (e.g. `'PE-AUTH-001' | 'PE-USR-001'`).
 *                   Defaults to `string` for untyped usage.
 * @template TType - Union of valid error type strings you define (e.g. `'authentication_error' | 'validation_error'`).
 *                   Defaults to `string` for untyped usage.
 *
 * @example Fully typed usage
 * ```ts
 * type AppCode = 'PE-AUTH-001' | 'PE-VAL-001';
 * type AppType = 'authentication_error' | 'validation_error';
 *
 * const response: LogixiaErrorResponse<AppCode, AppType> = { ... };
 * ```
 */
export interface LogixiaErrorResponse<
  TCode extends string = string,
  TType extends string = string,
> {
  /** Always `false` — allows `if (response.success)` branching on the client. */
  success: false;

  error: {
    /**
     * Broad category that tells the client **how** to handle this error.
     * e.g. `'validation_error'` → show field errors; `'authentication_error'` → redirect to login.
     */
    type: TType;

    /**
     * Machine-readable, stable error identifier.
     * e.g. `'PE-AUTH-001'` — never changes; safe to switch/match on.
     */
    code: TCode;

    /**
     * Human-readable message shown to the end-user.
     * May change between releases — do not rely on it programmatically.
     */
    message: string;

    /**
     * The specific request field that caused this error (Stripe pattern).
     * e.g. `'email'` | `'metadata.name'`
     */
    param?: string;

    /**
     * Array of field-level errors for batch validation failures (GitHub pattern).
     * Only present when more than one field is invalid.
     */
    details?: ErrorDetail[];

    /**
     * Documentation URL for this specific error (Twilio pattern).
     * e.g. `'https://docs.example.com/errors/PE-AUTH-001'`
     */
    doc_url?: string;
  };

  meta: {
    /** Trace identifier for log correlation. Absent when traceId is disabled. */
    trace_id?: string;
    /** ISO 8601 timestamp of when the error was produced. */
    timestamp: string;
    /** Request path that caused the error. e.g. `'/api/v1/auth/login'` */
    path: string;
    /** HTTP status code mirrored in the body for clients that can't read headers. */
    status: number;
  };

  /**
   * Developer / diagnostic context.
   *
   * ⚠️ **Strip this in production.** The `ErrorResponseBuilder` always populates it
   * (when possible); your exception filter should call `delete response.debug` before
   * sending the response when `NODE_ENV === 'production'`.
   */
  debug?: {
    /** Full stack trace of the underlying error. */
    stack?: string;
    /** Serialised `error.cause` (ES 2022 chained errors). */
    cause?: string;
    /** Originating micro-service name. e.g. `'gatekeeper'` | `'worker'` */
    service?: string;
    /** Wall-clock time in ms from `request.startTime` to error handling. */
    duration_ms?: number;
  };
}

/**
 * A single field-level validation error (GitHub pattern).
 *
 * @example
 * ```ts
 * { field: 'email', message: 'must be a valid email address', code: 'invalid_format' }
 * { field: 'password', message: 'required',                   code: 'required'       }
 * ```
 */
export interface ErrorDetail {
  /** Dot-notation field path. e.g. `'email'` | `'user.address.zip'` */
  field: string;
  /** Human-readable reason this field failed. */
  message: string;
  /**
   * Machine-readable failure code for this field.
   * Suggested values: `'required'` | `'invalid_format'` | `'too_long'` | `'too_short'` |
   * `'out_of_range'` | `'invalid_enum_value'` | `'duplicate'`
   */
  code: string;
}
