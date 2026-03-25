/**
 * logixia/exceptions
 *
 * A framework-agnostic, strictly typed exception system that produces the
 * industry-standard `LogixiaErrorResponse` wire format.
 *
 * Usage in three steps:
 *
 * **Step 1 — Define your code + type unions (optional but recommended)**
 * ```ts
 * type AppCode = 'PE-AUTH-001' | 'PE-VAL-001' | 'PE-DB-001';
 * type AppType = 'authentication_error' | 'validation_error' | 'server_error';
 * ```
 *
 * **Step 2 — Throw**
 * ```ts
 * import { LogixiaException } from 'logixia';
 *
 * throw new LogixiaException<AppCode, AppType>({
 *   code:       'PE-AUTH-001',
 *   type:       'authentication_error',
 *   httpStatus: 401,
 *   message:    'Invalid email or password.',
 * });
 * ```
 *
 * **Step 3 — Format in your filter**
 * ```ts
 * import { ErrorResponseBuilder } from 'logixia';
 *
 * const { response, httpStatus } = ErrorResponseBuilder.build<AppCode, AppType>({
 *   exception,
 *   traceId:   request.headers['x-trace-id'] as string | undefined,
 *   path:      request.url,
 *   service:   process.env.SERVICE_NAME,
 *   startTime: request.startTime,
 * });
 *
 * if (process.env.NODE_ENV === 'production') delete response.debug;
 * res.status(httpStatus).json(response);
 * ```
 */

export type { BuildParams } from './builder.js';
export { ErrorResponseBuilder, generateRequestId, generateTraceId } from './builder.js';
export type { LogixiaExceptionOptions } from './exception.js';
export { isLogixiaException, LogixiaException } from './exception.js';
export type { ErrorDetail, LogixiaErrorResponse } from './types.js';
