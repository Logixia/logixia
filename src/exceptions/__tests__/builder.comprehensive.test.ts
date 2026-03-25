/**
 * Comprehensive tests for ErrorResponseBuilder and generateTraceId
 *
 * Covers:
 *  - generateTraceId: format validation
 *  - ErrorResponseBuilder.build with LogixiaException
 *  - ErrorResponseBuilder.build with NestJS HttpException (duck-typed)
 *  - ErrorResponseBuilder.build with plain Error
 *  - ErrorResponseBuilder.build with non-Error thrown values
 *  - debug block population: stack, cause, service, duration_ms
 *  - meta block: trace_id, timestamp, path, status
 *  - httpStatusToType mapping
 *  - traceId auto-generation vs explicit
 */

import { ErrorResponseBuilder, generateTraceId } from '../builder';
import { LogixiaException } from '../exception';

// ── generateTraceId ──────────────────────────────────────────────────────────

describe('generateTraceId', () => {
  it('returns a UUID v4 string', () => {
    expect(generateTraceId()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
  });

  it('generates unique IDs', () => {
    const ids = new Set(Array.from({ length: 100 }, () => generateTraceId()));
    expect(ids.size).toBe(100);
  });
});

// ── ErrorResponseBuilder.build — LogixiaException ────────────────────────────

describe('ErrorResponseBuilder.build — LogixiaException', () => {
  const baseException = new LogixiaException({
    code: 'PE-AUTH-001',
    type: 'authentication_error',
    httpStatus: 401,
    message: 'Invalid credentials.',
  });

  it('returns httpStatus from the exception', () => {
    const { httpStatus } = ErrorResponseBuilder.build({
      exception: baseException,
      path: '/api/auth/login',
    });
    expect(httpStatus).toBe(401);
  });

  it('returns success: false', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: baseException,
      path: '/api/auth/login',
    });
    expect(response.success).toBe(false);
  });

  it('populates error.type from errorType', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: baseException,
      path: '/api/auth/login',
    });
    expect(response.error.type).toBe('authentication_error');
  });

  it('populates error.code from errorCode', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: baseException,
      path: '/api/auth/login',
    });
    expect(response.error.code).toBe('PE-AUTH-001');
  });

  it('populates error.message from exception message', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: baseException,
      path: '/api/auth/login',
    });
    expect(response.error.message).toBe('Invalid credentials.');
  });

  it('populates meta.path', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: baseException,
      path: '/api/auth/login',
    });
    expect(response.meta.path).toBe('/api/auth/login');
  });

  it('populates meta.status from httpStatus', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: baseException,
      path: '/api/auth/login',
    });
    expect(response.meta.status).toBe(401);
  });

  it('populates meta.timestamp as ISO string', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: baseException,
      path: '/api/auth/login',
    });
    expect(() => new Date(response.meta.timestamp)).not.toThrow();
    expect(new Date(response.meta.timestamp).toISOString()).toBe(response.meta.timestamp);
  });

  it('uses provided traceId', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: baseException,
      path: '/api',
      traceId: 'trace-123',
    });
    expect(response.meta.trace_id).toBe('trace-123');
  });

  it('auto-generates traceId when not provided', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: baseException,
      path: '/api',
    });
    expect(response.meta.trace_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
  });

  it('includes error.param when set', () => {
    const ex = new LogixiaException({
      code: 'PE-VAL-001',
      type: 'validation_error',
      httpStatus: 400,
      message: 'Invalid email',
      param: 'email',
    });
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api' });
    expect(response.error.param).toBe('email');
  });

  it('does not include param when not set', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: baseException,
      path: '/api',
    });
    expect(response.error.param).toBeUndefined();
  });

  it('includes error.details when set', () => {
    const details = [
      { field: 'email', message: 'Invalid', code: 'invalid_format' },
      { field: 'name', message: 'Required', code: 'required' },
    ];
    const ex = new LogixiaException({
      code: 'PE-VAL-001',
      type: 'validation_error',
      httpStatus: 422,
      message: 'Validation failed',
      details,
    });
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api' });
    expect(response.error.details).toEqual(details);
  });

  it('does not include details when details is empty array', () => {
    const ex = new LogixiaException({
      code: 'PE-VAL-001',
      type: 'validation_error',
      httpStatus: 400,
      message: 'Validation failed',
      details: [],
    });
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api' });
    expect(response.error.details).toBeUndefined();
  });

  it('includes error.doc_url when set', () => {
    const ex = new LogixiaException({
      code: 'PE-AUTH-001',
      type: 'authentication_error',
      httpStatus: 401,
      message: 'Auth failed',
      docUrl: 'https://docs.example.com/errors/PE-AUTH-001',
    });
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api' });
    expect(response.error.doc_url).toBe('https://docs.example.com/errors/PE-AUTH-001');
  });

  it('includes debug.service when provided', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: baseException,
      path: '/api',
      service: 'auth-service',
    });
    expect(response.debug?.service).toBe('auth-service');
  });

  it('includes debug.duration_ms when startTime provided', () => {
    const startTime = Date.now() - 100;
    const { response } = ErrorResponseBuilder.build({
      exception: baseException,
      path: '/api',
      startTime,
    });
    expect(typeof response.debug?.duration_ms).toBe('number');
    expect(response.debug!.duration_ms!).toBeGreaterThanOrEqual(0);
  });

  it('includes debug.stack', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: baseException,
      path: '/api',
    });
    expect(typeof response.debug?.stack).toBe('string');
  });

  it('includes debug.cause when exception has a cause', () => {
    const cause = new Error('root cause');
    const ex = new LogixiaException({
      code: 'PE-DB-001',
      type: 'server_error',
      httpStatus: 500,
      message: 'DB failed',
      cause,
    });
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api' });
    expect(response.debug?.cause).toBe('root cause');
  });
});

// ── ErrorResponseBuilder.build — NestJS HttpException (duck-typed) ────────────

describe('ErrorResponseBuilder.build — HttpException (duck-typed)', () => {
  function makeHttpException(status: number, responseBody: unknown) {
    return {
      getStatus: () => status,
      getResponse: () => responseBody,
      message: 'NestJS exception message',
    };
  }

  it('handles a plain string response body', () => {
    const ex = makeHttpException(404, 'Not Found');
    const { response, httpStatus } = ErrorResponseBuilder.build({ exception: ex, path: '/api' });
    expect(httpStatus).toBe(404);
    expect(response.error.message).toBe('Not Found');
  });

  it('handles a NestJS-style object response body', () => {
    const ex = makeHttpException(400, {
      statusCode: 400,
      message: 'Bad request',
      error: 'Bad Request',
    });
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api' });
    expect(response.error.message).toBe('Bad request');
  });

  it('handles array message in NestJS validation response', () => {
    const ex = makeHttpException(422, {
      statusCode: 422,
      message: ['email must be an email', 'name should not be empty'],
      error: 'Unprocessable Entity',
    });
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api' });
    expect(response.error.message).toBe('email must be an email, name should not be empty');
  });

  it('maps 401 to authentication_error type', () => {
    const ex = makeHttpException(401, 'Unauthorized');
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api' });
    expect(response.error.type).toBe('authentication_error');
  });

  it('maps 403 to authorization_error type', () => {
    const ex = makeHttpException(403, 'Forbidden');
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api' });
    expect(response.error.type).toBe('authorization_error');
  });

  it('maps 404 to not_found_error type', () => {
    const ex = makeHttpException(404, 'Not Found');
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api' });
    expect(response.error.type).toBe('not_found_error');
  });

  it('maps 409 to conflict_error type', () => {
    const ex = makeHttpException(409, 'Conflict');
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api' });
    expect(response.error.type).toBe('conflict_error');
  });

  it('maps 422 to validation_error type', () => {
    const ex = makeHttpException(422, 'Unprocessable');
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api' });
    expect(response.error.type).toBe('validation_error');
  });

  it('maps 429 to rate_limit_error type', () => {
    const ex = makeHttpException(429, 'Too Many Requests');
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api' });
    expect(response.error.type).toBe('rate_limit_error');
  });

  it('maps 500 to server_error type', () => {
    const ex = makeHttpException(500, 'Internal Server Error');
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api' });
    expect(response.error.type).toBe('server_error');
  });

  it('maps 400 to api_error type', () => {
    const ex = makeHttpException(400, 'Bad Request');
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api' });
    expect(response.error.type).toBe('api_error');
  });

  it('generates HTTP_<status> code', () => {
    const ex = makeHttpException(404, 'Not Found');
    const { response } = ErrorResponseBuilder.build({ exception: ex, path: '/api' });
    expect(response.error.code).toBe('HTTP_404');
  });
});

// ── ErrorResponseBuilder.build — plain Error / unknown ───────────────────────

describe('ErrorResponseBuilder.build — plain Error and unknown values', () => {
  it('returns httpStatus 500 for a plain Error', () => {
    const { httpStatus } = ErrorResponseBuilder.build({
      exception: new Error('Something broke'),
      path: '/api',
    });
    expect(httpStatus).toBe(500);
  });

  it('returns server_error type for a plain Error', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: new Error('Something broke'),
      path: '/api',
    });
    expect(response.error.type).toBe('server_error');
  });

  it('returns INTERNAL_SERVER_ERROR code for a plain Error', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: new Error('Something broke'),
      path: '/api',
    });
    expect(response.error.code).toBe('INTERNAL_SERVER_ERROR');
  });

  it('returns generic message for a plain Error', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: new Error('Something broke'),
      path: '/api',
    });
    expect(response.error.message).toBe('An unexpected error occurred.');
  });

  it('handles string thrown as exception', () => {
    const { httpStatus, response } = ErrorResponseBuilder.build({
      exception: 'string error',
      path: '/api',
    });
    expect(httpStatus).toBe(500);
    expect(response.error.code).toBe('INTERNAL_SERVER_ERROR');
  });

  it('handles null thrown as exception', () => {
    const { httpStatus } = ErrorResponseBuilder.build({
      exception: null,
      path: '/api',
    });
    expect(httpStatus).toBe(500);
  });

  it('handles undefined thrown as exception', () => {
    const { httpStatus } = ErrorResponseBuilder.build({
      exception: undefined,
      path: '/api',
    });
    expect(httpStatus).toBe(500);
  });

  it('handles plain object thrown as exception', () => {
    const { httpStatus } = ErrorResponseBuilder.build({
      exception: { code: 'ERR', detail: 'problem' },
      path: '/api',
    });
    expect(httpStatus).toBe(500);
  });

  it('includes debug.stack for plain Error', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: new Error('stack test'),
      path: '/api',
    });
    expect(typeof response.debug?.stack).toBe('string');
  });
});

// ── All optional build params ─────────────────────────────────────────────────

describe('ErrorResponseBuilder.build — optional params', () => {
  it('includes duration_ms when startTime is provided', () => {
    const startTime = Date.now() - 200;
    const { response } = ErrorResponseBuilder.build({
      exception: new Error('test'),
      path: '/api',
      startTime,
    });
    expect(response.debug?.duration_ms).toBeGreaterThanOrEqual(0);
  });

  it('does not include duration_ms when startTime is omitted', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: new Error('test'),
      path: '/api',
    });
    // duration_ms should not be present
    expect(response.debug?.duration_ms).toBeUndefined();
  });

  it('includes service in debug when provided', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: new Error('test'),
      path: '/api',
      service: 'worker',
    });
    expect(response.debug?.service).toBe('worker');
  });

  it('meta.trace_id uses provided traceId', () => {
    const { response } = ErrorResponseBuilder.build({
      exception: new Error('test'),
      path: '/api',
      traceId: 'custom-trace-id',
    });
    expect(response.meta.trace_id).toBe('custom-trace-id');
  });
});
