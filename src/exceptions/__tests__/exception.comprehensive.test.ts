/**
 * Comprehensive tests for LogixiaException and isLogixiaException
 *
 * Covers:
 *  - Basic construction and property access
 *  - All constructor options (code, type, httpStatus, message, param, details, docUrl, cause, metadata)
 *  - ES2022 cause chain integration
 *  - instanceof checks and prototype chain
 *  - isLogixiaException type guard
 *  - Typed generics (TCode, TType)
 *  - Edge cases: missing optional fields, empty arrays
 */

import type { LogixiaExceptionOptions } from '../exception';
import { isLogixiaException, LogixiaException } from '../exception';

// ── Basic construction ────────────────────────────────────────────────────────

describe('LogixiaException — construction', () => {
  const baseOptions: LogixiaExceptionOptions = {
    code: 'PE-AUTH-001',
    type: 'authentication_error',
    httpStatus: 401,
    message: 'Invalid email or password.',
  };

  it('is an instance of Error', () => {
    const ex = new LogixiaException(baseOptions);
    expect(ex instanceof Error).toBe(true);
  });

  it('is an instance of LogixiaException', () => {
    const ex = new LogixiaException(baseOptions);
    expect(ex instanceof LogixiaException).toBe(true);
  });

  it('has name "LogixiaException"', () => {
    const ex = new LogixiaException(baseOptions);
    expect(ex.name).toBe('LogixiaException');
  });

  it('sets errorCode from options.code', () => {
    const ex = new LogixiaException(baseOptions);
    expect(ex.errorCode).toBe('PE-AUTH-001');
  });

  it('sets errorType from options.type', () => {
    const ex = new LogixiaException(baseOptions);
    expect(ex.errorType).toBe('authentication_error');
  });

  it('sets httpStatus from options.httpStatus', () => {
    const ex = new LogixiaException(baseOptions);
    expect(ex.httpStatus).toBe(401);
  });

  it('sets message from options.message', () => {
    const ex = new LogixiaException(baseOptions);
    expect(ex.message).toBe('Invalid email or password.');
  });

  it('has undefined param when not provided', () => {
    const ex = new LogixiaException(baseOptions);
    expect(ex.param).toBeUndefined();
  });

  it('has undefined details when not provided', () => {
    const ex = new LogixiaException(baseOptions);
    expect(ex.details).toBeUndefined();
  });

  it('has undefined docUrl when not provided', () => {
    const ex = new LogixiaException(baseOptions);
    expect(ex.docUrl).toBeUndefined();
  });

  it('has undefined metadata when not provided', () => {
    const ex = new LogixiaException(baseOptions);
    expect(ex.metadata).toBeUndefined();
  });
});

// ── Optional fields ───────────────────────────────────────────────────────────

describe('LogixiaException — optional fields', () => {
  it('sets param (Stripe pattern)', () => {
    const ex = new LogixiaException({
      code: 'PE-USR-002',
      type: 'conflict_error',
      httpStatus: 409,
      message: 'Email already in use.',
      param: 'email',
    });
    expect(ex.param).toBe('email');
  });

  it('sets details array (GitHub pattern)', () => {
    const details = [
      { field: 'email', message: 'must be a valid email', code: 'invalid_format' },
      { field: 'password', message: 'required', code: 'required' },
    ];
    const ex = new LogixiaException({
      code: 'PE-VAL-001',
      type: 'validation_error',
      httpStatus: 400,
      message: 'Validation failed.',
      details,
    });
    expect(ex.details).toEqual(details);
    expect(ex.details!.length).toBe(2);
    expect(ex.details![0].field).toBe('email');
    expect(ex.details![1].code).toBe('required');
  });

  it('sets docUrl (Twilio pattern)', () => {
    const ex = new LogixiaException({
      code: 'PE-AUTH-001',
      type: 'authentication_error',
      httpStatus: 401,
      message: 'Auth failed.',
      docUrl: 'https://docs.example.com/errors/PE-AUTH-001',
    });
    expect(ex.docUrl).toBe('https://docs.example.com/errors/PE-AUTH-001');
  });

  it('sets metadata (logging only)', () => {
    const metadata = { userId: 'u_abc', attemptCount: 3 };
    const ex = new LogixiaException({
      code: 'PE-AUTH-001',
      type: 'authentication_error',
      httpStatus: 401,
      message: 'Too many attempts.',
      metadata,
    });
    expect(ex.metadata).toEqual(metadata);
    expect((ex.metadata as Record<string, unknown>).userId).toBe('u_abc');
  });
});

// ── ES2022 cause chain ────────────────────────────────────────────────────────

describe('LogixiaException — cause chain', () => {
  it('sets the cause via ES2022 Error options', () => {
    const rootCause = new Error('Database connection failed');
    const ex = new LogixiaException({
      code: 'PE-DB-001',
      type: 'server_error',
      httpStatus: 500,
      message: 'Failed to save record.',
      cause: rootCause,
    });
    expect((ex as Error & { cause?: unknown }).cause).toBe(rootCause);
  });

  it('cause is accessible via the standard Error cause property', () => {
    const cause = new Error('original');
    const ex = new LogixiaException({
      code: 'CODE',
      type: 'server_error',
      httpStatus: 500,
      message: 'Wrapped',
      cause,
    });
    expect((ex as Error & { cause?: Error }).cause?.message).toBe('original');
  });

  it('works without cause', () => {
    const ex = new LogixiaException({
      code: 'CODE',
      type: 'server_error',
      httpStatus: 500,
      message: 'No cause',
    });
    expect((ex as Error & { cause?: unknown }).cause).toBeUndefined();
  });
});

// ── Various HTTP statuses ─────────────────────────────────────────────────────

describe('LogixiaException — HTTP status codes', () => {
  const cases: Array<[number, string, string]> = [
    [400, 'api_error', 'Bad request'],
    [401, 'authentication_error', 'Unauthorized'],
    [403, 'authorization_error', 'Forbidden'],
    [404, 'not_found_error', 'Not found'],
    [409, 'conflict_error', 'Conflict'],
    [422, 'validation_error', 'Unprocessable entity'],
    [429, 'rate_limit_error', 'Too many requests'],
    [500, 'server_error', 'Internal server error'],
  ];

  it.each(cases)('accepts httpStatus %i', (status, type, msg) => {
    const ex = new LogixiaException({ code: 'X', type, httpStatus: status, message: msg });
    expect(ex.httpStatus).toBe(status);
  });
});

// ── Typed generics ────────────────────────────────────────────────────────────

describe('LogixiaException — typed generics', () => {
  type AppCode = 'PE-AUTH-001' | 'PE-VAL-001' | 'PE-DB-001';
  type AppType = 'authentication_error' | 'validation_error' | 'server_error';

  it('retains type information at runtime', () => {
    const ex = new LogixiaException<AppCode, AppType>({
      code: 'PE-AUTH-001',
      type: 'authentication_error',
      httpStatus: 401,
      message: 'Auth failed.',
    });
    expect(ex.errorCode).toBe('PE-AUTH-001');
    expect(ex.errorType).toBe('authentication_error');
  });
});

// ── Stack trace ───────────────────────────────────────────────────────────────

describe('LogixiaException — stack trace', () => {
  it('has a stack trace', () => {
    const ex = new LogixiaException({
      code: 'X',
      type: 'server_error',
      httpStatus: 500,
      message: 'Test',
    });
    expect(typeof ex.stack).toBe('string');
    expect(ex.stack!.length).toBeGreaterThan(0);
  });

  it('stack includes the exception name', () => {
    const ex = new LogixiaException({
      code: 'X',
      type: 'server_error',
      httpStatus: 500,
      message: 'Test stack',
    });
    expect(ex.stack).toContain('LogixiaException');
  });
});

// ── isLogixiaException ────────────────────────────────────────────────────────

describe('isLogixiaException', () => {
  it('returns true for a LogixiaException instance', () => {
    const ex = new LogixiaException({
      code: 'X',
      type: 'server_error',
      httpStatus: 500,
      message: 'test',
    });
    expect(isLogixiaException(ex)).toBe(true);
  });

  it('returns false for a plain Error', () => {
    expect(isLogixiaException(new Error('plain'))).toBe(false);
  });

  it('returns false for null', () => {
    expect(isLogixiaException(null)).toBe(false);
  });

  it('returns false for undefined', () => {
    expect(isLogixiaException()).toBe(false);
  });

  it('returns false for a plain object', () => {
    expect(isLogixiaException({ code: 'X', type: 'Y', httpStatus: 400, message: 'z' })).toBe(false);
  });

  it('returns false for a string', () => {
    expect(isLogixiaException('error string')).toBe(false);
  });

  it('returns false for a number', () => {
    expect(isLogixiaException(42)).toBe(false);
  });

  it('returns false for a TypeError', () => {
    expect(isLogixiaException(new TypeError('type error'))).toBe(false);
  });

  it('works as a type guard — narrows the type correctly', () => {
    const err: unknown = new LogixiaException({
      code: 'PE-AUTH-001',
      type: 'authentication_error',
      httpStatus: 401,
      message: 'Auth',
    });

    if (isLogixiaException(err)) {
      // TypeScript should allow accessing errorCode here
      expect(err.errorCode).toBe('PE-AUTH-001');
    } else {
      fail('Should have been a LogixiaException');
    }
  });
});

// ── throw / catch patterns ────────────────────────────────────────────────────

describe('LogixiaException — throw and catch', () => {
  it('can be thrown and caught as an Error', () => {
    expect(() => {
      throw new LogixiaException({
        code: 'PE-AUTH-001',
        type: 'authentication_error',
        httpStatus: 401,
        message: 'Auth failed',
      });
    }).toThrow('Auth failed');
  });

  it('can be caught and identified with isLogixiaException', () => {
    let caught: unknown;
    try {
      throw new LogixiaException({
        code: 'PE-AUTH-001',
        type: 'authentication_error',
        httpStatus: 401,
        message: 'Auth failed',
      });
    } catch (e) {
      caught = e;
    }
    expect(isLogixiaException(caught)).toBe(true);
    if (isLogixiaException(caught)) {
      expect(caught.httpStatus).toBe(401);
    }
  });

  it('preserves all fields after being caught', () => {
    const details = [{ field: 'email', message: 'Invalid', code: 'invalid' }];
    let caught: unknown;
    try {
      throw new LogixiaException({
        code: 'PE-VAL-001',
        type: 'validation_error',
        httpStatus: 400,
        message: 'Validation failed',
        param: 'email',
        details,
        docUrl: 'https://docs.example.com',
        metadata: { traceId: 'abc' },
      });
    } catch (e) {
      caught = e;
    }

    if (isLogixiaException(caught)) {
      expect(caught.errorCode).toBe('PE-VAL-001');
      expect(caught.errorType).toBe('validation_error');
      expect(caught.httpStatus).toBe(400);
      expect(caught.param).toBe('email');
      expect(caught.details).toEqual(details);
      expect(caught.docUrl).toBe('https://docs.example.com');
      expect((caught.metadata as Record<string, unknown>).traceId).toBe('abc');
    }
  });
});
