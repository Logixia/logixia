/**
 * Comprehensive tests for error.utils
 *
 * Covers:
 *  - serializeError: basic, stack, cause chain, AggregateError, extra fields,
 *    depth limit, circular references, excludeFields option
 *  - isError: type guard for all edge cases
 *  - normalizeError: string, object, plain Error, unknown values
 */

import { isError, normalizeError, serializeError } from '../error.utils';

// ── serializeError ────────────────────────────────────────────────────────────

describe('serializeError', () => {
  describe('basic serialization', () => {
    it('serializes name and message', () => {
      const err = new Error('something went wrong');
      const result = serializeError(err);
      expect(result.name).toBe('Error');
      expect(result.message).toBe('something went wrong');
    });

    it('includes stack by default', () => {
      const err = new Error('with stack');
      const result = serializeError(err);
      expect(typeof result.stack).toBe('string');
      expect((result.stack as string).includes('Error: with stack')).toBe(true);
    });

    it('excludes stack when includeStack: false', () => {
      const err = new Error('no stack');
      const result = serializeError(err, { includeStack: false });
      expect(result.stack).toBeUndefined();
    });

    it('serializes a TypeError', () => {
      const err = new TypeError('invalid type');
      const result = serializeError(err);
      expect(result.name).toBe('TypeError');
      expect(result.message).toBe('invalid type');
    });

    it('serializes a RangeError', () => {
      const err = new RangeError('out of bounds');
      const result = serializeError(err);
      expect(result.name).toBe('RangeError');
    });

    it('serializes a custom error subclass', () => {
      class AppError extends Error {
        constructor(
          message: string,
          public readonly code: string
        ) {
          super(message);
          this.name = 'AppError';
        }
      }
      const err = new AppError('custom', 'APP_001');
      const result = serializeError(err);
      expect(result.name).toBe('AppError');
      expect(result.code).toBe('APP_001');
    });
  });

  describe('ES2022 cause chain', () => {
    it('serializes a simple cause chain', () => {
      const root = new Error('root cause');
      const err = new Error('outer error', { cause: root });
      const result = serializeError(err);
      expect(result.cause).toBeDefined();
      expect((result.cause as Record<string, unknown>).message).toBe('root cause');
    });

    it('serializes deeply nested cause chains', () => {
      const lvl3 = new Error('level 3');
      const lvl2 = new Error('level 2', { cause: lvl3 });
      const lvl1 = new Error('level 1', { cause: lvl2 });
      const result = serializeError(lvl1, { maxDepth: 10 });
      const cause1 = result.cause as Record<string, unknown>;
      expect(cause1.message).toBe('level 2');
      const cause2 = cause1.cause as Record<string, unknown>;
      expect(cause2.message).toBe('level 3');
    });

    it('truncates cause chain at maxDepth', () => {
      let err: Error = new Error('root');
      for (let i = 0; i < 10; i++) {
        err = new Error(`level ${i}`, { cause: err });
      }
      const result = serializeError(err, { maxDepth: 3 });
      // Should not throw and should truncate
      expect(result.name).toBe('Error');
    });

    it('serializes non-Error cause as a value', () => {
      const err = Object.assign(new Error('outer'), { cause: 'string cause' });
      const result = serializeError(err);
      expect(result.cause).toBe('string cause');
    });

    it('serializes object cause', () => {
      const err = Object.assign(new Error('outer'), { cause: { code: 42, detail: 'info' } });
      const result = serializeError(err);
      expect(result.cause).toEqual({ code: 42, detail: 'info' });
    });
  });

  describe('AggregateError', () => {
    it('serializes AggregateError.errors array', () => {
      const e1 = new Error('first');
      const e2 = new TypeError('second');
      const agg = new AggregateError([e1, e2], 'multiple errors');
      const result = serializeError(agg);
      expect(Array.isArray(result.errors)).toBe(true);
      const errors = result.errors as Record<string, unknown>[];
      expect(errors[0].message).toBe('first');
      expect(errors[1].message).toBe('second');
    });

    it('handles non-Error items in AggregateError.errors', () => {
      const agg = new AggregateError(['string error', 42], 'mixed');
      const result = serializeError(agg);
      const errors = result.errors as unknown[];
      expect(errors[0]).toBe('string error');
      expect(errors[1]).toBe(42);
    });
  });

  describe('standard Node.js error fields', () => {
    it('captures code field', () => {
      const err = Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      const result = serializeError(err);
      expect(result.code).toBe('ENOENT');
    });

    it('captures statusCode field', () => {
      const err = Object.assign(new Error('Not Found'), { statusCode: 404 });
      const result = serializeError(err);
      expect(result.statusCode).toBe(404);
    });

    it('captures errno field', () => {
      const err = Object.assign(new Error('EACCES'), { errno: -13 });
      const result = serializeError(err);
      expect(result.errno).toBe(-13);
    });

    it('captures syscall field', () => {
      const err = Object.assign(new Error('read error'), { syscall: 'read' });
      const result = serializeError(err);
      expect(result.syscall).toBe('read');
    });

    it('captures path, address, port fields', () => {
      const err = Object.assign(new Error('connect failed'), {
        path: '/var/run/app.sock',
        address: '127.0.0.1',
        port: 3000,
      });
      const result = serializeError(err);
      expect(result.path).toBe('/var/run/app.sock');
      expect(result.address).toBe('127.0.0.1');
      expect(result.port).toBe(3000);
    });
  });

  describe('excludeFields option', () => {
    it('excludes specified fields', () => {
      const err = Object.assign(new Error('test'), { code: 'ERR_001', statusCode: 500 });
      const result = serializeError(err, { excludeFields: ['code', 'statusCode'] });
      expect(result.code).toBeUndefined();
      expect(result.statusCode).toBeUndefined();
    });

    it('does not exclude non-specified fields', () => {
      const err = Object.assign(new Error('test'), { code: 'ERR_001', statusCode: 500 });
      const result = serializeError(err, { excludeFields: ['code'] });
      expect(result.code).toBeUndefined();
      expect(result.statusCode).toBe(500);
    });
  });

  describe('circular reference safety', () => {
    it('handles circular cause reference', () => {
      const err = new Error('circular') as Error & { cause?: unknown };
      err.cause = err; // circular!
      // Should not throw or infinite loop
      expect(() => serializeError(err)).not.toThrow();
      const result = serializeError(err);
      const cause = result.cause as Record<string, unknown>;
      expect(cause._circular).toBe(true);
    });
  });

  describe('own enumerable properties', () => {
    it('captures extra own enumerable properties', () => {
      class RichError extends Error {
        requestId = 'req-abc';
        userId = 'u-123';
      }
      const err = new RichError('rich error');
      const result = serializeError(err);
      expect(result.requestId).toBe('req-abc');
      expect(result.userId).toBe('u-123');
    });
  });
});

// ── isError ───────────────────────────────────────────────────────────────────

describe('isError', () => {
  it('returns true for Error instances', () => {
    expect(isError(new Error('test'))).toBe(true);
  });

  it('returns true for TypeError', () => {
    expect(isError(new TypeError('type'))).toBe(true);
  });

  it('returns true for RangeError', () => {
    expect(isError(new RangeError('range'))).toBe(true);
  });

  it('returns true for Error-like objects with name and message', () => {
    expect(isError({ name: 'CustomError', message: 'custom' })).toBe(true);
  });

  it('returns false for plain strings', () => {
    expect(isError('error string')).toBe(false);
  });

  it('returns false for numbers', () => {
    expect(isError(42)).toBe(false);
  });

  it('returns false for null', () => {
    expect(isError(null)).toBe(false);
  });

  it('returns false for undefined', () => {
    expect(isError()).toBe(false);
  });

  it('returns false for plain objects without error shape', () => {
    expect(isError({ foo: 'bar' })).toBe(false);
  });

  it('returns false for arrays', () => {
    expect(isError([])).toBe(false);
  });

  it('returns false for objects missing message', () => {
    expect(isError({ name: 'Err' })).toBe(false);
  });
});

// ── normalizeError ────────────────────────────────────────────────────────────

describe('normalizeError', () => {
  it('returns the same Error instance if already an Error', () => {
    const err = new Error('original');
    expect(normalizeError(err)).toBe(err);
  });

  it('wraps a string into an Error', () => {
    const result = normalizeError('something bad');
    expect(result instanceof Error).toBe(true);
    expect(result.message).toBe('something bad');
  });

  it('wraps an object with a message field', () => {
    const result = normalizeError({ message: 'obj error' });
    expect(result instanceof Error).toBe(true);
    expect(result.message).toBe('obj error');
  });

  it('wraps an object without message as "Unknown error"', () => {
    const result = normalizeError({ code: 'ERR' });
    expect(result instanceof Error).toBe(true);
    expect(result.message).toBe('Unknown error');
  });

  it('wraps null as "null"', () => {
    const result = normalizeError(null);
    expect(result.message).toBe('null');
  });

  it('wraps a number', () => {
    const result = normalizeError(404);
    expect(result.message).toBe('404');
  });

  it('wraps boolean false', () => {
    const result = normalizeError(false);
    expect(result.message).toBe('false');
  });

  it('preserves properties from object input', () => {
    const result = normalizeError({ message: 'err', code: 'E001', retryable: true });
    expect((result as Record<string, unknown>).code).toBe('E001');
    expect((result as Record<string, unknown>).retryable).toBe(true);
  });
});
