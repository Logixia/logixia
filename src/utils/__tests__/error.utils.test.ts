/**
 * Comprehensive tests for error serialization utilities
 *
 * Covers: serializeError (standard fields, cause chain, AggregateError,
 * depth limit, circular reference guard, excludeFields, includeStack),
 * isError (type guard), normalizeError (coercion).
 */

import { isError, normalizeError, serializeError } from '../error.utils';

// ── serializeError — basic fields ────────────────────────────────────────────

describe('serializeError — basic fields', () => {
  it('serializes name and message', () => {
    const err = new Error('Something went wrong');
    const result = serializeError(err);
    expect(result.name).toBe('Error');
    expect(result.message).toBe('Something went wrong');
  });

  it('includes stack trace by default', () => {
    const err = new Error('boom');
    const result = serializeError(err);
    expect(typeof result.stack).toBe('string');
    expect((result.stack as string).length).toBeGreaterThan(0);
  });

  it('omits stack when includeStack is false', () => {
    const err = new Error('no stack');
    const result = serializeError(err, { includeStack: false });
    expect(result.stack).toBeUndefined();
  });

  it('preserves the error name for custom error types', () => {
    class DatabaseError extends Error {
      constructor(msg: string) {
        super(msg);
        this.name = 'DatabaseError';
      }
    }
    const err = new DatabaseError('Connection refused');
    const result = serializeError(err);
    expect(result.name).toBe('DatabaseError');
  });

  it('returns a plain object (not an Error instance)', () => {
    const err = new Error('test');
    const result = serializeError(err);
    expect(result).not.toBeInstanceOf(Error);
    expect(typeof result).toBe('object');
  });
});

// ── serializeError — standard Node.js / HTTP extra fields ────────────────────

describe('serializeError — standard extra fields', () => {
  it('captures the code field (Node.js system errors)', () => {
    const err = Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    const result = serializeError(err);
    expect(result.code).toBe('ENOENT');
  });

  it('captures statusCode (HTTP errors)', () => {
    const err = Object.assign(new Error('Not Found'), { statusCode: 404 });
    const result = serializeError(err);
    expect(result.statusCode).toBe(404);
  });

  it('captures status field', () => {
    const err = Object.assign(new Error('Forbidden'), { status: 403 });
    const result = serializeError(err);
    expect(result.status).toBe(403);
  });

  it('captures errno', () => {
    const err = Object.assign(new Error('ECONNREFUSED'), { errno: -61 });
    const result = serializeError(err);
    expect(result.errno).toBe(-61);
  });

  it('captures syscall', () => {
    const err = Object.assign(new Error('connect'), { syscall: 'connect' });
    const result = serializeError(err);
    expect(result.syscall).toBe('connect');
  });

  it('captures path', () => {
    const err = Object.assign(new Error('file not found'), { path: '/var/log/app.log' });
    const result = serializeError(err);
    expect(result.path).toBe('/var/log/app.log');
  });

  it('captures address and port', () => {
    const err = Object.assign(new Error('listen EADDRINUSE'), { address: '0.0.0.0', port: 3000 });
    const result = serializeError(err);
    expect(result.address).toBe('0.0.0.0');
    expect(result.port).toBe(3000);
  });

  it('captures type field', () => {
    const err = Object.assign(new Error('type error'), { type: 'custom' });
    const result = serializeError(err);
    expect(result.type).toBe('custom');
  });

  it('excludes fields listed in excludeFields', () => {
    const err = Object.assign(new Error('oops'), { code: 'ERR_X', statusCode: 500 });
    const result = serializeError(err, { excludeFields: ['code', 'statusCode'] });
    expect(result.code).toBeUndefined();
    expect(result.statusCode).toBeUndefined();
  });

  it('captures arbitrary own enumerable properties', () => {
    const err = Object.assign(new Error('custom'), { requestId: 'abc-123', userId: 42 });
    const result = serializeError(err);
    expect(result.requestId).toBe('abc-123');
    expect(result.userId).toBe(42);
  });
});

// ── serializeError — ES2022 cause chain ──────────────────────────────────────

describe('serializeError — ES2022 cause chain', () => {
  it('serializes a simple cause', () => {
    const root = new Error('root cause');
    const wrapped = new Error('outer error', { cause: root });
    const result = serializeError(wrapped);
    expect(result.cause).toBeDefined();
    expect((result.cause as Record<string, unknown>).message).toBe('root cause');
  });

  it('serializes a multi-level cause chain', () => {
    const level3 = new Error('level 3');
    const level2 = new Error('level 2', { cause: level3 });
    const level1 = new Error('level 1', { cause: level2 });

    const result = serializeError(level1);
    const l2 = result.cause as Record<string, unknown>;
    const l3 = l2.cause as Record<string, unknown>;

    expect(l2.message).toBe('level 2');
    expect(l3.message).toBe('level 3');
  });

  it('truncates cause chain at maxDepth', () => {
    const deep = new Error('deep');
    const mid = new Error('mid', { cause: deep });
    const top = new Error('top', { cause: mid });

    const result = serializeError(top, { maxDepth: 1 });
    // At maxDepth=1 the cause should be truncated
    const cause = result.cause as Record<string, unknown>;
    // cause itself is depth=1, so it gets _truncated: true
    expect(cause._truncated).toBe(true);
  });

  it('handles non-Error cause value', () => {
    const err = new Error('outer') as Error & { cause?: unknown };
    err.cause = { code: 'CUSTOM', detail: 'some info' };
    const result = serializeError(err);
    expect((result.cause as Record<string, unknown>).code).toBe('CUSTOM');
  });

  it('handles string cause', () => {
    const err = new Error('outer') as Error & { cause?: unknown };
    err.cause = 'something failed';
    const result = serializeError(err);
    expect(result.cause).toBe('something failed');
  });
});

// ── serializeError — AggregateError ──────────────────────────────────────────

describe('serializeError — AggregateError', () => {
  it('serializes AggregateError.errors array', () => {
    const e1 = new Error('first');
    const e2 = new Error('second');
    const agg = new AggregateError([e1, e2], 'multiple failures');
    const result = serializeError(agg);

    expect(Array.isArray(result.errors)).toBe(true);
    const errors = result.errors as Array<Record<string, unknown>>;
    expect(errors).toHaveLength(2);
    expect(errors[0]!.message).toBe('first');
    expect(errors[1]!.message).toBe('second');
  });

  it('serializes non-Error items in AggregateError.errors', () => {
    const agg = new AggregateError(['string error', 42], 'mixed errors');
    const result = serializeError(agg);
    const errors = result.errors as unknown[];
    expect(errors[0]).toBe('string error');
    expect(errors[1]).toBe(42);
  });

  it('sets errors field only for AggregateError, not regular Error', () => {
    const err = new Error('regular');
    const result = serializeError(err);
    expect(result.errors).toBeUndefined();
  });
});

// ── serializeError — circular reference guard ────────────────────────────────

describe('serializeError — circular reference guard', () => {
  it('handles a directly self-referencing cause', () => {
    const err = new Error('circular') as Error & { cause?: unknown };
    err.cause = err; // self-reference

    // Should not throw / stack overflow
    const result = serializeError(err);
    expect(result.message).toBe('circular');
    // The cause should be detected as circular
    const cause = result.cause as Record<string, unknown>;
    expect(cause._circular).toBe(true);
  });
});

// ── serializeError — depth option ────────────────────────────────────────────

describe('serializeError — maxDepth option', () => {
  it('defaults to maxDepth=5', () => {
    // Build a chain of 4 levels — should all survive
    let err: Error = new Error('level-4');
    for (let i = 3; i >= 1; i--) {
      err = new Error(`level-${i}`, { cause: err });
    }
    const result = serializeError(err);
    // level-1 → cause → level-2 → cause → level-3 → cause → level-4
    const l2 = result.cause as Record<string, unknown>;
    const l3 = l2.cause as Record<string, unknown>;
    expect(l3).toBeDefined();
    expect((l3.cause as Record<string, unknown>).message).toBe('level-4');
  });

  it('respects a custom maxDepth of 2', () => {
    const deep = new Error('deep');
    const mid = new Error('mid', { cause: deep });
    const top = new Error('top', { cause: mid });

    const result = serializeError(top, { maxDepth: 2 });
    const cause1 = result.cause as Record<string, unknown>;
    expect(cause1.message).toBe('mid');
    // cause of mid is at depth=2 → truncated
    const cause2 = cause1.cause as Record<string, unknown>;
    expect(cause2._truncated).toBe(true);
  });
});

// ── isError ───────────────────────────────────────────────────────────────────

describe('isError', () => {
  it('returns true for a native Error', () => {
    expect(isError(new Error('x'))).toBe(true);
  });

  it('returns true for a custom error subclass', () => {
    class CustomError extends Error {}
    expect(isError(new CustomError('y'))).toBe(true);
  });

  it('returns true for an error-shaped plain object', () => {
    expect(isError({ name: 'MyError', message: 'oops' })).toBe(true);
  });

  it('returns false for a plain string', () => {
    expect(isError('error string')).toBe(false);
  });

  it('returns false for null', () => {
    expect(isError(null)).toBe(false);
  });

  it('returns false for undefined', () => {
    expect(isError()).toBe(false);
  });

  it('returns false for a number', () => {
    expect(isError(42)).toBe(false);
  });

  it('returns false for a plain object without name/message', () => {
    expect(isError({ code: 'ERR' })).toBe(false);
  });
});

// ── normalizeError ────────────────────────────────────────────────────────────

describe('normalizeError', () => {
  it('returns the same Error instance when given an Error', () => {
    const err = new Error('original');
    expect(normalizeError(err)).toBe(err);
  });

  it('wraps a string in a new Error', () => {
    const result = normalizeError('something broke');
    expect(result).toBeInstanceOf(Error);
    expect(result.message).toBe('something broke');
  });

  it('wraps an error-shaped object with a message', () => {
    const result = normalizeError({ message: 'db error', code: 'DB_ERR' });
    expect(result).toBeInstanceOf(Error);
    expect(result.message).toBe('db error');
  });

  it('wraps an object without a message using "Unknown error"', () => {
    const result = normalizeError({ code: 'UNKNOWN' });
    expect(result.message).toBe('Unknown error');
  });

  it('wraps null into an Error with String(null)', () => {
    const result = normalizeError(null);
    expect(result).toBeInstanceOf(Error);
    expect(result.message).toBe('null');
  });

  it('wraps undefined into an Error with String(undefined)', () => {
    const result = normalizeError();
    expect(result).toBeInstanceOf(Error);
    expect(result.message).toBe('undefined');
  });

  it('wraps a number into an Error', () => {
    const result = normalizeError(42);
    expect(result).toBeInstanceOf(Error);
    expect(result.message).toBe('42');
  });

  it('copies extra properties from object input onto the resulting Error', () => {
    const result = normalizeError({ message: 'fail', statusCode: 500 }) as Error & {
      statusCode?: number;
    };
    expect(result.statusCode).toBe(500);
  });

  it('handles a custom Error subclass as-is', () => {
    class ValidationError extends Error {
      constructor(msg: string) {
        super(msg);
        this.name = 'ValidationError';
      }
    }
    const ve = new ValidationError('invalid input');
    expect(normalizeError(ve)).toBe(ve);
  });
});

// ── serializeValue branch coverage ───────────────────────────────────────────
// These tests exercise serializeValue branches through own-property serialization.

describe('serializeError — serializeValue branch coverage', () => {
  it('handles an own property whose value is itself an Error (nested error in prop)', () => {
    const inner = new Error('inner error');
    const outer = Object.assign(new Error('outer'), { nested: inner });
    const result = serializeError(outer);
    // The 'nested' field should be a serialized Error object
    const nested = result.nested as Record<string, unknown>;
    expect(nested.message).toBe('inner error');
    expect(nested.name).toBe('Error');
  });

  it('handles an own property whose value is an Array', () => {
    const err = Object.assign(new Error('with array'), { tags: ['a', 'b', 'c'] });
    const result = serializeError(err);
    expect(result.tags).toEqual(['a', 'b', 'c']);
  });

  it('handles an own property whose value is a Symbol (stringified)', () => {
    const sym = Symbol('test-sym');
    const err = Object.assign(new Error('with symbol'), { sym });
    const result = serializeError(err);
    // Symbol falls through to String(value) → 'Symbol(test-sym)'
    expect(typeof result.sym).toBe('string');
    expect(result.sym).toContain('Symbol');
  });

  it('handles an own property with a BigInt value (stringified)', () => {
    // Use string-based BigInt constructor to avoid no-loss-of-precision lint rule
    const err = Object.assign(new Error('with bigint'), { count: BigInt('9007199254740993') });
    const result = serializeError(err);
    expect(typeof result.count).toBe('string');
  });

  it('handles an own property with a getter that throws (Unserializable)', () => {
    const err = new Error('bad getter');
    Object.defineProperty(err, 'explosive', {
      get() {
        throw new Error('getter blew up');
      },
      enumerable: true,
      configurable: true,
    });
    const result = serializeError(err);
    expect(result.explosive).toBe('[Unserializable]');
  });

  it('serializeValue returns [Max Depth] when remainingDepth is 0', () => {
    // Trigger via a very deep cause chain with maxDepth=1
    const inner = new Error('level-2');
    const outer = new Error('level-1', { cause: inner });
    // cause is at depth=1, which hits the maxDepth=1 guard
    const result = serializeError(outer, { maxDepth: 1 });
    expect((result.cause as Record<string, unknown>)._truncated).toBe(true);
  });

  it('serializeValue handles a Date inside own props', () => {
    const date = new Date('2024-06-15T00:00:00Z');
    const err = Object.assign(new Error('with date'), { createdAt: date });
    const result = serializeError(err);
    expect(result.createdAt).toBe(date.toISOString());
  });

  it('serializeValue handles null inside own props', () => {
    const err = Object.assign(new Error('with null'), { data: null });
    const result = serializeError(err);
    expect(result.data).toBeNull();
  });
});
