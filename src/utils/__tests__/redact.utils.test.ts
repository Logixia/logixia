/**
 * Comprehensive tests for the log redaction engine
 *
 * Covers: pathToRegExp logic (via matchesPath), redactObject (deep traversal),
 * applyRedaction (convenience wrapper), censor string, wildcard patterns,
 * arrays, nested objects, regex pattern redaction, and edge cases.
 */

import { applyRedaction, redactObject } from '../redact.utils';

// ── Helpers ───────────────────────────────────────────────────────────────────

const CENSOR = '[REDACTED]';

// ── redactObject — path-based redaction ──────────────────────────────────────

describe('redactObject — path-based redaction', () => {
  it('redacts a top-level exact path', () => {
    const result = redactObject({ password: 'secret', name: 'Alice' }, { paths: ['password'] });
    expect(result.password).toBe(CENSOR);
    expect(result.name).toBe('Alice');
  });

  it('redacts a nested dot-notation path', () => {
    const obj = { user: { password: 'secret', email: 'a@b.com' } };
    const result = redactObject(obj, { paths: ['user.password'] });
    expect((result.user as Record<string, unknown>).password).toBe(CENSOR);
    expect((result.user as Record<string, unknown>).email).toBe('a@b.com');
  });

  it('redacts using * wildcard matching exactly one segment', () => {
    // '*.authorization' matches <ONE_SEGMENT>.authorization
    // 'meta.authorization' → one segment + authorization → matches ✓
    // 'req.headers.authorization' → two segments before authorization → does NOT match *
    const obj = { meta: { authorization: 'key' }, config: { authorization: 'cfg-key' } };
    const result = redactObject(obj, { paths: ['*.authorization'] });
    expect((result.meta as Record<string, unknown>).authorization).toBe(CENSOR);
    expect((result.config as Record<string, unknown>).authorization).toBe(CENSOR);
  });

  it('* wildcard only matches exactly one segment (not two)', () => {
    const obj = { a: { b: { c: 'deep' } } };
    // '*.c' should NOT match 'a.b.c' because * only spans one segment
    const result = redactObject(obj, { paths: ['*.c'] });
    expect((result.a as Record<string, unknown>).b).toEqual({ c: 'deep' });
  });

  it('redacts using ** wildcard matching any depth', () => {
    const obj = { x: { y: { z: 'secret' } } };
    const result = redactObject(obj, { paths: ['**'] });
    // ** at root means "any full path", which matches x too
    expect(result.x).toBe(CENSOR);
  });

  it('redacts a deeply nested path (3+ levels)', () => {
    const obj = { a: { b: { c: { token: 'abc' } } } };
    const result = redactObject(obj, { paths: ['a.b.c.token'] });
    expect(((result.a as Record<string, unknown>).b as Record<string, unknown>).c).toEqual({
      token: CENSOR,
    });
  });

  it('uses a custom censor string', () => {
    const result = redactObject({ ssn: '123-45-6789' }, { paths: ['ssn'], censor: '***' });
    expect(result.ssn).toBe('***');
  });

  it('does not mutate the original object', () => {
    const original = { user: { password: 'secret' } };
    redactObject(original, { paths: ['user.password'] });
    expect((original.user as Record<string, unknown>).password).toBe('secret');
  });

  it('leaves non-matching fields untouched', () => {
    const obj = { name: 'Bob', age: 30 };
    const result = redactObject(obj, { paths: ['password'] });
    expect(result).toEqual({ name: 'Bob', age: 30 });
  });

  it('handles multiple paths at once', () => {
    const obj = { user: 'alice', password: 'pass', token: 'tok' };
    const result = redactObject(obj, { paths: ['password', 'token'] });
    expect(result.password).toBe(CENSOR);
    expect(result.token).toBe(CENSOR);
    expect(result.user).toBe('alice');
  });

  it('redacts numeric values at matching paths', () => {
    const obj = { account: { pin: 1234 } };
    const result = redactObject(obj, { paths: ['account.pin'] });
    expect((result.account as Record<string, unknown>).pin).toBe(CENSOR);
  });

  it('redacts boolean values at matching paths', () => {
    const obj = { flags: { isAdmin: true } };
    const result = redactObject(obj, { paths: ['flags.isAdmin'] });
    expect((result.flags as Record<string, unknown>).isAdmin).toBe(CENSOR);
  });
});

// ── redactObject — pattern-based redaction ───────────────────────────────────

describe('redactObject — pattern-based redaction', () => {
  it('applies a regex pattern to string values', () => {
    const obj = { message: 'Token is Bearer abc123' };
    const result = redactObject(obj, { patterns: [/Bearer\s+\S+/gi] });
    expect(result.message).toBe(`Token is ${CENSOR}`);
  });

  it('applies multiple regex patterns to a single string', () => {
    const obj = { log: 'sk-abc1234567890123456789012345678901234 and password=secret' };
    const result = redactObject(obj, {
      patterns: [/sk-[a-z0-9]{32,}/gi, /password=\S+/gi],
    });
    expect(result.log).toContain(CENSOR);
    expect(result.log).not.toContain('sk-abc');
    expect(result.log).not.toContain('password=secret');
  });

  it('pattern redaction does not affect non-string values', () => {
    const obj = { count: 42, flag: true };
    const result = redactObject(obj, { patterns: [/\d+/g] });
    expect(result.count).toBe(42);
    expect(result.flag).toBe(true);
  });

  it('pattern redaction applies inside nested objects', () => {
    const obj = { headers: { authorization: 'Bearer my-token-here' } };
    const result = redactObject(obj, { patterns: [/Bearer\s+\S+/gi] });
    expect((result.headers as Record<string, unknown>).authorization).toBe(`${CENSOR}`);
  });

  it('uses a custom censor string for pattern replacement', () => {
    const obj = { token: 'Bearer abc' };
    const result = redactObject(obj, { patterns: [/Bearer\s+\S+/gi], censor: '<TOKEN>' });
    expect(result.token).toBe('<TOKEN>');
  });
});

// ── redactObject — array handling ─────────────────────────────────────────────

describe('redactObject — array handling', () => {
  it('recurses into array items that are plain objects', () => {
    const obj = {
      users: [
        { name: 'Alice', password: 'pass1' },
        { name: 'Bob', password: 'pass2' },
      ],
    };
    const result = redactObject(obj, { paths: ['users.password'] });
    const users = result.users as Array<Record<string, unknown>>;
    expect(users[0]!.password).toBe(CENSOR);
    expect(users[1]!.password).toBe(CENSOR);
    expect(users[0]!.name).toBe('Alice');
  });

  it('applies pattern redaction to string items in an array', () => {
    const obj = { tokens: ['Bearer tok1', 'plain text', 'Bearer tok2'] };
    const result = redactObject(obj, { patterns: [/Bearer\s+\S+/gi] });
    const tokens = result.tokens as string[];
    expect(tokens[0]).toBe(CENSOR);
    expect(tokens[1]).toBe('plain text');
    expect(tokens[2]).toBe(CENSOR);
  });

  it('passes through non-string, non-object array items as-is', () => {
    const obj = { ids: [1, 2, 3] };
    const result = redactObject(obj, { patterns: [/\d+/g] });
    expect(result.ids).toEqual([1, 2, 3]);
  });

  it('handles empty arrays without error', () => {
    const obj = { tags: [] as unknown[] };
    const result = redactObject(obj, { paths: ['tags'] });
    // 'tags' itself is an array (not a plain obj), so path redaction hits it
    expect(result.tags).toBe(CENSOR);
  });
});

// ── redactObject — special value pass-through ────────────────────────────────

describe('redactObject — special value pass-through', () => {
  it('passes Date objects through without modification', () => {
    const date = new Date('2024-01-01');
    const obj = { createdAt: date };
    const result = redactObject(obj, { paths: ['something.else'] });
    expect(result.createdAt).toBe(date);
  });

  it('passes Error objects through without modification', () => {
    const err = new Error('oops');
    const obj = { lastError: err };
    const result = redactObject(obj, { paths: ['something.else'] });
    expect(result.lastError).toBe(err);
  });

  it('passes null values through', () => {
    const obj = { value: null };
    const result = redactObject(obj as Record<string, unknown>, { paths: ['other'] });
    expect(result.value).toBeNull();
  });

  it('handles objects with no matching paths or patterns (identity-like)', () => {
    const obj = { a: 1, b: 'hello', c: true };
    const result = redactObject(obj, { paths: ['x.y.z'] });
    expect(result).toEqual({ a: 1, b: 'hello', c: true });
  });
});

// ── applyRedaction — convenience wrapper ─────────────────────────────────────

describe('applyRedaction', () => {
  it('returns undefined when payload is undefined', () => {
    expect(applyRedaction(undefined, { paths: ['password'] })).toBeUndefined();
  });

  it('returns payload as-is when config is undefined', () => {
    const obj = { password: 'secret' };
    expect(applyRedaction(obj)).toBe(obj);
  });

  it('returns payload as-is when both paths and patterns are empty', () => {
    const obj = { password: 'secret' };
    expect(applyRedaction(obj, { paths: [], patterns: [] })).toBe(obj);
  });

  it('returns payload as-is when config has no paths or patterns keys', () => {
    const obj = { password: 'secret' };
    expect(applyRedaction(obj, {})).toBe(obj);
  });

  it('applies redaction when paths are provided', () => {
    const obj = { password: 'secret', name: 'Alice' };
    const result = applyRedaction(obj, { paths: ['password'] });
    expect(result!.password).toBe(CENSOR);
    expect(result!.name).toBe('Alice');
  });

  it('applies redaction when patterns are provided', () => {
    const obj = { auth: 'Bearer tok' };
    const result = applyRedaction(obj, { patterns: [/Bearer\s+\S+/gi] });
    expect(result!.auth).toBe(CENSOR);
  });

  it('returns a new object, never the original', () => {
    const obj = { password: 'secret' };
    const result = applyRedaction(obj, { paths: ['password'] });
    expect(result).not.toBe(obj);
  });

  it('does not redact when paths array has entries but none match', () => {
    const obj = { name: 'Bob' };
    const result = applyRedaction(obj, { paths: ['password'] });
    expect(result!.name).toBe('Bob');
  });
});

// ── Pattern cache ─────────────────────────────────────────────────────────────

describe('path pattern cache', () => {
  it('hitting the same pattern multiple times produces consistent results', () => {
    const config = { paths: ['user.token'] };
    const obj1 = { user: { token: 'abc', name: 'Alice' } };
    const obj2 = { user: { token: 'xyz', name: 'Bob' } };

    const r1 = redactObject(obj1, config);
    const r2 = redactObject(obj2, config);

    expect((r1.user as Record<string, unknown>).token).toBe(CENSOR);
    expect((r2.user as Record<string, unknown>).token).toBe(CENSOR);
  });
});
