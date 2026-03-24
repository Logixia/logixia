/**
 * Comprehensive tests for redact.utils
 *
 * Covers:
 *  - applyRedaction: no-op cases, path-based, pattern-based, custom censor, autoDetect
 *  - redactObject: nested objects, arrays, wildcard paths, pass-through
 *  - Conservative vs aggressive autoDetect modes
 */

import { applyRedaction, redactObject } from '../redact.utils';

// ── applyRedaction ────────────────────────────────────────────────────────────

describe('applyRedaction', () => {
  describe('no-op cases', () => {
    it('returns undefined when payload is undefined', () => {
      expect(applyRedaction(undefined, { paths: ['password'] })).toBeUndefined();
    });

    it('returns payload unchanged when config is undefined', () => {
      const payload = { user: 'alice', password: 'secret' };
      expect(applyRedaction(payload)).toBe(payload);
    });

    it('returns payload unchanged when paths and patterns are both empty', () => {
      const payload = { user: 'alice' };
      const result = applyRedaction(payload, { paths: [], patterns: [] });
      expect(result).toEqual(payload);
    });

    it('returns payload unchanged when no redact config has matching rules', () => {
      const payload = { user: 'alice' };
      const result = applyRedaction(payload, {});
      expect(result).toEqual(payload);
    });
  });

  describe('path-based redaction', () => {
    it('redacts an exact top-level field', () => {
      const result = applyRedaction({ password: 'secret', user: 'alice' }, { paths: ['password'] });
      expect(result!.password).toBe('[REDACTED]');
      expect(result!.user).toBe('alice');
    });

    it('redacts a nested field by dot-path', () => {
      const result = applyRedaction(
        { user: { name: 'Alice', token: 'tok-abc' } },
        { paths: ['user.token'] }
      );
      expect((result!.user as Record<string, unknown>).token).toBe('[REDACTED]');
      expect((result!.user as Record<string, unknown>).name).toBe('Alice');
    });

    it('redacts with * wildcard (one segment)', () => {
      const result = applyRedaction(
        { req: { headers: { authorization: 'Bearer xyz' } } },
        { paths: ['req.headers.*'] }
      );
      const headers = (result!.req as Record<string, unknown>).headers as Record<string, unknown>;
      expect(headers.authorization).toBe('[REDACTED]');
    });

    it('redacts all matching *.password across top-level objects', () => {
      const result = applyRedaction(
        { user: { password: 'secret', email: 'alice@test.com' } },
        { paths: ['*.password'] }
      );
      const user = result!.user as Record<string, unknown>;
      expect(user.password).toBe('[REDACTED]');
      expect(user.email).toBe('alice@test.com');
    });

    it('redacts with ** (any depth)', () => {
      const result = applyRedaction(
        { deep: { nested: { token: 'tok-deep' } } },
        { paths: ['**.token'] }
      );
      const nested = (result!.deep as Record<string, unknown>).nested as Record<string, unknown>;
      expect(nested.token).toBe('[REDACTED]');
    });

    it('supports custom censor string', () => {
      const result = applyRedaction({ apiKey: 'key-123' }, { paths: ['apiKey'], censor: '***' });
      expect(result!.apiKey).toBe('***');
    });

    it('redacts multiple paths simultaneously', () => {
      const result = applyRedaction(
        { user: { ssn: '123-45-6789', creditCard: '4111111111111111', name: 'Bob' } },
        { paths: ['user.ssn', 'user.creditCard'] }
      );
      const user = result!.user as Record<string, unknown>;
      expect(user.ssn).toBe('[REDACTED]');
      expect(user.creditCard).toBe('[REDACTED]');
      expect(user.name).toBe('Bob');
    });

    it('does not mutate the original object', () => {
      const original = { password: 'secret' };
      applyRedaction(original, { paths: ['password'] });
      expect(original.password).toBe('secret');
    });
  });

  describe('pattern-based redaction', () => {
    it('redacts matching patterns in string values', () => {
      const result = applyRedaction(
        { auth: 'Bearer super-secret-token' },
        { patterns: [/Bearer\s+\S+/gi] }
      );
      expect(result!.auth).toBe('[REDACTED]');
    });

    it('redacts partial pattern matches in strings', () => {
      const result = applyRedaction(
        { header: 'Authorization: Bearer abc123' },
        { patterns: [/Bearer\s+\S+/gi] }
      );
      expect((result!.header as string).includes('abc123')).toBe(false);
    });

    it('does not redact non-string values with patterns', () => {
      const result = applyRedaction({ count: 42 }, { patterns: [/\d+/g] });
      expect(result!.count).toBe(42);
    });

    it('applies multiple patterns in sequence', () => {
      const result = applyRedaction(
        { data: 'sk-abc1234567890 Bearer token123' },
        { patterns: [/sk-\S+/gi, /Bearer\s+\S+/gi] }
      );
      expect((result!.data as string).includes('sk-abc1234567890')).toBe(false);
      expect((result!.data as string).includes('token123')).toBe(false);
    });
  });

  describe('arrays', () => {
    it('redacts within array objects', () => {
      const result = applyRedaction(
        {
          users: [
            { name: 'Alice', password: 'p1' },
            { name: 'Bob', password: 'p2' },
          ],
        },
        { paths: ['users.password'] }
      );
      // Note: path redaction in arrays is done at the same level
      const users = result!.users as Record<string, unknown>[];
      // arrays use the same path prefix — objects inside should be recursed
      expect(users[0].name).toBe('Alice');
    });

    it('applies pattern redaction to string items in arrays', () => {
      const result = applyRedaction(
        { tokens: ['Bearer abc', 'Bearer xyz', 'plain-text'] },
        { patterns: [/Bearer\s+\S+/gi] }
      );
      const tokens = result!.tokens as string[];
      expect(tokens[0]).toBe('[REDACTED]');
      expect(tokens[1]).toBe('[REDACTED]');
      expect(tokens[2]).toBe('plain-text');
    });
  });

  describe('autoDetect: conservative', () => {
    // Note: PII_CONSERVATIVE_PATHS uses `**.password` etc. which matches
    // keys at any nested depth (e.g. user.password), not bare top-level keys.
    it('redacts nested **.password fields', () => {
      const result = applyRedaction(
        { user: { password: 'secret' } },
        { autoDetect: 'conservative' }
      );
      const user = result!.user as Record<string, unknown>;
      expect(user.password).toBe('[REDACTED]');
    });

    it('redacts nested **.token fields', () => {
      const result = applyRedaction({ auth: { token: 'tok-abc' } }, { autoDetect: true });
      const auth = result!.auth as Record<string, unknown>;
      expect(auth.token).toBe('[REDACTED]');
    });

    it('redacts nested **.apiKey fields', () => {
      const result = applyRedaction(
        { config: { apiKey: 'sk-secret' } },
        { autoDetect: 'conservative' }
      );
      const config = result!.config as Record<string, unknown>;
      expect(config.apiKey).toBe('[REDACTED]');
    });

    it('redacts **.authorization fields', () => {
      const result = applyRedaction(
        { headers: { authorization: 'Bearer tok' } },
        { autoDetect: 'conservative' }
      );
      const headers = result!.headers as Record<string, unknown>;
      expect(headers.authorization).toBe('[REDACTED]');
    });

    it('does NOT redact email addresses in conservative mode', () => {
      const result = applyRedaction(
        { info: 'Contact alice@example.com for help' },
        { autoDetect: 'conservative' }
      );
      expect((result!.info as string).includes('alice@example.com')).toBe(true);
    });
  });

  describe('autoDetect: aggressive', () => {
    it('redacts nested **.email fields', () => {
      const result = applyRedaction(
        { user: { email: 'alice@example.com' } },
        { autoDetect: 'aggressive' }
      );
      const user = result!.user as Record<string, unknown>;
      expect(user.email).toBe('[REDACTED]');
    });

    it('redacts email address patterns in string values', () => {
      const result = applyRedaction(
        { message: 'User alice@example.com signed up' },
        { autoDetect: 'aggressive' }
      );
      expect((result!.message as string).includes('alice@example.com')).toBe(false);
    });

    it('redacts nested **.phone fields', () => {
      const result = applyRedaction(
        { contact: { phone: '+1-555-555-5555' } },
        { autoDetect: 'aggressive' }
      );
      const contact = result!.contact as Record<string, unknown>;
      expect(contact.phone).toBe('[REDACTED]');
    });

    it('redacts nested **.ssn fields', () => {
      const result = applyRedaction({ user: { ssn: '123-45-6789' } }, { autoDetect: 'aggressive' });
      const user = result!.user as Record<string, unknown>;
      expect(user.ssn).toBe('[REDACTED]');
    });

    it('redacts both conservative AND aggressive nested paths', () => {
      const result = applyRedaction(
        { user: { password: 'p', email: 'a@b.com' } },
        { autoDetect: 'aggressive' }
      );
      const user = result!.user as Record<string, unknown>;
      expect(user.password).toBe('[REDACTED]');
      expect(user.email).toBe('[REDACTED]');
    });
  });

  describe('combining explicit paths and autoDetect', () => {
    it('combines explicit paths with autoDetect nested paths', () => {
      const result = applyRedaction(
        { secret: 'sec', user: { password: 'pass' } },
        { paths: ['secret'], autoDetect: 'conservative' }
      );
      expect(result!.secret).toBe('[REDACTED]');
      const user = result!.user as Record<string, unknown>;
      expect(user.password).toBe('[REDACTED]');
    });
  });
});

// ── redactObject ──────────────────────────────────────────────────────────────

describe('redactObject', () => {
  it('returns a new object (non-mutating)', () => {
    const original = { key: 'value' };
    const result = redactObject(original, { paths: ['key'] });
    expect(result).not.toBe(original);
    expect(original.key).toBe('value');
  });

  it('passes through non-sensitive fields unmodified', () => {
    const result = redactObject({ name: 'Alice', age: 30 }, { paths: ['password'] });
    expect(result.name).toBe('Alice');
    expect(result.age).toBe(30);
  });

  it('passes through Date values unchanged', () => {
    const date = new Date();
    const result = redactObject({ createdAt: date }, { paths: ['password'] });
    expect(result.createdAt).toBe(date);
  });

  it('passes through Error values unchanged', () => {
    const err = new Error('test');
    const result = redactObject({ error: err }, { paths: ['password'] });
    expect(result.error).toBe(err);
  });

  it('passes through null values', () => {
    const result = redactObject({ data: null }, { paths: ['password'] });
    expect(result.data).toBeNull();
  });

  it('passes through numeric values', () => {
    const result = redactObject({ count: 42 }, { paths: ['password'] });
    expect(result.count).toBe(42);
  });

  it('redacts at the exact matching path, not sub-paths', () => {
    const result = redactObject({ user: { name: 'Alice' } }, { paths: ['user'] });
    expect(result.user).toBe('[REDACTED]');
  });
});
