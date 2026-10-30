import { applyRedaction, applyRedactionToString, redactObject } from '../redact.utils';

const PATHS = { paths: ['**.password', '**.token', '**.authorization'] };

describe('redaction depth and size bounds', () => {
  it('does not overflow the stack on very deeply nested arrays', () => {
    const body = JSON.parse('['.repeat(30_000) + ']'.repeat(30_000)) as unknown;
    const out = applyRedaction({ body }, PATHS);
    expect(JSON.stringify(out)).toContain('[MaxDepth]');
  });

  it('does not overflow the stack on deeply nested objects', () => {
    let deep: Record<string, unknown> = { password: 'x' };
    for (let i = 0; i < 5000; i++) deep = { n: deep };
    expect(() => redactObject({ deep }, PATHS)).not.toThrow();
  });

  it('caps the number of visited nodes', () => {
    const big = Array.from({ length: 50_000 }, () => ({ a: 1 }));
    const out = redactObject({ big }, PATHS);
    expect((out.big as unknown[]).includes('[MaxNodes]')).toBe(true);
  });

  it('truncates oversized strings instead of emitting them unscanned', () => {
    const text = 'x'.repeat(20_000) + 'Bearer abc123';
    const out = applyRedactionToString(text, { patterns: [/Bearer\s+\S+/g] });
    expect(out).not.toContain('abc123');
    expect(out).toContain('unscanned');
  });
});

describe('applyRedactionToString coercion', () => {
  const cfg = { autoDetect: true as const };
  it.each([[{ a: 1 }], [['a', 'b']], [42], [null], [undefined]])('accepts %p', (input) => {
    expect(() => applyRedactionToString(input, cfg)).not.toThrow();
    expect(typeof applyRedactionToString(input, cfg)).toBe('string');
  });

  it('still redacts secrets inside a coerced object', () => {
    const out = applyRedactionToString({ h: 'Bearer secrettoken123' }, cfg);
    expect(out).not.toContain('secrettoken123');
  });
});

describe('pattern scanning runs in linear time', () => {
  const crafted: [string, 'conservative' | 'aggressive', string][] = [
    ['aws-like a/', 'conservative', 'a/'.repeat(25_000)],
    ['jwt-like eyJ', 'conservative', 'eyJ'.repeat(17_000)],
    ['email-like a.', 'aggressive', 'a.'.repeat(25_000)],
    ['jwt dotted', 'conservative', 'eyJ.'.repeat(12_500)],
    ['digits', 'aggressive', '1 '.repeat(25_000)],
  ];
  it.each(crafted)('%s input of ~50KB redacts in under 100ms', (_n, mode, input) => {
    const start = process.hrtime.bigint();
    applyRedaction({ v: input }, { autoDetect: mode });
    const ms = Number(process.hrtime.bigint() - start) / 1e6;
    expect(ms).toBeLessThan(100);
  });

  it('still redacts JWTs, emails and AWS secrets', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.c2lnbmF0dXJl';
    const aws = 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    const out = applyRedaction(
      { a: jwt, b: aws, c: 'mail bob@example.com now' },
      { autoDetect: 'aggressive' }
    ) as Record<string, string>;
    expect(out.a).toBe('[REDACTED]');
    expect(out.b).not.toContain('wJalrXUtnFEMI');
    expect(out.c).not.toContain('bob@example.com');
  });
});

describe('redaction of values previously treated as opaque', () => {
  it('redacts own properties of nested Errors', () => {
    const err = new Error('boom') as Error & Record<string, unknown>;
    err.token = 'ERRTOK';
    err.password = 'ERRPW';
    err.config = { headers: { authorization: 'Bearer ERRBEARER' } };
    const json = JSON.stringify(applyRedaction({ err }, PATHS));
    expect(json).not.toMatch(/ERRTOK|ERRPW|ERRBEARER/);
    expect(json).toContain('boom');
  });

  it('redacts Error subclasses and their cause chain', () => {
    class HttpError extends Error {
      password = 'SUBPW';
    }
    const cause = Object.assign(new Error('inner'), { token: 'CAUSETOK' });
    const err = new HttpError('outer', { cause });
    const json = JSON.stringify(applyRedaction({ err }, PATHS));
    expect(json).not.toMatch(/SUBPW|CAUSETOK/);
    expect(json).toContain('inner');
  });

  it('redacts the toJSON() result of objects that define it', () => {
    class AxiosLike extends Error {
      toJSON() {
        return { config: { headers: { authorization: 'Bearer AXTOK' } }, password: 'TJPW' };
      }
    }
    const plain = { toJSON: () => ({ password: 'PLAINPW', ok: 1 }) };
    const json = JSON.stringify(applyRedaction({ e: new AxiosLike('x'), plain }, PATHS));
    expect(json).not.toMatch(/AXTOK|TJPW|PLAINPW/);
    expect(json).toContain('"ok":1');
  });

  it('fails closed when toJSON throws', () => {
    const bad = {
      toJSON() {
        throw new Error('nope');
      },
    };
    const out = applyRedaction({ bad }, PATHS) as Record<string, unknown>;
    expect(out.bad).toBe('[RedactionFailed]');
  });

  it('strips credentials from URL instances and applies patterns', () => {
    const url = new URL('https://user:pass@example.com/x?k=Bearer%20abc');
    const out = applyRedaction({ url }, { patterns: [/example/g], paths: ['nothing'] }) as {
      url: unknown;
    };
    expect(String(out.url)).not.toContain('pass');
    expect(String(out.url)).not.toContain('example');
  });

  it('keeps clean URL instances untouched', () => {
    const url = new URL('https://example.com/a');
    const out = redactObject({ url }, { patterns: [/zzz/g] });
    expect(out.url).toBe(url);
  });
});

describe('auto-detect paths', () => {
  it.each([
    'cookie',
    'set-cookie',
    'x-api-key',
    'session',
    'proxy-authorization',
    'x-auth-token',
    'x-access-token',
  ])('redacts %s by name', (name) => {
    const out = applyRedaction({ headers: { [name]: 'SECRETVAL' } }, { autoDetect: true });
    expect(JSON.stringify(out)).not.toContain('SECRETVAL');
  });
});
