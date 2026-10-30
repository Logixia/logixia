import { createExpressContextMiddleware, LogixiaContext } from '../../context/async-context';
import { extractTraceId, generateTraceId, sanitizeIncomingId } from '../trace.utils';

describe('sanitizeIncomingId', () => {
  it('accepts safe ids and trims surrounding whitespace', () => {
    expect(sanitizeIncomingId('abc-123_x.y:z')).toBe('abc-123_x.y:z');
    expect(sanitizeIncomingId('  abc  ')).toBe('abc');
    expect(sanitizeIncomingId(['first', 'second'])).toBe('first');
  });

  it.each([
    ['CRLF', 'a\r\nb'],
    ['escape', '\u001b[2J'],
    ['space', 'a b'],
    ['empty', ''],
    ['too long', 'x'.repeat(129)],
    ['huge', 'x'.repeat(16 * 1024)],
  ])('rejects %s', (_n, v) => {
    expect(sanitizeIncomingId(v)).toBeUndefined();
  });

  it('rejects non-strings', () => {
    expect(sanitizeIncomingId(42)).toBeUndefined();
    expect(sanitizeIncomingId()).toBeUndefined();
  });
});

describe('extractTraceId with hostile values', () => {
  it('ignores invalid header/query/body values', () => {
    expect(
      extractTraceId({ headers: { 'x-trace-id': 'a\nb' } }, { header: 'x-trace-id' })
    ).toBeUndefined();
    expect(extractTraceId({ query: { t: 'x'.repeat(200) } }, { query: 't' })).toBeUndefined();
    expect(extractTraceId({ body: { t: '\u001b]0;x' } }, { body: 't' })).toBeUndefined();
  });

  it('still parses W3C traceparent', () => {
    const tid = 'a'.repeat(32);
    expect(
      extractTraceId(
        { headers: { traceparent: `00-${tid}-${'b'.repeat(16)}-01` } },
        { header: 'traceparent' }
      )
    ).toBe(tid);
  });
});

describe('generateTraceId', () => {
  it('returns a UUID v4', () => {
    expect(generateTraceId()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab]/i);
  });
});

describe('createExpressContextMiddleware trace id', () => {
  it('replaces an unsafe incoming trace id with a generated one', () => {
    let seen: string | undefined;
    createExpressContextMiddleware()({ headers: { 'x-trace-id': 'a\r\nb' } }, {}, () => {
      seen = LogixiaContext.get()?.traceId;
    });
    expect(seen).toMatch(/^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/);
  });

  it('keeps a valid incoming trace id', () => {
    let seen: string | undefined;
    createExpressContextMiddleware()({ headers: { 'x-trace-id': 'ok-1' } }, {}, () => {
      seen = LogixiaContext.get()?.traceId;
    });
    expect(seen).toBe('ok-1');
  });
});

describe('LogixiaContext.set', () => {
  it('ignores prototype keys', () => {
    LogixiaContext.run({ a: 1 }, () => {
      LogixiaContext.set(JSON.parse('{"__proto__":{"polluted":"yes"},"b":2}'));
      const ctx = LogixiaContext.get() as Record<string, unknown>;
      expect(ctx.b).toBe(2);
      expect(ctx.polluted).toBeUndefined();
    });
  });
});
