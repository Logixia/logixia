import {
  buildNameSet,
  DEFAULT_REDACT_QUERY_PARAMS,
  redactUrlsInText,
  scrubValues,
  sensitiveQueryValues,
} from '../sensitive-names';

const names = buildNameSet(DEFAULT_REDACT_QUERY_PARAMS, undefined);

describe('sensitiveQueryValues', () => {
  it('returns raw and decoded values of sensitive params only', () => {
    const values = sensitiveQueryValues('/a?token=a%20b%26c&page=12345&api_key=zzz999', names);
    expect(values).toEqual(expect.arrayContaining(['a%20b%26c', 'a b&c', 'zzz999']));
    expect(values).not.toContain('12345');
  });

  it('ignores short and already redacted values and urls without a query', () => {
    expect(sensitiveQueryValues('/a?token=ab&code=[REDACTED]', names)).toEqual([]);
    expect(sensitiveQueryValues('/a', names)).toEqual([]);
  });

  it('matches names case-insensitively', () => {
    expect(sensitiveQueryValues('/a?X-Amz-Signature=sig123', names)).toEqual(['sig123']);
  });
});

describe('scrubValues', () => {
  it('replaces every literal occurrence, longest first, with no regex semantics', () => {
    expect(scrubValues('a.*b a.*b abc', ['a.*b', 'abc'])).toBe('[REDACTED] [REDACTED] [REDACTED]');
    expect(scrubValues('xyz', [])).toBe('xyz');
  });
});

describe('redactUrlsInText', () => {
  it('redacts each query in free text up to whitespace or a quote', () => {
    expect(redactUrlsInText('GET /a?token=abc123&x=1 then "/b?code=zz1" end', names)).toBe(
      'GET /a?token=[REDACTED]&x=1 then "/b?code=[REDACTED]" end'
    );
  });

  it('is linear on pathological input', () => {
    const text = '?'.repeat(50_000);
    const start = Date.now();
    redactUrlsInText(text, names);
    expect(Date.now() - start).toBeLessThan(1000);
  });
});

describe('DEFAULT_REDACT_QUERY_PARAMS', () => {
  it.each([
    'accesstoken',
    'refreshtoken',
    'id_token',
    'client_secret',
    'sessionid',
    'jwt',
    'x-api-key',
    'x-amz-signature',
    'x-amz-security-token',
    'x-goog-signature',
    'x-goog-credential',
  ])('includes %s', (name) => {
    expect(names.has(name)).toBe(true);
  });
});
