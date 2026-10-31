/**
 * Regression test: the correlation helpers must find the incoming correlation
 * ID when the `header` option is passed in mixed case (e.g. `X-Correlation-ID`).
 * Node lower-cases incoming header names, so the lookup has to be lower-cased too.
 *
 * Incoming IDs are also validated: over-long or newline-containing values are
 * dropped and a fresh ID is generated instead.
 */

import { LogixiaContext } from '../context/async-context';
import { childFromRequest, correlationMiddleware } from '../correlation';

interface FakeLogger {
  child(ctx: Record<string, unknown>): FakeLogger;
}

function runMiddleware(
  options: Parameters<typeof correlationMiddleware>[0],
  headers: Record<string, string>
): unknown {
  const middleware = correlationMiddleware(options);
  let seen: unknown;

  middleware({ headers }, { setHeader: jest.fn() }, () => {
    seen = LogixiaContext.get()?.correlationId;
  });

  return seen;
}

describe('correlationMiddleware header lookup', () => {
  it('reads an incoming ID when the header option is mixed case', () => {
    const seen = runMiddleware(
      { header: 'X-Correlation-ID' },
      { 'x-correlation-id': 'incoming-abc-123' }
    );

    expect(seen).toBe('incoming-abc-123');
  });

  it('replaces an over-long or newline-containing incoming ID', () => {
    const tooLong = 'a'.repeat(129);
    const withNewline = 'abc\ndef';

    expect(runMiddleware({}, { 'x-correlation-id': tooLong })).not.toBe(tooLong);
    expect(runMiddleware({}, { 'x-correlation-id': withNewline })).not.toBe(withNewline);
  });
});

describe('childFromRequest header lookup', () => {
  it('reads an incoming ID when the correlationHeader option is mixed case', () => {
    const childCtx: Record<string, unknown>[] = [];
    const logger: FakeLogger = {
      child(ctx) {
        childCtx.push(ctx);
        return logger;
      },
    };

    childFromRequest({ headers: { 'x-correlation-id': 'incoming-abc-123' } }, logger, {
      correlationHeader: 'X-Correlation-ID',
    });

    expect(childCtx[0]?.['correlationId']).toBe('incoming-abc-123');
  });
});

describe('childFromRequest url redaction', () => {
  const capture = (req: Record<string, unknown>, options = {}) => {
    const childCtx: Record<string, unknown>[] = [];
    const logger: FakeLogger = {
      child(ctx) {
        childCtx.push(ctx);
        return logger;
      },
    };
    childFromRequest(req, logger, options);
    return childCtx[0];
  };

  it('redacts sensitive query values and prefers originalUrl', () => {
    const ctx = capture({ url: '/r?token=abc123', originalUrl: '/api/r?token=abc123&page=2' });
    expect(ctx?.['url']).toBe('/api/r?token=[REDACTED]&page=2');
  });

  it('honours redactQueryParams', () => {
    const ctx = capture({ url: '/j?invite=magic77' }, { redactQueryParams: ['invite'] });
    expect(ctx?.['url']).toBe('/j?invite=[REDACTED]');
  });
});
