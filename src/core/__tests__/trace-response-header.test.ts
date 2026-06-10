/**
 * resolveResponseHeader() — configurable response header for the trace ID.
 *
 * Contract:
 *  - `undefined` config        → default `'X-Trace-Id'`
 *  - `{ responseHeader: 'X' }` → that string
 *  - `{ responseHeader: false }` → `null` (suppress header entirely)
 */

import {
  DEFAULT_TRACE_RESPONSE_HEADER,
  resolveResponseHeader,
  traceMiddleware,
} from '../trace.middleware';

describe('resolveResponseHeader', () => {
  it('returns the default header name when config is undefined', () => {
    expect(resolveResponseHeader()).toBe(DEFAULT_TRACE_RESPONSE_HEADER);
  });

  it('returns the default header name when config has no responseHeader', () => {
    expect(resolveResponseHeader({ enabled: true })).toBe(DEFAULT_TRACE_RESPONSE_HEADER);
  });

  it('returns a user-configured header name', () => {
    expect(resolveResponseHeader({ enabled: true, responseHeader: 'X-Correlation-ID' })).toBe(
      'X-Correlation-ID'
    );
  });

  it('returns null when responseHeader is explicitly false (suppress)', () => {
    expect(resolveResponseHeader({ enabled: true, responseHeader: false })).toBeNull();
  });
});

describe('traceMiddleware — response-API robustness', () => {
  const mkReq = () =>
    ({ method: 'GET', url: '/', headers: {}, get: () => '', ip: '' }) as unknown as Parameters<
      ReturnType<typeof traceMiddleware>
    >[0];
  const asRes = (r: unknown) => r as Parameters<ReturnType<typeof traceMiddleware>>[1];

  it('uses res.setHeader on an Express-style response', () => {
    const mw = traceMiddleware();
    const setHeader = jest.fn();
    let nextCalled = false;
    mw(mkReq(), asRes({ setHeader }), () => {
      nextCalled = true;
    });
    expect(setHeader).toHaveBeenCalledWith(DEFAULT_TRACE_RESPONSE_HEADER, expect.any(String));
    expect(nextCalled).toBe(true);
  });

  it('falls back to reply.header on a Fastify-style response (no setHeader)', () => {
    const mw = traceMiddleware();
    const header = jest.fn();
    mw(mkReq(), asRes({ header }), () => {});
    expect(header).toHaveBeenCalledWith(DEFAULT_TRACE_RESPONSE_HEADER, expect.any(String));
  });

  it('does not throw when the response has no header method and still calls next', () => {
    const mw = traceMiddleware();
    let nextCalled = false;
    expect(() =>
      mw(mkReq(), asRes({}), () => {
        nextCalled = true;
      })
    ).not.toThrow();
    expect(nextCalled).toBe(true);
  });

  it('skips setting the header when headers are already sent', () => {
    const mw = traceMiddleware();
    const setHeader = jest.fn();
    mw(mkReq(), asRes({ setHeader, headersSent: true }), () => {});
    expect(setHeader).not.toHaveBeenCalled();
  });
});
