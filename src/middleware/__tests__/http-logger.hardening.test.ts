import type { IBaseLogger } from '../../types';
import { applyRedaction } from '../../utils/redact.utils';
import { createExpressMiddleware, type IncomingRequest } from '../http-logger';

function setup(options = {}, redact = true) {
  const calls: { message: string; data: Record<string, unknown> }[] = [];
  const logger = {
    logLevel: (_l: string, message: string, data: Record<string, unknown>) => {
      // Mirror what the real logger does to the payload before transports see it.
      const out = redact ? applyRedaction(data, { paths: ['**.password'] }) : data;
      calls.push({ message, data: out as Record<string, unknown> });
      return Promise.resolve();
    },
    warn: () => Promise.resolve(),
  } as unknown as IBaseLogger;
  const mw = createExpressMiddleware(logger, { requestLevel: 'info', ...options });
  const run = (req: IncomingRequest) => mw(req, { statusCode: 200 }, () => {});
  return { calls, run };
}

describe('http-logger hardening', () => {
  it('redacts by path before truncating an oversized body', () => {
    const { calls, run } = setup({ logBody: true, bodyMaxBytes: 100 });
    run({
      method: 'POST',
      url: '/',
      headers: {},
      body: { password: 'BIGPW', pad: 'x'.repeat(500) },
    });
    const body = calls[0]!.data.body;
    expect(JSON.stringify(body)).not.toContain('BIGPW');
    expect(JSON.stringify(body).length).toBeLessThan(400);
  });

  it('keeps constructor fields and an own __proto__ key when pruning a body', () => {
    const { calls, run } = setup({ logBody: true, bodyMaxBytes: 100 }, false);
    const body = JSON.parse(
      '{"constructor":"UserService","__proto__":{"x":1},"pad":"' + 'x'.repeat(500) + '"}'
    ) as unknown;
    run({ method: 'POST', url: '/', headers: {}, body });
    const out = calls[0]!.data.body as Record<string, unknown>;
    expect(out['constructor']).toBe('UserService');
    expect(Object.prototype.hasOwnProperty.call(out, '__proto__')).toBe(true);
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
  });

  it('bounds deeply nested bodies', () => {
    const { calls, run } = setup({ logBody: true, bodyMaxBytes: 100 });
    const body = JSON.parse('['.repeat(5000) + ']'.repeat(5000)) as unknown;
    run({ method: 'POST', url: '/', headers: {}, body });
    expect(calls).toHaveLength(1);
  });

  it('merges custom redactHeaders with the defaults', () => {
    const { calls, run } = setup({ redactHeaders: ['x-foo'] }, false);
    run({
      method: 'GET',
      url: '/',
      headers: {
        'x-foo': 'a',
        authorization: 'b',
        'proxy-authorization': 'c',
        'x-auth-token': 'd',
        'x-csrf-token': 'e',
        'x-amz-security-token': 'f',
        'x-ok': 'visible',
      },
    });
    const h = calls[0]!.data.headers as Record<string, string>;
    for (const name of [
      'x-foo',
      'authorization',
      'proxy-authorization',
      'x-auth-token',
      'x-csrf-token',
      'x-amz-security-token',
    ]) {
      expect(h[name]).toBe('[REDACTED]');
    }
    expect(h['x-ok']).toBe('visible');
  });

  it('redacts sensitive query parameters by default', () => {
    const { calls, run } = setup({}, false);
    run({ method: 'GET', url: '/cb?code=abc&page=2&Access_Token=xyz&tok%65n=q#frag', headers: {} });
    expect(calls[0]!.data.url).toBe(
      '/cb?code=[REDACTED]&page=2&Access_Token=[REDACTED]&tok%65n=[REDACTED]#frag'
    );
  });

  it('supports custom query parameter names', () => {
    const { calls, run } = setup({ redactQueryParams: ['ticket'] }, false);
    run({ method: 'GET', url: '/x?ticket=t1&keep=1', headers: {} });
    expect(calls[0]!.data.url).toBe('/x?ticket=[REDACTED]&keep=1');
  });

  it('does not produce an unhandled rejection when the logger rejects', async () => {
    const unhandled = jest.fn();
    process.on('unhandledRejection', unhandled);
    const logger = {
      logLevel: () => Promise.reject(new Error('log failed')),
      warn: () => Promise.reject(new Error('log failed')),
    } as unknown as IBaseLogger;
    const mw = createExpressMiddleware(logger, { requestLevel: 'info' });
    mw({ method: 'GET', url: '/', headers: {} }, { statusCode: 200 }, () => {});
    await new Promise((r) => setTimeout(r, 20));
    process.off('unhandledRejection', unhandled);
    expect(unhandled).not.toHaveBeenCalled();
  });
});

describe('http-logger body pruning', () => {
  const bodyOf = (body: unknown) => {
    const { calls, run } = setup({ logBody: true, bodyMaxBytes: 200 }, false);
    run({ method: 'POST', url: '/', headers: {}, body });
    return calls[0]!.data.body as Record<string, unknown>;
  };
  const pad = 'x'.repeat(400);

  it('does not treat shared (non-circular) objects as cycles', () => {
    const addr = { city: 'Paris' };
    const body = bodyOf({ billing: addr, shipping: addr, pad });
    expect(body.billing).toEqual({ city: 'Paris' });
    expect(body.shipping).toEqual({ city: 'Paris' });
  });

  it('still cuts real cycles', () => {
    const a: Record<string, unknown> = { pad };
    a.self = a;
    expect(() => bodyOf(a)).not.toThrow();
  });

  it('summarises Buffers and typed arrays', () => {
    const body = bodyOf({ buf: Buffer.alloc(1000), pad });
    expect(body.buf).toBe('[Buffer 1000 bytes]');
  });

  it('keeps Date, Map and Set content', () => {
    const body = bodyOf({
      d: new Date(0),
      m: new Map([['k', 'v']]),
      s: new Set(['a']),
      pad,
    });
    expect(body.d).toBe('1970-01-01T00:00:00.000Z');
    expect(body.m).toEqual([['k', 'v']]);
    expect(body.s).toEqual(['a']);
  });

  it('uses toJSON() for non-plain objects', () => {
    const body = bodyOf({ x: { toJSON: () => ({ a: 1 }) }, pad });
    expect(body.x).toEqual({ a: 1 });
  });

  it('reports a failing logger call through the internal error reporter', async () => {
    const spy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const logger = {
      logLevel: () => Promise.reject(new Error('sink down')),
      warn: () => Promise.resolve(),
    } as unknown as IBaseLogger;
    const mw = createExpressMiddleware(logger, { requestLevel: 'info' });
    mw({ method: 'GET', url: '/', headers: {} }, { statusCode: 200 }, () => {});
    await new Promise((r) => setTimeout(r, 20));
    const written = spy.mock.calls.map((c) => String(c[0])).join('');
    spy.mockRestore();
    expect(written).toContain('log call failed');
  });
});
