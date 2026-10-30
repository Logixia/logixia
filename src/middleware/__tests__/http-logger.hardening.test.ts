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
