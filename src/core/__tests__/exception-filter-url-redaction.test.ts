import type { ArgumentsHost } from '@nestjs/common';
import { NotFoundException } from '@nestjs/common';

import { createLogger } from '../../index';
import type { LogixiaLoggerService } from '../logitron-nestjs.service';
import { LogixiaExceptionFilter } from '../nestjs-extras';

function makeHost(url: string, extra: Record<string, unknown> = {}) {
  const json = jest.fn();
  const response = { status: jest.fn().mockReturnThis(), json, setHeader: jest.fn() };
  const request = { method: 'GET', url, headers: {}, ...extra };
  const host = {
    switchToHttp: () => ({ getRequest: () => request, getResponse: () => response }),
  } as unknown as ArgumentsHost;
  return { host, json };
}

function makeLogger() {
  const calls: Record<string, unknown>[] = [];
  const messages: unknown[] = [];
  const record = (msg: unknown, meta: Record<string, unknown>) => {
    messages.push(msg);
    calls.push(meta);
    return Promise.resolve();
  };
  const logger = { error: record, warn: record } as unknown as LogixiaLoggerService;
  return { logger, calls, messages };
}

describe('LogixiaExceptionFilter URL redaction', () => {
  it('redacts sensitive query values in the logged url and the response path', () => {
    const { logger, calls } = makeLogger();
    const { host, json } = makeHost('/reset?token=abc123&page=2&code=xyz');
    new LogixiaExceptionFilter(logger).catch(new Error('boom'), host);

    const body = JSON.stringify(json.mock.calls[0]![0]);
    expect(body).not.toContain('abc123');
    expect(body).not.toContain('xyz');
    expect(json.mock.calls[0]![0].meta.path).toBe('/reset?token=[REDACTED]&page=2&code=[REDACTED]');

    expect(calls).toHaveLength(1);
    expect(calls[0]!['url']).toBe('/reset?token=[REDACTED]&page=2&code=[REDACTED]');
  });

  it('honours extra redactQueryParams', () => {
    const { logger, calls } = makeLogger();
    const { host } = makeHost('/report?tenant=acme&sessionKey=s3cr3t');
    new LogixiaExceptionFilter(logger, undefined, { redactQueryParams: ['sessionKey'] }).catch(
      new Error('boom'),
      host
    );
    expect(calls[0]!['url']).toBe('/report?tenant=acme&sessionKey=[REDACTED]');
  });

  it('leaves urls without a query string unchanged', () => {
    const { logger, calls } = makeLogger();
    const { host, json } = makeHost('/orders/42');
    new LogixiaExceptionFilter(logger).catch(new Error('boom'), host);
    expect(calls[0]!['url']).toBe('/orders/42');
    expect(json.mock.calls[0]![0].meta.path).toBe('/orders/42');
  });

  it('scrubs the URL out of a Nest 404 message in the response and the warn log', () => {
    const { logger, messages } = makeLogger();
    const { host, json } = makeHost('/reset?token=abc123');
    new LogixiaExceptionFilter(logger).catch(
      new NotFoundException('Cannot GET /reset?token=abc123'),
      host
    );
    const body = json.mock.calls[0]![0];
    expect(body.error.message).toBe('Cannot GET /reset?token=[REDACTED]');
    expect(JSON.stringify(body)).not.toContain('abc123');
    expect(String(messages[0])).not.toContain('abc123');
    expect(String(messages[0])).toContain('Cannot GET /reset?token=[REDACTED]');
  });

  it('redacts a query embedded in a message even when it is not this request url', () => {
    const { logger, messages } = makeLogger();
    const { host, json } = makeHost('/proxy');
    new LogixiaExceptionFilter(logger).catch(
      new NotFoundException('upstream https://x.test/a?api_key=zzz999&ok=1 failed'),
      host
    );
    expect(json.mock.calls[0]![0].error.message).toBe(
      'upstream https://x.test/a?api_key=[REDACTED]&ok=1 failed'
    );
    expect(String(messages[0])).not.toContain('zzz999');
  });

  it('logs a sanitized copy on 5xx without mutating the original exception', () => {
    const { logger, messages } = makeLogger();
    const { host, json } = makeHost('/export?api_key=sk_live_987654');
    const cause = new Error('connect failed for /export?api_key=sk_live_987654');
    const original = new Error('failed GET /export?api_key=sk_live_987654', { cause });
    const originalMessage = original.message;
    const originalStack = original.stack;

    new LogixiaExceptionFilter(logger).catch(original, host);

    const logged = messages[0] as Error & { cause?: unknown };
    expect(logged).toBeInstanceOf(Error);
    expect(logged).not.toBe(original);
    expect(logged.name).toBe('Error');
    expect(logged.message).toBe('failed GET /export?api_key=[REDACTED]');
    expect(logged.stack).not.toContain('sk_live_987654');
    expect(String(logged.cause)).not.toContain('sk_live_987654');
    expect(JSON.stringify(json.mock.calls[0]![0])).not.toContain('sk_live_987654');
    expect(original.message).toBe(originalMessage);
    expect(original.stack).toBe(originalStack);
    expect((original as Error & { cause?: unknown }).cause).toBe(cause);
  });

  it('scrubs the stack and cause in exposeDebug output', () => {
    const { logger } = makeLogger();
    const { host, json } = makeHost('/export?token=hunter22');
    const err = new Error('bad /export?token=hunter22', {
      cause: new Error('inner token=hunter22 rejected'),
    });
    new LogixiaExceptionFilter(logger, undefined, { exposeDebug: true, exposeCause: true }).catch(
      err,
      host
    );
    const body = json.mock.calls[0]![0];
    expect(body.debug.stack).toContain('[REDACTED]');
    expect(JSON.stringify(body)).not.toContain('hunter22');
  });

  it('scrubs string fields under error.details without mutating the exception', () => {
    const { LogixiaException } = jest.requireActual('../../exceptions/exception');
    const { logger } = makeLogger();
    const { host, json } = makeHost('/x?token=abc123');
    const details = [{ field: 'url', message: 'bad /x?token=abc123' }];
    const ex = new LogixiaException({
      errorType: 'validation_error',
      errorCode: 'V1',
      message: 'invalid token abc123',
      httpStatus: 422,
      details,
    });
    new LogixiaExceptionFilter(logger).catch(ex, host);
    const body = json.mock.calls[0]![0];
    expect(JSON.stringify(body)).not.toContain('abc123');
    expect(details[0]!.message).toBe('bad /x?token=abc123');
  });

  it('does not scrub short or unrelated values', () => {
    const { logger } = makeLogger();
    const { host, json } = makeHost('/x?code=ab');
    new LogixiaExceptionFilter(logger).catch(new NotFoundException('ab is not a page'), host);
    expect(json.mock.calls[0]![0].error.message).toBe('ab is not a page');
  });

  it('redacts the expanded default names, camelCase and AWS presigned params', () => {
    const { logger, calls } = makeLogger();
    const { host } = makeHost(
      '/f?accessToken=aaa111&sessionId=bbb222&X-Amz-Signature=ccc333&X-Amz-Credential=ddd444&page=1'
    );
    new LogixiaExceptionFilter(logger).catch(new Error('boom'), host);
    expect(calls[0]!['url']).toBe(
      '/f?accessToken=[REDACTED]&sessionId=[REDACTED]&X-Amz-Signature=[REDACTED]&X-Amz-Credential=[REDACTED]&page=1'
    );
  });

  it('prefers originalUrl over url', () => {
    const { logger, calls } = makeLogger();
    const { host, json } = makeHost('/reset?token=abc123', {
      originalUrl: '/api/v1/reset?token=abc123',
    });
    new LogixiaExceptionFilter(logger).catch(new Error('boom'), host);
    expect(calls[0]!['url']).toBe('/api/v1/reset?token=[REDACTED]');
    expect(json.mock.calls[0]![0].meta.path).toBe('/api/v1/reset?token=[REDACTED]');
  });

  it('merges LoggerConfig.redact.queryParams', () => {
    const { logger, calls } = makeLogger();
    const { host } = makeHost('/join?invite=magic77&page=2');
    new LogixiaExceptionFilter(logger, { redact: { queryParams: ['invite'] } }).catch(
      new Error('boom'),
      host
    );
    expect(calls[0]!['url']).toBe('/join?invite=[REDACTED]&page=2');
  });

  it('keeps custom error properties on 5xx while scrubbing their strings', () => {
    const { logger, messages } = makeLogger();
    const { host } = makeHost('/x?token=abc123');
    const original = Object.assign(new Error('upstream failed'), {
      errorCode: 'E_UP',
      status: 502,
      details: { url: '/x?token=abc123', tries: [1, 2], when: new Date(0) },
    });
    new LogixiaExceptionFilter(logger).catch(original, host);

    const logged = messages[0] as Error & Record<string, unknown>;
    expect(logged).toBeInstanceOf(Error);
    expect(logged['errorCode']).toBe('E_UP');
    expect(logged['status']).toBe(502);
    const details = logged['details'] as Record<string, unknown>;
    expect(details['url']).toBe('/x?token=[REDACTED]');
    expect(details['tries']).toEqual([1, 2]);
    expect(typeof details['when']).toBe('string');
    expect(JSON.stringify(details)).not.toContain('abc123');
    expect((original as unknown as { details: { url: string } }).details.url).toBe(
      '/x?token=abc123'
    );
  });

  it('survives cycles in error properties', () => {
    const { logger, messages } = makeLogger();
    const { host } = makeHost('/x?token=abc123');
    const err = new Error('loop abc123') as Error & { self?: unknown };
    err.self = err;
    new LogixiaExceptionFilter(logger).catch(err, host);
    const logged = messages[0] as Error & { self?: unknown };
    expect(logged.message).toBe('loop [REDACTED]');
    expect(JSON.stringify(logged.self)).not.toContain('abc123');
    expect(logged.self).toEqual(expect.objectContaining({ _circular: true }));
  });

  describe('5xx copy keeps keys so logger redaction applies', () => {
    class FakeHeaders {
      Authorization = 'Basic dXNlcjpwYXNz';
      'X-Api-Key' = 'live_supersecret';
      toString(): string {
        return `Authorization: ${this.Authorization}\nX-Api-Key: ${this['X-Api-Key']}`;
      }
    }

    function realLogger() {
      const entries: string[] = [];
      const logger = createLogger({
        appName: 'test',
        redact: { autoDetect: true },
        transports: {
          custom: [{ name: 'cap', write: (e: unknown) => void entries.push(JSON.stringify(e)) }],
        },
      } as never);
      return { logger: logger as unknown as LogixiaLoggerService, entries };
    }

    it('redacts AxiosHeaders-like values by key and leaves no free-text secret', async () => {
      const { logger, entries } = realLogger();
      const { host } = makeHost('/x');
      const err = Object.assign(new Error('Request failed'), {
        config: { headers: new FakeHeaders() },
        response: { headers: new FakeHeaders(), data: { q: new URLSearchParams('token=abc123') } },
      });
      new LogixiaExceptionFilter(logger).catch(err, host);
      await new Promise((r) => setTimeout(r, 50));
      const all = entries.join('\n');
      expect(all).toContain('[REDACTED]');
      expect(all).not.toContain('dXNlcjpwYXNz');
      expect(all).not.toContain('live_supersecret');
    });

    it('scrubs a URLSearchParams value carrying a request secret', () => {
      const { logger, messages } = makeLogger();
      const { host } = makeHost('/x?token=abc123');
      const err = Object.assign(new Error('boom'), { params: new URLSearchParams('token=abc123') });
      new LogixiaExceptionFilter(logger).catch(err, host);
      expect(JSON.stringify(messages[0])).not.toContain('abc123');
    });

    it('still responds when a property getter throws', () => {
      const { logger, messages } = makeLogger();
      const { host, json } = makeHost('/x?token=abc123');
      const err = new Error('boom abc123');
      Object.defineProperty(err, 'bad', {
        enumerable: true,
        get() {
          throw new Error('getter exploded');
        },
      });
      expect(() => new LogixiaExceptionFilter(logger).catch(err, host)).not.toThrow();
      expect(json).toHaveBeenCalledTimes(1);
      expect((messages[0] as Error).message).not.toContain('abc123');
    });

    it('falls back to a minimal error for a revoked proxy', () => {
      const { logger, messages } = makeLogger();
      const { host, json } = makeHost('/x');
      const { proxy, revoke } = Proxy.revocable(new Error('x'), {});
      revoke();
      expect(() => new LogixiaExceptionFilter(logger).catch(proxy, host)).not.toThrow();
      expect(json).toHaveBeenCalledTimes(1);
      expect(messages[0]).toBeInstanceOf(Error);
    });
  });
});
