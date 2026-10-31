import type { ArgumentsHost } from '@nestjs/common';

import type { LogixiaLoggerService } from '../logitron-nestjs.service';
import { LogixiaExceptionFilter } from '../nestjs-extras';

function makeHost(url: string) {
  const json = jest.fn();
  const response = { status: jest.fn().mockReturnThis(), json, setHeader: jest.fn() };
  const request = { method: 'GET', url, headers: {} };
  const host = {
    switchToHttp: () => ({ getRequest: () => request, getResponse: () => response }),
  } as unknown as ArgumentsHost;
  return { host, json };
}

function makeLogger() {
  const calls: Record<string, unknown>[] = [];
  const record = (_msg: unknown, meta: Record<string, unknown>) => {
    calls.push(meta);
    return Promise.resolve();
  };
  const logger = { error: record, warn: record } as unknown as LogixiaLoggerService;
  return { logger, calls };
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
});
