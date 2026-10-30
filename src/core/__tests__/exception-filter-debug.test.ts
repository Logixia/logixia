import type { ArgumentsHost } from '@nestjs/common';

import { LogixiaExceptionFilter } from '../nestjs-extras';

function makeHost(setHeader: jest.Mock = jest.fn(), traceHeader = 'trace-1') {
  const json = jest.fn();
  const response = { status: jest.fn().mockReturnThis(), json, setHeader };
  const request = { method: 'GET', url: '/x', headers: { 'x-trace-id': traceHeader } };
  const host = {
    switchToHttp: () => ({ getRequest: () => request, getResponse: () => response }),
  } as unknown as ArgumentsHost;
  return { host, json };
}

const boom = new Error('boom', { cause: new Error('postgres://u:secret@db/x') });

describe('LogixiaExceptionFilter debug exposure', () => {
  const prev = process.env['NODE_ENV'];
  afterEach(() => {
    if (prev === undefined) delete process.env['NODE_ENV'];
    else process.env['NODE_ENV'] = prev;
  });

  it.each(['production', 'staging', undefined])(
    'omits debug by default when NODE_ENV=%s',
    (env) => {
      if (env === undefined) delete process.env['NODE_ENV'];
      else process.env['NODE_ENV'] = env;
      const { host, json } = makeHost();
      new LogixiaExceptionFilter().catch(boom, host);
      expect(json.mock.calls[0]![0].debug).toBeUndefined();
      expect(JSON.stringify(json.mock.calls[0]![0])).not.toContain('secret');
    }
  );

  it('includes stack but not cause with exposeDebug', () => {
    const { host, json } = makeHost();
    new LogixiaExceptionFilter(undefined, undefined, { exposeDebug: true }).catch(boom, host);
    const body = json.mock.calls[0]![0];
    expect(body.debug.stack).toBeDefined();
    expect(body.debug.cause).toBeUndefined();
  });

  it('includes cause only with exposeDebug and exposeCause', () => {
    const { host, json } = makeHost();
    new LogixiaExceptionFilter(undefined, undefined, {
      exposeDebug: true,
      exposeCause: true,
    }).catch(boom, host);
    expect(json.mock.calls[0]![0].debug.cause).toContain('secret');
  });

  it('still responds when setHeader throws', () => {
    const { host, json } = makeHost(
      jest.fn(() => {
        throw new Error('ERR_HTTP_HEADERS_SENT');
      })
    );
    expect(() => new LogixiaExceptionFilter().catch(boom, host)).not.toThrow();
    expect(json).toHaveBeenCalled();
  });

  it('ignores an unsafe x-trace-id header', () => {
    const { host, json } = makeHost(jest.fn(), 'a\r\nb');
    new LogixiaExceptionFilter().catch(boom, host);
    expect(json.mock.calls[0]![0].meta.trace_id).toBeUndefined();
  });
});
