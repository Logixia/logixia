import { TraceContext } from '../../utils/trace.utils';
import { TraceMiddleware, traceMiddleware } from '../trace.middleware';

const req = (extra: Record<string, unknown>) =>
  ({
    method: 'GET',
    url: '/reset?token=abc123',
    headers: {},
    get: () => '',
    ip: '',
    ...extra,
  }) as never;

function storedUrl(run: (next: () => void) => void): unknown {
  let url: unknown;
  run(() => {
    url = (TraceContext.instance.storage.getStore() as Record<string, unknown>)['url'];
  });
  return url;
}

describe('trace context url redaction', () => {
  it('redacts the url stored by TraceMiddleware', () => {
    const mw = new TraceMiddleware({ enabled: true });
    expect(storedUrl((next) => mw.use(req({}), { setHeader: jest.fn() } as never, next))).toBe(
      '/reset?token=[REDACTED]'
    );
  });

  it('redacts the url stored by traceMiddleware() and prefers originalUrl', () => {
    const mw = traceMiddleware({ enabled: true });
    const url = storedUrl((next) =>
      mw(req({ originalUrl: '/api/reset?token=abc123' }), { setHeader: jest.fn() } as never, next)
    );
    expect(url).toBe('/api/reset?token=[REDACTED]');
  });

  it('honours extra query params', () => {
    const mw = new TraceMiddleware({ enabled: true }, ['invite']);
    const url = storedUrl((next) =>
      mw.use(req({ url: '/j?invite=magic77' }), { setHeader: jest.fn() } as never, next)
    );
    expect(url).toBe('/j?invite=[REDACTED]');
  });
});
