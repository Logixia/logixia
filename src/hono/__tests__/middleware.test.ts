import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';

import { getCurrentTraceId } from '../../utils/trace.utils';
import { createHonoMiddleware, type HonoContextLike, type HonoLoggerLike } from '../middleware';

interface Call {
  level: 'info' | 'warn' | 'error';
  message: string;
  data: Record<string, unknown>;
}

function makeLogger(): { logger: HonoLoggerLike; calls: Call[] } {
  const calls: Call[] = [];
  const at =
    (level: Call['level']) =>
    (message: string, data: Record<string, unknown> = {}) => {
      calls.push({ level, message, data });
    };
  return { logger: { info: at('info'), warn: at('warn'), error: at('error') }, calls };
}

const TRACEPARENT = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

describe('createHonoMiddleware with Hono', () => {
  it('logs completion and sets the response header on c.json', async () => {
    const { logger, calls } = makeLogger();
    const app = new Hono();
    app.use(createHonoMiddleware(logger));
    app.get('/orders/:id', (c) => c.json({ id: c.req.param('id'), trace: c.get('traceId') }));

    const res = await app.request('/orders/42');

    const traceId = res.headers.get('x-trace-id');
    expect(traceId).toMatch(/^[\da-f-]{36}$/);
    expect((await res.json()) as unknown).toEqual({ id: '42', trace: traceId });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      level: 'info',
      message: 'request completed',
      data: { traceId, method: 'GET', path: '/orders/42', status: 200 },
    });
    expect(typeof calls[0]?.data['duration']).toBe('number');
  });

  it('reuses an incoming trace header and parses traceparent', async () => {
    const { logger, calls } = makeLogger();
    const app = new Hono();
    app.use(createHonoMiddleware(logger));
    app.get('/', (c) => c.text('ok'));

    const first = await app.request('/', { headers: { 'x-request-id': 'req_abc.1' } });
    const second = await app.request('/', { headers: { traceparent: TRACEPARENT } });

    expect(first.headers.get('x-trace-id')).toBe('req_abc.1');
    expect(second.headers.get('x-trace-id')).toBe('4bf92f3577b34da6a3ce929d0e0e4736');
    expect(calls.map((call) => call.data['traceId'])).toEqual([
      'req_abc.1',
      '4bf92f3577b34da6a3ce929d0e0e4736',
    ]);
  });

  it('ignores an unsafe incoming id and generates one', async () => {
    const { logger } = makeLogger();
    const app = new Hono();
    app.use(createHonoMiddleware(logger));
    app.get('/', (c) => c.text('ok'));

    const res = await app.request('/', { headers: { 'x-trace-id': 'a b<script>' } });

    expect(res.headers.get('x-trace-id')).toMatch(/^[\da-f-]{36}$/);
  });

  it('runs the handler inside the trace scope', async () => {
    const { logger } = makeLogger();
    const app = new Hono();
    app.use(createHonoMiddleware(logger));
    app.get('/', async (c) => {
      await Promise.resolve();
      return c.text(getCurrentTraceId() ?? 'none');
    });

    const res = await app.request('/', { headers: { 'x-trace-id': 'trace-in-als' } });

    expect(await res.text()).toBe('trace-in-als');
    expect(getCurrentTraceId()).toBeUndefined();
  });

  it('redacts secret query parameters from the logged path', async () => {
    const { logger, calls } = makeLogger();
    const app = new Hono();
    app.use(createHonoMiddleware(logger, { redactQueryParams: ['session'] }));
    app.get('/cb', (c) => c.text('ok'));

    await app.request('/cb?code=abc&token=t0k&session=s3&page=2');

    const path = String(calls[0]?.data['path']);
    expect(path).toContain('page=2');
    expect(path).not.toMatch(/abc|t0k|s3/);
  });

  it('sets the header on a raw Response and on an onError response', async () => {
    const { logger } = makeLogger();
    const app = new Hono();
    app.use(createHonoMiddleware(logger));
    app.get('/raw', () => new Response('raw', { status: 201 }));
    app.get('/boom', () => {
      throw new Error('boom');
    });
    app.onError((_err, c) => c.json({ error: 'internal' }, 500));

    const raw = await app.request('/raw', { headers: { 'x-trace-id': 't-raw' } });
    const boom = await app.request('/boom', { headers: { 'x-trace-id': 't-boom' } });

    expect(raw.status).toBe(201);
    expect(raw.headers.get('x-trace-id')).toBe('t-raw');
    expect(boom.status).toBe(500);
    expect(boom.headers.get('x-trace-id')).toBe('t-boom');
  });

  it('sets the header on a response with immutable headers', async () => {
    const { logger } = makeLogger();
    const app = new Hono();
    app.use(createHonoMiddleware(logger));
    app.get('/proxy', () => Response.redirect('https://example.com/', 302));

    const res = await app.request('/proxy', { headers: { 'x-trace-id': 't-proxy' } });

    expect(res.status).toBe(302);
    expect(res.headers.get('x-trace-id')).toBe('t-proxy');
  });

  it('logs a thrown error at error level with its stack', async () => {
    const { logger, calls } = makeLogger();
    const app = new Hono();
    app.use(createHonoMiddleware(logger));
    app.get('/boom', () => {
      throw new Error('boom', { cause: new Error('root') });
    });
    app.onError((_err, c) => c.text('internal', 500));

    const res = await app.request('/boom');

    expect(res.status).toBe(500);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      level: 'error',
      message: 'request failed',
      data: { status: 500, error: { name: 'Error', message: 'boom', cause: { message: 'root' } } },
    });
    expect(String((calls[0]?.data['error'] as { stack: string }).stack)).toContain('boom');
  });

  it('logs a client error from an HTTPException at warn level', async () => {
    const { logger, calls } = makeLogger();
    const app = new Hono();
    app.use(createHonoMiddleware(logger));
    app.get('/forbidden', () => {
      throw new HTTPException(403, { message: 'Forbidden' });
    });

    const res = await app.request('/forbidden');

    expect(res.status).toBe(403);
    expect(calls[0]).toMatchObject({ level: 'warn', data: { status: 403 } });
  });

  it('logs a 5xx response without a thrown error at error level', async () => {
    const { logger, calls } = makeLogger();
    const app = new Hono();
    app.use(createHonoMiddleware(logger));
    app.get('/down', (c) => c.text('down', 503));

    await app.request('/down');

    expect(calls[0]).toMatchObject({ level: 'error', message: 'request completed' });
  });

  it('skips matching requests entirely', async () => {
    const { logger, calls } = makeLogger();
    const app = new Hono();
    app.use(createHonoMiddleware(logger, { skip: (c) => c.req.url.endsWith('/health') }));
    app.get('/health', (c) => c.text('ok'));

    const res = await app.request('/health');

    expect(res.headers.get('x-trace-id')).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it('supports a custom header, no response header and extra fields', async () => {
    const { logger, calls } = makeLogger();
    const app = new Hono();
    app.use(
      createHonoMiddleware(logger, {
        traceIdHeader: 'x-my-trace',
        responseHeader: false,
        extraFields: (c) => ({ tenant: c.req.header('x-tenant') }),
      })
    );
    app.get('/', (c) => c.text('ok'));

    const res = await app.request('/', { headers: { 'x-my-trace': 'mine', 'x-tenant': 'acme' } });

    expect(res.headers.get('x-trace-id')).toBeNull();
    expect(calls[0]?.data).toMatchObject({ traceId: 'mine', tenant: 'acme' });
  });
});

describe('createHonoMiddleware with a minimal context', () => {
  function makeContext(url: string, headers: Record<string, string> = {}) {
    const store = new Map<string, unknown>();
    const responseHeaders = new Headers();
    const c = {
      req: {
        method: 'POST',
        url,
        header: (name: string) => headers[name],
      },
      res: new Response('ok', { status: 202 }),
      header: (name: string, value: string) => responseHeaders.set(name, value),
      set: (key: string, value: unknown) => store.set(key, value),
    } as unknown as HonoContextLike;
    return { c, store, responseHeaders };
  }

  it('logs and rethrows an error that escapes next()', async () => {
    const { logger, calls } = makeLogger();
    const { c } = makeContext('http://localhost/a?b=1');
    const middleware = createHonoMiddleware(logger);

    await expect(middleware(c, () => Promise.reject(new Error('escaped')))).rejects.toThrow(
      'escaped'
    );

    expect(calls[0]).toMatchObject({
      level: 'error',
      data: { status: 500, path: '/a?b=1', error: { message: 'escaped' } },
    });
  });

  it('records the status the handler set and stores the trace id', async () => {
    const { logger, calls } = makeLogger();
    const { c, store, responseHeaders } = makeContext('http://localhost', { 'x-trace-id': 't1' });

    await createHonoMiddleware(logger)(c, async () => {});

    expect(store.get('traceId')).toBe('t1');
    expect(responseHeaders.get('x-trace-id')).toBe('t1');
    expect(calls[0]?.data).toMatchObject({ method: 'POST', path: '/', status: 202 });
  });

  it('survives a logger that throws or rejects', async () => {
    const unhandled = jest.fn();
    process.on('unhandledRejection', unhandled);
    const logger: HonoLoggerLike = {
      info: () => Promise.reject(new Error('transport down')),
      warn: () => {
        throw new Error('sync');
      },
      error: () => {
        throw new Error('sync');
      },
    };
    const { c } = makeContext('http://localhost/');

    await expect(createHonoMiddleware(logger)(c, async () => {})).resolves.toBeUndefined();
    await new Promise((resolve) => setImmediate(resolve));

    process.off('unhandledRejection', unhandled);
    expect(unhandled).not.toHaveBeenCalled();
  });
});
