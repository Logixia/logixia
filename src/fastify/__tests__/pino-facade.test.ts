import Fastify, { type FastifyInstance } from 'fastify';

import { createFastifyContextHook } from '../../context/async-context';
import { createLogger } from '../../core/logitron-logger';
import { _shutdownRegistrySize } from '../../utils/shutdown.utils';
import { extractTraceId, generateTraceId } from '../../utils/trace.utils';
import { createFastifyLogger } from '../pino-facade';

interface Captured {
  level: string;
  message: string;
  traceId?: string | undefined;
  payload?: Record<string, unknown> | undefined;
}

function makeLogger(config: Record<string, unknown> = {}) {
  const entries: Captured[] = [];
  const logger = createLogger({
    appName: 'fastify-test',
    environment: 'test',
    traceId: true,
    gracefulShutdown: false,
    transports: { console: { level: 'verbose' } },
    silent: false,
    levelOptions: { level: 'info' },
    ...config,
  } as never);
  logger.use({
    name: 'capture',
    onLog(entry) {
      entries.push(entry as unknown as Captured);
      return null;
    },
  });
  return { logger, entries };
}

const wait = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

describe('createFastifyLogger call shapes', () => {
  it('maps (obj, msg) to message and data', async () => {
    const { logger, entries } = makeLogger();
    const log = createFastifyLogger(logger);

    log.info({ userId: 'u1', plan: 'pro' }, 'user %s signed in', 'alice');

    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      level: 'info',
      message: 'user alice signed in',
      payload: { userId: 'u1', plan: 'pro' },
    });
  });

  it('interpolates %s %d %i %f %j %o %O %% and ignores extra args like pino', () => {
    const { logger, entries } = makeLogger();
    const log = createFastifyLogger(logger);

    log.info(
      '%s|%d|%i|%f|%j|%o|%O|%%|%s',
      'a',
      '4',
      '5.9',
      '1.5',
      { k: 1 },
      [1],
      { z: 2 },
      'last',
      'extra'
    );
    log.info('100%');
    log.info('missing %s %s', 'one');
    log.info(42 as unknown as string);

    expect(entries.map((e) => e.message)).toEqual([
      'a|4|5|1.5|{"k":1}|[1]|{"z":2}|%|last',
      '100%',
      'missing one %s',
      '42',
    ]);
  });

  it('serializes an Error as the first argument, with and without a message', () => {
    const { logger, entries } = makeLogger();
    const log = createFastifyLogger(logger);
    const err = new Error('db down', { cause: new Error('socket closed') });

    log.error(err);
    log.error(err, 'query %s failed', 'users');
    log.error({ err, orderId: 7 }, 'order failed');
    log.warn({ err });

    expect(entries.map((e) => e.message)).toEqual([
      'db down',
      'query users failed',
      'order failed',
      'db down',
    ]);
    for (const entry of entries) {
      const error = entry.payload?.['error'] as Record<string, unknown>;
      expect(error).toMatchObject({
        name: 'Error',
        message: 'db down',
        cause: { message: 'socket closed' },
      });
      expect(String(error['stack'])).toContain('db down');
      expect(entry.payload).not.toHaveProperty('err');
    }
    expect(entries[2]?.payload).toMatchObject({ orderId: 7 });
  });

  it('maps fatal to error and keeps pino level names working', () => {
    const { logger, entries } = makeLogger({ levelOptions: { level: 'trace' } });
    const log = createFastifyLogger(logger);

    log.fatal('f');
    log.trace('t');
    log.debug('d');
    log.warn('w');
    log.silent('never');

    expect(entries.map((e) => `${e.level}:${e.message}`)).toEqual([
      'error:f',
      'trace:t',
      'debug:d',
      'warn:w',
    ]);
  });

  it('returns void and swallows throwing and rejecting loggers', async () => {
    const unhandled = jest.fn();
    process.on('unhandledRejection', unhandled);
    const failing = {
      info: () => Promise.reject(new Error('rejected')),
      warn: () => {
        throw new Error('thrown');
      },
      error: () => Promise.reject(new Error('rejected')),
      debug: () => {},
      trace: () => {},
      getLevel: () => 'info',
      getContext: () => '',
      child: () => failing,
    };
    const log = createFastifyLogger(failing as never);

    expect(log.info('a')).toBeUndefined();
    expect(log.warn('b')).toBeUndefined();
    expect(log.error(new Error('c'))).toBeUndefined();
    await wait();
    process.off('unhandledRejection', unhandled);

    expect(unhandled).not.toHaveBeenCalled();
  });
});

describe('createFastifyLogger levels', () => {
  it('maps level to getLevel/setLevel and supports silent', () => {
    const { logger, entries } = makeLogger();
    const log = createFastifyLogger(logger);

    expect(log.level).toBe('info');
    expect(log.levelVal).toBe(30);
    expect(log.isLevelEnabled('warn')).toBe(true);
    expect(log.isLevelEnabled('debug')).toBe(false);

    log.level = 'debug';
    expect(logger.getLevel()).toBe('debug');
    expect(log.isLevelEnabled('debug')).toBe(true);
    log.debug('now visible');

    log.level = 'fatal';
    expect(logger.getLevel()).toBe('error');
    log.level = 'silent';
    expect(log.level).toBe('silent');
    expect(log.levelVal).toBe(Infinity);
    expect(log.isLevelEnabled('error')).toBe(false);
    log.error('muted');
    log.level = 'info';
    log.info('unmuted');

    expect(entries.map((e) => e.message)).toEqual(['now visible', 'unmuted']);
  });

  it('keeps a child level independent of its parent', () => {
    const { logger, entries } = makeLogger();
    const root = createFastifyLogger(logger);
    const noisy = root.child({ reqId: 'a' }, { level: 'debug' });
    const quiet = root.child({ reqId: 'b' });

    noisy.debug('from noisy');
    quiet.debug('from quiet');
    noisy.level = 'error';
    noisy.info('hidden now');

    expect(noisy.level).toBe('error');
    expect(quiet.level).toBe('info');
    expect(root.level).toBe('info');
    expect(entries.map((e) => e.message)).toEqual(['from noisy']);
  });
});

describe('createFastifyLogger child()', () => {
  it('carries bindings as context data, through nested children', () => {
    const { logger, entries } = makeLogger();
    const root = createFastifyLogger(logger);

    const child = root.child({ reqId: 'r-1' }).child({ route: '/x' });
    child.info('hello');

    expect(child.bindings()).toEqual({ reqId: 'r-1', route: '/x' });
    expect(entries[0]?.payload).toMatchObject({ reqId: 'r-1', route: '/x' });
  });

  it('applies child serializers over inherited ones', () => {
    const { logger, entries } = makeLogger();
    const root = createFastifyLogger(logger);
    const child = root.child(
      {},
      { serializers: { user: (u) => ({ id: (u as { id: string }).id }) } }
    );

    child.info({ user: { id: 'u1', password: 'x' } }, 'who');

    expect(entries[0]?.payload).toEqual({ user: { id: 'u1' } });
  });

  it('allows overriding the default serializers', () => {
    const { logger, entries } = makeLogger();
    const log = createFastifyLogger(logger, { serializers: { res: () => 'custom' } });

    log.info({ res: { statusCode: 200 } }, 'x');

    expect(entries[0]?.payload).toEqual({ res: 'custom' });
  });

  it('does not grow the shutdown registry or leak heap across many children', async () => {
    const { logger } = makeLogger({ silent: true });
    const root = createFastifyLogger(logger);
    const before = _shutdownRegistrySize();

    for (let i = 0; i < 50_000; i++) root.child({ reqId: `req-${i}` }).info({ i }, 'request');

    expect(_shutdownRegistrySize()).toBe(before);
  });
});

describe('createFastifyLogger with real Fastify', () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  function build(options: { genReqId?: boolean; hook?: boolean; logLevel?: string } = {}) {
    const { logger, entries } = makeLogger(
      options.logLevel ? { levelOptions: { level: options.logLevel } } : {}
    );
    app = Fastify({
      loggerInstance: createFastifyLogger(logger) as never,
      ...(options.genReqId
        ? {
            genReqId: (req) => extractTraceId(req, { header: ['x-trace-id'] }) ?? generateTraceId(),
          }
        : {}),
    });
    if (options.hook) app.addHook('onRequest', createFastifyContextHook());
    return { app, logger, entries };
  }

  it('accepts the facade and logs serialized req and res only', async () => {
    const { app, entries } = build();
    app.get('/orders/:id', async (request) => {
      request.log.info({ orderId: 1 }, 'handling');
      return { ok: true };
    });

    const res = await app.inject({
      url: '/orders/9?token=SECRET&page=2',
      headers: { cookie: 'sid=1' },
    });
    await app.close();

    expect(res.statusCode).toBe(200);
    const incoming = entries.find((e) => e.message === 'incoming request');
    const completed = entries.find((e) => e.message === 'request completed');
    expect(incoming?.payload?.['req']).toEqual({
      method: 'GET',
      url: '/orders/9?token=[REDACTED]&page=2',
      hostname: 'localhost',
      remoteAddress: '127.0.0.1',
      remotePort: undefined,
      reqId: 'req-1',
    });
    expect(completed?.payload?.['res']).toEqual({ statusCode: 200 });
    expect(completed?.payload).toHaveProperty('responseTime');
    expect(JSON.stringify(entries)).not.toMatch(/SECRET|sid=1|"raw"|"socket"/);
    expect(entries.every((e) => e.payload?.['reqId'] === 'req-1')).toBe(true);
  });

  it('logs thrown route errors with stack and cause', async () => {
    const { app, entries } = build();
    app.get('/boom', async () => {
      throw new Error('boom', { cause: new Error('root cause') });
    });

    const res = await app.inject({ url: '/boom' });

    expect(res.statusCode).toBe(500);
    const failure = entries.find((e) => e.level === 'error' && e.message === 'boom');
    expect(failure?.payload?.['error']).toMatchObject({
      message: 'boom',
      cause: { message: 'root cause' },
    });
    expect(String((failure?.payload?.['error'] as { stack: string }).stack)).toContain('boom');
  });

  it('logs the 404 string message', async () => {
    const { app, entries } = build();

    const res = await app.inject({ url: '/missing' });

    expect(res.statusCode).toBe(404);
    expect(entries.map((e) => e.message)).toContain('Route GET:/missing not found');
  });

  it('keeps a route logLevel from leaking into other routes', async () => {
    const { app, entries } = build();
    app.get('/a', { logLevel: 'debug' }, async (request) => {
      request.log.debug('debug in a');
      return 'a';
    });
    app.get('/b', async (request) => {
      request.log.debug('debug in b');
      return 'b';
    });

    await app.inject({ url: '/a' });
    await app.inject({ url: '/b' });

    const messages = entries.map((e) => e.message);
    expect(messages).toContain('debug in a');
    expect(messages).not.toContain('debug in b');
  });

  it('uses reqId as the trace ID of every entry when genReqId returns a trace id', async () => {
    const { app, entries } = build({ genReqId: true, hook: true });
    app.get('/', async (request) => {
      request.log.info('in handler');
      return 'ok';
    });

    await app.inject({ url: '/', headers: { 'x-trace-id': 'trace-abc' } });

    expect(entries.length).toBeGreaterThanOrEqual(3);
    expect(new Set(entries.map((e) => e.traceId))).toEqual(new Set(['trace-abc']));
    expect(entries.every((e) => e.payload?.['reqId'] === 'trace-abc')).toBe(true);
  });

  it('falls back to a per-logger trace id for the first entry when reqId is a counter', async () => {
    const { app, entries } = build({ hook: true });
    app.get('/', async (request) => {
      request.log.info('in handler');
      return 'ok';
    });

    await app.inject({ url: '/', headers: { 'x-trace-id': 'trace-abc' } });

    const incoming = entries.find((e) => e.message === 'incoming request');
    const handler = entries.find((e) => e.message === 'in handler');
    expect(handler?.traceId).toBe('trace-abc');
    expect(incoming?.traceId).not.toBe('trace-abc');
    expect(incoming?.payload?.['reqId']).toBe('req-1');
  });
});
