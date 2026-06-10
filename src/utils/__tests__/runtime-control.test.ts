/**
 * Tests for dynamic runtime log-level reconfiguration (R3 + R4).
 *
 * Covers the logger's setNamespaceLevels/patch/get methods, the SIGUSR2-style
 * signal cycler, and the HTTP admin handler (GET reads, POST sets, bad input
 * rejected).
 */

import { LogixiaLogger } from '../../core/logitron-logger';
import type { LogLevelString, NamespaceLevels } from '../../types';
import {
  createLevelControlHandler,
  type ReconfigurableLogger,
  registerLevelSignal,
} from '../runtime-control';
import { resetShutdownHandlers } from '../shutdown.utils';

const BASE = {
  appName: 'TestApp',
  format: { timestamp: false, colorize: false, json: false },
  traceId: false,
  silent: true,
};

afterEach(() => {
  resetShutdownHandlers();
});

describe('LogixiaLogger — runtime namespace level methods', () => {
  it('setNamespaceLevels replaces the map and getNamespaceLevels returns a copy', () => {
    const logger = new LogixiaLogger({ ...BASE });
    logger.setNamespaceLevels({ 'db.*': 'debug', '*': 'info' });
    expect(logger.getNamespaceLevels()).toEqual({ 'db.*': 'debug', '*': 'info' });

    // Returned object is a copy — mutating it doesn't affect internal state.
    const snap = logger.getNamespaceLevels();
    snap['db.*'] = 'trace';
    expect(logger.getNamespaceLevels()['db.*']).toBe('debug');
  });

  it('patchNamespaceLevels merges into the existing map', () => {
    const logger = new LogixiaLogger({ ...BASE });
    logger.setNamespaceLevels({ 'db.*': 'debug' });
    logger.patchNamespaceLevels({ 'http.*': 'warn' });
    expect(logger.getNamespaceLevels()).toEqual({ 'db.*': 'debug', 'http.*': 'warn' });
  });

  it('a child logger in a matching namespace honors a runtime level change', async () => {
    const lines: string[] = [];
    const orig = process.stdout.write.bind(process.stdout);
    (process.stdout as NodeJS.WriteStream).write = ((c: unknown) => {
      lines.push(String(c ?? ''));
      return true;
    }) as typeof process.stdout.write;

    try {
      const logger = new LogixiaLogger({
        ...BASE,
        silent: false,
        levelOptions: { level: 'info' },
      });
      const db = logger.child('db.queries');
      // At info level, a debug line is suppressed.
      await db.debug('before');
      const beforeCount = lines.filter((l) => l.includes('before')).length;

      // Flip db.* to debug at runtime.
      logger.setNamespaceLevels({ 'db.*': 'debug' });
      const db2 = logger.child('db.queries');
      await db2.debug('after');
      const afterCount = lines.filter((l) => l.includes('after')).length;

      expect(beforeCount).toBe(0);
      expect(afterCount).toBe(1);
    } finally {
      (process.stdout as NodeJS.WriteStream).write = orig;
    }
  });
});

describe('registerLevelSignal', () => {
  it('cycles the level on each signal and dispose removes the listener', () => {
    const logger = new LogixiaLogger({ ...BASE, levelOptions: { level: 'info' } });
    const dispose = registerLevelSignal(logger, { signal: 'SIGUSR2' });

    expect(logger.getLevel()).toBe('info');
    process.emit('SIGUSR2', 'SIGUSR2');
    expect(logger.getLevel()).toBe('debug'); // info → debug
    process.emit('SIGUSR2', 'SIGUSR2');
    expect(logger.getLevel()).toBe('trace'); // debug → trace

    dispose();
    const before = logger.getLevel();
    process.emit('SIGUSR2', 'SIGUSR2');
    expect(logger.getLevel()).toBe(before); // listener removed → no change

    process.removeAllListeners('SIGUSR2');
  });

  it('uses a custom cycle when provided', () => {
    const logger = new LogixiaLogger({ ...BASE, levelOptions: { level: 'error' } });
    const cycle: LogLevelString[] = ['error', 'warn'] as unknown as LogLevelString[];
    const dispose = registerLevelSignal(logger, { cycle });
    process.emit('SIGUSR2', 'SIGUSR2');
    expect(logger.getLevel()).toBe('warn');
    process.emit('SIGUSR2', 'SIGUSR2');
    expect(logger.getLevel()).toBe('error'); // wraps
    dispose();
    process.removeAllListeners('SIGUSR2');
  });
});

describe('createLevelControlHandler', () => {
  function fakeRes() {
    return {
      statusCode: 200,
      headers: {} as Record<string, string>,
      body: '',
      setHeader(k: string, v: string) {
        this.headers[k] = v;
      },
      end(b?: string) {
        this.body = b ?? '';
      },
    };
  }

  function makeLogger() {
    let level: LogLevelString = 'info' as LogLevelString;
    let ns: NamespaceLevels = {};
    const logger: ReconfigurableLogger = {
      getLevel: () => level,
      setLevel: (l) => {
        level = l;
      },
      setNamespaceLevels: (l) => {
        ns = { ...l };
      },
      getNamespaceLevels: () => ({ ...ns }),
    };
    return logger;
  }

  it('GET returns the current level and namespace levels', () => {
    const handler = createLevelControlHandler(makeLogger());
    const res = fakeRes();
    handler({ method: 'GET' }, res);
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body)).toEqual({ level: 'info', namespaceLevels: {} });
  });

  it('POST with a body object (Express style) sets the level', () => {
    const logger = makeLogger();
    const handler = createLevelControlHandler(logger);
    const res = fakeRes();
    handler({ method: 'POST', body: { level: 'debug' } } as never, res);
    expect(res.statusCode).toBe(200);
    expect(logger.getLevel()).toBe('debug');
  });

  it('POST sets namespace levels', () => {
    const logger = makeLogger();
    const handler = createLevelControlHandler(logger);
    const res = fakeRes();
    handler({ method: 'POST', body: { namespaceLevels: { 'db.*': 'trace' } } } as never, res);
    expect(logger.getNamespaceLevels!()).toEqual({ 'db.*': 'trace' });
  });

  it('rejects an unknown level with 400', () => {
    const handler = createLevelControlHandler(makeLogger());
    const res = fakeRes();
    handler({ method: 'POST', body: { level: 'loud' } } as never, res);
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toContain('unknown level');
  });

  it('rejects a non-GET/POST method with 405', () => {
    const handler = createLevelControlHandler(makeLogger());
    const res = fakeRes();
    handler({ method: 'DELETE' }, res);
    expect(res.statusCode).toBe(405);
  });

  it('reads a streamed raw body when req.on is provided (Node http style)', () => {
    const logger = makeLogger();
    const handler = createLevelControlHandler(logger);
    const res = fakeRes();
    const listeners: Record<string, (c?: unknown) => void> = {};
    const req = {
      method: 'POST',
      on(event: string, cb: (c?: unknown) => void) {
        listeners[event] = cb;
      },
    };
    handler(req, res);
    listeners['data']!('{"level":');
    listeners['data']!('"warn"}');
    listeners['end']!();
    expect(logger.getLevel()).toBe('warn');
  });
});
