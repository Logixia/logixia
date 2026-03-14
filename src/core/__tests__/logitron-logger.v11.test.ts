/**
 * Logixia v1.1 core logger tests
 *
 * Covers:
 *  - Feature 1: Graceful shutdown auto-registration via config
 *  - Feature 2: Built-in log redaction (path + pattern) in log payload
 *  - Feature 3: Per-namespace log levels + LOGIXIA_LEVEL_<NS> ENV overrides
 *  - Feature 5: Adaptive log level from NODE_ENV / LOGIXIA_LEVEL env vars
 *
 * Uses console spies to observe log output — no transports needed.
 */

import { resetShutdownHandlers } from '../../utils/shutdown.utils';
import { createLogger, LogixiaLogger } from '../logitron-logger';

// ── Helpers ───────────────────────────────────────────────────────────────────

const BASE_CONFIG = {
  appName: 'TestApp',
  environment: 'development' as const,
  format: { timestamp: false, colorize: false, json: false },
  traceId: false,
  silent: false,
};

/**
 * Spy on all console output methods and accumulate messages in a plain array
 * that is NOT cleared when `restore()` is called.
 */
function spyConsole() {
  const captured: string[] = [];
  const push = (m: unknown) => captured.push(String(m ?? ''));

  // Intercept process.stdout/stderr writes (used by the optimised output path)
  const realStdoutWrite = process.stdout.write.bind(process.stdout);
  const realStderrWrite = process.stderr.write.bind(process.stderr);
  (process.stdout as NodeJS.WriteStream).write = (chunk: unknown) => {
    captured.push(String(chunk ?? ''));
    return true;
  };
  (process.stderr as NodeJS.WriteStream).write = (chunk: unknown) => {
    captured.push(String(chunk ?? ''));
    return true;
  };

  // Also intercept console.* as a fallback (some paths may still use console)
  const spies = {
    log: jest.spyOn(console, 'log').mockImplementation(push),
    error: jest.spyOn(console, 'error').mockImplementation(push),
    warn: jest.spyOn(console, 'warn').mockImplementation(push),
    debug: jest.spyOn(console, 'debug').mockImplementation(push),
  };

  return {
    /** All messages logged across all output channels, in order */
    get messages() {
      return captured;
    },
    restore() {
      (process.stdout as NodeJS.WriteStream).write = realStdoutWrite as typeof process.stdout.write;
      (process.stderr as NodeJS.WriteStream).write = realStderrWrite as typeof process.stderr.write;
      spies.log.mockRestore();
      spies.error.mockRestore();
      spies.warn.mockRestore();
      spies.debug.mockRestore();
    },
  };
}

// ── Setup / Teardown ──────────────────────────────────────────────────────────

let savedEnv: Record<string, string | undefined>;

beforeEach(() => {
  resetShutdownHandlers();
  process.removeAllListeners('SIGTERM');
  process.removeAllListeners('SIGINT');

  // Snapshot relevant env vars before each test
  savedEnv = {
    LOGIXIA_LEVEL: process.env['LOGIXIA_LEVEL'],
    LOGIXIA_LEVEL_DB: process.env['LOGIXIA_LEVEL_DB'],
    LOGIXIA_LEVEL_HTTP: process.env['LOGIXIA_LEVEL_HTTP'],
    NODE_ENV: process.env['NODE_ENV'],
    CI: process.env['CI'],
  };
  delete process.env['LOGIXIA_LEVEL'];
  delete process.env['LOGIXIA_LEVEL_DB'];
  delete process.env['LOGIXIA_LEVEL_HTTP'];
});

afterEach(() => {
  resetShutdownHandlers();
  process.removeAllListeners('SIGTERM');
  process.removeAllListeners('SIGINT');

  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

// ── Feature 5: Adaptive log level ────────────────────────────────────────────

describe('Feature 5 — Adaptive log level', () => {
  it('uses DEBUG level when NODE_ENV=development and no config level set', () => {
    process.env['NODE_ENV'] = 'development';
    delete process.env['LOGIXIA_LEVEL'];

    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: undefined });
    expect(logger.getLevel()).toBe('debug');
  });

  it('uses WARN level when NODE_ENV=test', () => {
    process.env['NODE_ENV'] = 'test';
    delete process.env['LOGIXIA_LEVEL'];

    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: undefined });
    expect(logger.getLevel()).toBe('warn');
  });

  it('uses INFO level when NODE_ENV=production', () => {
    process.env['NODE_ENV'] = 'production';
    delete process.env['LOGIXIA_LEVEL'];

    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: undefined });
    expect(logger.getLevel()).toBe('info');
  });

  it('uses INFO level when CI=true and no NODE_ENV', () => {
    delete process.env['NODE_ENV'];
    process.env['CI'] = 'true';

    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: undefined });
    expect(logger.getLevel()).toBe('info');

    delete process.env['CI'];
  });

  it('LOGIXIA_LEVEL env var overrides NODE_ENV-based level', () => {
    process.env['NODE_ENV'] = 'development'; // would yield debug
    process.env['LOGIXIA_LEVEL'] = 'error';

    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: undefined });
    expect(logger.getLevel()).toBe('error');
  });

  it('explicit config levelOptions.level takes precedence over NODE_ENV default', () => {
    process.env['NODE_ENV'] = 'development'; // would yield debug
    delete process.env['LOGIXIA_LEVEL'];

    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'verbose' },
    });
    expect(logger.getLevel()).toBe('verbose');
  });

  it('LOGIXIA_LEVEL wins over explicit config level', () => {
    process.env['LOGIXIA_LEVEL'] = 'trace';

    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'error' },
    });
    expect(logger.getLevel()).toBe('trace');
  });

  it('falls back to INFO when NODE_ENV is not set and CI not set', () => {
    delete process.env['NODE_ENV'];
    delete process.env['CI'];
    delete process.env['LOGIXIA_LEVEL'];

    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: undefined });
    expect(logger.getLevel()).toBe('info');
  });
});

// ── Feature 3: Per-namespace log levels ──────────────────────────────────────

describe('Feature 3 — Per-namespace log levels', () => {
  it('a child logger uses namespaceLevels config to determine its level', async () => {
    const spy = spyConsole();

    const parent = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'error' }, // parent only logs errors
      namespaceLevels: { db: 'debug' }, // but "db" namespace → debug
    });

    const db = parent.child('db');
    await db.debug('database query executed');

    spy.restore();
    expect(spy.messages.some((m) => m.includes('database query executed'))).toBe(true);
  });

  it('a non-matching namespace falls back to the global level', async () => {
    const spy = spyConsole();

    const parent = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'error' },
      namespaceLevels: { db: 'debug' },
    });

    const http = parent.child('http');
    await http.debug('http request'); // should be suppressed

    spy.restore();
    expect(spy.messages.join('')).toBe(''); // nothing logged
  });

  it('wildcard namespace pattern db.* matches sub-namespace db.queries', async () => {
    const spy = spyConsole();

    const parent = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'error' },
      namespaceLevels: { 'db.*': 'debug' },
    });

    const dbQ = parent.child('db.queries');
    await dbQ.debug('query ran');

    spy.restore();
    expect(spy.messages.some((m) => m.includes('query ran'))).toBe(true);
  });

  it('more-specific (longer) pattern wins over less-specific', async () => {
    const spy = spyConsole();

    const parent = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'error' },
      namespaceLevels: {
        'db.*': 'debug', // less specific
        'db.queries': 'trace', // more specific → wins
      },
    });

    const dbQ = parent.child('db.queries');
    await dbQ.trace('very verbose trace');

    spy.restore();
    expect(spy.messages.some((m) => m.includes('very verbose trace'))).toBe(true);
  });

  it('LOGIXIA_LEVEL_DB env var overrides namespaceLevels config for "db" context', async () => {
    process.env['LOGIXIA_LEVEL_DB'] = 'trace';

    const spy = spyConsole();

    const parent = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'error' },
      namespaceLevels: { db: 'warn' }, // config says warn, env overrides to trace
    });

    const dbLogger = parent.child('db');
    await dbLogger.trace('trace message via env');

    spy.restore();
    expect(spy.messages.some((m) => m.includes('trace message via env'))).toBe(true);
  });

  it('LOGIXIA_LEVEL_DB also applies to sub-contexts like "db.queries"', async () => {
    process.env['LOGIXIA_LEVEL_DB'] = 'debug';

    const spy = spyConsole();

    const parent = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'error' },
    });

    const dbQ = parent.child('db.queries');
    await dbQ.debug('sub-context debug');

    spy.restore();
    expect(spy.messages.some((m) => m.includes('sub-context debug'))).toBe(true);
  });

  it('LOGIXIA_LEVEL global env is respected when no namespace matches', async () => {
    process.env['LOGIXIA_LEVEL'] = 'debug';

    const spy = spyConsole();

    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'error' },
    });

    await logger.debug('global env debug');

    spy.restore();
    expect(spy.messages.some((m) => m.includes('global env debug'))).toBe(true);
  });

  it('a logger with no context ignores namespaceLevels', async () => {
    const spy = spyConsole();

    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'error' },
      namespaceLevels: { db: 'debug' },
    });

    // no context set — still at 'error' level
    await logger.debug('should be suppressed');

    spy.restore();
    expect(spy.messages.join('')).toBe('');
  });

  it('exact namespace match "payment" at trace level', async () => {
    const spy = spyConsole();

    const parent = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'error' },
      namespaceLevels: { payment: 'trace' },
    });

    const payment = parent.child('payment');
    await payment.trace('payment trace');

    spy.restore();
    expect(spy.messages.some((m) => m.includes('payment trace'))).toBe(true);
  });

  it('namespace level does not bleed into sibling namespaces', async () => {
    const spy = spyConsole();

    const parent = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'error' },
      namespaceLevels: { db: 'debug' },
    });

    const cache = parent.child('cache');
    await cache.debug('cache debug'); // should be suppressed — 'cache' is not 'db'

    spy.restore();
    expect(spy.messages.join('')).toBe('');
  });
});

// ── Feature 2: Built-in log redaction ────────────────────────────────────────

describe('Feature 2 — Built-in log redaction', () => {
  it('redacts a configured path from the log payload', async () => {
    const spy = spyConsole();

    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'info' },
      redact: { paths: ['password'] },
    });

    await logger.info('user logged in', { password: 'mySecret', user: 'alice' });

    spy.restore();
    const combined = spy.messages.join(' ');
    expect(combined).not.toContain('mySecret');
    expect(combined).toContain('[REDACTED]');
    expect(combined).toContain('alice');
  });

  it('redacts a regex pattern from string values in payload', async () => {
    const spy = spyConsole();

    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'info' },
      redact: { patterns: [/Bearer\s+\S+/gi] },
    });

    await logger.info('auth attempt', { auth: 'Bearer super-secret-token' });

    spy.restore();
    const combined = spy.messages.join(' ');
    expect(combined).not.toContain('super-secret-token');
    expect(combined).toContain('[REDACTED]');
  });

  it('does not redact when no redact config is provided', async () => {
    const spy = spyConsole();

    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'info' },
    });

    await logger.info('plain log', { token: 'my-token' });

    spy.restore();
    expect(spy.messages.join(' ')).toContain('my-token');
  });

  it('uses a custom censor string from redact config', async () => {
    const spy = spyConsole();

    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'info' },
      redact: { paths: ['apiKey'], censor: '***' },
    });

    await logger.info('api call', { apiKey: 'sk-12345678' });

    spy.restore();
    const combined = spy.messages.join(' ');
    expect(combined).toContain('***');
    expect(combined).not.toContain('sk-12345678');
  });

  it('redaction applies even when contextData is merged', async () => {
    const spy = spyConsole();

    const parent = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'info' },
      redact: { paths: ['secret'] },
    });

    const child = parent.child('service', { secret: 'very-secret' });
    await child.info('event with context secret');

    spy.restore();
    expect(spy.messages.join(' ')).not.toContain('very-secret');
  });

  it('redacts multiple paths simultaneously', async () => {
    const spy = spyConsole();

    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'info' },
      redact: { paths: ['user.token', 'user.ssn'] },
    });

    await logger.info('profile', { user: { token: 'tok-abc', ssn: '123-45-6789', name: 'Bob' } });

    spy.restore();
    const combined = spy.messages.join(' ');
    expect(combined).not.toContain('tok-abc');
    expect(combined).not.toContain('123-45-6789');
    expect(combined).toContain('Bob');
  });
});

// ── Feature 1: Graceful shutdown via config ───────────────────────────────────

describe('Feature 1 — Graceful shutdown via config', () => {
  let exitSpy: jest.SpyInstance;

  beforeEach(() => {
    exitSpy = jest.spyOn(process, 'exit').mockImplementation((() => {}) as never);
  });

  afterEach(() => {
    exitSpy.mockRestore();
  });

  it('gracefulShutdown: true registers the logger for shutdown', async () => {
    const closeSpy = jest.fn(() => Promise.resolve());

    class TrackedLogger extends LogixiaLogger {
      override async close(): Promise<void> {
        await super.close();
        closeSpy();
      }
    }

    expect(
      new TrackedLogger({
        ...BASE_CONFIG,
        levelOptions: { level: 'info' },
        gracefulShutdown: true,
      })
    ).toBeInstanceOf(LogixiaLogger);

    process.emit('SIGTERM', 'SIGTERM');
    await new Promise((r) => setImmediate(r));

    expect(closeSpy).toHaveBeenCalledTimes(1);
    expect(exitSpy).toHaveBeenCalledWith(0);
  });

  it('gracefulShutdown: false does not register the logger', async () => {
    const closeSpy = jest.fn(() => Promise.resolve());

    class TrackedLogger extends LogixiaLogger {
      override async close(): Promise<void> {
        await super.close();
        closeSpy();
      }
    }

    expect(
      new TrackedLogger({
        ...BASE_CONFIG,
        levelOptions: { level: 'info' },
        gracefulShutdown: false,
      })
    ).toBeInstanceOf(LogixiaLogger);

    process.emit('SIGTERM', 'SIGTERM');
    await new Promise((r) => setImmediate(r));

    expect(closeSpy).not.toHaveBeenCalled();
  });

  it('gracefulShutdown object config with enabled:true works', async () => {
    const closeSpy = jest.fn(() => Promise.resolve());

    class TrackedLogger extends LogixiaLogger {
      override async close(): Promise<void> {
        await super.close();
        closeSpy();
      }
    }

    expect(
      new TrackedLogger({
        ...BASE_CONFIG,
        levelOptions: { level: 'info' },
        gracefulShutdown: { enabled: true, timeout: 1000 },
      })
    ).toBeInstanceOf(LogixiaLogger);

    process.emit('SIGTERM', 'SIGTERM');
    await new Promise((r) => setImmediate(r));

    expect(closeSpy).toHaveBeenCalledTimes(1);
  });

  it('gracefulShutdown with enabled:false does not register', async () => {
    const closeSpy = jest.fn(() => Promise.resolve());

    class TrackedLogger extends LogixiaLogger {
      override async close(): Promise<void> {
        await super.close();
        closeSpy();
      }
    }

    expect(
      new TrackedLogger({
        ...BASE_CONFIG,
        levelOptions: { level: 'info' },
        gracefulShutdown: { enabled: false },
      })
    ).toBeInstanceOf(LogixiaLogger);

    process.emit('SIGTERM', 'SIGTERM');
    await new Promise((r) => setImmediate(r));

    expect(closeSpy).not.toHaveBeenCalled();
  });

  it('logger.close() deregisters itself from the shutdown registry', async () => {
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'info' },
      gracefulShutdown: true,
    });

    await logger.close(); // manual close deregisters

    const closeSpy = jest.spyOn(logger, 'close');
    process.emit('SIGTERM', 'SIGTERM');
    await new Promise((r) => setImmediate(r));

    expect(closeSpy).not.toHaveBeenCalled();
  });
});

// ── General logger functionality ──────────────────────────────────────────────

describe('General logger — shouldLog / filtering', () => {
  it('logs messages at or above the configured level', async () => {
    const spy = spyConsole();

    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'warn' },
    });

    await logger.warn('warn message');
    await logger.error('error message');

    spy.restore();
    expect(spy.messages.some((m) => m.includes('warn message'))).toBe(true);
    expect(spy.messages.some((m) => m.includes('error message'))).toBe(true);
  });

  it('suppresses messages below the configured level', async () => {
    const spy = spyConsole();

    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'warn' },
    });

    await logger.info('info message');
    await logger.debug('debug message');

    spy.restore();
    const combined = spy.messages.join(' ');
    expect(combined).not.toContain('info message');
    expect(combined).not.toContain('debug message');
  });

  it('silent mode suppresses all output', async () => {
    const spy = spyConsole();

    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      silent: true,
      levelOptions: { level: 'trace' },
    });

    await logger.error('silent error');
    await logger.info('silent info');

    spy.restore();
    expect(spy.messages.join(' ')).toBe('');
  });

  it('setLevel dynamically changes the active log level', async () => {
    const spy = spyConsole();

    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'error' },
    });

    await logger.debug('before setLevel'); // suppressed

    logger.setLevel('debug');
    await logger.debug('after setLevel'); // should appear

    spy.restore();
    const combined = spy.messages.join(' ');
    expect(combined).not.toContain('before setLevel');
    expect(combined).toContain('after setLevel');
  });

  it('error() with an Error object serializes it into the payload', async () => {
    const spy = spyConsole();

    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'error' },
    });

    const err = new Error('Something broke');
    await logger.error(err);

    spy.restore();
    expect(spy.messages.join(' ')).toContain('Something broke');
  });

  it('info() with payload appends it to the log line', async () => {
    const spy = spyConsole();

    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'info' },
    });

    await logger.info('user action', { userId: 'u-123' });

    spy.restore();
    expect(spy.messages.join(' ')).toContain('u-123');
  });

  it('context is included in log output for a child logger', async () => {
    const spy = spyConsole();

    const parent = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: { level: 'info' },
    });

    const child = parent.child('payment-service');
    await child.info('processing payment');

    spy.restore();
    expect(spy.messages.join(' ')).toContain('payment-service');
  });
});

// ── createLogger factory ──────────────────────────────────────────────────────

describe('createLogger factory', () => {
  it('returns a typed logger with standard methods', () => {
    const logger = createLogger({ ...BASE_CONFIG, levelOptions: { level: 'info' } });
    expect(typeof logger.info).toBe('function');
    expect(typeof logger.debug).toBe('function');
    expect(typeof logger.error).toBe('function');
    expect(typeof logger.warn).toBe('function');
  });

  it('attaches custom level methods from levelOptions.levels', () => {
    const logger = createLogger({
      ...BASE_CONFIG,
      levelOptions: {
        level: 'info',
        levels: { audit: 6 },
      },
    });
    expect(typeof (logger as unknown as Record<string, unknown>)['audit']).toBe('function');
  });

  it('custom level method actually logs at the right level', async () => {
    const spy = spyConsole();

    const logger = createLogger({
      ...BASE_CONFIG,
      levelOptions: {
        level: 'audit',
        levels: { error: 0, warn: 1, info: 2, debug: 3, trace: 4, verbose: 5, audit: 6 },
      },
    });

    await (logger as any).audit('audit event occurred');

    spy.restore();
    expect(spy.messages.join(' ')).toContain('audit event occurred');
  });
});
