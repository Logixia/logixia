/**
 * Comprehensive tests for LogixiaLogger core
 *
 * Covers:
 *  - Timer API: time, timeEnd, timeAsync (including error propagation)
 *  - Field management: enableField, disableField, isFieldEnabled, getFieldState, resetFieldState
 *  - Transport management: warn when no transport manager
 *  - Child loggers: context propagation, contextData inheritance
 *  - JSON format output
 *  - Colorize / non-colorize output
 *  - Plugin system: use, unuse, onLog mutation, cancellation
 *  - healthCheck / flush / close with no transport
 *  - AsyncLocalStorage context auto-merge
 *  - Multiple levels in one logger session
 *  - Payload in logs
 *  - Silent mode
 */

import { LogixiaContext } from '../../context/async-context';
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

function spyOutput() {
  const lines: string[] = [];
  const origOut = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);

  (process.stdout as NodeJS.WriteStream).write = (chunk: unknown) => {
    lines.push(String(chunk ?? ''));
    return true;
  };
  (process.stderr as NodeJS.WriteStream).write = (chunk: unknown) => {
    lines.push(String(chunk ?? ''));
    return true;
  };

  return {
    get lines() {
      return lines;
    },
    joined() {
      return lines.join('');
    },
    restore() {
      (process.stdout as NodeJS.WriteStream).write = origOut as typeof process.stdout.write;
      (process.stderr as NodeJS.WriteStream).write = origErr as typeof process.stderr.write;
    },
  };
}

let savedEnv: Record<string, string | undefined>;

beforeEach(() => {
  resetShutdownHandlers();
  process.removeAllListeners('SIGTERM');
  process.removeAllListeners('SIGINT');
  savedEnv = {
    LOGIXIA_LEVEL: process.env['LOGIXIA_LEVEL'],
    NODE_ENV: process.env['NODE_ENV'],
  };
  delete process.env['LOGIXIA_LEVEL'];
  process.env['NODE_ENV'] = 'test'; // suppresses debug noise in tests
});

afterEach(() => {
  resetShutdownHandlers();
  process.removeAllListeners('SIGTERM');
  process.removeAllListeners('SIGINT');
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

// ── Timer API ─────────────────────────────────────────────────────────────────

describe('Timer API', () => {
  it('timeEnd returns a duration in ms', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'info' } });
    logger.time('op');
    await new Promise((r) => setTimeout(r, 5));
    const duration = await logger.timeEnd('op');
    out.restore();
    expect(typeof duration).toBe('number');
    expect(duration!).toBeGreaterThanOrEqual(0);
  });

  it('timeEnd logs a message with duration info', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'info' } });
    logger.time('my-op');
    await logger.timeEnd('my-op');
    out.restore();
    expect(out.joined()).toContain("Timer 'my-op' finished");
  });

  it('timeEnd logs a warning when label does not exist', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'warn' } });
    const result = await logger.timeEnd('nonexistent');
    out.restore();
    expect(result).toBeUndefined();
    expect(out.joined()).toContain("Timer 'nonexistent' does not exist");
  });

  it('timeEnd removes the timer after logging', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'info' } });
    logger.time('once');
    await logger.timeEnd('once');
    // Calling again should produce a warning
    const result = await logger.timeEnd('once');
    out.restore();
    expect(result).toBeUndefined();
  });

  it('timeAsync returns the value from the async function', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'info' } });
    const result = await logger.timeAsync('db-query', async () => {
      await Promise.resolve();
      return 'query-result';
    });
    out.restore();
    expect(result).toBe('query-result');
  });

  it('timeAsync still logs timing when the function throws', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'info' } });
    await expect(
      logger.timeAsync('failing-op', async () => {
        throw new Error('op failed');
      })
    ).rejects.toThrow('op failed');
    out.restore();
    expect(out.joined()).toContain("Timer 'failing-op' finished");
  });

  it('close() warns about open timers', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'warn' } });
    logger.time('open-timer');
    await logger.close();
    out.restore();
    expect(out.joined()).toContain("Timer 'open-timer' was not ended properly");
  });

  it('multiple concurrent timers are tracked independently', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'info' } });
    logger.time('t1');
    logger.time('t2');
    const d1 = await logger.timeEnd('t1');
    const d2 = await logger.timeEnd('t2');
    out.restore();
    expect(typeof d1).toBe('number');
    expect(typeof d2).toBe('number');
  });
});

// ── Field management ──────────────────────────────────────────────────────────

describe('Field management', () => {
  it('isFieldEnabled returns true for a field not in fieldState', () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG });
    expect(logger.isFieldEnabled('timestamp')).toBe(true);
  });

  it('disableField makes isFieldEnabled return false', () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG });
    logger.disableField('timestamp');
    expect(logger.isFieldEnabled('timestamp')).toBe(false);
  });

  it('enableField makes isFieldEnabled return true again', () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG });
    logger.disableField('timestamp');
    logger.enableField('timestamp');
    expect(logger.isFieldEnabled('timestamp')).toBe(true);
  });

  it('getFieldState returns all standard fields', () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG });
    const state = logger.getFieldState();
    expect(typeof state.timestamp).toBe('boolean');
    expect(typeof state.level).toBe('boolean');
    expect(typeof state.message).toBe('boolean');
    expect(typeof state.appName).toBe('boolean');
    expect(typeof state.traceId).toBe('boolean');
  });

  it('resetFieldState clears all overrides', () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG });
    logger.disableField('level');
    logger.resetFieldState();
    expect(logger.isFieldEnabled('level')).toBe(true);
  });

  it('disabling "level" field removes level bracket from output', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'info' } });
    logger.disableField('level');
    await logger.info('no level shown');
    out.restore();
    expect(out.joined()).not.toContain('[INFO]');
    expect(out.joined()).toContain('no level shown');
  });

  it('disabling "message" field suppresses message output', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'info' } });
    logger.disableField('message');
    await logger.info('hidden message');
    out.restore();
    expect(out.joined()).not.toContain('hidden message');
  });
});

// ── JSON format ───────────────────────────────────────────────────────────────

describe('JSON format', () => {
  it('outputs valid JSON when format.json is true', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      format: { json: true },
      levelOptions: { level: 'info' },
    });
    await logger.info('json log', { key: 'val' });
    out.restore();
    const parsed = JSON.parse(out.joined());
    expect(parsed.level).toBe('info');
    expect(parsed.message).toBe('json log');
    expect(parsed.appName).toBe('TestApp');
  });

  it('includes payload in JSON output', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      format: { json: true },
      levelOptions: { level: 'info' },
    });
    await logger.info('with payload', { userId: 'u-1', action: 'login' });
    out.restore();
    const parsed = JSON.parse(out.joined());
    expect(parsed.payload?.userId).toBe('u-1');
  });
});

// ── Colorize output ───────────────────────────────────────────────────────────

describe('Colorize output', () => {
  it('includes ANSI escape codes when colorize is true', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      format: { colorize: true, timestamp: false },
      levelOptions: { level: 'info' },
    });
    await logger.info('colored output');
    out.restore();
    expect(out.joined()).toContain('\x1b[');
  });

  it('does not include ANSI escape codes when colorize is false', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      format: { colorize: false, timestamp: false },
      levelOptions: { level: 'info' },
    });
    await logger.info('plain output');
    out.restore();
    expect(out.joined()).not.toContain('\x1b[');
  });
});

// ── Child logger ──────────────────────────────────────────────────────────────

describe('Child logger', () => {
  it('child logger inherits the parent config', async () => {
    const out = spyOutput();
    const parent = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'info' } });
    const child = parent.child('auth-service');
    await child.info('child log');
    out.restore();
    expect(out.joined()).toContain('child log');
    expect(out.joined()).toContain('auth-service');
  });

  it('child logger has the correct context', () => {
    const parent = new LogixiaLogger({ ...BASE_CONFIG });
    const child = parent.child('payment');
    expect(child.getContext()).toBe('payment');
  });

  it('child logger with data still logs successfully', async () => {
    const out = spyOutput();
    const parent = new LogixiaLogger({
      ...BASE_CONFIG,
      format: { json: true },
      levelOptions: { level: 'info' },
    });
    const child = parent.child('svc', { serviceVersion: '2.0' });
    await child.info('child msg');
    out.restore();
    const parsed = JSON.parse(out.joined());
    expect(parsed.message).toBe('child msg');
    expect(parsed.context).toBe('svc');
  });

  it('child logger does not affect parent context', () => {
    const parent = new LogixiaLogger({ ...BASE_CONFIG });
    parent.child('child-ctx');
    expect(parent.getContext()).toBe('');
  });

  it('setContext changes the context on the logger', () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG });
    logger.setContext('new-context');
    expect(logger.getContext()).toBe('new-context');
  });
});

// ── Plugin integration ────────────────────────────────────────────────────────

describe('Plugin integration', () => {
  it('use() registers a plugin and returns the logger (chainable)', () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG });
    const result = logger.use({ name: 'plugin-a' });
    expect(result).toBe(logger);
  });

  it('unuse() removes a plugin and returns the logger (chainable)', () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG });
    logger.use({ name: 'plugin-a' });
    const result = logger.unuse('plugin-a');
    expect(result).toBe(logger);
  });

  it('plugin onLog hook receives the log entry', async () => {
    const received: string[] = [];
    const out = spyOutput();
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'info' } });
    logger.use({
      name: 'spy',
      onLog(entry) {
        received.push(entry.message);
        return entry;
      },
    });
    await logger.info('plugin message');
    out.restore();
    expect(received).toContain('plugin message');
  });

  it('plugin can cancel a log entry by returning null', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'info' } });
    logger.use({
      name: 'canceller',
      onLog() {
        return null;
      },
    });
    await logger.info('should be cancelled');
    out.restore();
    expect(out.joined()).not.toContain('should be cancelled');
  });

  it('plugin can enrich a log entry', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      format: { json: true },
      levelOptions: { level: 'info' },
    });
    logger.use({
      name: 'enricher',
      onLog(entry) {
        return { ...entry, payload: { ...entry.payload, enriched: true } };
      },
    });
    await logger.info('enriched log');
    out.restore();
    const parsed = JSON.parse(out.joined());
    expect(parsed.payload?.enriched).toBe(true);
  });

  it('plugin onShutdown is called when logger is closed', async () => {
    const shutdownCalled = jest.fn();
    const logger = new LogixiaLogger({ ...BASE_CONFIG });
    logger.use({ name: 'shutdown-plugin', onShutdown: shutdownCalled });
    await logger.close();
    expect(shutdownCalled).toHaveBeenCalledTimes(1);
  });

  it('unuse removes a plugin so its hooks no longer run', async () => {
    const received: string[] = [];
    const out = spyOutput();
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'info' } });
    logger.use({
      name: 'removable',
      onLog(entry) {
        received.push(entry.message);
        return entry;
      },
    });
    logger.unuse('removable');
    await logger.info('after unuse');
    out.restore();
    expect(received).not.toContain('after unuse');
  });
});

// ── AsyncLocalStorage context auto-merge ─────────────────────────────────────

describe('AsyncLocalStorage context auto-merge', () => {
  it('merges ALS context fields into log payload', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      format: { json: true },
      levelOptions: { level: 'info' },
    });

    await new Promise<void>((resolve) => {
      LogixiaContext.run({ requestId: 'req-abc', userId: 'u-99' }, async () => {
        await logger.info('with context');
        resolve();
      });
    });

    out.restore();
    const parsed = JSON.parse(out.joined());
    expect(parsed.payload?.requestId).toBe('req-abc');
    expect(parsed.payload?.userId).toBe('u-99');
  });

  it('explicit data overrides ALS context fields', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      format: { json: true },
      levelOptions: { level: 'info' },
    });

    await new Promise<void>((resolve) => {
      LogixiaContext.run({ requestId: 'from-context' }, async () => {
        await logger.info('override', { requestId: 'from-data' });
        resolve();
      });
    });

    out.restore();
    const parsed = JSON.parse(out.joined());
    expect(parsed.payload?.requestId).toBe('from-data');
  });
});

// ── healthCheck and flush ─────────────────────────────────────────────────────

describe('healthCheck', () => {
  it('returns healthy: false when no transport manager', async () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG });
    const result = await logger.healthCheck();
    expect(result.healthy).toBe(false);
  });
});

describe('flush', () => {
  it('resolves without error when no transport manager', async () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG });
    await expect(logger.flush()).resolves.toBeUndefined();
  });
});

// ── close ─────────────────────────────────────────────────────────────────────

describe('close', () => {
  it('resolves without error', async () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG });
    await expect(logger.close()).resolves.toBeUndefined();
  });

  it('clears all open timers', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'warn' } });
    logger.time('t1');
    logger.time('t2');
    await logger.close();
    out.restore();
    const msg = out.joined();
    expect(msg).toContain("'t1' was not ended properly");
    expect(msg).toContain("'t2' was not ended properly");
  });
});

// ── Transport management stubs (no transport manager) ────────────────────────

describe('Transport management (no transport manager)', () => {
  it('getAvailableTransports returns empty array', () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG });
    expect(logger.getAvailableTransports()).toEqual([]);
  });

  it('getTransportLevels returns undefined', () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG });
    expect(logger.getTransportLevels('console')).toBeUndefined();
  });
});

// ── Custom levels ─────────────────────────────────────────────────────────────

describe('Custom levels', () => {
  it('creates custom level method on the logger instance', () => {
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: {
        level: 'kafka',
        levels: { error: 0, warn: 1, info: 2, debug: 3, kafka: 4 },
      },
    });

    expect(typeof (logger as any).kafka).toBe('function');
  });

  it('custom level method logs at that level', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: {
        level: 'kafka',
        levels: { error: 0, warn: 1, info: 2, debug: 3, kafka: 4 },
      },
    });

    await (logger as any).kafka('kafka event', { topic: 'users' });
    out.restore();
    expect(out.joined()).toContain('kafka event');
  });

  it('createLogger factory creates typed logger with custom level methods', () => {
    const logger = createLogger({
      ...BASE_CONFIG,
      levelOptions: {
        level: 'audit',
        levels: { error: 0, warn: 1, info: 2, debug: 3, audit: 4 },
      },
    });

    expect(typeof (logger as any).audit).toBe('function');
  });
});

// ── setLevel dynamic change ───────────────────────────────────────────────────

describe('setLevel', () => {
  it('setLevel and getLevel round-trip', () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'error' } });
    logger.setLevel('debug');
    expect(logger.getLevel()).toBe('debug');
  });

  it('setLevel enables previously suppressed levels', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'error' } });
    await logger.debug('before change');
    logger.setLevel('debug');
    await logger.debug('after change');
    out.restore();
    expect(out.joined()).not.toContain('before change');
    expect(out.joined()).toContain('after change');
  });
});

// ── Error object logging ──────────────────────────────────────────────────────

describe('error() with Error object', () => {
  it('serializes the Error into the payload', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      format: { json: true },
      levelOptions: { level: 'error' },
    });
    const err = new Error('DB connection lost');
    await logger.error(err);
    out.restore();
    const parsed = JSON.parse(out.joined());
    expect(parsed.message).toBe('DB connection lost');
    expect(parsed.payload?.error?.name).toBe('Error');
  });

  it('merges extra data alongside the serialized error', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      format: { json: true },
      levelOptions: { level: 'error' },
    });
    const err = new Error('Fail');
    await logger.error(err, { requestId: 'req-1' });
    out.restore();
    const parsed = JSON.parse(out.joined());
    expect(parsed.payload?.requestId).toBe('req-1');
    expect(parsed.payload?.error).toBeDefined();
  });
});

// ── appName in output ─────────────────────────────────────────────────────────

describe('appName in output', () => {
  it('includes the app name in text output', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      appName: 'MyService',
      levelOptions: { level: 'info' },
    });
    await logger.info('app name check');
    out.restore();
    expect(out.joined()).toContain('MyService');
  });
});

// ── Silent mode ───────────────────────────────────────────────────────────────

describe('silent mode', () => {
  it('suppresses all output when silent: true', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      silent: true,
      levelOptions: { level: 'trace' },
    });
    await logger.error('silent error');
    await logger.info('silent info');
    await logger.debug('silent debug');
    out.restore();
    expect(out.joined()).toBe('');
  });
});
