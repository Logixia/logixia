/**
 * Level validation (issue #29).
 *
 *  1. `LOGIXIA_LEVEL=DEBUG` (upper case) enables debug logging
 *  2. An unknown initial level warns once and falls back to info
 *  3. A valid custom level such as `kafka` is accepted without a warning
 *  4. `setLevel('nope')` warns and keeps the current level
 *
 * Plus: setLevel() case normalisation, and invalid namespace / ENV overrides
 * falling back to the configured level instead of being applied unchecked.
 */

import { createLogger, LogixiaLogger } from '../logitron-logger';

const BASE_CONFIG = {
  appName: 'TestApp',
  format: { timestamp: false, colorize: false, json: false },
  traceId: false,
  silent: false,
};

const ENV_KEYS = [
  'LOGIXIA_LEVEL',
  'LOGIXIA_LEVEL_DB',
  'LOGIXIA_SILENT_INTERNAL',
  'NODE_ENV',
  'CI',
] as const;

describe('Log level validation (issue #29)', () => {
  let stdoutSpy: jest.SpyInstance;
  let stderrSpy: jest.SpyInstance;
  const savedEnv: Partial<Record<(typeof ENV_KEYS)[number], string>> = {};

  /** Everything written to stdout/stderr (log lines and internal diagnostics). */
  const output = (): string =>
    [...stdoutSpy.mock.calls, ...stderrSpy.mock.calls].map((c) => String(c[0])).join('');

  /** Only the internalWarn() lines. */
  const warnings = (): string[] =>
    stderrSpy.mock.calls.map((c) => String(c[0])).filter((l) => l.startsWith('[logixia:warn]'));

  beforeEach(() => {
    for (const key of ENV_KEYS) {
      savedEnv[key] = process.env[key];
      delete process.env[key];
    }
    stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    stdoutSpy.mockRestore();
    stderrSpy.mockRestore();
    for (const key of ENV_KEYS) {
      const value = savedEnv[key];
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  it('LOGIXIA_LEVEL=DEBUG (upper case) enables debug logging', async () => {
    process.env['LOGIXIA_LEVEL'] = 'DEBUG';
    const logger = new LogixiaLogger(BASE_CONFIG);

    await logger.debug('debug-visible');

    expect(logger.getLevel()).toBe('debug');
    expect(output()).toContain('debug-visible');
    expect(warnings()).toHaveLength(0);
  });

  it('an unknown initial level warns once and falls back to info', async () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'warning' } });

    // Trigger further cache rebuilds — the warning must not repeat.
    logger.disableField('level');
    logger.enableField('level');
    logger.setNamespaceLevels({});

    await logger.info('info-visible');
    await logger.debug('debug-hidden');

    const warns = warnings();
    expect(warns).toHaveLength(1);
    expect(warns[0]).toContain('warning');
    expect(warns[0]).toContain('info');
    expect(logger.getLevel()).toBe('info');
    expect(output()).toContain('info-visible');
    expect(output()).not.toContain('debug-hidden');
  });

  it('accepts a valid custom level such as kafka', async () => {
    const logger = createLogger({
      ...BASE_CONFIG,
      levelOptions: {
        level: 'kafka',
        levels: { error: 0, warn: 1, info: 2, kafka: 3 },
      },
    });

    await logger.logLevel('kafka', 'kafka-visible');

    expect(logger.getLevel()).toBe('kafka');
    expect(output()).toContain('kafka-visible');
    expect(warnings()).toHaveLength(0);
  });

  it("setLevel('nope') warns and keeps the current level", async () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'warn' } });

    logger.setLevel('nope');
    await logger.info('info-hidden');
    await logger.warn('warn-visible');

    const warns = warnings();
    expect(warns).toHaveLength(1);
    expect(warns[0]).toContain('nope');
    expect(logger.getLevel()).toBe('warn');
    expect(output()).not.toContain('info-hidden');
    expect(output()).toContain('warn-visible');
  });

  it('a runtime setLevel() survives cache rebuilds and outranks ENV and namespace levels', async () => {
    process.env['LOGIXIA_LEVEL'] = 'error';
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'info' } });

    logger.setLevel('debug');
    logger.enableField('level');
    logger.setNamespaceLevels({ '*': 'error' });
    logger.patchNamespaceLevels({ db: 'error' });
    await logger.debug('debug-visible');

    expect(logger.getLevel()).toBe('debug');
    expect(output()).toContain('debug-visible');
  });

  it("setLevel('WARN') normalizes to warn", async () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'debug' } });

    logger.setLevel('WARN');
    await logger.info('info-hidden');
    await logger.warn('warn-visible');

    expect(logger.getLevel()).toBe('warn');
    expect(output()).not.toContain('info-hidden');
    expect(output()).toContain('warn-visible');
    expect(warnings()).toHaveLength(0);
  });

  it('an invalid namespaceLevels override warns and falls back to the configured level', async () => {
    const logger = new LogixiaLogger(
      { ...BASE_CONFIG, levelOptions: { level: 'warn' }, namespaceLevels: { db: 'chatty' } },
      'db'
    );
    logger.setNamespaceLevels({ db: 'chatty' }); // cache rebuild must not re-warn

    await logger.info('info-hidden');
    await logger.warn('warn-visible');

    const warns = warnings();
    expect(warns).toHaveLength(1);
    expect(warns[0]).toContain('chatty');
    expect(warns[0]).toContain("namespaceLevels['db']");
    expect(logger.getLevel()).toBe('warn');
    expect(output()).not.toContain('info-hidden');
    expect(output()).toContain('warn-visible');
  });

  it('an invalid namespaced ENV override warns and falls back to the configured level', async () => {
    process.env['LOGIXIA_LEVEL_DB'] = 'chatty';
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'warn' } }, 'db');
    logger.setNamespaceLevels({}); // cache rebuild must not re-warn

    await logger.info('info-hidden');
    await logger.warn('warn-visible');

    const warns = warnings();
    expect(warns).toHaveLength(1);
    expect(warns[0]).toContain('chatty');
    expect(warns[0]).toContain('LOGIXIA_LEVEL_DB');
    expect(logger.getLevel()).toBe('warn');
    expect(output()).not.toContain('info-hidden');
    expect(output()).toContain('warn-visible');
  });

  it('an invalid LOGIXIA_LEVEL warns once and falls back to the configured level', async () => {
    process.env['LOGIXIA_LEVEL'] = 'chatty';
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'warn' } });
    logger.setNamespaceLevels({}); // cache rebuild must not re-warn

    await logger.info('info-hidden');
    await logger.warn('warn-visible');

    const warns = warnings();
    expect(warns).toHaveLength(1);
    expect(warns[0]).toContain('chatty');
    expect(warns[0]).toContain('LOGIXIA_LEVEL');
    expect(logger.getLevel()).toBe('warn');
    expect(output()).not.toContain('info-hidden');
    expect(output()).toContain('warn-visible');
  });
});
