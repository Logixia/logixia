/**
 * Regression: `transports.console.level` (and database `level`) was accepted by
 * the config type but ignored, because the transport instances never exposed
 * `level` for TransportManager's per-transport level check.
 */

import { createLogger } from '../../index';
import { ConsoleTransport } from '../console.transport';
import { DatabaseTransport } from '../database.transport';
import { buildLevelValues, meetsTransportLevel } from '../level-filter';

describe('per-transport level', () => {
  let out: string[];
  let err: string[];
  let outSpy: jest.SpyInstance;
  let errSpy: jest.SpyInstance;

  beforeEach(() => {
    out = [];
    err = [];
    outSpy = jest.spyOn(process.stdout, 'write').mockImplementation((c: unknown) => {
      out.push(String(c));
      return true;
    });
    errSpy = jest.spyOn(process.stderr, 'write').mockImplementation((c: unknown) => {
      err.push(String(c));
      return true;
    });
  });

  afterEach(() => {
    outSpy.mockRestore();
    errSpy.mockRestore();
  });

  it('exposes the configured level on console and database transports', () => {
    expect(new ConsoleTransport({ level: 'warn' }).level).toBe('warn');
    expect(new ConsoleTransport().level).toBeUndefined();
    expect(
      new DatabaseTransport({ type: 'sqlite', database: ':memory:', level: 'error' }).level
    ).toBe('error');
  });

  it('console level filters entries below it end to end', async () => {
    const logger = createLogger({
      appName: 'lvl',
      levelOptions: { level: 'debug' },
      transports: { console: { level: 'warn', format: 'json' } },
    });
    await logger.debug('dbg-line');
    await logger.info('info-line');
    await logger.warn('warn-line');
    await logger.error('error-line');
    await logger.close();

    const all = [...out, ...err].join('');
    expect(all).not.toContain('dbg-line');
    expect(all).not.toContain('info-line');
    expect(all).toContain('warn-line');
    expect(all).toContain('error-line');
  });

  it('console without a level still receives every enabled level', async () => {
    const logger = createLogger({
      appName: 'lvl',
      levelOptions: { level: 'debug' },
      transports: { console: { format: 'json' } },
    });
    await logger.debug('dbg-line');
    await logger.close();
    expect([...out, ...err].join('')).toContain('dbg-line');
  });

  it('filters with custom levels using the logger severity values', async () => {
    const logger = createLogger({
      appName: 'lvl',
      levelOptions: {
        level: 'debug',
        levels: { error: 0, audit: 1, info: 2, debug: 3, chatty: 4 },
      },
      transports: { console: { level: 'audit', format: 'json' } },
    });
    await logger.logLevel('chatty', 'chatty-line');
    await logger.info('info-line');
    await logger.logLevel('audit', 'audit-line');
    await logger.error('error-line');
    await logger.close();

    const all = [...out, ...err].join('');
    expect(all).not.toContain('chatty-line');
    expect(all).not.toContain('info-line');
    expect(all).toContain('audit-line');
    expect(all).toContain('error-line');
  });

  it('a built-in threshold still admits custom levels that are more severe', async () => {
    const logger = createLogger({
      appName: 'lvl',
      levelOptions: {
        level: 'debug',
        levels: { error: 0, audit: 1, info: 2, debug: 3, chatty: 4 },
      },
      transports: { console: { level: 'info', format: 'json' } },
    });
    await logger.logLevel('chatty', 'chatty-line');
    await logger.logLevel('audit', 'audit-line');
    await logger.close();

    const all = [...out, ...err].join('');
    expect(all).not.toContain('chatty-line');
    expect(all).toContain('audit-line');
  });
});

describe('meetsTransportLevel', () => {
  const values = buildLevelValues({ audit: 1, chatty: 9 });

  it('compares on the logger scale and never filters without a threshold', () => {
    expect(meetsTransportLevel(undefined, 'chatty', values)).toBe(true);
    expect(meetsTransportLevel('warn', 'audit', values)).toBe(true);
    expect(meetsTransportLevel('warn', 'info', values)).toBe(false);
    expect(meetsTransportLevel('WARN', 'error', values)).toBe(true);
    expect(meetsTransportLevel('audit', 'info', values)).toBe(false);
  });

  it('does not filter on an unknown threshold or entry level', () => {
    expect(meetsTransportLevel('nope', 'info', values)).toBe(true);
    expect(meetsTransportLevel('warn', 'nope', values)).toBe(true);
  });
});
