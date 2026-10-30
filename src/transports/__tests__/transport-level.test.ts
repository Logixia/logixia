/**
 * Regression: `transports.console.level` (and database `level`) was accepted by
 * the config type but ignored, because the transport instances never exposed
 * `level` for TransportManager's per-transport level check.
 */

import { createLogger } from '../../index';
import { ConsoleTransport } from '../console.transport';
import { DatabaseTransport } from '../database.transport';

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
});
