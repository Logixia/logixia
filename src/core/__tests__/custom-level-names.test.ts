/**
 * Custom level names that contain capitals, and namespace levels that depend on setContext().
 */

import { createLogger, LogixiaLogger } from '../logixia-logger';

function setup(extra: Record<string, unknown> = {}) {
  const lines: string[] = [];
  const logger = createLogger({
    appName: 'a',
    traceId: false,
    levelOptions: {
      level: 'info',
      levels: { error: 0, warn: 1, info: 2, dbQuery: 2, HTTP: 2, debug: 3 },
    },
    transports: {
      custom: [
        {
          name: 'mem',
          write: (e: { level: string; context?: string; message: string }) =>
            void lines.push(`${e.level}|${e.context ?? ''}|${e.message}`),
        },
      ],
    },
    ...extra,
  });
  return { logger, lines };
}

describe('custom level names with capitals', () => {
  it('creates a working method with the exact declared name', async () => {
    const { logger, lines } = setup();
    await logger.dbQuery('exact');
    await logger.HTTP('upper');
    expect(lines).toEqual(['dbQuery||exact', 'HTTP||upper']);
  });

  it('keeps a lowercase alias that logs at the declared level', async () => {
    const { logger, lines } = setup();
    await (logger as unknown as Record<string, (m: string) => Promise<void>>)['dbquery']!('alias');
    await (logger as unknown as Record<string, (m: string) => Promise<void>>)['http']!('alias');
    expect(lines).toEqual(['dbQuery||alias', 'HTTP||alias']);
  });

  it('gives child loggers the same methods', async () => {
    const { logger, lines } = setup();
    const child = logger.child('Child');
    expect(typeof child.dbQuery).toBe('function');
    await child.dbQuery('from child');
    await child.child('Grand').HTTP('from grandchild');
    expect(lines).toEqual(['dbQuery|Child|from child', 'HTTP|Grand|from grandchild']);
  });

  it('lets an exact lowercase level win over the alias of a capitalised one', async () => {
    const lines: string[] = [];
    const logger = createLogger({
      appName: 'a',
      levelOptions: { level: 'info', levels: { error: 0, HTTP: 2, http: 2 } },
      transports: {
        custom: [{ name: 'm', write: (e: { level: string }) => void lines.push(e.level) }],
      },
    });
    await logger.HTTP('x');
    await logger.http('y');
    expect(lines).toEqual(['HTTP', 'http']);
  });

  it('does not replace a built-in method with a level of the same name', () => {
    const logger = new LogixiaLogger({
      appName: 'a',
      levelOptions: { level: 'info', levels: { error: 0, INFO: 2 } },
    });
    expect(logger.info).toBe(LogixiaLogger.prototype.info);
  });
});

describe('setContext() and namespace levels', () => {
  it('re-resolves the level when the context changes', async () => {
    const { logger, lines } = setup({ namespaceLevels: { db: 'debug' } });
    await logger.debug('before');
    logger.setContext('db');
    await logger.debug('after');
    logger.setContext('other');
    await logger.debug('after leaving');
    expect(lines).toEqual(['debug|db|after']);
  });
});
