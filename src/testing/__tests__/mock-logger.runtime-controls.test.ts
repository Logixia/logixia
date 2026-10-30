/**
 * createMockLogger: namespace level state round-trips and healthCheck is configurable.
 */

import { createMockLogger } from '../mock-logger';

describe('createMockLogger runtime controls', () => {
  it('namespace levels start empty', () => {
    expect(createMockLogger().logger.getNamespaceLevels()).toEqual({});
  });

  it('setNamespaceLevels replaces and getNamespaceLevels returns a copy', () => {
    const { logger } = createMockLogger();
    logger.setNamespaceLevels({ db: 'debug', http: 'warn' });
    logger.setNamespaceLevels({ db: 'error' });

    const levels = logger.getNamespaceLevels();
    expect(levels).toEqual({ db: 'error' });
    levels['db'] = 'trace';
    expect(logger.getNamespaceLevels()).toEqual({ db: 'error' });
  });

  it('patchNamespaceLevels merges into the existing map', () => {
    const { logger } = createMockLogger();
    logger.setNamespaceLevels({ db: 'debug' });
    logger.patchNamespaceLevels({ http: 'warn', db: 'info' });
    expect(logger.getNamespaceLevels()).toEqual({ db: 'info', http: 'warn' });
  });

  it('children share namespace levels with the parent', () => {
    const { logger } = createMockLogger();
    const child = logger.child('db') as typeof logger;
    logger.setNamespaceLevels({ db: 'debug' });
    expect(child.getNamespaceLevels()).toEqual({ db: 'debug' });
  });

  it('healthCheck is healthy by default', async () => {
    const { logger } = createMockLogger();
    await expect(logger.healthCheck()).resolves.toEqual({ healthy: true, details: {} });
  });

  it('healthy: false option and setHealth() simulate an unhealthy logger', async () => {
    const mock = createMockLogger({ healthy: false });
    await expect(mock.logger.healthCheck()).resolves.toEqual({ healthy: false, details: {} });

    mock.setHealth(true);
    expect((await mock.logger.healthCheck()).healthy).toBe(true);

    mock.setHealth(false, { transport: 'file' });
    await expect(mock.logger.healthCheck()).resolves.toEqual({
      healthy: false,
      details: { transport: 'file' },
    });
  });

  it('flush resolves', async () => {
    await expect(createMockLogger().logger.flush()).resolves.toBeUndefined();
  });
});
