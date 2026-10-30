/**
 * Namespace level state is shared between a logger and its children, and custom
 * level names cannot collide with logger methods.
 */

import { createLogger } from '../logitron-logger';

const BASE_CONFIG = {
  appName: 'TestApp',
  format: { timestamp: false, colorize: false, json: false },
  traceId: false,
  silent: false,
  levelOptions: { level: 'warn' },
};

describe('shared namespace levels', () => {
  let stdoutSpy: jest.SpyInstance;

  beforeEach(() => {
    stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
  });
  afterEach(() => stdoutSpy.mockRestore());

  const written = (): string => stdoutSpy.mock.calls.map((c) => String(c[0])).join('');

  it('setNamespaceLevels on the parent changes an existing child', async () => {
    const parent = createLogger(BASE_CONFIG);
    const child = parent.child('db.queries');

    await child.info('before');
    expect(written()).not.toContain('before');

    parent.setNamespaceLevels({ 'db.*': 'debug' });
    await child.info('after');
    expect(written()).toContain('after');
  });

  it('patchNamespaceLevels on the parent changes an existing child', async () => {
    const parent = createLogger(BASE_CONFIG);
    const child = parent.child('http');

    parent.patchNamespaceLevels({ http: 'info' });
    await child.info('patched');
    expect(written()).toContain('patched');
  });

  it('calling it on a child affects the parent family and siblings', async () => {
    const parent = createLogger(BASE_CONFIG, 'api');
    const a = parent.child('a');
    const b = parent.child('b');

    a.setNamespaceLevels({ b: 'debug', api: 'info' });

    await b.debug('sibling');
    await parent.info('parent');
    expect(written()).toContain('sibling');
    expect(written()).toContain('parent');
    expect(parent.getNamespaceLevels()).toEqual({ b: 'debug', api: 'info' });
    expect(b.getNamespaceLevels()).toEqual({ b: 'debug', api: 'info' });
  });

  it('removing levels on the parent raises the threshold again', async () => {
    const parent = createLogger({ ...BASE_CONFIG, namespaceLevels: { x: 'debug' } });
    const child = parent.child('x');

    await child.debug('visible');
    parent.setNamespaceLevels({});
    await child.debug('hidden');

    expect(written()).toContain('visible');
    expect(written()).not.toContain('hidden');
  });

  it('does not mutate the caller config', () => {
    const namespaceLevels = { x: 'debug' };
    const logger = createLogger({ ...BASE_CONFIG, namespaceLevels });
    logger.patchNamespaceLevels({ y: 'info' });
    expect(namespaceLevels).toEqual({ x: 'debug' });
  });
});

describe('reserved custom level names', () => {
  it.each(['flush', 'setLevel', 'healthCheck', 'child', 'close', 'setNamespaceLevels'])(
    'createLogger throws for a level named %s',
    (name) => {
      expect(() =>
        createLogger({
          appName: 'x',
          levelOptions: { level: 'info', levels: { info: 2, [name]: 3 } },
        })
      ).toThrow(new RegExp(`reserved logger method name.*${name}`));
    }
  );

  it('still accepts the built-in level names and ordinary custom levels', () => {
    expect(() =>
      createLogger({
        appName: 'x',
        silent: true,
        levelOptions: {
          level: 'info',
          levels: { error: 0, warn: 1, info: 2, debug: 3, audit: 2 },
        },
      })
    ).not.toThrow();
  });
});
