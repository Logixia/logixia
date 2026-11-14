/**
 * LogixiaLoggerService against NestJS's `LoggerService` contract:
 * `method(message, ...optionalParams)` where a trailing string is the context.
 */

import * as shutdownUtils from '../../utils/shutdown.utils';
import { LogixiaLoggerService } from '../logixia-nestjs.service';

interface Captured {
  level: string;
  message: string;
  context?: string;
  data?: Record<string, unknown>;
}

function makeService(extra: Record<string, unknown> = {}) {
  const entries: Captured[] = [];
  const service = new LogixiaLoggerService({
    appName: 'NestApp',
    traceId: false,
    levelOptions: { level: 'verbose' },
    transports: { custom: [{ name: 'capture', write: (e: Captured) => void entries.push(e) }] },
    ...extra,
  } as never);
  return { service, entries };
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 10));

describe('per-call context', () => {
  it('uses a trailing string as the context of that call only', async () => {
    const { service, entries } = makeService();
    service.log('first', 'UsersService');
    service.log('second');
    service.warn('third', 'OrdersService');
    service.debug('fourth');
    await settle();
    expect(entries.map((e) => e.context ?? '')).toEqual(['UsersService', '', 'OrdersService', '']);
    expect(service.getContext()).toBeUndefined();
    expect(service.getLogger().getContext()).toBe('');
  });

  it('keeps the explicit setContext() context for calls without one', async () => {
    const { service, entries } = makeService();
    service.setContext('Explicit');
    service.log('a', 'PerCall');
    service.log('b');
    await settle();
    expect(entries.map((e) => e.context)).toEqual(['PerCall', 'Explicit']);
    expect(service.getContext()).toBe('Explicit');
  });

  it('applies namespace levels of the per-call context', async () => {
    const { service, entries } = makeService({
      levelOptions: { level: 'info' },
      namespaceLevels: { db: 'debug' },
    });
    service.debug('hidden');
    service.debug('shown', 'db');
    service.debug('hidden again');
    await settle();
    expect(entries.map((e) => e.message)).toEqual(['shown']);
  });
});

describe('optional params', () => {
  it('merges object params into the data and keeps the context', async () => {
    const { service, entries } = makeService();
    service.log('user created', { id: 42 }, 'UsersService');
    service.log('no context', { id: 7 });
    await settle();
    expect(entries[0]).toMatchObject({ message: 'user created', context: 'UsersService' });
    expect(entries[0]?.data).toMatchObject({ id: 42 });
    expect(entries[1]?.data).toMatchObject({ id: 7 });
    expect(entries[1]?.context).toBeUndefined();
  });

  it('error(message, stack, context) keeps the stack and the context', async () => {
    const { service, entries } = makeService();
    service.error('Boom', 'stack-trace-here', 'AuthService');
    await settle();
    expect(entries[0]).toMatchObject({ level: 'error', context: 'AuthService' });
    expect(entries[0]?.data).toMatchObject({ stack: 'stack-trace-here' });
  });

  it('error(message, context) treats a lone non-stack string as the context', async () => {
    const { service, entries } = makeService();
    service.error(new Error('db down'), 'UsersService');
    service.error('plain', 'Plain');
    await settle();
    expect(entries[0]?.context).toBe('UsersService');
    expect(entries[0]?.data?.['error']).toMatchObject({ message: 'db down' });
    expect(entries[1]).toMatchObject({ context: 'Plain' });
    expect(entries[1]?.data ?? {}).not.toHaveProperty('stack');
  });

  it('error(message, stack) treats a lone stack-shaped string as the stack', async () => {
    const { service, entries } = makeService();
    const stack = 'Error: x\n    at foo (file.js:1:1)';
    service.error('failed', stack);
    await settle();
    expect(entries[0]?.data).toMatchObject({ stack });
    expect(entries[0]?.context).toBeUndefined();
  });

  it('keeps the native single-object overloads returning a promise', async () => {
    const { service, entries } = makeService();
    await service.warn('w', { a: 1 });
    await service.error('e', { b: 2 });
    expect(entries.map((e) => e.data)).toEqual([
      expect.objectContaining({ a: 1 }),
      expect.objectContaining({ b: 2 }),
    ]);
  });
});

describe('fatal()', () => {
  it('logs at error with a fatal marker and the per-call context', async () => {
    const { service, entries } = makeService();
    service.fatal('going down', 'Bootstrap');
    await settle();
    expect(entries[0]).toMatchObject({
      level: 'error',
      message: 'going down',
      context: 'Bootstrap',
    });
    expect(entries[0]?.data).toMatchObject({ fatal: true });
  });

  it('uses a configured custom fatal level instead', async () => {
    const { service, entries } = makeService({
      levelOptions: { level: 'info', levels: { error: 0, warn: 1, info: 2, fatal: 0, debug: 3 } },
    });
    service.fatal('going down');
    await settle();
    expect(entries[0]?.level).toBe('fatal');
  });
});

describe('setLogLevels()', () => {
  it('uses the most verbose requested level as the threshold', async () => {
    const { service, entries } = makeService();
    service.setLogLevels(['error']);
    service.log('hidden');
    service.warn('hidden');
    service.error('shown');
    service.setLogLevels(['error', 'warn', 'log']);
    service.log('shown too');
    service.debug('hidden');
    service.setLogLevels(['verbose']);
    service.verbose('and this');
    await settle();
    expect(entries.map((e) => e.message)).toEqual(['shown', 'shown too', 'and this']);
  });

  it('ignores unknown names and an empty list', () => {
    const { service } = makeService();
    service.setLogLevels(['error']);
    service.setLogLevels([]);
    service.setLogLevels(['nonsense']);
    expect(service.getLevel()).toBe('error');
  });
});

describe('child()', () => {
  it('wraps the core child instead of building another root logger', () => {
    const { service } = makeService({ gracefulShutdown: true });
    const register = jest.spyOn(shutdownUtils, 'registerForShutdown');
    try {
      for (let i = 0; i < 20; i++) service.child(`Req${i}`, { requestId: i });
      expect(register).not.toHaveBeenCalled();
    } finally {
      register.mockRestore();
    }
  });

  it('logs with its context and bound data, and exposes custom level methods', async () => {
    const { service, entries } = makeService({
      levelOptions: { level: 'info', levels: { error: 0, warn: 1, info: 2, dbQuery: 2 } },
    });
    const child = service.child('Orders', { requestId: 'r1' });
    child.log('hello');
    await child.dbQuery('select 1');
    expect(child.getContext()).toBe('Orders');
    expect(entries.map((e) => [e.level, e.context])).toEqual([
      ['info', 'Orders'],
      ['dbQuery', 'Orders'],
    ]);
    expect(entries[0]?.data).toMatchObject({ requestId: 'r1' });
  });
});
