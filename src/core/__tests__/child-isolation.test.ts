/**
 * What child() must keep doing however it is built: hide the config, keep its own
 * level, timers, fields and fallback trace ID, and run its bindings through the
 * same redaction and level rules as the parent.
 */
import * as util from 'util';

import { resetShutdownHandlers } from '../../utils/shutdown.utils';
import { createLogger, LogixiaLogger } from '../logixia-logger';

type Line = Record<string, unknown> & { payload?: Record<string, unknown> };

let written: string[] = [];
let stdoutSpy: jest.SpyInstance;
let stderrSpy: jest.SpyInstance;

beforeEach(() => {
  written = [];
  const capture = (chunk: unknown): boolean => {
    written.push(String(chunk));
    return true;
  };
  stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(capture as never);
  stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(capture as never);
});

afterEach(() => {
  stdoutSpy.mockRestore();
  stderrSpy.mockRestore();
  resetShutdownHandlers();
  delete process.env['LOGIXIA_LEVEL_LATE'];
});

function jsonLogger(extra: Record<string, unknown> = {}): LogixiaLogger {
  return new LogixiaLogger({
    appName: 'iso',
    environment: 'test',
    levelOptions: { level: 'info' },
    format: { json: true, timestamp: true, colorize: false },
    ...extra,
  } as never);
}

function lines(): Line[] {
  return written
    .join('')
    .split('\n')
    .filter((l) => l.startsWith('{'))
    .map((l) => JSON.parse(l) as Line);
}

function dumps(subject: unknown): string[] {
  const safe = (fn: () => string): string => {
    try {
      return fn();
    } catch {
      return '';
    }
  };
  return [
    safe(() => JSON.stringify(subject)),
    safe(() => util.inspect(subject, { depth: 10 })),
    safe(() => util.inspect(subject, { depth: 10, showHidden: true })),
    safe(() => util.inspect(subject, { depth: 10, showHidden: true, customInspect: false })),
    safe(() => JSON.stringify({ ...(subject as object) })),
    safe(() => util.format('%s %j %o', subject, subject, subject)),
  ];
}

describe('child() isolation', () => {
  it('hides the config on the root and on children', () => {
    const root = jsonLogger({
      transports: { analytics: { datadog: { apiKey: 'CHILD-ISO-DD-KEY' } } },
    });
    const child = root.child('req', { k: 1 });
    const grandchild = (child as unknown as LogixiaLogger).child('inner');
    for (const subject of [root, child, grandchild]) {
      for (const text of dumps(subject)) expect(text).not.toContain('CHILD-ISO-DD-KEY');
      expect(Object.keys(subject)).not.toContain('config');
      expect(Object.getOwnPropertyDescriptor(subject, 'config')?.enumerable).not.toBe(true);
    }
  });

  it('keeps a child level change off the parent', async () => {
    const root = jsonLogger();
    const child = root.child('c');
    child.setLevel('debug');
    expect(child.getLevel()).toBe('debug');
    expect(root.getLevel()).toBe('info');
    await root.debug('root-debug');
    await child.debug('child-debug');
    expect(lines().map((l) => l['message'])).toEqual(['child-debug']);
  });

  it('keeps a parent level change made after child() off the child', async () => {
    const root = jsonLogger();
    const child = root.child('c');
    root.setLevel('debug');
    expect(root.getLevel()).toBe('debug');
    expect(child.getLevel()).toBe('info');
    await child.debug('child-debug');
    await root.debug('root-debug');
    expect(lines().map((l) => l['message'])).toEqual(['root-debug']);
  });

  it('gives a child its own timers', async () => {
    const root = jsonLogger();
    const child = root.child('c');
    child.time('t');
    expect(await root.timeEnd('t')).toBeUndefined();
    expect(typeof (await child.timeEnd('t'))).toBe('number');
  });

  it('gives a child its own field toggles', async () => {
    const root = new LogixiaLogger({
      appName: 'fields',
      levelOptions: { level: 'info' },
      format: { json: false, timestamp: false, colorize: false },
    } as never);
    const child = root.child('c') as unknown as LogixiaLogger;
    child.disableField('appName');
    await child.info('from-child');
    await root.info('from-root');
    const out = written.join('');
    expect(out).toMatch(/\[fields\][^\n]*from-root/);
    expect(out).not.toMatch(/\[fields\][^\n]*from-child/);
    expect(root.isFieldEnabled('appName')).toBe(true);
  });

  it('redacts the bindings of a child', async () => {
    const root = jsonLogger({ redact: { paths: ['password'] } });
    await root.child('c', { password: 'CHILD-PW-VALUE', user: 'u1' }).info('m');
    const [line] = lines();
    expect(JSON.stringify(line)).not.toContain('CHILD-PW-VALUE');
    expect(line!.payload!['user']).toBe('u1');
  });

  it('lets call data override a binding with the same key', async () => {
    const root = jsonLogger();
    await root.child('c', { k: 'bound', other: 1 }).info('m', { k: 'call' });
    expect(lines()[0]!.payload).toEqual({ k: 'call', other: 1 });
  });

  it('serializes an Error held in a binding', async () => {
    const root = jsonLogger();
    await root.child('c', { cause: new Error('bound-error') }).info('m');
    const payload = lines()[0]!.payload as { cause: { message: string; stack: string } };
    expect(payload.cause.message).toBe('bound-error');
    expect(typeof payload.cause.stack).toBe('string');
  });

  it('gives each child its own stable fallback trace ID', async () => {
    const root = jsonLogger();
    const a = root.child('a');
    const b = root.child('b');
    await a.info('a1');
    await a.info('a2');
    await b.info('b1');
    await root.info('r1');
    const [a1, a2, b1, r1] = lines().map((l) => l['traceId']);
    expect(a1).toBe(a2);
    expect(typeof a1).toBe('string');
    expect(new Set([a1, b1, r1]).size).toBe(3);
  });

  it('gives children the custom level methods', async () => {
    const root = createLogger({
      appName: 'lv',
      levelOptions: { level: 'info', levels: { error: 0, warn: 1, info: 2, audit: 2 } },
      format: { json: true, timestamp: false, colorize: false },
    });
    const child = root.child('c') as unknown as { audit(m: string): Promise<void> };
    await child.audit('audited');
    expect(lines()[0]).toMatchObject({ level: 'audit', message: 'audited', context: 'c' });
  });

  it('applies namespace levels by child context', async () => {
    const root = jsonLogger({ namespaceLevels: { db: 'debug' } });
    await root.child('db').debug('db-debug');
    await root.child('http').debug('http-debug');
    expect(lines().map((l) => l['message'])).toEqual(['db-debug']);
  });

  it('reads LOGIXIA_LEVEL_<NS> when the child is created', async () => {
    const root = jsonLogger();
    process.env['LOGIXIA_LEVEL_LATE'] = 'debug';
    await root.child('late').debug('late-debug');
    expect(lines().map((l) => l['message'])).toEqual(['late-debug']);
  });

  it('merges bindings through a chain of children', async () => {
    const root = jsonLogger();
    const child = root.child('a', { one: 1 }) as unknown as LogixiaLogger;
    await child.child('b', { two: 2 }).info('m');
    expect(lines()[0]).toMatchObject({ context: 'b', payload: { one: 1, two: 2 } });
  });
});
