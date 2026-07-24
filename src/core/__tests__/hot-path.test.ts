/**
 * Correctness tests for the hot-path performance optimizations.
 *
 * These pin the behavior that the sync-write fast path could regress:
 *  - logger.info() is still awaitable whether the write completed sync or async.
 *  - The synchronous console path actually produces output (exactly once).
 *  - A genuinely async transport is still awaited (its write completes before
 *    the awaited log call resolves).
 *  - A throwing transport falls back to a direct stdout/stderr write (no loss),
 *    and the awaited log call does not reject.
 *  - The cached timestamp still yields a valid ISO-8601 string and advances.
 */

import type { ITransport, TransportLogEntry } from '../../types/transport.types';
import { resetShutdownHandlers } from '../../utils/shutdown.utils';
import { LogixiaLogger } from '../logitron-logger';

const BASE = {
  appName: 'TestApp',
  environment: 'development' as const,
  format: { timestamp: true, colorize: false, json: false },
  traceId: false,
};

function spyStdout() {
  const lines: string[] = [];
  const out = process.stdout.write.bind(process.stdout);
  const err = process.stderr.write.bind(process.stderr);
  (process.stdout as NodeJS.WriteStream).write = ((c: unknown) => {
    lines.push(String(c ?? ''));
    return true;
  }) as typeof process.stdout.write;
  (process.stderr as NodeJS.WriteStream).write = ((c: unknown) => {
    lines.push(String(c ?? ''));
    return true;
  }) as typeof process.stderr.write;
  return {
    joined: () => lines.join(''),
    count: (s: string) => lines.filter((l) => l.includes(s)).length,
    restore: () => {
      (process.stdout as NodeJS.WriteStream).write = out;
      (process.stderr as NodeJS.WriteStream).write = err;
    },
  };
}

beforeEach(() => {
  resetShutdownHandlers();
  process.env['NODE_ENV'] = 'test';
});
afterEach(() => resetShutdownHandlers());

describe('hot path — synchronous console write', () => {
  it('logger.info() is awaitable and writes output exactly once', async () => {
    const spy = spyStdout();
    const logger = new LogixiaLogger({ ...BASE, levelOptions: { level: 'info' } });
    const ret = logger.info('hello-sync');
    // The call is awaitable (whether it returned void or a Promise).
    await expect(Promise.resolve(ret)).resolves.toBeUndefined();
    spy.restore();
    expect(spy.count('hello-sync')).toBe(1);
  });

  it('renders the message and payload on the sync path', async () => {
    const spy = spyStdout();
    const logger = new LogixiaLogger({ ...BASE, levelOptions: { level: 'info' } });
    await logger.info('with-payload', { userId: 'u-1' });
    spy.restore();
    expect(spy.joined()).toContain('with-payload');
    expect(spy.joined()).toContain('u-1');
  });
});

describe('hot path — genuinely async transport is still awaited', () => {
  it('the async transport write completes before the awaited log resolves', async () => {
    let written = false;
    const asyncTransport: ITransport = {
      name: 'async-test',
      write: (_entry: TransportLogEntry) =>
        new Promise<void>((resolve) =>
          setTimeout(() => {
            written = true;
            resolve();
          }, 5)
        ),
    };

    const spy = spyStdout();
    // A transport manager only exists when `transports` is configured; register
    // the async transport through `custom`.
    const logger = new LogixiaLogger({
      ...BASE,
      levelOptions: { level: 'info' },
      transports: { custom: [asyncTransport] },
    } as never);

    await logger.info('async-line');
    spy.restore();
    // If the await didn't actually wait for the async transport, this would be false.
    expect(written).toBe(true);
  });
});

describe('hot path — transport failure falls back to direct write', () => {
  it('a throwing transport does not reject the log and still emits output', async () => {
    const spy = spyStdout();
    const boom: ITransport = {
      name: 'boom',
      write: () => {
        throw new Error('transport exploded');
      },
    };
    const logger = new LogixiaLogger({
      ...BASE,
      levelOptions: { level: 'info' },
      transports: { custom: [boom] },
    } as never);

    await expect(Promise.resolve(logger.info('fallback-line'))).resolves.toBeUndefined();
    spy.restore();
    // The fallback path wrote the line to stdout/stderr despite the transport throw.
    expect(spy.joined()).toContain('fallback-line');
  });
});

describe('hot path — cached timestamp', () => {
  it('emits a valid ISO-8601 timestamp', async () => {
    const spy = spyStdout();
    const logger = new LogixiaLogger({ ...BASE, levelOptions: { level: 'info' } });
    await logger.info('ts-check');
    spy.restore();
    const m = spy.joined().match(/\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)\]/);
    expect(m).not.toBeNull();
    expect(Number.isNaN(Date.parse(m![1]!))).toBe(false);
  });

  it('advances across a clock tick (timestamps are not frozen)', async () => {
    const spy = spyStdout();
    const logger = new LogixiaLogger({ ...BASE, levelOptions: { level: 'info' } });
    await logger.info('t-a');
    await new Promise((r) => setTimeout(r, 5));
    await logger.info('t-b');
    spy.restore();
    const stamps = [...spy.joined().matchAll(/\[(\d{4}-\d{2}-\d{2}T[\d:.]+Z)\]/g)].map((x) => x[1]);
    expect(stamps.length).toBeGreaterThanOrEqual(2);
    // The two logs are ≥5ms apart, so their cached timestamps must differ.
    expect(stamps[0]).not.toBe(stamps[stamps.length - 1]);
  });
});
