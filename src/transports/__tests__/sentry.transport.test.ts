import { createLogger } from '../../index';
import type { TransportLogEntry } from '../../types/transport.types';
import { type SentryLike, SentryTransport } from '../sentry.transport';

function entry(over: Partial<TransportLogEntry> = {}): TransportLogEntry {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    level: 'error',
    message: 'boom',
    ...over,
  };
}

interface Call {
  fn: string;
  args: unknown[];
}

/** A structural fake: records every call, scope setters included. */
function fakeSentry(opts: { scope?: boolean; logger?: boolean; flush?: SentryLike['flush'] } = {}) {
  const calls: Call[] = [];
  const rec =
    (fn: string) =>
    (...args: unknown[]) => {
      calls.push({ fn, args });
      return null;
    };
  const sentry: SentryLike = {
    captureException: rec('captureException'),
    captureMessage: rec('captureMessage'),
    addBreadcrumb: rec('addBreadcrumb'),
  };
  if (opts.scope !== false) {
    sentry.withScope = (cb) => {
      calls.push({ fn: 'withScope', args: [] });
      cb({
        setLevel: rec('setLevel'),
        setTag: rec('setTag'),
        setExtras: rec('setExtras'),
        setContext: rec('setContext'),
      });
    };
  }
  if (opts.logger) {
    sentry.logger = {
      trace: rec('logger.trace'),
      debug: rec('logger.debug'),
      info: rec('logger.info'),
      warn: rec('logger.warn'),
      error: rec('logger.error'),
      fatal: rec('logger.fatal'),
    };
  }
  if (opts.flush) sentry.flush = opts.flush;
  return { sentry, calls, of: (fn: string) => calls.filter((c) => c.fn === fn) };
}

describe('SentryTransport', () => {
  let stderr: jest.SpyInstance;
  beforeEach(() => {
    stderr = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });
  afterEach(() => stderr.mockRestore());
  const logged = (): string => stderr.mock.calls.map((c) => String(c[0])).join('');

  describe('config', () => {
    it('requires a sentry object with the capture functions', () => {
      expect(() => new SentryTransport({ sentry: {} as SentryLike })).toThrow(TypeError);
      expect(() => new SentryTransport(undefined as never)).toThrow(TypeError);
    });

    it('rejects an unknown minLevel', () => {
      expect(() => new SentryTransport({ sentry: fakeSentry().sentry, minLevel: 'loud' })).toThrow(
        /unknown minLevel/
      );
    });

    it('leaves transport.level unset so the manager hands it every level', () => {
      expect(new SentryTransport({ sentry: fakeSentry().sentry }).level).toBeUndefined();
    });
  });

  describe('events', () => {
    it('captures a message with the mapped severity, tags and context', () => {
      const f = fakeSentry();
      new SentryTransport({ sentry: f.sentry }).write(
        entry({
          message: 'payment failed',
          data: { orderId: 'o_1' },
          traceId: 'trace-abc',
          context: 'Checkout',
          appName: 'api',
          environment: 'prod',
        })
      );
      expect(f.of('captureMessage')[0]!.args).toEqual(['payment failed', 'error']);
      expect(f.of('setLevel')[0]!.args).toEqual(['error']);
      const tags = Object.fromEntries(f.of('setTag').map((c) => c.args as [string, string]));
      expect(tags).toEqual({ logixia_level: 'error', trace_id: 'trace-abc', context: 'Checkout' });
      expect(f.of('setExtras')[0]!.args[0]).toEqual({ orderId: 'o_1' });
      expect(f.of('setContext')[0]!.args).toEqual([
        'logixia',
        {
          level: 'error',
          traceId: 'trace-abc',
          context: 'Checkout',
          appName: 'api',
          environment: 'prod',
        },
      ]);
    });

    it('rebuilds the serialized error with its name, message and stack', () => {
      const f = fakeSentry();
      const stack = 'TypeError: bad\n    at handler (/app/src/handler.ts:10:5)';
      new SentryTransport({ sentry: f.sentry }).write(
        entry({
          message: 'bad',
          data: { error: { name: 'TypeError', message: 'bad', stack }, userId: 'u1' },
        })
      );
      expect(f.of('captureMessage')).toHaveLength(0);
      const captured = f.of('captureException')[0]!.args[0] as Error;
      expect(captured).toBeInstanceOf(Error);
      expect(captured.name).toBe('TypeError');
      expect(captured.message).toBe('bad');
      expect(captured.stack).toBe(stack);
      expect(f.of('setExtras')[0]!.args[0]).toEqual({ userId: 'u1' });
    });

    it('rebuilds a cause chain and keeps the log message when it differs', () => {
      const f = fakeSentry();
      new SentryTransport({ sentry: f.sentry }).write(
        entry({
          message: 'order failed',
          data: {
            error: {
              name: 'Error',
              message: 'outer',
              cause: { name: 'RangeError', message: 'inner', stack: 'RangeError: inner\n at x' },
            },
          },
        })
      );
      const captured = f.of('captureException')[0]!.args[0] as Error & { cause?: Error };
      expect(captured.stack).toBe('Error: outer');
      expect(captured.cause?.name).toBe('RangeError');
      expect(captured.cause?.stack).toContain('at x');
      expect(f.of('setExtras')[0]!.args[0]).toEqual({ logMessage: 'order failed' });
    });

    it('passes a real Error held in data.error through unchanged', () => {
      const f = fakeSentry();
      const err = new Error('live');
      new SentryTransport({ sentry: f.sentry }).write(
        entry({ message: 'live', data: { error: err } })
      );
      expect(f.of('captureException')[0]!.args[0]).toBe(err);
    });

    it('treats a non-error data.error as payload', () => {
      const f = fakeSentry();
      new SentryTransport({ sentry: f.sentry }).write(entry({ data: { error: 'E_TIMEOUT' } }));
      expect(f.of('captureMessage')).toHaveLength(1);
      expect(f.of('setExtras')[0]!.args[0]).toMatchObject({ error: 'E_TIMEOUT' });
    });

    it('uses a capture-context hint when the SDK has no withScope', () => {
      const f = fakeSentry({ scope: false });
      new SentryTransport({ sentry: f.sentry }).write(
        entry({ data: { a: 1 }, traceId: 't1', context: 'Svc' })
      );
      expect(f.of('captureMessage')[0]!.args).toEqual([
        'boom',
        {
          level: 'error',
          tags: { logixia_level: 'error', trace_id: 't1', context: 'Svc' },
          extra: { a: 1 },
          contexts: { logixia: { level: 'error', traceId: 't1', context: 'Svc' } },
        },
      ]);
    });

    it('maps fatal and warn severities and honours minLevel', () => {
      const f = fakeSentry();
      const t = new SentryTransport({ sentry: f.sentry, minLevel: 'warn' });
      t.write(entry({ level: 'fatal' }));
      t.write(entry({ level: 'warn' }));
      t.write(entry({ level: 'info' }));
      expect(f.of('captureMessage').map((c) => c.args[1])).toEqual(['fatal', 'warning']);
      expect(f.of('addBreadcrumb')).toHaveLength(1);
    });

    it('maps custom levels through levelMap and falls back to info (a breadcrumb)', () => {
      const f = fakeSentry();
      const t = new SentryTransport({
        sentry: f.sentry,
        levelMap: { audit: 'warning', page: 'fatal' },
      });
      t.write(entry({ level: 'page' }));
      t.write(entry({ level: 'audit' }));
      t.write(entry({ level: 'kafka' }));
      expect(f.of('captureMessage').map((c) => c.args[1])).toEqual(['fatal']);
      expect(f.of('addBreadcrumb').map((c) => (c.args[0] as { level: string }).level)).toEqual([
        'warning',
        'info',
      ]);
    });
  });

  describe('breadcrumbs and logs', () => {
    it('adds a breadcrumb for lower levels by default', () => {
      const f = fakeSentry();
      new SentryTransport({ sentry: f.sentry }).write(
        entry({
          level: 'info',
          message: 'cache miss',
          data: { key: 'k' },
          context: 'Cache',
          traceId: 't',
        })
      );
      expect(f.calls.map((c) => c.fn)).toEqual(['addBreadcrumb']);
      expect(f.calls[0]!.args[0]).toEqual({
        category: 'Cache',
        message: 'cache miss',
        level: 'info',
        timestamp: new Date('2026-01-01T00:00:00.000Z').getTime() / 1000,
        data: { key: 'k', traceId: 't' },
      });
    });

    it('drops lower levels when breadcrumbs are off', () => {
      const f = fakeSentry();
      new SentryTransport({ sentry: f.sentry, breadcrumbs: false }).write(entry({ level: 'info' }));
      expect(f.calls).toHaveLength(0);
    });

    it('sends lower levels to the Logs API when logs: true', () => {
      const f = fakeSentry({ logger: true });
      const t = new SentryTransport({ sentry: f.sentry, logs: true });
      t.write(
        entry({ level: 'warn', message: 'slow', data: { ms: 900, meta: { a: 1 } }, traceId: 't' })
      );
      t.write(entry({ level: 'trace', message: 'tick' }));
      expect(f.of('logger.warn')[0]!.args).toEqual([
        'slow',
        { ms: 900, meta: '{"a":1}', trace_id: 't' },
      ]);
      expect(f.of('logger.trace')).toHaveLength(1);
      expect(f.of('addBreadcrumb')).toHaveLength(0);
    });

    it('still sends events (not logs) at or above minLevel when logs: true', () => {
      const f = fakeSentry({ logger: true });
      new SentryTransport({ sentry: f.sentry, logs: true }).write(entry());
      expect(f.of('captureMessage')).toHaveLength(1);
      expect(f.of('logger.error')).toHaveLength(0);
    });

    it('falls back to breadcrumbs, with one warning, when logs: true but no logger', () => {
      const f = fakeSentry();
      const t = new SentryTransport({ sentry: f.sentry, logs: true });
      t.write(entry({ level: 'info' }));
      t.write(entry({ level: 'info' }));
      expect(f.of('addBreadcrumb')).toHaveLength(2);
      expect(logged().match(/sentry\.logger is unavailable/g)).toHaveLength(1);
    });
  });

  describe('failures', () => {
    it('never throws from write and reports through stderr', () => {
      const f = fakeSentry();
      f.sentry.captureMessage = () => {
        throw new Error('sdk down');
      };
      f.sentry.addBreadcrumb = () => {
        throw new Error('crumb down');
      };
      const t = new SentryTransport({ sentry: f.sentry });
      expect(() => t.write(entry())).not.toThrow();
      expect(() => t.write(entry({ level: 'info' }))).not.toThrow();
      expect(logged()).toContain('sdk down');
      expect(logged()).toContain('crumb down');
    });
  });

  describe('flush and close', () => {
    it('calls sentry.flush with the bounded timeout', async () => {
      const flush = jest.fn().mockResolvedValue(true);
      const t = new SentryTransport({ sentry: fakeSentry({ flush }).sentry, flushTimeoutMs: 750 });
      await t.flush();
      await t.close();
      expect(flush).toHaveBeenCalledTimes(2);
      expect(flush).toHaveBeenCalledWith(750);
    });

    it('defaults the timeout to 2000 ms', async () => {
      const flush = jest.fn().mockResolvedValue(true);
      await new SentryTransport({ sentry: fakeSentry({ flush }).sentry }).close();
      expect(flush).toHaveBeenCalledWith(2000);
    });

    it('resolves even when sentry.flush never settles', async () => {
      jest.useFakeTimers();
      try {
        const flush = jest.fn(() => new Promise<never>(() => {}));
        const t = new SentryTransport({
          sentry: fakeSentry({ flush }).sentry,
          flushTimeoutMs: 100,
        });
        const done = t.close();
        await jest.advanceTimersByTimeAsync(200);
        await expect(done).resolves.toBeUndefined();
      } finally {
        jest.useRealTimers();
      }
    });

    it('swallows a rejecting flush and does nothing without one', async () => {
      const flush = jest.fn().mockRejectedValue(new Error('net'));
      await expect(
        new SentryTransport({ sentry: fakeSentry({ flush }).sentry }).flush()
      ).resolves.toBeUndefined();
      expect(logged()).toContain('flush failed');
      await expect(
        new SentryTransport({ sentry: fakeSentry().sentry }).flush()
      ).resolves.toBeUndefined();
    });
  });

  describe('through a real logger', () => {
    it('sends redacted payloads and stacks, and the real error stack', async () => {
      const f = fakeSentry();
      const logger = createLogger({
        appName: 'app',
        silent: false,
        transports: { custom: [new SentryTransport({ sentry: f.sentry })] },
        redact: { paths: ['password', 'error.stack'], patterns: [/sk_live_\w+/g] },
      });
      await logger.error('login failed', {
        password: 'hunter2',
        user: 'a',
        note: 'sk_live_abc123',
      });
      await logger.info('step done', { password: 'hunter3' });
      await logger.close();

      const extras = f.of('setExtras')[0]!.args[0] as Record<string, unknown>;
      expect(extras['password']).not.toBe('hunter2');
      expect(extras['user']).toBe('a');
      const everything = JSON.stringify(f.calls);
      expect(everything).not.toContain('hunter2');
      expect(everything).not.toContain('hunter3');
      expect(everything).not.toContain('sk_live_abc123');
      expect(f.of('addBreadcrumb')).toHaveLength(1);
    });

    it('captures logger.error(err) with a redacted stack', async () => {
      const f = fakeSentry();
      const logger = createLogger({
        appName: 'app',
        transports: { custom: [new SentryTransport({ sentry: f.sentry })] },
        redact: { paths: ['error.stack'] },
      });
      await logger.error(new RangeError('out of range'));
      const captured = f.of('captureException')[0]!.args[0] as Error;
      expect(captured.name).toBe('RangeError');
      expect(captured.message).toBe('out of range');
      expect(captured.stack).not.toContain('sentry.transport.test');
    });

    it('keeps the real stack when not redacted', async () => {
      const f = fakeSentry();
      const logger = createLogger({
        appName: 'app',
        transports: { custom: [new SentryTransport({ sentry: f.sentry })] },
      });
      await logger.error(new RangeError('out of range'));
      const captured = f.of('captureException')[0]!.args[0] as Error;
      expect(captured.stack).toContain('sentry.transport.test');
    });

    it('carries the trace id and context logger namespace', async () => {
      const f = fakeSentry();
      const logger = createLogger({
        appName: 'app',
        transports: { custom: [new SentryTransport({ sentry: f.sentry })] },
      }).child('Billing');
      await logger.error('declined', { traceId: 'trace-1' });
      const tags = Object.fromEntries(f.of('setTag').map((c) => c.args as [string, string]));
      expect(tags['context']).toBe('Billing');
    });
  });
});
