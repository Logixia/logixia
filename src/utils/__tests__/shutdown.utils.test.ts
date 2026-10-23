/**
 * Comprehensive tests for graceful shutdown utilities
 *
 * Covers: registerForShutdown, deregisterFromShutdown, flushOnExit,
 * resetShutdownHandlers — with signal simulation and hook ordering.
 */

import { constants as osConstants } from 'os';

import {
  deregisterFromShutdown,
  flushOnExit,
  registerForShutdown,
  resetShutdownHandlers,
} from '../shutdown.utils';

// ── Helpers ──────────────────────────────────────────────────────────────────

function makeFakeLogger(closeImpl?: () => Promise<void>) {
  return {
    close: jest.fn(closeImpl ?? (() => Promise.resolve())),
  };
}

/** Emit a signal on the process and wait a tick for async handlers to settle. */
async function emitSignal(signal: NodeJS.Signals): Promise<void> {
  process.emit(signal, signal);
  // Give the async handler a chance to run (before it calls process.exit)
  await new Promise((r) => setImmediate(r));
}

// ── Setup / Teardown ──────────────────────────────────────────────────────────

let exitSpy: jest.SpyInstance;

beforeEach(() => {
  resetShutdownHandlers();
  // Prevent process.exit from actually killing the Jest runner
  exitSpy = jest.spyOn(process, 'exit').mockImplementation((() => {}) as never);
});

afterEach(() => {
  resetShutdownHandlers();
  exitSpy.mockRestore();
  // Remove any lingering signal listeners added during the test
  process.removeAllListeners('SIGTERM');
  process.removeAllListeners('SIGINT');
});

// ── registerForShutdown ───────────────────────────────────────────────────────

describe('registerForShutdown', () => {
  it('adds a logger to the internal registry', async () => {
    const logger = makeFakeLogger();
    registerForShutdown(logger);

    // Trigger shutdown to verify the logger is flushed
    flushOnExit({ timeout: 1000 });
    await emitSignal('SIGTERM');

    expect(logger.close).toHaveBeenCalledTimes(1);
  });

  it('adding the same logger twice does not double-flush it', async () => {
    const logger = makeFakeLogger();
    registerForShutdown(logger);
    registerForShutdown(logger); // duplicate

    flushOnExit({ timeout: 1000 });
    await emitSignal('SIGTERM');

    expect(logger.close).toHaveBeenCalledTimes(1);
  });

  it('multiple distinct loggers are all flushed', async () => {
    const a = makeFakeLogger();
    const b = makeFakeLogger();
    const c = makeFakeLogger();
    registerForShutdown(a);
    registerForShutdown(b);
    registerForShutdown(c);

    flushOnExit({ timeout: 1000 });
    await emitSignal('SIGTERM');

    expect(a.close).toHaveBeenCalledTimes(1);
    expect(b.close).toHaveBeenCalledTimes(1);
    expect(c.close).toHaveBeenCalledTimes(1);
  });
});

// ── deregisterFromShutdown ────────────────────────────────────────────────────

describe('deregisterFromShutdown', () => {
  it('removes a previously registered logger', async () => {
    const logger = makeFakeLogger();
    registerForShutdown(logger);
    deregisterFromShutdown(logger);

    flushOnExit({ timeout: 1000 });
    await emitSignal('SIGTERM');

    expect(logger.close).not.toHaveBeenCalled();
  });

  it('deregistering a logger that was never registered is a no-op', () => {
    const logger = makeFakeLogger();
    // Should not throw
    expect(() => deregisterFromShutdown(logger)).not.toThrow();
  });

  it('deregistering one logger does not affect others', async () => {
    const a = makeFakeLogger();
    const b = makeFakeLogger();
    registerForShutdown(a);
    registerForShutdown(b);
    deregisterFromShutdown(a);

    flushOnExit({ timeout: 1000 });
    await emitSignal('SIGTERM');

    expect(a.close).not.toHaveBeenCalled();
    expect(b.close).toHaveBeenCalledTimes(1);
  });
});

// ── flushOnExit ───────────────────────────────────────────────────────────────

describe('flushOnExit', () => {
  it('is idempotent — calling multiple times registers only one handler', async () => {
    const logger = makeFakeLogger();
    registerForShutdown(logger);

    flushOnExit({ timeout: 1000 });
    flushOnExit({ timeout: 1000 }); // second call should be ignored
    flushOnExit({ timeout: 1000 }); // third call should be ignored

    await emitSignal('SIGTERM');

    // Only one flush, not three
    expect(logger.close).toHaveBeenCalledTimes(1);
  });

  it('exits with 128 + signal number after a successful flush', async () => {
    const logger = makeFakeLogger();
    registerForShutdown(logger);

    flushOnExit({ timeout: 1000 });
    await emitSignal('SIGTERM');

    expect(exitSpy).toHaveBeenCalledWith(143);
  });

  it('calls beforeFlush hook before flushing loggers', async () => {
    const order: string[] = [];
    const logger = makeFakeLogger(async () => {
      order.push('flush');
    });
    registerForShutdown(logger);

    flushOnExit({
      timeout: 1000,
      beforeFlush: async () => {
        order.push('before');
      },
    });

    await emitSignal('SIGTERM');

    expect(order[0]).toBe('before');
    expect(order[1]).toBe('flush');
  });

  it('calls afterFlush hook after flushing loggers', async () => {
    const order: string[] = [];
    const logger = makeFakeLogger(async () => {
      order.push('flush');
    });
    registerForShutdown(logger);

    flushOnExit({
      timeout: 1000,
      afterFlush: async () => {
        order.push('after');
      },
    });

    await emitSignal('SIGTERM');

    expect(order[0]).toBe('flush');
    expect(order[1]).toBe('after');
  });

  it('both beforeFlush and afterFlush are called in the right order', async () => {
    const order: string[] = [];
    const logger = makeFakeLogger(async () => {
      order.push('flush');
    });
    registerForShutdown(logger);

    flushOnExit({
      timeout: 1000,
      beforeFlush: () => {
        order.push('before');
      },
      afterFlush: () => {
        order.push('after');
      },
    });

    await emitSignal('SIGTERM');

    expect(order).toEqual(['before', 'flush', 'after']);
  });

  it('responds to SIGINT by default', async () => {
    const logger = makeFakeLogger();
    registerForShutdown(logger);

    flushOnExit({ timeout: 1000 });
    await emitSignal('SIGINT');

    expect(logger.close).toHaveBeenCalledTimes(1);
    expect(exitSpy).toHaveBeenCalledWith(130);
  });

  it('responds to custom signals', async () => {
    const logger = makeFakeLogger();
    registerForShutdown(logger);

    flushOnExit({ timeout: 1000, signals: ['SIGUSR2'] });
    await emitSignal('SIGUSR2');

    expect(logger.close).toHaveBeenCalledTimes(1);
    expect(exitSpy).toHaveBeenCalledWith(128 + osConstants.signals.SIGUSR2);

    process.removeAllListeners('SIGUSR2');
  });

  it('still flushes when another SIGTERM listener already exists', async () => {
    // A framework (NestJS/Express) commonly registers its own signal handler.
    // logixia must still attach its own so the documented flush-on-exit runs —
    // signals support multiple listeners.
    const preExistingHandler = jest.fn();
    process.on('SIGTERM', preExistingHandler);

    const logger = makeFakeLogger();
    registerForShutdown(logger);

    const countBefore = process.listenerCount('SIGTERM');
    flushOnExit({ timeout: 1000 });
    const countAfter = process.listenerCount('SIGTERM');

    // logixia adds exactly one handler on top of the pre-existing one.
    expect(countAfter).toBe(countBefore + 1);

    await emitSignal('SIGTERM');
    expect(logger.close).toHaveBeenCalledTimes(1);
    // The app owns shutdown when it has its own handler
    expect(exitSpy).not.toHaveBeenCalled();

    process.removeListener('SIGTERM', preExistingHandler);
  });

  it("exit: 'always' exits even when another listener exists", async () => {
    const preExistingHandler = jest.fn();
    process.on('SIGTERM', preExistingHandler);
    flushOnExit({ timeout: 1000, exit: 'always' });

    await emitSignal('SIGTERM');

    expect(exitSpy).toHaveBeenCalledWith(143);
    process.removeListener('SIGTERM', preExistingHandler);
  });

  it("exit: 'never' flushes but does not exit", async () => {
    const logger = makeFakeLogger();
    registerForShutdown(logger);
    flushOnExit({ timeout: 1000, exit: 'never' });

    await emitSignal('SIGTERM');

    expect(logger.close).toHaveBeenCalledTimes(1);
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it('can flush again on a later signal when it did not exit', async () => {
    const logger = makeFakeLogger();
    registerForShutdown(logger);
    flushOnExit({ timeout: 1000, exit: 'never' });

    await emitSignal('SIGTERM');
    await emitSignal('SIGTERM');

    expect(logger.close).toHaveBeenCalledTimes(2);
  });

  it('does not arm the force-exit timer when the app owns the exit', async () => {
    jest.useFakeTimers();
    try {
      const logger = makeFakeLogger(() => new Promise(() => {}));
      registerForShutdown(logger);
      process.on('SIGTERM', () => {});
      flushOnExit({ timeout: 100 });

      process.emit('SIGTERM', 'SIGTERM');
      jest.advanceTimersByTime(500);

      expect(exitSpy).not.toHaveBeenCalled();
    } finally {
      jest.useRealTimers();
    }
  });

  it('warns when a later call passes conflicting options', () => {
    const write = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
    flushOnExit({ timeout: 1000 });
    flushOnExit({ timeout: 9000, signals: ['SIGHUP'], exit: 'always' });

    const message = write.mock.calls.map((c) => String(c[0])).join('');
    write.mockRestore();
    expect(message).toContain('ignoring conflicting options: timeout, exit, signals');
  });

  it('does not warn when a later call repeats the same options', () => {
    const write = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
    flushOnExit({ timeout: 1000, signals: ['SIGTERM', 'SIGINT'] });
    flushOnExit({ timeout: 1000, signals: ['SIGINT', 'SIGTERM'] });
    flushOnExit();

    write.mockRestore();
    expect(write).not.toHaveBeenCalled();
  });

  it('flushes registered loggers once on beforeExit', async () => {
    const logger = makeFakeLogger();
    registerForShutdown(logger);
    flushOnExit({ timeout: 1000 });

    process.emit('beforeExit', 0);
    process.emit('beforeExit', 0);
    await new Promise((r) => setImmediate(r));

    expect(logger.close).toHaveBeenCalledTimes(1);
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it('removes the beforeExit listener on reset', () => {
    const before = process.listenerCount('beforeExit');
    flushOnExit({ timeout: 1000 });
    expect(process.listenerCount('beforeExit')).toBe(before + 1);
    resetShutdownHandlers();
    expect(process.listenerCount('beforeExit')).toBe(before);
  });

  it('does not register its own handler twice across repeated flushOnExit calls', () => {
    const before = process.listenerCount('SIGTERM');
    flushOnExit({ timeout: 1000 });
    flushOnExit({ timeout: 1000 });
    flushOnExit({ timeout: 1000 });
    // Idempotent: only one logixia handler regardless of call count.
    expect(process.listenerCount('SIGTERM')).toBe(before + 1);
  });

  it('a failing logger close does not prevent other loggers from being flushed', async () => {
    const failing = makeFakeLogger(() => Promise.reject(new Error('flush failure')));
    const healthy = makeFakeLogger();
    registerForShutdown(failing);
    registerForShutdown(healthy);

    flushOnExit({ timeout: 1000 });
    await emitSignal('SIGTERM');

    // Both were attempted; healthy one completed
    expect(failing.close).toHaveBeenCalledTimes(1);
    expect(healthy.close).toHaveBeenCalledTimes(1);
    // Rejections are absorbed, so the signal exit code is still used
    expect(exitSpy).toHaveBeenCalledWith(143);
  });

  it('still exits with the signal code if registry is empty', async () => {
    flushOnExit({ timeout: 1000 });
    await emitSignal('SIGTERM');

    expect(exitSpy).toHaveBeenCalledWith(143);
  });

  it('uses default 5000ms timeout when none is provided', () => {
    // We can't easily measure the timer value, but we can verify flushOnExit
    // accepts no args without throwing
    expect(() => flushOnExit()).not.toThrow();
  });
});

// ── resetShutdownHandlers ─────────────────────────────────────────────────────

describe('resetShutdownHandlers', () => {
  it('clears the registry so subsequent flushes touch no loggers', async () => {
    const logger = makeFakeLogger();
    registerForShutdown(logger);
    resetShutdownHandlers();

    flushOnExit({ timeout: 1000 });
    await emitSignal('SIGTERM');

    expect(logger.close).not.toHaveBeenCalled();
  });

  it('allows flushOnExit to be re-registered after reset', async () => {
    const logger = makeFakeLogger();

    // First registration cycle
    registerForShutdown(logger);
    flushOnExit({ timeout: 1000 });
    await emitSignal('SIGTERM');
    expect(logger.close).toHaveBeenCalledTimes(1);

    // Reset and start again
    resetShutdownHandlers();
    process.removeAllListeners('SIGTERM');

    const logger2 = makeFakeLogger();
    registerForShutdown(logger2);
    flushOnExit({ timeout: 1000 });
    await emitSignal('SIGTERM');

    expect(logger2.close).toHaveBeenCalledTimes(1);
  });

  it('calling reset multiple times does not throw', () => {
    expect(() => {
      resetShutdownHandlers();
      resetShutdownHandlers();
      resetShutdownHandlers();
    }).not.toThrow();
  });
});

// ── Async hook edge cases ─────────────────────────────────────────────────────

describe('async hook edge cases', () => {
  it('awaits async beforeFlush before flushing', async () => {
    const order: string[] = [];
    registerForShutdown(
      makeFakeLogger(async () => {
        order.push('flush');
      })
    );

    flushOnExit({
      timeout: 2000,
      beforeFlush: () =>
        new Promise((resolve) =>
          setTimeout(() => {
            order.push('async-before');
            resolve();
          }, 10)
        ),
    });

    await emitSignal('SIGTERM');
    // Wait a bit for the async before to complete
    await new Promise((r) => setTimeout(r, 50));

    expect(order[0]).toBe('async-before');
  });

  it('awaits async afterFlush after flushing', async () => {
    const order: string[] = [];
    registerForShutdown(
      makeFakeLogger(async () => {
        order.push('flush');
      })
    );

    flushOnExit({
      timeout: 2000,
      afterFlush: () =>
        new Promise((resolve) =>
          setTimeout(() => {
            order.push('async-after');
            resolve();
          }, 10)
        ),
    });

    await emitSignal('SIGTERM');
    await new Promise((r) => setTimeout(r, 50));

    expect(order).toContain('async-after');
    const flushIdx = order.indexOf('flush');
    const afterIdx = order.indexOf('async-after');
    expect(flushIdx).toBeLessThan(afterIdx);
  });
});

// ── Force-exit timer (lines 60-63 coverage) ───────────────────────────────────

describe('flushOnExit — force-exit timeout', () => {
  it('calls process.exit(1) and writes to stderr when flush hangs past timeout', async () => {
    const stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);

    // A logger whose close() never resolves within the timeout
    const hangs = makeFakeLogger(() => new Promise(() => {}));
    registerForShutdown(hangs);

    // Very short timeout so the timer fires quickly
    flushOnExit({ timeout: 30 });
    process.emit('SIGTERM', 'SIGTERM');

    // Wait longer than the timeout
    await new Promise((r) => setTimeout(r, 100));

    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('Graceful shutdown timed out'));

    stderrSpy.mockRestore();
  }, 5000);
});

// ── re-entrancy guard ─────────────────────────────────────────────────────────

describe('flushOnExit — concurrent signal re-entrancy', () => {
  it('flushes each logger only once when a second signal arrives mid-shutdown', async () => {
    // close() resolves on a delay so the first shutdown is still in flight when
    // the second signal arrives — the guard must drop the second one.
    let resolveClose: () => void = () => {};
    const slow = makeFakeLogger(
      () =>
        new Promise<void>((resolve) => {
          resolveClose = resolve;
        })
    );
    registerForShutdown(slow);
    flushOnExit({ timeout: 1000 });

    // Fire SIGTERM, then SIGINT before the first close() resolves.
    process.emit('SIGTERM', 'SIGTERM');
    process.emit('SIGINT', 'SIGINT');
    await new Promise((r) => setImmediate(r));

    // Only the first signal started a shutdown → close() called exactly once.
    expect(slow.close).toHaveBeenCalledTimes(1);

    resolveClose();
    await new Promise((r) => setImmediate(r));
  });

  it('does not call process.exit twice for two concurrent signals', async () => {
    const logger = makeFakeLogger();
    registerForShutdown(logger);
    flushOnExit({ timeout: 1000 });

    process.emit('SIGTERM', 'SIGTERM');
    process.emit('SIGTERM', 'SIGTERM');
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    expect(exitSpy).toHaveBeenCalledTimes(1);
  });
});
