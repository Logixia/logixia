/**
 * Graceful shutdown utilities for Logixia
 *
 * Ensures all in-flight logs are flushed to every transport before the process
 * exits on SIGTERM / SIGINT — solving the "last N seconds of logs are lost on
 * deployment" problem reported in Pino issue #2002 and LogDNA issue #15.
 */

export interface FlushOnExitOptions {
  /** How long (ms) to wait for transports to flush before force-exiting. Default: 5000 */
  timeout?: number;
  /** OS signals that trigger a graceful flush. Default: ['SIGTERM', 'SIGINT'] */
  signals?: NodeJS.Signals[];
  /** Called just before flushing starts — useful for stopping traffic intake */
  beforeFlush?: () => void | Promise<void>;
  /** Called after all loggers have flushed successfully */
  afterFlush?: () => void | Promise<void>;
}

type Closeable = { close(): Promise<void> };

/** Module-level registry of all logger instances that have opted into graceful shutdown */
const registry = new Set<Closeable>();
let shutdownHandlerRegistered = false;

/**
 * Register a logger instance so it is included in the graceful shutdown flush.
 * Called automatically when `gracefulShutdown: true` is set in logger config.
 */
export function registerForShutdown(logger: Closeable): void {
  registry.add(logger);
}

/**
 * Deregister a logger (e.g. after `logger.close()` is called manually).
 */
export function deregisterFromShutdown(logger: Closeable): void {
  registry.delete(logger);
}

/**
 * Register SIGTERM / SIGINT handlers that flush all registered loggers before
 * the process exits. Idempotent — calling multiple times is safe.
 *
 * @example
 * ```ts
 * import { flushOnExit } from 'logixia';
 * flushOnExit({ timeout: 5000 });
 * ```
 */
export function flushOnExit(options: FlushOnExitOptions = {}): void {
  if (shutdownHandlerRegistered) return;
  shutdownHandlerRegistered = true;

  const { timeout = 5000, signals = ['SIGTERM', 'SIGINT'], beforeFlush, afterFlush } = options;

  const handler = async (signal: NodeJS.Signals) => {
    // Force-exit safety net — if flushing hangs, don't block the process forever
    const forceExitTimer = setTimeout(() => {
      process.stderr.write(
        `[logixia] Graceful shutdown timed out after ${timeout}ms on ${signal}. Force-exiting.\n`
      );
      process.exit(1);
    }, timeout).unref();

    try {
      if (beforeFlush) await beforeFlush();

      // Flush all registered loggers concurrently, ignoring individual failures
      await Promise.allSettled([...registry].map((logger) => logger.close()));

      if (afterFlush) await afterFlush();
    } finally {
      clearTimeout(forceExitTimer);
      process.exit(0);
    }
  };

  for (const signal of signals) {
    // Only add if not already handled (avoids double-handling in long-lived processes)
    if (process.listenerCount(signal) === 0) {
      process.on(signal, handler);
    }
  }
}

/**
 * Remove all graceful shutdown handlers and clear the registry.
 * Primarily useful in tests.
 */
export function resetShutdownHandlers(): void {
  registry.clear();
  shutdownHandlerRegistered = false;
}
