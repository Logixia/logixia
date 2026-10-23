/**
 * Graceful shutdown utilities for Logixia
 *
 * Ensures all in-flight logs are flushed to every transport before the process
 * exits on SIGTERM / SIGINT — solving the "last N seconds of logs are lost on
 * deployment" problem reported in Pino issue #2002 and LogDNA issue #15.
 */

import { constants as osConstants } from 'node:os';

export type ExitMode = 'auto' | 'always' | 'never';

export interface FlushOnExitOptions {
  /** How long (ms) to wait for transports to flush before force-exiting. Default: 5000 */
  timeout?: number;
  /** OS signals that trigger a graceful flush. Default: ['SIGTERM', 'SIGINT'] */
  signals?: NodeJS.Signals[];
  /** Called just before flushing starts — useful for stopping traffic intake */
  beforeFlush?: () => void | Promise<void>;
  /** Called after all loggers have flushed successfully */
  afterFlush?: () => void | Promise<void>;
  /**
   * Whether logixia ends the process after flushing.
   * - `'auto'` (default): exit only when logixia's handler is the only listener for the
   *   signal. If the app registered its own handler (server.close(), NestJS shutdown
   *   hooks), logixia just flushes and leaves the exit to the app.
   * - `'always'`: always exit after the flush.
   * - `'never'`: never exit; only flush.
   * When logixia exits it uses 128 + the signal number.
   */
  exit?: ExitMode;
}

type Closeable = { close(): Promise<void>; flush?(): Promise<void> };

const MAX_BEFORE_EXIT_FLUSHES = 5;

/** Module-level registry of all logger instances that have opted into graceful shutdown */
const registry = new Set<Closeable>();
let shutdownHandlerRegistered = false;
/** Guards the handler against re-entrancy: a second signal (e.g. SIGINT after
 * SIGTERM, or an impatient double Ctrl+C) must not start a second concurrent
 * flush+exit, which could exit the process and truncate the first flush mid-write. */
let shutdownInProgress = false;
/** Our own handler + the signals we attached it to, so reset() can detach exactly it. */
let activeHandler: ((signal: NodeJS.Signals) => void | Promise<void>) | undefined;
let activeSignals: NodeJS.Signals[] = [];
let activeOptions: FlushOnExitOptions | undefined;
let beforeExitHandler: (() => void) | undefined;

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
 * the process exits. Idempotent — the first call wins and later calls with
 * conflicting options print a warning. The process is ended with 128 + signal
 * number only when logixia's handler is the sole listener for that signal (see
 * `exit`); otherwise it just flushes and leaves shutdown to the application.
 * Loggers are also flushed (not closed) on `beforeExit`.
 *
 * @example
 * ```ts
 * import { flushOnExit } from 'logixia';
 * flushOnExit({ timeout: 5000 });
 * ```
 */
export function flushOnExit(options: FlushOnExitOptions = {}): void {
  if (shutdownHandlerRegistered) {
    warnOnConflict(activeOptions, options);
    return;
  }
  shutdownHandlerRegistered = true;
  activeOptions = options;

  const {
    timeout = 5000,
    signals = ['SIGTERM', 'SIGINT'],
    beforeFlush,
    afterFlush,
    exit = 'auto',
  } = options;

  const shouldExit = (signal: NodeJS.Signals): boolean =>
    exit === 'always' || (exit === 'auto' && process.listenerCount(signal) <= 1);

  const handler = async (signal: NodeJS.Signals) => {
    // Re-entrancy guard: a flush is already running from an earlier signal.
    // Starting a second one would race two close()/exit() sequences and could
    // truncate the in-flight flush — exactly the log loss we are preventing.
    if (shutdownInProgress) return;
    shutdownInProgress = true;

    // Force-exit safety net — if flushing hangs, don't block the process forever.
    // Only armed when logixia owns the exit; otherwise the app decides.
    const forceExitTimer = shouldExit(signal)
      ? setTimeout(() => {
          // Keep the force-exit message visible even when internal logs are silenced.
          process.stderr.write(
            `[logixia] Graceful shutdown timed out after ${timeout}ms on ${signal}. Force-exiting.\n`
          );
          process.exit(1);
        }, timeout).unref()
      : undefined;

    try {
      if (beforeFlush) await beforeFlush();

      // Flush all registered loggers concurrently, ignoring individual failures
      await Promise.allSettled([...registry].map((logger) => logger.close()));

      if (afterFlush) await afterFlush();
    } catch (err) {
      process.stderr.write(`[logixia] Shutdown hook failed: ${String(err)}\n`);
    } finally {
      clearTimeout(forceExitTimer);
      if (shouldExit(signal)) {
        process.exit(128 + (osConstants.signals[signal] ?? 0));
      }
      shutdownInProgress = false;
    }
  };

  // Register our own handler unconditionally. Signals support multiple
  // listeners, so other frameworks' handlers (NestJS/Express) don't block ours —
  // the previous `listenerCount === 0` guard meant the documented flush silently
  // never ran whenever any other listener existed. The `shutdownHandlerRegistered`
  // flag above keeps THIS function idempotent (one logixia handler, not N).
  activeHandler = handler;
  activeSignals = signals;
  for (const signal of signals) {
    process.on(signal, activeHandler);
  }

  // Normal exit (event loop drained): flush, never close, since beforeExit can fire
  // again and the app may keep logging. Not re-entrant, and capped so a transport
  // that schedules work on every flush cannot keep the process alive forever.
  let beforeExitFlushes = 0;
  let beforeExitFlushing = false;
  beforeExitHandler = () => {
    if (beforeExitFlushing || shutdownInProgress || beforeExitFlushes >= MAX_BEFORE_EXIT_FLUSHES) {
      return;
    }
    beforeExitFlushing = true;
    beforeExitFlushes += 1;
    void Promise.allSettled([...registry].map((logger) => logger.flush?.())).finally(() => {
      beforeExitFlushing = false;
    });
  };
  process.on('beforeExit', beforeExitHandler);
}

function warnOnConflict(active: FlushOnExitOptions | undefined, next: FlushOnExitOptions): void {
  if (!active) return;
  const conflicts: string[] = [];
  if (next.timeout !== undefined && next.timeout !== (active.timeout ?? 5000)) {
    conflicts.push('timeout');
  }
  if (next.exit !== undefined && next.exit !== (active.exit ?? 'auto')) conflicts.push('exit');
  if (next.signals !== undefined) {
    const current = new Set(active.signals ?? ['SIGTERM', 'SIGINT']);
    if (next.signals.length !== current.size || next.signals.some((sig) => !current.has(sig))) {
      conflicts.push('signals');
    }
  }
  if (next.beforeFlush && next.beforeFlush !== active.beforeFlush) conflicts.push('beforeFlush');
  if (next.afterFlush && next.afterFlush !== active.afterFlush) conflicts.push('afterFlush');
  if (conflicts.length === 0) return;
  process.stderr.write(
    `[logixia] flushOnExit was already configured; ignoring conflicting options: ${conflicts.join(', ')}.\n`
  );
}

/**
 * Remove all graceful shutdown handlers and clear the registry.
 * Primarily useful in tests.
 */
export function resetShutdownHandlers(): void {
  registry.clear();
  if (activeHandler) {
    for (const signal of activeSignals) {
      process.removeListener(signal, activeHandler);
    }
  }
  if (beforeExitHandler) process.removeListener('beforeExit', beforeExitHandler);
  beforeExitHandler = undefined;
  activeHandler = undefined;
  activeSignals = [];
  activeOptions = undefined;
  shutdownHandlerRegistered = false;
  shutdownInProgress = false;
}
