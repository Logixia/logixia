/**
 * logixia — Worker Thread Transport
 *
 * Offloads JSON serialization and all I/O to a Node.js worker thread,
 * completely eliminating any event-loop impact from logging. The main thread
 * only posts a raw message to the worker — it never calls JSON.stringify or
 * any I/O syscalls on the hot path.
 *
 * Architecture:
 *   Main thread  →  MessageChannel  →  Worker thread  →  Wrapped transport
 *
 * The worker runs an ordinary logixia transport (file, database, console…)
 * inside its own event loop. If the worker crashes it is restarted automatically
 * (up to `maxRestarts` times) and buffered messages are replayed.
 *
 * @example
 * ```ts
 * import { WorkerTransport } from 'logixia/worker';
 *
 * const logger = createLogger({
 *   transports: {
 *     // Run file transport inside a worker thread — zero event-loop impact
 *     custom: [
 *       new WorkerTransport({
 *         transportType: 'file',
 *         transportConfig: { filename: 'app.log', dirname: './logs' },
 *         bufferSize: 500,
 *         maxRestarts: 3,
 *       }),
 *     ],
 *   },
 * });
 * ```
 */

import path from 'node:path';
import { Worker } from 'node:worker_threads';

import type { ITransport, TransportLogEntry } from '../types/transport.types';
import { internalError, internalWarn } from '../utils/internal-log';
import { protectSecrets } from './secret-config';

export interface WorkerTransportConfig {
  /**
   * Which built-in logixia transport to run inside the worker thread.
   * The worker resolves the correct module automatically.
   */
  transportType: 'file' | 'database' | 'console';
  /** Config forwarded verbatim to the wrapped transport constructor. */
  transportConfig: Record<string, unknown>;
  /**
   * Max log entries to buffer in the main thread while the worker is starting
   * or restarting. Entries beyond this limit are dropped with a warning.
   * @default 1000
   */
  bufferSize?: number;
  /**
   * How many times to restart the worker if it crashes unexpectedly.
   * @default 3
   */
  maxRestarts?: number;
  /**
   * Custom level severities (`levelOptions.levels`) the wrapped transport's own
   * `level` is compared against inside the worker. Built-in levels need no entry.
   */
  levels?: Record<string, number>;
  /**
   * Log level filter — only entries at or above this level are forwarded.
   * Useful for routing only errors to an expensive transport in a worker.
   */
  level?: string;
}

/**
 * Transport that runs a wrapped transport inside a dedicated Node.js worker
 * thread, completely removing JSON serialization and I/O from the main event loop.
 */
export class WorkerTransport implements ITransport {
  public readonly name = 'worker';
  public readonly level: string | undefined;
  public readonly batchSize = 1;
  public readonly flushInterval = 0;

  private worker: Worker | null = null;
  private ready = false;
  private readonly buffer: TransportLogEntry[] = [];
  private readonly bufferSize: number;
  private restarts = 0;
  private readonly maxRestarts: number;
  private readonly config: WorkerTransportConfig;
  /** Pending restart-backoff timer, so close() can cancel a queued restart. */
  private restartTimer: NodeJS.Timeout | null = null;
  /** Set once close() begins, so a worker 'exit' no longer triggers a restart. */
  private closing = false;
  /** Writes have been posted since the last flush; keeps the beforeExit flush from looping. */
  private dirty = false;
  /** Run once the worker reports ready, used when the process wants to exit before that. */
  private onReady: (() => void) | undefined;
  /** Max time to wait for the worker's 'flushed' ack before giving up. */
  private readonly FLUSH_TIMEOUT_MS = 5000;
  /** Max time to wait for a graceful worker exit before force-terminating. */
  private readonly SHUTDOWN_TIMEOUT_MS = 5000;

  constructor(config: WorkerTransportConfig) {
    this.config = config;
    this.bufferSize = config.bufferSize ?? 1000;
    this.maxRestarts = config.maxRestarts ?? 3;
    this.level = config.level;
    protectSecrets(this, ['config']);
    this.startWorker();
    process.on('beforeExit', this.flushForExit);
  }

  /**
   * The worker is unref'd so it never keeps the process alive on its own; the
   * trade-off is that lines still queued on it would be lost when the event loop
   * drains. On beforeExit, re-ref the worker until it acknowledges a flush.
   */
  private readonly flushForExit = (): void => {
    const worker = this.worker;
    if (!worker || this.closing || !this.dirty) return;
    worker.ref();
    const timer = setTimeout(() => worker.unref(), this.FLUSH_TIMEOUT_MS);
    const done = (): void => {
      clearTimeout(timer);
      worker.unref();
    };
    if (this.ready) {
      void this.flush().finally(done);
    } else {
      this.onReady = () => void this.flush().finally(done);
    }
  };

  private startWorker(): void {
    try {
      this.worker = new Worker(this.workerFile(), {
        workerData: {
          transportType: this.config.transportType,
          transportConfig: this.config.transportConfig,
          levels: this.config.levels,
        },
      });

      this.worker.on('message', (msg: { type: string; error?: string }) => {
        if (msg.type === 'ready') {
          this.ready = true;
          this.drainBuffer();
          const onReady = this.onReady;
          this.onReady = undefined;
          onReady?.();
        } else if (msg.type === 'error' || msg.type === 'write-error') {
          internalError(
            `WorkerTransport [${this.config.transportType}]: ${msg.error ?? 'unknown'}`
          );
        }
      });

      this.worker.on('error', (err) => {
        internalError('WorkerTransport worker error', err);
        this.handleWorkerExit();
      });

      this.worker.on('exit', (code) => {
        if (code !== 0) {
          internalWarn(`WorkerTransport worker exited with code ${code}`);
          this.handleWorkerExit();
        }
      });

      // After the listeners: adding a 'message' listener re-refs the worker's port.
      this.worker.unref();
    } catch (err) {
      internalError('WorkerTransport failed to start', err);
    }
  }

  /** The worker entry is always built as CommonJS, next to this module's output. */
  protected workerFile(): string {
    return path.join(__dirname, 'worker-entry.js');
  }

  private handleWorkerExit(): void {
    this.ready = false;
    // Don't resurrect a worker we're intentionally shutting down — close() sets
    // `closing` and nulls the worker, so a late 'exit'/'error' event must not
    // queue a restart (which would spawn a fresh leaked thread post-shutdown).
    if (this.closing) return;
    if (this.restarts < this.maxRestarts) {
      this.restarts++;
      internalWarn(`WorkerTransport restarting (attempt ${this.restarts}/${this.maxRestarts})`);
      // Small backoff before restart. unref() so a perpetually-failing worker's
      // pending restart never keeps the process alive on its own.
      this.restartTimer = setTimeout(() => {
        this.restartTimer = null;
        this.startWorker();
      }, 500 * this.restarts);
      if (this.restartTimer.unref) this.restartTimer.unref();
    } else {
      internalError(
        `WorkerTransport exhausted ${this.maxRestarts} restart attempts — transport disabled`
      );
    }
  }

  private drainBuffer(): void {
    while (this.buffer.length > 0 && this.ready && this.worker) {
      const entry = this.buffer.shift();
      if (entry) {
        this.worker.postMessage({ type: 'write', entry });
      }
    }
  }

  write(entry: TransportLogEntry): void {
    this.dirty = true;
    if (this.ready && this.worker) {
      this.worker.postMessage({ type: 'write', entry });
    } else {
      if (this.buffer.length >= this.bufferSize) {
        internalWarn('WorkerTransport buffer full — dropping oldest entry');
        this.buffer.shift();
      }
      this.buffer.push(entry);
    }
  }

  async flush(): Promise<void> {
    if (!this.ready || !this.worker) return;
    const worker = this.worker;
    this.dirty = false;
    // Unref'd between flushes; ref'd here so an awaited flush() keeps the process alive.
    worker.ref();
    return new Promise<void>((resolve) => {
      // Time-box the flush: if the worker dies or restarts before answering,
      // the 'flushed' message would never arrive and this promise would hang
      // forever, blocking shutdown until the force-exit timer kills the process
      // (losing everything). Resolve on timeout so close() can still terminate.
      const timer = setTimeout(() => {
        worker.off('message', handler);
        worker.unref?.();
        resolve();
      }, this.FLUSH_TIMEOUT_MS);
      if (timer.unref) timer.unref();

      const handler = (msg: { type: string }) => {
        if (msg.type === 'flushed') {
          clearTimeout(timer);
          worker.off('message', handler);
          worker.unref?.();
          resolve();
        }
      };
      worker.on('message', handler);
      worker.postMessage({ type: 'flush' });
    });
  }

  /**
   * Flush the worker's buffer and terminate the thread on shutdown.
   *
   * This MUST be named close() — TransportManager.close() invokes
   * transport.close(), so a method named only shutdown() was never called on
   * graceful exit, leaking the worker thread and dropping its buffered logs.
   */
  async close(): Promise<void> {
    // Stop the restart loop first: cancel any queued backoff restart and flag
    // that further worker exits are expected (so handleWorkerExit no-ops).
    this.closing = true;
    process.removeListener('beforeExit', this.flushForExit);
    if (this.restartTimer) {
      clearTimeout(this.restartTimer);
      this.restartTimer = null;
    }

    if (!this.worker) return;
    const worker = this.worker;
    this.worker = null;

    // Push any locally-buffered (pre-ready) entries first: the worker's port
    // queues them until its listener attaches, so they are handled before the
    // shutdown message, which flushes the wrapped transport and exits.
    this.drainBufferTo(worker);
    worker.postMessage({ type: 'shutdown' });
    // The worker is unref'd, so hold the process open until it has drained and exited.
    worker.ref();

    await new Promise<void>((resolve) => {
      // Don't wait forever for a wedged worker — terminate() it after a timeout.
      const timer = setTimeout(() => {
        worker.terminate().finally(() => resolve());
      }, this.SHUTDOWN_TIMEOUT_MS);
      if (timer.unref) timer.unref();

      worker.once('exit', () => {
        clearTimeout(timer);
        resolve();
      });
    });
  }

  /** Back-compat alias — prefer close(). */
  async shutdown(): Promise<void> {
    await this.close();
  }

  private drainBufferTo(worker: Worker): void {
    while (this.buffer.length > 0) {
      const entry = this.buffer.shift();
      if (entry) worker.postMessage({ type: 'write', entry });
    }
  }
}
