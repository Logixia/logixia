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
 * import { WorkerTransport } from 'logixia';
 *
 * const logger = createLogger({
 *   transports: {
 *     // Run file transport inside a worker thread — zero event-loop impact
 *     worker: new WorkerTransport({
 *       transportType: 'file',
 *       transportConfig: { filename: 'app.log', dirname: './logs' },
 *       bufferSize: 500,
 *       maxRestarts: 3,
 *     }),
 *   },
 * });
 * ```
 */

import { Worker } from 'node:worker_threads';

import type { ITransport, TransportLogEntry } from '../types/transport.types';
import { internalError, internalWarn } from '../utils/internal-log';

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
   * Log level filter — only entries at or above this level are forwarded.
   * Useful for routing only errors to an expensive transport in a worker.
   */
  level?: string;
}

/** Inline worker script — avoids a separate file on disk */
const WORKER_SCRIPT = `
const { parentPort, workerData } = require('node:worker_threads');
const { transportType, transportConfig } = workerData;

let transport;

async function loadTransport() {
  switch (transportType) {
    case 'file': {
      const { FileTransport } = await import('./file.transport.js');
      transport = new FileTransport(transportConfig);
      break;
    }
    case 'database': {
      const { DatabaseTransport } = await import('./database.transport.js');
      transport = new DatabaseTransport(transportConfig);
      break;
    }
    case 'console':
    default: {
      const { ConsoleTransport } = await import('./console.transport.js');
      transport = new ConsoleTransport(transportConfig);
      break;
    }
  }
}

loadTransport().then(() => {
  parentPort.postMessage({ type: 'ready' });
}).catch((err) => {
  parentPort.postMessage({ type: 'error', error: err.message });
  process.exit(1);
});

parentPort.on('message', async (msg) => {
  if (msg.type === 'write') {
    try {
      await transport.write(msg.entry);
    } catch (err) {
      parentPort.postMessage({ type: 'write-error', error: err.message, entry: msg.entry });
    }
  } else if (msg.type === 'flush') {
    try {
      if (typeof transport.flush === 'function') await transport.flush();
      parentPort.postMessage({ type: 'flushed' });
    } catch (err) {
      parentPort.postMessage({ type: 'flush-error', error: err.message });
    }
  } else if (msg.type === 'shutdown') {
    if (typeof transport.flush === 'function') {
      try { await transport.flush(); } catch { /* ignore */ }
    }
    process.exit(0);
  }
});
`.trim();

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

  constructor(config: WorkerTransportConfig) {
    this.config = config;
    this.bufferSize = config.bufferSize ?? 1000;
    this.maxRestarts = config.maxRestarts ?? 3;
    this.level = config.level;
    this.startWorker();
  }

  private startWorker(): void {
    try {
      this.worker = new Worker(WORKER_SCRIPT, {
        eval: true,
        workerData: {
          transportType: this.config.transportType,
          transportConfig: this.config.transportConfig,
        },
      });

      this.worker.on('message', (msg: { type: string; error?: string }) => {
        if (msg.type === 'ready') {
          this.ready = true;
          this.drainBuffer();
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
    } catch (err) {
      internalError('WorkerTransport failed to start', err);
    }
  }

  private handleWorkerExit(): void {
    this.ready = false;
    if (this.restarts < this.maxRestarts) {
      this.restarts++;
      internalWarn(`WorkerTransport restarting (attempt ${this.restarts}/${this.maxRestarts})`);
      // Small backoff before restart
      setTimeout(() => this.startWorker(), 500 * this.restarts);
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
    return new Promise<void>((resolve) => {
      const handler = (msg: { type: string }) => {
        if (msg.type === 'flushed') {
          this.worker?.off('message', handler);
          resolve();
        }
      };
      this.worker!.on('message', handler);
      this.worker!.postMessage({ type: 'flush' });
    });
  }

  async shutdown(): Promise<void> {
    if (this.worker) {
      this.worker.postMessage({ type: 'shutdown' });
      await new Promise<void>((resolve) => {
        this.worker!.once('exit', () => resolve());
      });
      this.worker = null;
    }
  }
}
