/**
 * Tests for WorkerTransport lifecycle (close/flush) using an injected fake
 * worker, so no real worker thread (which would need built dist/ files) spawns.
 *
 * Regression coverage:
 *  - close() exists and is what TransportManager calls (a method named only
 *    shutdown() was never invoked on graceful exit → leaked thread + lost logs).
 *  - close() posts a 'shutdown' message and resolves on the worker's 'exit'.
 *  - flush() resolves on a 'flushed' ack and does NOT hang when the ack never
 *    comes (time-boxed) — otherwise shutdown blocks until force-exit.
 */

import { EventEmitter } from 'node:events';

import type { TransportLogEntry } from '../../types/transport.types';
import { WorkerTransport } from '../worker.transport';

/** A fake worker that records postMessage calls and lets tests emit events. */
class FakeWorker extends EventEmitter {
  public readonly posted: Array<{ type: string; entry?: TransportLogEntry }> = [];
  public terminated = false;

  postMessage(msg: { type: string; entry?: TransportLogEntry }): void {
    this.posted.push(msg);
  }

  async terminate(): Promise<number> {
    this.terminated = true;
    this.emit('exit', 1);
    return 1;
  }
}

interface WorkerInternals {
  worker: { terminate?(): Promise<number> } | null;
  ready: boolean;
  restartTimer: NodeJS.Timeout | null;
  closing: boolean;
  maxRestarts: number;
}

/**
 * Build a WorkerTransport with its real worker replaced by a fake, marked ready.
 *
 * The constructor spawns a real worker thread (which can't resolve its transport
 * module in the test env), so we immediately tear that down and inject the fake.
 */
function makeWithFakeWorker(): { transport: WorkerTransport; fake: FakeWorker } {
  const transport = new WorkerTransport({ transportType: 'console', transportConfig: {} });
  const internals = transport as unknown as WorkerInternals;
  // Disable the auto-restart machinery and terminate the auto-spawned real worker
  // so no thread or backoff timer leaks during the test.
  internals.maxRestarts = 0;
  if (internals.restartTimer) {
    clearTimeout(internals.restartTimer);
    internals.restartTimer = null;
  }
  const realWorker = internals.worker;
  if (realWorker && typeof realWorker.terminate === 'function') {
    realWorker.terminate().catch(() => {});
  }

  const fake = new FakeWorker();
  internals.worker = fake;
  internals.ready = true;
  internals.closing = false;
  return { transport, fake };
}

function makeEntry(i: number): TransportLogEntry {
  return { timestamp: new Date('2026-01-01T00:00:00.000Z'), level: 'info', message: `w-${i}` };
}

describe('WorkerTransport — lifecycle', () => {
  it('exposes close() (the method TransportManager actually calls)', () => {
    const { transport } = makeWithFakeWorker();
    expect(typeof (transport as unknown as { close: unknown }).close).toBe('function');
  });

  it('close() posts a shutdown message and resolves on worker exit', async () => {
    const { transport, fake } = makeWithFakeWorker();

    const closePromise = transport.close();
    // The worker acknowledges by exiting.
    fake.emit('exit', 0);
    await closePromise;

    expect(fake.posted.some((m) => m.type === 'shutdown')).toBe(true);
  });

  it('shutdown() is a back-compat alias for close()', async () => {
    const { transport, fake } = makeWithFakeWorker();
    const p = transport.shutdown();
    fake.emit('exit', 0);
    await p;
    expect(fake.posted.some((m) => m.type === 'shutdown')).toBe(true);
  });

  it('flush() resolves on a flushed ack', async () => {
    const { transport, fake } = makeWithFakeWorker();

    const flushPromise = transport.flush();
    // Worker responds.
    fake.emit('message', { type: 'flushed' });
    await expect(flushPromise).resolves.toBeUndefined();

    expect(fake.posted.some((m) => m.type === 'flush')).toBe(true);
  });

  it('flush() does not hang forever when the worker never acks', async () => {
    jest.useFakeTimers();
    try {
      const { transport } = makeWithFakeWorker();
      const flushPromise = transport.flush();
      // No 'flushed' message ever arrives — advance past the flush timeout.
      jest.advanceTimersByTime(5000);
      await expect(flushPromise).resolves.toBeUndefined();
    } finally {
      jest.useRealTimers();
    }
  });

  it('close() forwards locally-buffered entries to the worker before shutdown', async () => {
    const transport = new WorkerTransport({ transportType: 'console', transportConfig: {} });
    const internals = transport as unknown as WorkerInternals;
    internals.maxRestarts = 0;
    if (internals.restartTimer) {
      clearTimeout(internals.restartTimer);
      internals.restartTimer = null;
    }
    const realWorker = internals.worker;
    if (realWorker && typeof realWorker.terminate === 'function') {
      realWorker.terminate().catch(() => {});
    }

    const fake = new FakeWorker();
    // Not ready yet → writes go to the local buffer.
    internals.ready = false;
    internals.worker = fake;
    transport.write(makeEntry(0));
    transport.write(makeEntry(1));

    // Now mark ready and close — buffered entries must be forwarded.
    internals.ready = true;
    const closePromise = transport.close();
    fake.emit('exit', 0);
    await closePromise;

    const writes = fake.posted.filter((m) => m.type === 'write');
    expect(writes).toHaveLength(2);
    expect(fake.posted.some((m) => m.type === 'shutdown')).toBe(true);
  });
});
