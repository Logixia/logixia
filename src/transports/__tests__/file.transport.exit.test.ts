import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';

import type { TransportLogEntry } from '../../types/transport.types';
import { FileTransport } from '../file.transport';

function entry(i: number): TransportLogEntry {
  return { timestamp: new Date('2026-01-01T00:00:00.000Z'), level: 'info', message: `line-${i}` };
}

describe('FileTransport JSON core fields', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'logixia-file-fields-'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('writes context, traceId, appName and environment like the console transport', async () => {
    const t = new FileTransport({ dirname: dir, filename: 'f.log', format: 'json' });
    await t.write({
      ...entry(1),
      context: 'PaymentService',
      traceId: 'trace-abc',
      appName: 'checkout',
      environment: 'prod',
      data: { amount: 5 },
    });
    await t.close();
    const parsed = JSON.parse(readFileSync(path.join(dir, 'f.log'), 'utf8'));
    expect(parsed).toMatchObject({
      level: 'info',
      message: 'line-1',
      context: 'PaymentService',
      traceId: 'trace-abc',
      appName: 'checkout',
      environment: 'prod',
      amount: 5,
    });
  });
});

describe('FileTransport exit handling', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'logixia-file-exit-'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('flushes batched lines synchronously when the process exits', async () => {
    const before = process.listenerCount('exit');
    const t = new FileTransport({ dirname: dir, filename: 'e.log' });
    for (let i = 0; i < 10; i++) await t.write(entry(i));
    expect(process.listenerCount('exit')).toBe(before + 1);

    const listeners = process.listeners('exit');
    listeners[listeners.length - 1]!.call(process, 0);

    const lines = readFileSync(path.join(dir, 'e.log'), 'utf8').trim().split('\n');
    expect(lines).toHaveLength(10);
    expect(JSON.parse(lines[9]!).message).toBe('line-9');
    await t.close();
  });

  it('does not write lines twice when the exit flush follows a normal flush', async () => {
    const t = new FileTransport({ dirname: dir, filename: 'e.log' });
    for (let i = 0; i < 3; i++) await t.write(entry(i));
    await t.flush();
    const listeners = process.listeners('exit');
    listeners[listeners.length - 1]!.call(process, 0);
    expect(readFileSync(path.join(dir, 'e.log'), 'utf8').trim().split('\n')).toHaveLength(3);
    await t.close();
  });

  it('registers one exit listener per transport and removes it on close', async () => {
    const before = process.listenerCount('exit');
    const t = new FileTransport({ dirname: dir, filename: 'e.log' });
    for (let i = 0; i < 5; i++) await t.write(entry(i));
    expect(process.listenerCount('exit')).toBe(before + 1);
    await t.close();
    expect(process.listenerCount('exit')).toBe(before);
  });

  it('does not hold the event loop open with the flush timer', async () => {
    const t = new FileTransport({ dirname: dir, filename: 'e.log' });
    await t.write(entry(0));
    const timer = (t as unknown as { batchTimer?: NodeJS.Timeout }).batchTimer;
    expect(timer).toBeDefined();
    expect(timer!.hasRef()).toBe(false);
    await t.close();
  });
});
