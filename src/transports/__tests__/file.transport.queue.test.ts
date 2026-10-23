import * as fs from 'node:fs';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';

import type { TransportLogEntry } from '../../types/transport.types';
import { internalWarn } from '../../utils/internal-log';
import { FileTransport } from '../file.transport';

jest.mock('node:fs', () => {
  const actual = jest.requireActual<typeof fs>('node:fs');
  return { ...actual, appendFile: jest.fn(actual.appendFile) };
});
jest.mock('../../utils/internal-log', () => ({
  ...jest.requireActual('../../utils/internal-log'),
  internalWarn: jest.fn(),
}));

const realAppendFile = jest.requireActual<typeof fs>('node:fs').appendFile;
const appendMock = fs.appendFile as unknown as jest.Mock;

function makeEntry(index: number): TransportLogEntry {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    level: 'info',
    message: `q-${index}`,
  };
}

function stallAppends() {
  const release: Array<() => void> = [];
  appendMock.mockImplementation((...args: unknown[]) => {
    release.push(() => (realAppendFile as (...a: unknown[]) => void)(...args));
  });
  return {
    pending: () => release.length,
    releaseAll: () => {
      for (const r of release.splice(0)) r();
    },
  };
}

const queueLength = (t: FileTransport): number => {
  const internals = t as unknown as { batch: unknown[]; inFlight: number };
  return internals.batch.length + internals.inFlight;
};

describe('FileTransport maxQueue', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'logixia-file-queue-'));
    appendMock.mockReset();
    appendMock.mockImplementation(realAppendFile);
    (internalWarn as jest.Mock).mockClear();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('drop-oldest keeps the queue at the cap and keeps the newest lines', async () => {
    const stall = stallAppends();
    const transport = new FileTransport({
      dirname: dir,
      filename: 'q.log',
      batchSize: 10,
      maxQueue: 1000,
      queuePolicy: 'drop-oldest',
    });

    let peak = 0;
    for (let i = 0; i < 5000; i += 1) {
      void transport.write(makeEntry(i));
      peak = Math.max(peak, queueLength(transport));
    }
    expect(peak).toBeLessThanOrEqual(1000);
    expect(queueLength(transport)).toBe(1000);
    expect(internalWarn).toHaveBeenCalled();

    appendMock.mockImplementation(realAppendFile);
    stall.releaseAll();
    await transport.close();

    const lines = fs.readFileSync(path.join(dir, 'q.log'), 'utf8').split('\n').filter(Boolean);
    expect(lines).toHaveLength(1000);
    expect(lines[0]).toContain('"q-0"');
    expect(lines[lines.length - 1]).toContain('"q-4999"');
    expect(lines.some((l) => l.includes('"q-1500"'))).toBe(false);
  });

  it('drop-newest keeps the oldest lines', async () => {
    const stall = stallAppends();
    const transport = new FileTransport({
      dirname: dir,
      filename: 'q.log',
      batchSize: 5000,
      flushInterval: 0,
      maxQueue: 1000,
      queuePolicy: 'drop-newest',
    });

    for (let i = 0; i < 3000; i += 1) void transport.write(makeEntry(i));
    expect(queueLength(transport)).toBe(1000);

    appendMock.mockImplementation(realAppendFile);
    stall.releaseAll();
    const closing = transport.close();
    await closing;

    const text = fs.readFileSync(path.join(dir, 'q.log'), 'utf8');
    expect(text.split('\n').filter(Boolean)).toHaveLength(1000);
    expect(text).toContain('"q-0"');
    expect(text).toContain('"q-999"');
    expect(text).not.toContain('"q-1000"');
  });

  it('reports drops at most once per interval and the remainder on close', async () => {
    const stall = stallAppends();
    const transport = new FileTransport({
      dirname: dir,
      filename: 'q.log',
      batchSize: 5000,
      flushInterval: 0,
      maxQueue: 10,
      queuePolicy: 'drop-newest',
    });
    for (let i = 0; i < 100; i += 1) void transport.write(makeEntry(i));
    expect(internalWarn).toHaveBeenCalledTimes(1);

    appendMock.mockImplementation(realAppendFile);
    expect(queueLength(transport)).toBe(10);
    stall.releaseAll();
    await transport.close();
    const last = (internalWarn as jest.Mock).mock.calls.at(-1)?.[0] as string;
    expect(last).toMatch(/dropped 89 log lines/);
  });

  it('block makes write() wait until the writer catches up and loses nothing', async () => {
    const stall = stallAppends();
    const transport = new FileTransport({
      dirname: dir,
      filename: 'q.log',
      batchSize: 10,
      flushInterval: 0,
      maxQueue: 20,
      queuePolicy: 'block',
    });

    const writes: Array<Promise<void>> = [];
    let settled = 0;
    for (let i = 0; i < 100; i += 1) {
      writes.push(
        transport.write(makeEntry(i)).then(() => {
          settled += 1;
        })
      );
    }
    await new Promise((r) => setImmediate(r));
    expect(queueLength(transport)).toBeLessThanOrEqual(20);
    expect(settled).toBeLessThan(100);

    appendMock.mockImplementation(realAppendFile);
    stall.releaseAll();
    await Promise.all(writes);
    await transport.close();

    const lines = fs.readFileSync(path.join(dir, 'q.log'), 'utf8').split('\n').filter(Boolean);
    expect(lines).toHaveLength(100);
    expect(internalWarn).not.toHaveBeenCalled();
  });

  it('flush() resolves once the kept entries are written', async () => {
    const stall = stallAppends();
    const transport = new FileTransport({
      dirname: dir,
      filename: 'q.log',
      batchSize: 1000,
      flushInterval: 0,
      maxQueue: 5,
      queuePolicy: 'drop-oldest',
    });
    for (let i = 0; i < 3; i += 1) void transport.write(makeEntry(i));
    let flushed = false;
    const flushing = transport.flush().then(() => {
      flushed = true;
    });
    for (let i = 3; i < 8; i += 1) void transport.write(makeEntry(i));
    await new Promise((r) => setImmediate(r));
    expect(flushed).toBe(false);

    appendMock.mockImplementation(realAppendFile);
    stall.releaseAll();
    await flushing;
    await transport.close();

    const lines = fs.readFileSync(path.join(dir, 'q.log'), 'utf8').split('\n').filter(Boolean);
    expect(lines).toHaveLength(5);
    expect(lines[0]).toContain('"q-0"');
    expect(lines[4]).toContain('"q-7"');
  });

  it('ignores an invalid maxQueue with a warning', async () => {
    const transport = new FileTransport({ dirname: dir, filename: 'q.log', maxQueue: 0 });
    expect(internalWarn).toHaveBeenCalledWith(expect.stringContaining('maxQueue'));
    for (let i = 0; i < 50; i += 1) void transport.write(makeEntry(i));
    expect(queueLength(transport)).toBe(50);
    await transport.close();
  });
});
