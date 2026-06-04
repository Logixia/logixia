/**
 * Tests for FileTransport batching + flush correctness.
 *
 * Regression coverage for the batch-flush race: addToBatch() fires flush()
 * un-awaited on every Nth entry, so a synchronous burst of writes triggers
 * many overlapping flushes. Before the fix each overlapping flush snapshotted
 * the not-yet-cleared batch and wrote it again, turning N log calls into N²
 * file lines. The fix detaches the batch synchronously before awaiting and
 * serializes concurrent flushes.
 */

import * as fs from 'node:fs';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';

import type { TransportLogEntry } from '../../types/transport.types';
import { FileTransport } from '../file.transport';

function makeEntry(index: number): TransportLogEntry {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    level: 'info',
    message: `burst-line-${index}`,
  };
}

function readLines(filePath: string): string[] {
  if (!fs.existsSync(filePath)) return [];
  return readFileSync(filePath, 'utf8').split('\n').filter(Boolean);
}

describe('FileTransport — batch flush', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'logixia-file-transport-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('writes each entry exactly once on a synchronous un-awaited burst far larger than batchSize', async () => {
    const filename = 'burst.log';
    const transport = new FileTransport({ dirname: dir, filename, batchSize: 100 });

    const total = 500;
    // Fire the whole burst synchronously without awaiting each write — exactly like
    // a buffered-log flush replaying many entries. write() returns immediately while
    // addToBatch fires its threshold flushes in the background.
    const writes: Array<Promise<void>> = [];
    for (let index = 0; index < total; index += 1) {
      writes.push(transport.write(makeEntry(index)));
    }
    await Promise.allSettled(writes);
    await transport.flush();

    const lines = readLines(path.join(dir, filename));
    expect(lines).toHaveLength(total);
    expect(new Set(lines).size).toBe(total);
  });

  it('flushes any partial batch left below the threshold', async () => {
    const filename = 'partial.log';
    const transport = new FileTransport({ dirname: dir, filename, batchSize: 100 });

    for (let index = 0; index < 7; index += 1) {
      await transport.write(makeEntry(index));
    }

    await transport.flush();

    expect(readLines(path.join(dir, filename))).toHaveLength(7);
  });

  it('is a no-op when flushed with an empty batch', async () => {
    const filename = 'empty.log';
    const transport = new FileTransport({ dirname: dir, filename, batchSize: 100 });

    await transport.flush();
    await transport.flush();

    expect(readLines(path.join(dir, filename))).toHaveLength(0);
  });

  it('does not re-write entries when flush() is called concurrently', async () => {
    const filename = 'concurrent.log';
    const transport = new FileTransport({ dirname: dir, filename, batchSize: 1000 });

    const writes: Array<Promise<void>> = [];
    for (let index = 0; index < 50; index += 1) {
      writes.push(transport.write(makeEntry(index)));
    }
    await Promise.allSettled(writes);

    // Several overlapping flushes must collapse to one logical drain.
    await Promise.all([transport.flush(), transport.flush(), transport.flush()]);
    await transport.flush();

    const lines = readLines(path.join(dir, filename));
    expect(lines).toHaveLength(50);
    expect(new Set(lines).size).toBe(50);
  });
});
