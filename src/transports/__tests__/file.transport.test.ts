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
import { gunzipSync } from 'node:zlib';

import type { TransportLogEntry } from '../../types/transport.types';
import { FileTransport, formatDatePattern, parseSize } from '../file.transport';

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

describe('FileTransport — sustained load', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'logixia-file-load-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('flush() returns while logging continues instead of waiting for a pause', async () => {
    const transport = new FileTransport({ dirname: dir, filename: 'app.log', batchSize: 100 });
    let running = true;
    let index = 0;
    const producer = (async () => {
      while (running) {
        for (let n = 0; n < 500; n += 1) void transport.write(makeEntry(index++));
        await new Promise(setImmediate);
      }
    })();

    await new Promise((resolve) => setTimeout(resolve, 20));
    const queuedBeforeFlush = index;
    await transport.flush();
    const stillRunning = running;
    running = false;
    await producer;
    await transport.close();

    expect(stillRunning).toBe(true);
    expect(readLines(path.join(dir, 'app.log')).length).toBeGreaterThanOrEqual(queuedBeforeFlush);
    expect(readLines(path.join(dir, 'app.log'))).toHaveLength(index);
  });

  it('does not queue a flush per log call while a drain is running', async () => {
    const transport = new FileTransport({ dirname: dir, filename: 'app.log', batchSize: 10 });
    const flush = jest.spyOn(transport, 'flush');

    for (let round = 0; round < 50; round += 1) {
      for (let n = 0; n < 200; n += 1) void transport.write(makeEntry(round * 200 + n));
      await new Promise(setImmediate);
    }
    await transport.close();

    expect(flush.mock.calls.length).toBeLessThan(5);
    expect(readLines(path.join(dir, 'app.log'))).toHaveLength(10_000);
  });

  it('rejects the flush that covers a failed write and keeps writing afterwards', async () => {
    process.env.LOGIXIA_SILENT_INTERNAL = '1';
    const live = path.join(dir, 'app.log');
    fs.mkdirSync(live); // appending to a directory fails with EISDIR
    const transport = new FileTransport({ dirname: dir, filename: 'app.log', batchSize: 1 });

    await expect(transport.write(makeEntry(0))).rejects.toThrow('File transport write failed');

    fs.rmdirSync(live);
    await transport.write(makeEntry(1));
    await transport.close();
    delete process.env.LOGIXIA_SILENT_INTERNAL;

    expect(readLines(live)).toEqual([expect.stringContaining('burst-line-1')]);
  });
});

describe('FileTransport — rotation', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'logixia-file-rotation-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('gzip-compresses the rotated file and removes the original when compress is set', async () => {
    const transport = new FileTransport({
      dirname: dir,
      filename: 'app.log',
      batchSize: 1,
      rotation: { interval: '1h', compress: true, maxFiles: 10 },
    });

    await transport.write(makeEntry(0));
    await transport.flush();
    // Force a rotation.
    await (transport as unknown as { rotate(): Promise<void> }).rotate();
    await transport.close();

    const files = fs.readdirSync(dir);
    // Exactly one compressed rotated file, and no uncompressed rotated original.
    expect(files.some((f) => /^app-.*\.log\.gz$/.test(f))).toBe(true);
    expect(files.some((f) => /^app-.*\.log$/.test(f))).toBe(false);
  });

  it('cleanup only deletes its own rotated files, not similarly-named ones', async () => {
    // An unrelated file that shares the base prefix must survive cleanup.
    const unrelated = path.join(dir, 'application.log');
    fs.writeFileSync(unrelated, 'not a logixia rotated file');

    const transport = new FileTransport({
      dirname: dir,
      filename: 'app.log',
      batchSize: 1,
      rotation: { interval: '1h', maxFiles: 1 },
    });

    // Create several rotated files so cleanup (maxFiles: 1) deletes the excess.
    for (let i = 0; i < 3; i += 1) {
      await transport.write(makeEntry(i));
      await transport.flush();
      await (transport as unknown as { rotate(): Promise<void> }).rotate();
    }
    await transport.close();

    // The unrelated file must NOT have been deleted by cleanup.
    expect(fs.existsSync(unrelated)).toBe(true);
  });
});

describe('FileTransport — size, date and custom rotation', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'logixia-file-size-'));
  });

  afterEach(() => {
    jest.useRealTimers();
    rmSync(dir, { recursive: true, force: true });
  });

  /** Every line in the directory, gzipped rotations included. */
  function allLines(): string[] {
    return fs.readdirSync(dir).flatMap((file) => {
      const raw = readFileSync(path.join(dir, file));
      const text = file.endsWith('.gz') ? gunzipSync(raw).toString('utf8') : raw.toString('utf8');
      return text.split('\n').filter(Boolean);
    });
  }

  function rotatedFiles(): string[] {
    return fs.readdirSync(dir).filter((f) => f !== 'app.log' && f.startsWith('app-'));
  }

  async function burst(transport: FileTransport, count: number, start = 0): Promise<void> {
    const writes: Array<Promise<void>> = [];
    for (let index = start; index < start + count; index += 1) {
      writes.push(transport.write(makeEntry(index)));
    }
    await Promise.all(writes);
    await transport.close();
  }

  it('rotates at maxSize and keeps the live file named app.log', async () => {
    const transport = new FileTransport({
      dirname: dir,
      filename: 'app.log',
      maxSize: '1KB',
      batchSize: 100,
    });

    await burst(transport, 200);

    expect(fs.existsSync(path.join(dir, 'app.log'))).toBe(true);
    expect(rotatedFiles().length).toBeGreaterThan(5);
    for (const file of fs.readdirSync(dir)) {
      expect(fs.statSync(path.join(dir, file)).size).toBeLessThanOrEqual(1024);
    }
    const lines = allLines();
    expect(lines).toHaveLength(200);
    expect(new Set(lines).size).toBe(200);
  });

  it('rotates unbatched writes fired without awaiting, in order', async () => {
    const transport = new FileTransport({
      dirname: dir,
      filename: 'app.log',
      maxSize: 1024,
      batchSize: 1,
    });

    await burst(transport, 150);

    for (const file of fs.readdirSync(dir)) {
      expect(fs.statSync(path.join(dir, file)).size).toBeLessThanOrEqual(1024);
    }
    const lines = allLines();
    expect(lines).toHaveLength(150);
    expect(new Set(lines).size).toBe(150);
    const live = readLines(path.join(dir, 'app.log')).map((l) => JSON.parse(l).message as string);
    const ids = live.map((m) => Number(m.replace('burst-line-', '')));
    expect(ids).toEqual([...ids].sort((a, b) => a - b));
  });

  it('prunes rotated files to the top-level maxFiles', async () => {
    const transport = new FileTransport({
      dirname: dir,
      filename: 'app.log',
      maxSize: 512,
      maxFiles: 2,
      batchSize: 10,
    });

    await burst(transport, 200);

    expect(rotatedFiles()).toHaveLength(2);
    expect(fs.existsSync(path.join(dir, 'app.log'))).toBe(true);
  });

  it('gzips rotated files when zippedArchive is set, losing no lines', async () => {
    const transport = new FileTransport({
      dirname: dir,
      filename: 'app.log',
      maxSize: '2kb',
      zippedArchive: true,
      batchSize: 25,
    });

    await burst(transport, 300);

    const rotated = rotatedFiles();
    expect(rotated.length).toBeGreaterThan(3);
    expect(rotated.every((f) => f.endsWith('.log.gz'))).toBe(true);
    const lines = allLines();
    expect(lines).toHaveLength(300);
    expect(new Set(lines).size).toBe(300);
  });

  it('never reuses a file name when it rotates many times in the same millisecond', async () => {
    const transport = new FileTransport({
      dirname: dir,
      filename: 'app.log',
      maxSize: 1, // every line gets its own file
      batchSize: 500,
    });

    await burst(transport, 300);

    expect(fs.readdirSync(dir)).toHaveLength(300);
    expect(new Set(allLines()).size).toBe(300);
  });

  it('counts the size of an existing file after a restart', async () => {
    const live = path.join(dir, 'app.log');
    fs.writeFileSync(live, 'x'.repeat(1000) + '\n');

    const transport = new FileTransport({
      dirname: dir,
      filename: 'app.log',
      maxSize: 1024,
      batchSize: 1,
    });
    await burst(transport, 1);

    const rotated = rotatedFiles();
    expect(rotated).toHaveLength(1);
    expect(readFileSync(path.join(dir, rotated[0]!), 'utf8')).toBe('x'.repeat(1000) + '\n');
    expect(readLines(live)).toHaveLength(1);
  });

  it('rotates when the datePattern period changes and names the file after the old period', async () => {
    jest.useFakeTimers({
      now: new Date(2026, 9, 21, 23, 59, 0),
      doNotFake: [
        'nextTick',
        'setImmediate',
        'clearImmediate',
        'setTimeout',
        'clearTimeout',
        'setInterval',
        'clearInterval',
        'queueMicrotask',
      ],
    });
    const transport = new FileTransport({
      dirname: dir,
      filename: 'app.log',
      datePattern: 'YYYY-MM-DD',
      batchSize: 1,
    });

    await transport.write(makeEntry(0));
    jest.setSystemTime(new Date(2026, 9, 22, 0, 0, 5));
    await transport.write(makeEntry(1));
    await transport.close();

    expect(readLines(path.join(dir, 'app-2026-10-21.log'))).toHaveLength(1);
    expect(readLines(path.join(dir, 'app.log'))).toHaveLength(1);
  });

  it('rotates when rotation.shouldRotate returns true', async () => {
    const transport = new FileTransport({
      dirname: dir,
      filename: 'app.log',
      batchSize: 1,
      rotation: { shouldRotate: (_file, stats) => stats.size > 0 },
    });

    for (let index = 0; index < 5; index += 1) {
      await transport.write(makeEntry(index));
    }
    await transport.close();

    expect(fs.readdirSync(dir).filter((f) => f.endsWith('.log'))).toHaveLength(5);
    expect(allLines()).toHaveLength(5);
  });

  it("does not prune another transport's files that share the prefix", async () => {
    const errors = new FileTransport({ dirname: dir, filename: 'app-error.log', batchSize: 1 });
    await errors.write(makeEntry(0));
    await errors.close();

    const transport = new FileTransport({
      dirname: dir,
      filename: 'app.log',
      maxSize: 200,
      maxFiles: 1,
      batchSize: 1,
    });
    await burst(transport, 20);

    expect(readLines(path.join(dir, 'app-error.log'))).toHaveLength(1);
  });

  it('ignores an unreadable maxSize instead of rotating on every line', async () => {
    process.env.LOGIXIA_SILENT_INTERNAL = '1';
    const transport = new FileTransport({
      dirname: dir,
      filename: 'app.log',
      maxSize: 'fifty megs',
      batchSize: 1,
    });
    await burst(transport, 10);
    delete process.env.LOGIXIA_SILENT_INTERNAL;

    expect(fs.readdirSync(dir)).toEqual(['app.log']);
  });
});

describe('parseSize', () => {
  it.each([
    [1024, 1024],
    ['100', 100],
    ['1KB', 1024],
    ['1.5k', 1536],
    ['50MB', 50 * 1024 ** 2],
    ['50 mb', 50 * 1024 ** 2],
    ['2GiB', 2 * 1024 ** 3],
    ['1g', 1024 ** 3],
  ])('parses %p', (input, expected) => {
    expect(parseSize(input)).toBe(expected);
  });

  it.each([['abc'], ['-5MB'], ['0'], [0], [-1], [Number.NaN], ['5XB']])('rejects %p', (input) => {
    expect(parseSize(input)).toBeUndefined();
  });
});

describe('formatDatePattern', () => {
  it('fills the date tokens in local time', () => {
    const date = new Date(2026, 0, 5, 7, 8, 9);
    expect(formatDatePattern(date, 'YYYY-MM-DD')).toBe('2026-01-05');
    expect(formatDatePattern(date, 'YYYY-MM-DD-HH')).toBe('2026-01-05-07');
    expect(formatDatePattern(date, 'YYYYMMDD_HHmmss')).toBe('20260105_070809');
  });
});
