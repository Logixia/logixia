import * as fs from 'node:fs';
import * as path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { promisify } from 'node:util';
import { createGzip } from 'node:zlib';

import type {
  FileStats,
  FileTransportConfig,
  IBatchTransport,
  ITransport,
  TransportLogEntry,
} from '../types/transport.types';
import { safeToString } from '../utils/coerce.utils';
import { internalError, internalWarn } from '../utils/internal-log';

const appendFile = promisify(fs.appendFile);
const rename = promisify(fs.rename);
const unlink = promisify(fs.unlink);
const readdir = promisify(fs.readdir);
const stat = promisify(fs.stat);

interface FlushWaiter {
  upTo: number;
  resolve: () => void;
  reject: (error: unknown) => void;
  error?: unknown;
}

const SIZE_UNITS: Record<string, number> = {
  '': 1,
  k: 1024,
  m: 1024 ** 2,
  g: 1024 ** 3,
  t: 1024 ** 4,
};

/**
 * Parses a size like `50MB`, `1.5g`, `512 KiB` or a plain byte count.
 * Units are binary (1KB = 1024 bytes). Returns undefined for anything else.
 */
export function parseSize(value: string | number | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value === 'number') {
    return Number.isFinite(value) && value > 0 ? Math.floor(value) : undefined;
  }
  // eslint-disable-next-line sonarjs/super-linear-regex -- anchored, bounded input from config
  const match = /^\s*(\d+(?:\.\d+)?)\s*([kmgt]?)(?:i?b)?\s*$/i.exec(value);
  if (!match) return undefined;
  const bytes = Math.floor(Number(match[1]) * (SIZE_UNITS[(match[2] ?? '').toLowerCase()] ?? 1));
  return bytes > 0 ? bytes : undefined;
}

/** Formats a date with the YYYY, MM, DD, HH, mm and ss tokens, in local time. */
export function formatDatePattern(date: Date, pattern: string): string {
  const pad = (n: number): string => String(n).padStart(2, '0');
  return pattern
    .replace(/YYYY/g, String(date.getFullYear()))
    .replace(/MM/g, pad(date.getMonth() + 1))
    .replace(/DD/g, pad(date.getDate()))
    .replace(/HH/g, pad(date.getHours()))
    .replace(/mm/g, pad(date.getMinutes()))
    .replace(/ss/g, pad(date.getSeconds()));
}

/**
 * Appends log entries to a local file with automatic rotation.
 *
 * Rotates by size (`maxSize`), by date (`datePattern`), by interval
 * (`rotation.interval`) or by a custom `rotation.shouldRotate` check. Rotated
 * files can be gzipped (`zippedArchive`) and pruned to the newest `maxFiles`.
 *
 * Without a `rotation` block the live file keeps its name (`app.log`) and
 * rotated files are renamed beside it (`app-2026-10-22T09-30-00-000.log`).
 * With a `rotation` block every file, the live one included, is timestamped.
 *
 * @example
 * transports: { file: { filename: 'app.log', dirname: './logs', maxSize: '50MB' } }
 */
export class FileTransport implements ITransport, IBatchTransport {
  public readonly name = 'file';
  public readonly level?: string | undefined;
  public readonly batchSize?: number;
  public readonly flushInterval?: number;
  public readonly filter?: (entry: TransportLogEntry) => boolean;

  private readonly config: FileTransportConfig;
  private readonly maxBytes: number | undefined;
  private readonly maxFiles: number | undefined;
  private readonly compress: boolean;
  private readonly intervalMs: number | undefined;
  private readonly timestampedActive: boolean;
  private readonly dir: string;
  private readonly base: string;
  private readonly ext: string;

  private batch: TransportLogEntry[] = [];
  private batchTimer?: NodeJS.Timeout | undefined;
  private lastRotation: Date = new Date();
  private currentFilePath: string;
  private bytesWritten = 0;
  private period: string | undefined;
  private rotateRequested = false;
  private rotationWaiters: Array<() => void> = [];
  /**
   * The one drain loop, or undefined when idle. Only one ever runs, so the batch
   * is never snapshotted and written twice, and rotation (which runs inside it)
   * never races a write.
   */
  private draining: Promise<void> | undefined;
  /** Entries queued and entries written (or failed) so far; flush() waits on these. */
  private enqueued = 0;
  private settled = 0;
  private flushWaiters: FlushWaiter[] = [];
  /** Gzip and pruning of rotated files run off the write path, one at a time. */
  private housekeeping: Promise<void> = Promise.resolve();

  constructor(config: FileTransportConfig) {
    this.config = {
      format: 'json',
      batchSize: 100,
      flushInterval: 5000,
      ...config,
    };
    this.level = config.level;
    this.batchSize = this.config.batchSize || 100;
    this.flushInterval = this.config.flushInterval || 5000;
    if (config.filter) this.filter = config.filter;

    const rotation = config.rotation;
    const rawMaxSize = rotation?.maxSize ?? config.maxSize;
    this.maxBytes = parseSize(rawMaxSize);
    if (rawMaxSize !== undefined && this.maxBytes === undefined) {
      internalWarn(
        `FileTransport: maxSize ${JSON.stringify(rawMaxSize)} is not a valid size (try '50MB'); size rotation is off`
      );
    }
    this.maxFiles = rotation?.maxFiles ?? config.maxFiles;
    this.compress = rotation?.compress ?? config.zippedArchive ?? false;
    this.intervalMs = rotation?.interval ? this.parseInterval(rotation.interval) : undefined;
    this.timestampedActive = rotation !== undefined;

    this.dir = this.resolveDir();
    this.ext = path.extname(config.filename);
    this.base = path.basename(config.filename, this.ext);
    try {
      fs.mkdirSync(this.dir, { recursive: true });
    } catch (error) {
      internalError(`FileTransport could not create ${this.dir}`, error);
    }

    this.currentFilePath = this.timestampedActive
      ? this.uniquePath(this.timestamp(new Date()))
      : path.join(this.dir, `${this.base}${this.ext}`);

    // Pick up where a previous process left off, so a restart next to a 49MB
    // app.log still rotates at 50MB and yesterday's file still rolls over today.
    let existing: fs.Stats | undefined;
    try {
      existing = fs.statSync(this.currentFilePath);
    } catch {
      existing = undefined;
    }
    this.bytesWritten = existing?.size ?? 0;
    if (config.datePattern) {
      this.period = formatDatePattern(existing?.mtime ?? new Date(), config.datePattern);
    }
  }

  async write(entry: TransportLogEntry): Promise<void> {
    try {
      if (this.config.batchSize && this.config.batchSize > 1) {
        this.addToBatch(entry);
      } else {
        // Unbatched writes still go through the drain so they stay in order and
        // share the rotation checks with batched ones.
        this.enqueue(entry);
        await this.flush();
      }
    } catch (error) {
      throw new Error(`File transport write failed: ${(error as Error).message}`, { cause: error });
    }
  }

  /**
   * Resolves once every entry queued before the call is on disk. It does not
   * wait for entries queued afterwards, so under steady traffic it still returns
   * instead of waiting for a quiet moment that never comes.
   */
  async flush(): Promise<void> {
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = undefined;
    }
    if (this.settled >= this.enqueued) return;

    const done = new Promise<void>((resolve, reject) => {
      this.flushWaiters.push({ upTo: this.enqueued, resolve, reject });
    });
    this.startDrain();
    await done;
  }

  /** Writes out anything pending, then starts a new file. */
  async rotate(): Promise<void> {
    await this.flush();
    const done = new Promise<void>((resolve) => this.rotationWaiters.push(resolve));
    this.rotateRequested = true;
    this.startDrain();
    await done;
  }

  private enqueue(entry: TransportLogEntry): void {
    this.batch.push(entry);
    this.enqueued += 1;
  }

  private startDrain(): void {
    if (this.draining) return;
    this.draining = this.drain().finally(() => {
      this.draining = undefined;
    });
  }

  /**
   * Writes the batch one snapshot at a time. Entries queued while a write is in
   * flight are picked up by the next iteration, so one drain empties the batch
   * however much is logged meanwhile.
   */
  private async drain(): Promise<void> {
    while (this.batch.length > 0 || this.rotateRequested) {
      if (this.rotateRequested) {
        this.rotateRequested = false;
        const waiting = this.rotationWaiters;
        this.rotationWaiters = [];
        try {
          await this.rotateFile();
        } catch (error) {
          internalError('FileTransport rotation failed', error);
        }
        for (const resolve of waiting) resolve();
        continue;
      }
      // Detach the current batch SYNCHRONOUSLY before awaiting, so entries pushed
      // during the write land in a fresh array and are never re-written.
      const pending = this.batch;
      this.batch = [];
      let failure: unknown;
      try {
        await this.writeBatch(pending);
      } catch (error) {
        failure = error;
      }
      this.settled += pending.length;
      this.settle(failure);
    }
  }

  /**
   * Resolves the flush() calls whose entries are now written. A failed batch
   * fails every flush still waiting, since each one covers that batch.
   */
  private settle(failure: unknown): void {
    if (failure !== undefined) {
      if (this.flushWaiters.length === 0) internalError('FileTransport write failed', failure);
      for (const waiter of this.flushWaiters) waiter.error ??= failure;
    }
    const waiting: FlushWaiter[] = [];
    for (const waiter of this.flushWaiters) {
      if (waiter.upTo > this.settled) waiting.push(waiter);
      else if (waiter.error === undefined) waiter.resolve();
      else waiter.reject(waiter.error);
    }
    this.flushWaiters = waiting;
  }

  private formatEntry(entry: TransportLogEntry): string {
    switch (this.config.format) {
      case 'json':
        return JSON.stringify({
          timestamp: entry.timestamp.toISOString(),
          level: entry.level,
          message: entry.message,
          ...(entry.data || {}),
        });

      case 'csv': {
        const safeMessage = safeToString(entry.message);
        const fields = [
          entry.timestamp.toISOString(),
          entry.level,
          `"${safeMessage.replace(/"/g, '""')}"`,
          safeToString(entry.context),
          safeToString(entry.traceId),
          JSON.stringify(entry.data || {}),
        ];
        return fields.join(',');
      }

      case 'text':
      default:
        return `${entry.timestamp.toISOString()} [${entry.level.toUpperCase()}] ${safeToString(entry.message)}${entry.data ? ' ' + JSON.stringify(entry.data) : ''}`;
    }
  }

  addToBatch(entry: TransportLogEntry): void {
    this.enqueue(entry);

    // While a drain is running it picks this entry up by itself. Starting a flush
    // per entry here used to park one pending promise per log call until traffic
    // paused, which under steady load grew the heap by ~600 bytes a line.
    if (this.batch.length >= (this.config.batchSize || 100) && !this.draining) {
      // Cancel any pending interval flush — the threshold flush supersedes it, and
      // a leftover timer would fire a redundant flush after the batch is already gone.
      if (this.batchTimer) {
        clearTimeout(this.batchTimer);
        this.batchTimer = undefined;
      }
      this.startDrain();
    } else if (!this.batchTimer && this.config.flushInterval) {
      this.batchTimer = setTimeout(() => {
        this.flush().catch((err: unknown) =>
          internalError('FileTransport interval flush failed', err)
        );
      }, this.config.flushInterval);
    }
  }

  /** Only ever called from drain(), so writes and rotations never overlap. */
  private async writeBatch(entries: TransportLogEntry[]): Promise<void> {
    if (entries.length === 0) return;

    if (this.timeToRotate()) await this.rotateFile();

    if (this.maxBytes === undefined) {
      const content = entries.map((entry) => this.formatEntry(entry)).join('\n') + '\n';
      await this.append(content);
      return;
    }

    // Split on line boundaries so no file grows past maxSize, except when a
    // single line is bigger than maxSize on its own.
    let chunk = '';
    let chunkBytes = 0;
    for (const entry of entries) {
      const line = this.formatEntry(entry) + '\n';
      const lineBytes = Buffer.byteLength(line);
      const used = this.bytesWritten + chunkBytes;
      if (used > 0 && used + lineBytes > this.maxBytes) {
        if (chunk) await this.append(chunk, chunkBytes);
        chunk = '';
        chunkBytes = 0;
        await this.rotateFile();
      }
      chunk += line;
      chunkBytes += lineBytes;
    }
    if (chunk) await this.append(chunk, chunkBytes);
  }

  private async append(content: string, bytes = Buffer.byteLength(content)): Promise<void> {
    await appendFile(this.currentFilePath, content);
    this.bytesWritten += bytes;
  }

  private timeToRotate(): boolean {
    if (
      this.intervalMs !== undefined &&
      Date.now() - this.lastRotation.getTime() >= this.intervalMs
    ) {
      return true;
    }
    if (this.config.datePattern && this.period !== undefined) {
      if (formatDatePattern(new Date(), this.config.datePattern) !== this.period) return true;
    }
    const shouldRotate = this.config.rotation?.shouldRotate;
    if (shouldRotate) {
      const stats: FileStats = {
        size: this.bytesWritten,
        created: this.lastRotation,
        modified: new Date(),
      };
      try {
        return shouldRotate(this.currentFilePath, stats);
      } catch (error) {
        internalError('FileTransport rotation.shouldRotate threw', error);
      }
    }
    return false;
  }

  private parseInterval(interval: string): number {
    // eslint-disable-next-line sonarjs/super-linear-regex -- simple bounded pattern for interval parsing
    const match = new RegExp(/(\d+)([hdwmy])/i).exec(interval);
    if (!match) return 24 * 60 * 60 * 1000; // Default 1 day

    const value = Number.parseInt(match[1] || '1', 10);
    const unit = (match[2] || 'h').toLowerCase();

    switch (unit) {
      case 'h':
        return value * 60 * 60 * 1000;
      case 'd':
        return value * 24 * 60 * 60 * 1000;
      case 'w':
        return value * 7 * 24 * 60 * 60 * 1000;
      case 'm':
        return value * 30 * 24 * 60 * 60 * 1000;
      case 'y':
        return value * 365 * 24 * 60 * 60 * 1000;
      default:
        return value * 60 * 60 * 1000;
    }
  }

  private async rotateFile(): Promise<void> {
    const now = new Date();
    let archived: string | undefined;

    if (this.timestampedActive) {
      archived = this.currentFilePath;
      this.currentFilePath = this.uniquePath(this.timestamp(now));
    } else {
      archived = this.uniquePath(this.period ?? this.timestamp(now));
      try {
        await rename(this.currentFilePath, archived);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
          internalError(`FileTransport could not rotate ${this.currentFilePath}`, error);
          // Keep writing to the same file and try again after another maxSize,
          // rather than retrying (and failing) on every line.
          this.bytesWritten = 0;
          return;
        }
        archived = undefined;
      }
    }

    this.bytesWritten = 0;
    this.lastRotation = now;
    if (this.config.datePattern) this.period = formatDatePattern(now, this.config.datePattern);

    if (archived === undefined || !fs.existsSync(archived)) return;
    const file = archived;
    this.housekeeping = this.housekeeping.then(async () => {
      if (this.compress) await this.compressFile(file);
      if (this.maxFiles) await this.cleanupOldFiles();
    });
  }

  private timestamp(date: Date): string {
    return date.toISOString().replace(/[:.]/g, '-').slice(0, 23);
  }

  /** `<base>-<stamp><ext>`, with `.1`, `.2`… added if that name (or its .gz) is taken. */
  private uniquePath(stamp: string): string {
    const taken = (p: string): boolean => fs.existsSync(p) || fs.existsSync(`${p}.gz`);
    let candidate = path.join(this.dir, `${this.base}-${stamp}${this.ext}`);
    let n = 0;
    while (taken(candidate) || candidate === this.currentFilePath) {
      n += 1;
      candidate = path.join(this.dir, `${this.base}-${stamp}.${n}${this.ext}`);
    }
    return candidate;
  }

  private resolveDir(): string {
    // If dirname is provided, use it; otherwise fall back to the directory part of filename
    if (this.config.dirname) {
      return this.config.dirname;
    }
    const fromFilename = path.dirname(this.config.filename);
    // path.dirname returns '.' for bare filenames like 'app.log' — use CWD in that case
    return fromFilename === '.' ? process.cwd() : fromFilename;
  }

  /**
   * Gzip the rotated file to `<file>.gz` and remove the original. Streams the
   * data so large log files don't have to be buffered in memory. Best-effort:
   * any failure is logged and leaves the original file intact rather than
   * throwing out of the rotation path.
   */
  private async compressFile(filePath: string): Promise<void> {
    const gzPath = `${filePath}.gz`;
    try {
      await pipeline(fs.createReadStream(filePath), createGzip(), fs.createWriteStream(gzPath));
      // Only delete the source once the compressed copy is fully written.
      await unlink(filePath);
    } catch (error) {
      internalError('Failed to compress rotated log file', error);
      // Clean up a partial .gz so a later cleanup pass doesn't keep a corrupt file.
      try {
        await unlink(gzPath);
      } catch {
        /* nothing to clean up */
      }
    }
  }

  /**
   * True for this transport's rotated files only: `<base>-<stamp><ext>` where the
   * stamp is digits and separators, optionally `.gz`. Another transport's
   * `app-error.log` must not count as one of `app.log`'s rotations.
   */
  private isOwnRotatedFile(file: string): boolean {
    const name = file.endsWith('.gz') ? file.slice(0, -3) : file;
    if (!name.startsWith(`${this.base}-`) || !name.endsWith(this.ext)) return false;
    const stamp = name.slice(this.base.length + 1, name.length - this.ext.length);
    return /^\d[\d\-_.T]*$/.test(stamp);
  }

  private async cleanupOldFiles(): Promise<void> {
    if (!this.maxFiles) return;

    try {
      const files = await readdir(this.dir);
      const active = path.basename(this.currentFilePath);

      const fileStats = await Promise.all(
        files
          .filter((file) => file !== active && this.isOwnRotatedFile(file))
          .map(async (file) => {
            const filePath = path.join(this.dir, file);
            const stats = await stat(filePath);
            return { path: filePath, mtime: stats.mtimeMs };
          })
      );
      const newestFirst = fileStats.sort(
        (a, b) => b.mtime - a.mtime || b.path.localeCompare(a.path)
      );

      for (const file of newestFirst.slice(this.maxFiles)) {
        await unlink(file.path);
      }
    } catch (error) {
      internalError('Failed to cleanup old log files', error);
    }
  }

  async close(): Promise<void> {
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = undefined;
    }
    await this.flush();
    await this.housekeeping;
  }
}
