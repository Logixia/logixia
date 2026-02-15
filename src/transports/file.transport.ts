import * as fs from "fs";
import * as path from "path";
import { promisify } from "util";
import { createWriteStream, WriteStream } from "fs";
import {
  ITransport,
  IBatchTransport,
  TransportLogEntry,
  FileTransportConfig,
  RotationConfig,
} from "../types/transport.types";

const writeFile = promisify(fs.writeFile);
const mkdir = promisify(fs.mkdir);
const unlink = promisify(fs.unlink);
const readdir = promisify(fs.readdir);
const stat = promisify(fs.stat);

export class FileTransport implements ITransport, IBatchTransport {
  public readonly name = "file";
  public readonly level?: string | undefined;
  public readonly batchSize?: number;
  public readonly flushInterval?: number;

  private config: FileTransportConfig;
  private writeStream?: WriteStream;
  private batch: TransportLogEntry[] = [];
  private batchTimer?: NodeJS.Timeout | undefined;
  private lastRotation: Date = new Date();
  private currentFilePath: string;

  constructor(config: FileTransportConfig) {
    this.config = {
      format: "json",
      batchSize: 100,
      flushInterval: 5000,
      ...config,
    };
    this.level = config.level;
    this.batchSize = this.config.batchSize || 100;
    this.flushInterval = this.config.flushInterval || 5000;
    this.currentFilePath = this.generateFilePath();
    this.ensureDirectoryExists();
  }

  async write(entry: TransportLogEntry): Promise<void> {
    try {
      if (this.shouldRotateNow()) {
        await this.rotate();
      }

      if (this.config.batchSize && this.config.batchSize > 1) {
        this.addToBatch(entry);
      } else {
        await this.writeBatch([entry]);
      }
    } catch (error) {
      throw new Error(
        `File transport write failed: ${(error as Error).message}`,
      );
    }
  }

  async flush(): Promise<void> {
    if (this.batch.length > 0) {
      await this.writeBatch([...this.batch]);
      this.batch = [];
    }

    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = undefined;
    }
  }

  private formatEntry(entry: TransportLogEntry): string {
    switch (this.config.format) {
      case "json":
        return JSON.stringify({
          timestamp: entry.timestamp.toISOString(),
          level: entry.level,
          message: entry.message,
          ...(entry.data || {}),
        });

      case "csv":
        const fields = [
          entry.timestamp.toISOString(),
          entry.level,
          `"${entry.message.replace(/"/g, '""')}"`,
          entry.context || "",
          entry.traceId || "",
          JSON.stringify(entry.data || {}),
        ];
        return fields.join(",");

      case "text":
      default:
        return `${entry.timestamp.toISOString()} [${entry.level.toUpperCase()}] ${entry.message}${entry.data ? " " + JSON.stringify(entry.data) : ""}`;
    }
  }

  addToBatch(entry: TransportLogEntry): void {
    this.batch.push(entry);

    if (this.batch.length >= (this.config.batchSize || 100)) {
      this.flush().catch(console.error);
    } else if (!this.batchTimer && this.config.flushInterval) {
      this.batchTimer = setTimeout(() => {
        this.flush().catch(console.error);
      }, this.config.flushInterval);
    }
  }

  private async writeBatch(entries: TransportLogEntry[]): Promise<void> {
    if (entries.length === 0) return;

    const content =
      entries.map((entry) => this.formatEntry(entry)).join("\n") + "\n";

    if (this.writeStream) {
      return new Promise((resolve, reject) => {
        this.writeStream!.write(content, (error) => {
          if (error) reject(error);
          else resolve();
        });
      });
    } else {
      await writeFile(this.currentFilePath, content, { flag: "a" });
    }
  }

  private shouldRotateNow(): boolean {
    if (!this.config.rotation) return false;

    const now = new Date();
    const timeDiff = now.getTime() - this.lastRotation.getTime();
    const rotationInterval = this.parseInterval(this.config.rotation.interval!);

    return timeDiff >= rotationInterval;
  }

  private parseInterval(interval: string): number {
    const match = interval.match(/(\d+)([hdwmy])/i);
    if (!match) return 24 * 60 * 60 * 1000; // Default 1 day

    const value = parseInt(match[1] || "1", 10);
    const unit = (match[2] || "h").toLowerCase();

    switch (unit) {
      case "h":
        return value * 60 * 60 * 1000;
      case "d":
        return value * 24 * 60 * 60 * 1000;
      case "w":
        return value * 7 * 24 * 60 * 60 * 1000;
      case "m":
        return value * 30 * 24 * 60 * 60 * 1000;
      case "y":
        return value * 365 * 24 * 60 * 60 * 1000;
      default:
        return value * 60 * 60 * 1000;
    }
  }

  private async rotate(): Promise<void> {
    await this.flush();

    if (this.writeStream) {
      this.writeStream.end();
      this.writeStream = undefined as any;
    }

    const oldPath = this.currentFilePath;
    this.currentFilePath = this.generateFilePath();
    this.lastRotation = new Date();

    // Compress old file if configured
    if (this.config.rotation?.compress) {
      await this.compressFile(oldPath);
    }

    // Clean up old files
    if (this.config.rotation?.maxFiles) {
      await this.cleanupOldFiles();
    }
  }

  private generateFilePath(): string {
    const now = new Date();
    const timestamp = now.toISOString().replace(/[:.]/g, "-").slice(0, 19);
    const dir = path.dirname(this.config.filename);
    const ext = path.extname(this.config.filename);
    const base = path.basename(this.config.filename, ext);

    if (this.config.rotation) {
      return path.join(dir, `${base}-${timestamp}${ext}`);
    }

    return this.config.filename;
  }

  private async ensureDirectoryExists(): Promise<void> {
    const dir = path.dirname(this.currentFilePath);
    try {
      await mkdir(dir, { recursive: true });
    } catch (error) {
      // Directory might already exist
    }
  }

  private async compressFile(filePath: string): Promise<void> {
    // Simple gzip compression implementation would go here
    // For now, just rename with .gz extension
    // In a real implementation, you'd use zlib
  }

  private async cleanupOldFiles(): Promise<void> {
    if (!this.config.rotation?.maxFiles) return;

    try {
      const dir = path.dirname(this.config.filename);
      const files = await readdir(dir);
      const base = path.basename(
        this.config.filename,
        path.extname(this.config.filename),
      );

      const logFiles = files
        .filter((file) => file.startsWith(base))
        .map(async (file) => {
          const filePath = path.join(dir, file);
          const stats = await stat(filePath);
          return { path: filePath, mtime: stats.mtime };
        });

      const fileStats = await Promise.all(logFiles);
      const sortedFiles = fileStats.sort(
        (a, b) => b.mtime.getTime() - a.mtime.getTime(),
      );

      const filesToDelete = sortedFiles.slice(this.config.rotation!.maxFiles!);

      for (const file of filesToDelete) {
        await unlink(file.path);
      }
    } catch (error) {
      console.error("Failed to cleanup old log files:", error);
    }
  }

  async close(): Promise<void> {
    await this.flush();

    if (this.writeStream) {
      return new Promise((resolve) => {
        this.writeStream!.end(() => resolve());
      });
    }
  }
}
