import type {
  AnalyticsTransportConfig,
  IBatchTransport,
  ITransport,
  TransportLogEntry,
} from '../types/transport.types';
import { internalError } from '../utils/internal-log';

export abstract class AnalyticsTransport implements ITransport, IBatchTransport {
  public readonly name: string;
  public readonly level?: string | undefined;
  public readonly batchSize?: number;
  public readonly flushInterval?: number;

  protected config: AnalyticsTransportConfig;
  protected batch: TransportLogEntry[] = [];
  protected batchTimer?: NodeJS.Timeout | undefined;
  protected isReady: boolean = false;
  /**
   * The in-flight drain promise, or undefined when idle. addToBatch() fires
   * flush() un-awaited on every Nth entry, so a synchronous burst can trigger
   * many overlapping flushes. Every caller joins this single promise instead of
   * starting its own drain, so a batch is never snapshotted and sent twice —
   * the overlapping-flush duplication that turns N logs into N² delivered events
   * (same class of bug fixed earlier in FileTransport / DatabaseTransport).
   */
  private flushPromise?: Promise<void> | undefined;

  constructor(name: string, config: AnalyticsTransportConfig) {
    this.name = name;
    this.config = {
      batchSize: 50,
      flushInterval: 10000, // 10 seconds
      enableUserTracking: true,
      enableEventTracking: true,
      ...config,
    };
    this.level = config.level;
    this.batchSize = this.config.batchSize || 50;
    this.flushInterval = this.config.flushInterval || 10000;

    this.initialize();
  }

  async write(entry: TransportLogEntry): Promise<void> {
    if (!this.isReady) {
      await this.waitForReady();
    }

    if (this.shouldSkipEntry(entry)) {
      return;
    }

    if (this.config.batchSize && this.config.batchSize > 1) {
      this.addToBatch(entry);
    } else {
      await this.sendEntry(entry);
    }
  }

  addToBatch(entry: TransportLogEntry): void {
    this.batch.push(entry);

    if (this.batch.length >= (this.config.batchSize || 50)) {
      this.flush().catch((err: unknown) => internalError(`${this.name} batch flush failed`, err));
    } else if (!this.batchTimer && this.config.flushInterval) {
      this.batchTimer = setTimeout(() => {
        this.flush().catch((err: unknown) =>
          internalError(`${this.name} interval flush failed`, err)
        );
      }, this.config.flushInterval);
    }
  }

  async flush(): Promise<void> {
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = undefined;
    }

    // Serialize concurrent flushes so overlapping un-awaited flushes (fired by
    // addToBatch on every Nth entry) all join the SAME drain instead of each
    // snapshotting the not-yet-cleared batch and sending it again.
    if (!this.flushPromise) {
      this.flushPromise = this.drain().finally(() => {
        this.flushPromise = undefined;
      });
    }

    await this.flushPromise;
  }

  /**
   * Drains the batch to the provider one snapshot at a time. The batch is
   * detached SYNCHRONOUSLY before awaiting sendBatch(), so entries appended by
   * concurrent writes land in a fresh array and are never sent twice. On failure
   * the snapshot is restored to the front of the batch for the next flush and
   * the loop stops, so a failing provider does not hot-spin.
   */
  private async drain(): Promise<void> {
    while (this.batch.length > 0) {
      const entriesToSend = this.batch;
      this.batch = [];

      try {
        await this.sendBatch(entriesToSend);
      } catch (error) {
        internalError(`Analytics transport ${this.name} flush failed`, error);
        // Re-add failed entries to the front of the batch for retry, then stop.
        this.batch.unshift(...entriesToSend);
        return;
      }
    }
  }

  async close(): Promise<void> {
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = undefined;
    }

    // Drain remaining entries on shutdown. A failed flush re-buffers its entries
    // (see drain()), so retry a bounded number of times before giving up — this
    // prevents the "last N seconds of logs lost on deploy" problem without
    // hanging shutdown on a permanently-failing provider.
    const MAX_CLOSE_FLUSH_ATTEMPTS = 3;
    for (
      let attempt = 0;
      attempt < MAX_CLOSE_FLUSH_ATTEMPTS && this.batch.length > 0;
      attempt += 1
    ) {
      await this.flush();
    }
    if (this.batch.length > 0) {
      internalError(
        `Analytics transport ${this.name} closing with ${this.batch.length} unflushed entr${this.batch.length === 1 ? 'y' : 'ies'} after ${MAX_CLOSE_FLUSH_ATTEMPTS} attempts`
      );
    }

    await this.cleanup();
  }

  protected shouldSkipEntry(entry: TransportLogEntry): boolean {
    // Skip debug/trace logs for analytics by default
    const skipLevels = ['debug', 'trace'];
    return skipLevels.includes(entry.level.toLowerCase());
  }

  protected transformEntry(entry: TransportLogEntry): Record<string, unknown> {
    const transformed: Record<string, unknown> = {
      timestamp: entry.timestamp.toISOString(),
      level: entry.level,
      message: entry.message,
      ...entry.data,
    };

    if (entry.context) {
      transformed.context = entry.context;
    }

    if (entry.traceId) {
      transformed.traceId = entry.traceId;
    }

    if (entry.appName) {
      transformed.appName = entry.appName;
    }

    if (entry.environment) {
      transformed.environment = entry.environment;
    }

    // Add custom properties
    if (this.config.customProperties) {
      Object.assign(transformed, this.config.customProperties);
    }

    return transformed;
  }

  protected async waitForReady(timeout: number = 5000): Promise<void> {
    const startTime = Date.now();
    while (!this.isReady && Date.now() - startTime < timeout) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    if (!this.isReady) {
      throw new Error(`Analytics transport ${this.name} failed to initialize within ${timeout}ms`);
    }
  }

  // Abstract methods to be implemented by specific analytics providers
  protected abstract initialize(): Promise<void> | void;
  protected abstract sendEntry(entry: TransportLogEntry): Promise<void>;
  protected abstract sendBatch(entries: TransportLogEntry[]): Promise<void>;
  protected abstract cleanup(): Promise<void> | void;
}

// Analytics Event Types
export interface AnalyticsEvent {
  name: string;
  properties?: Record<string, unknown>;
  userId?: string;
  sessionId?: string;
  timestamp?: Date;
}

export interface AnalyticsUser {
  id: string;
  properties?: Record<string, unknown>;
  traits?: Record<string, unknown>;
}

export interface AnalyticsMetric {
  name: string;
  value: number;
  unit?: string;
  tags?: Record<string, string>;
  timestamp?: Date;
}
