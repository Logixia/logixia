import type {
  AnalyticsTransportConfig,
  IBatchTransport,
  ITransport,
  TransportLogEntry,
} from "../types/transport.types";
import { internalError } from "../utils/internal-log";

export abstract class AnalyticsTransport
  implements ITransport, IBatchTransport
{
  public readonly name: string;
  public readonly level?: string | undefined;
  public readonly batchSize?: number;
  public readonly flushInterval?: number;

  protected config: AnalyticsTransportConfig;
  protected batch: TransportLogEntry[] = [];
  protected batchTimer?: NodeJS.Timeout;
  protected isReady: boolean = false;

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
        this.flush().catch((err: unknown) => internalError(`${this.name} interval flush failed`, err));
      }, this.config.flushInterval);
    }
  }

  async flush(): Promise<void> {
    if (this.batch.length === 0) return;

    const entriesToSend = [...this.batch];
    this.batch = [];

    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      delete this.batchTimer;
    }

    try {
      await this.sendBatch(entriesToSend);
    } catch (error) {
      internalError(`Analytics transport ${this.name} flush failed`, error);
      // Re-add failed entries to batch for retry
      this.batch.unshift(...entriesToSend);
    }
  }

  async close(): Promise<void> {
    await this.flush();
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
    }
    await this.cleanup();
  }

  protected shouldSkipEntry(entry: TransportLogEntry): boolean {
    // Skip debug/trace logs for analytics by default
    const skipLevels = ["debug", "trace"];
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
      throw new Error(
        `Analytics transport ${this.name} failed to initialize within ${timeout}ms`,
      );
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
