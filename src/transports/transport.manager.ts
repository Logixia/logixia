import { EventEmitter } from "node:events";
import * as readline from "node:readline";

import type { LogEntry } from "../types";
import type {
  IAsyncTransport,
  IBatchTransport,
  ITransport,
  TransportConfig,
  TransportLogEntry,
  TransportMetrics,
  TransportType} from "../types/transport.types";
import { internalLog, internalWarn } from "../utils/internal-log";
import { ConsoleTransport } from "./console.transport";
import { DatabaseTransport } from "./database.transport";
import { DataDogTransport } from "./datadog.transport";
import { FileTransport } from "./file.transport";
import { GoogleAnalyticsTransport } from "./google-analytics.transport";
import { MixpanelTransport } from "./mixpanel.transport";
import { SegmentTransport } from "./segment.transport";

export class TransportManager extends EventEmitter {
  private transports: Map<string, ITransport> = new Map();
  private metrics: Map<string, TransportMetrics> = new Map();
  private isShuttingDown = false;
  private transportLevelPreferences: Map<string, string[]> = new Map(); // Store user preferences for transport levels
  private promptForLevels: boolean = false; // Flag to enable/disable prompting

  constructor(config: TransportConfig = {}) {
    super();
    this.setupTransports(config);
  }

  private setupTransports(config: TransportConfig): void {
    if (config.console) {
      const consoleTransport = new ConsoleTransport(
        typeof config.console === "object" ? config.console : {},
      );
      this.addTransport(consoleTransport, "console");
    }

    // Setup file transports
    if (config.file) {
      const fileConfigs = Array.isArray(config.file)
        ? config.file
        : [config.file];
      for (const [index, fileConfig] of fileConfigs.entries()) {
        const fileTransport = new FileTransport(fileConfig);
        this.addTransport(fileTransport, `file-${index}`);
      }
    }

    // Setup database transports
    if (config.database) {
      const dbConfigs = Array.isArray(config.database)
        ? config.database
        : [config.database];
      for (const [index, dbConfig] of dbConfigs.entries()) {
        const dbTransport = new DatabaseTransport(dbConfig);
        this.addTransport(dbTransport, `database-${index}`);
      }
    }

    // Setup analytics transports
    if (config.analytics) {
      if (config.analytics.mixpanel) {
        const mixpanelConfigs = Array.isArray(config.analytics.mixpanel)
          ? config.analytics.mixpanel
          : [config.analytics.mixpanel];
        for (const [index, mixpanelConfig] of mixpanelConfigs.entries()) {
          const mixpanelTransport = new MixpanelTransport(mixpanelConfig);
          this.addTransport(mixpanelTransport, `mixpanel-${index}`);
        }
      }

      if (config.analytics.datadog) {
        const datadogConfigs = Array.isArray(config.analytics.datadog)
          ? config.analytics.datadog
          : [config.analytics.datadog];
        for (const [index, datadogConfig] of datadogConfigs.entries()) {
          const datadogTransport = new DataDogTransport(datadogConfig);
          this.addTransport(datadogTransport, `datadog-${index}`);
        }
      }

      if (config.analytics.googleAnalytics) {
        const gaConfigs = Array.isArray(config.analytics.googleAnalytics)
          ? config.analytics.googleAnalytics
          : [config.analytics.googleAnalytics];
        for (const [index, gaConfig] of gaConfigs.entries()) {
          const gaTransport = new GoogleAnalyticsTransport(gaConfig);
          this.addTransport(gaTransport, `google-analytics-${index}`);
        }
      }

      if (config.analytics.segment) {
        const segmentConfigs = Array.isArray(config.analytics.segment)
          ? config.analytics.segment
          : [config.analytics.segment];
        for (const [index, segmentConfig] of segmentConfigs.entries()) {
          const segmentTransport = new SegmentTransport(segmentConfig);
          this.addTransport(segmentTransport, `segment-${index}`);
        }
      }
    }

    // Setup custom transports
    if (config.custom) {
      for (const [index, transport] of config.custom.entries()) {
        this.addTransport(transport, `custom-${index}`);
      }
    }
  }

  addTransport(transport: ITransport, id?: string): void {
    const transportId = id || `${transport.name}-${Date.now()}`;
    this.transports.set(transportId, transport);

    // Initialize metrics
    this.metrics.set(transportId, {
      name: transportId,
      type: this.getTransportType(transport),
      logsWritten: 0,
      errors: 0,
      lastWrite: new Date(),
      averageWriteTime: 0,
    });

    this.emit("transport:added", transportId, transport);
  }

  removeTransport(id: string): boolean {
    const transport = this.transports.get(id);
    if (!transport) return false;

    this.transports.delete(id);
    this.metrics.delete(id);

    // Close transport if it has a close method
    if (transport.close) {
      transport.close().catch((error) => {
        this.emit("error", error, id);
      });
    }

    this.emit("transport:removed", id);
    return true;
  }

  async write(entry: LogEntry): Promise<void> {
    // Convert LogEntry to TransportLogEntry
    const transportEntry: TransportLogEntry = {
      timestamp: new Date(entry.timestamp),
      level: entry.level,
      message: entry.message,
      ...(entry.payload && { data: entry.payload }),
      ...(entry.context && { context: entry.context }),
      ...(entry.traceId && { traceId: entry.traceId }),
      ...(entry.appName && { appName: entry.appName }),
      ...(entry.environment && { environment: entry.environment }),
    };
    if (this.isShuttingDown) {
      throw new Error("TransportManager is shutting down");
    }

    const writePromises: Promise<void>[] = [];

    for (const [id, transport] of this.transports) {
      // Configure transport levels if prompting is enabled
      if (this.promptForLevels && !this.transportLevelPreferences.has(id)) {
        await this.configureTransportLevels(id);
      }

      // Check if transport should handle this log level
      if (!this.shouldTransportHandle(transport, transportEntry.level, id)) {
        continue;
      }

      const writePromise = this.writeToTransport(id, transport, transportEntry);
      writePromises.push(writePromise);
    }

    // Wait for all transports to complete (or fail)
    const results = await Promise.allSettled(writePromises);

    // Check for any failures
    const failures = results.filter(
      (result) => result.status === "rejected",
    ) as PromiseRejectedResult[];
    if (failures.length > 0) {
      const errors = failures.map((failure) => failure.reason);
      this.emit(
        "error",
        new Error(`Transport write failures: ${errors.join(", ")}`),
        "multiple",
      );
    }
  }

  private async writeToTransport(
    id: string,
    transport: ITransport,
    entry: TransportLogEntry,
  ): Promise<void> {
    const startTime = Date.now();
    const metrics = this.metrics.get(id)!;

    try {
      await transport.write(entry);

      // Update metrics
      const writeTime = Date.now() - startTime;
      metrics.logsWritten++;
      metrics.lastWrite = new Date();
      metrics.averageWriteTime = (metrics.averageWriteTime + writeTime) / 2;

      this.emit("log", entry);
    } catch (error) {
      metrics.errors++;
      this.emit("error", error, id);
      throw error;
    }
  }

  private shouldTransportHandle(
    transport: ITransport,
    level: string,
    transportId?: string,
  ): boolean {
    // Check user preferences first if transport ID is provided
    if (transportId && this.transportLevelPreferences.has(transportId)) {
      const allowedLevels = this.transportLevelPreferences.get(transportId)!;
      return allowedLevels.includes(level.toLowerCase());
    }

    if (!transport.level) return true;

    // Simple level comparison - you might want to implement proper level hierarchy
    const levels = ["error", "warn", "info", "debug", "trace", "verbose"];
    const transportLevelIndex = levels.indexOf(transport.level.toLowerCase());
    const entryLevelIndex = levels.indexOf(level.toLowerCase());

    if (transportLevelIndex === -1 || entryLevelIndex === -1) return true;

    return entryLevelIndex <= transportLevelIndex;
  }

  private getTransportType(transport: ITransport): TransportType {
    if (transport.name === "console") return "console";
    if (transport.name === "file") return "file";
    if (transport.name === "database") return "database";
    if (
      transport.name === "mixpanel" ||
      transport.name === "datadog" ||
      transport.name === "google-analytics" ||
      transport.name === "segment"
    ) {
      return "analytics" as TransportType;
    }
    return "custom";
  }

  // Async transport management
  async waitForReady(): Promise<void> {
    const readyPromises: Promise<boolean>[] = [];

    for (const transport of this.transports.values()) {
      if (this.isAsyncTransport(transport)) {
        readyPromises.push(transport.isReady());
      }
    }

    if (readyPromises.length > 0) {
      await Promise.all(readyPromises);
    }
  }

  async flush(): Promise<void> {
    const flushPromises: Promise<void>[] = [];

    for (const [id, transport] of this.transports) {
      if (this.isBatchTransport(transport)) {
        const flushPromise = transport.flush().catch((error) => {
          this.emit("error", error, id);
        });
        flushPromises.push(flushPromise);
      }
    }

    await Promise.allSettled(flushPromises);
    this.emit("flush", "all", this.transports.size);
  }

  async close(): Promise<void> {
    this.isShuttingDown = true;

    // Flush all transports first
    await this.flush();

    // Close all transports
    const closePromises: Promise<void>[] = [];

    for (const [id, transport] of this.transports) {
      if (transport.close) {
        const closePromise = transport.close().catch((error) => {
          this.emit("error", error, id);
        });
        closePromises.push(closePromise);
      }
    }

    await Promise.allSettled(closePromises);

    this.transports.clear();
    this.metrics.clear();
    this.removeAllListeners();
  }

  // Utility methods
  getTransports(): string[] {
    return Array.from(this.transports.keys());
  }

  getTransport(id: string): ITransport | undefined {
    return this.transports.get(id);
  }

  getMetrics(): TransportMetrics[] {
    return Array.from(this.metrics.values());
  }

  getMetricsForTransport(id: string): TransportMetrics | undefined {
    return this.metrics.get(id);
  }

  isTransportReady(id: string): Promise<boolean> {
    const transport = this.transports.get(id);
    if (!transport) return Promise.resolve(false);

    if (this.isAsyncTransport(transport)) {
      return transport.isReady();
    }

    return Promise.resolve(true);
  }

  // Type guards
  private isAsyncTransport(
    transport: ITransport,
  ): transport is IAsyncTransport {
    return (
      "isReady" in transport && typeof (transport as Record<string, unknown>).isReady === "function"
    );
  }

  private isBatchTransport(
    transport: ITransport,
  ): transport is IBatchTransport {
    return (
      "flush" in transport && typeof (transport as Record<string, unknown>).flush === "function"
    );
  }

  // Event handling helpers
  onLog(callback: (entry: TransportLogEntry) => void): void {
    this.on("log", callback);
  }

  onError(callback: (error: Error, transport: string) => void): void {
    this.on("error", callback);
  }

  onFlush(callback: (transport: string, count: number) => void): void {
    this.on("flush", callback);
  }

  onTransportAdded(
    callback: (id: string, transport: ITransport) => void,
  ): void {
    this.on("transport:added", callback);
  }

  onTransportRemoved(callback: (id: string) => void): void {
    this.on("transport:removed", callback);
  }

  // Health check
  async healthCheck(): Promise<{
    healthy: boolean;
    details: Record<string, unknown>;
  }> {
    const details: Record<string, unknown> = {};
    let healthy = true;

    for (const [id] of this.transports) {
      try {
        const isReady = await this.isTransportReady(id);
        details[id] = { ready: isReady, metrics: this.metrics.get(id) };
        if (!isReady) healthy = false;
      } catch (error) {
        details[id] = {
          error: error instanceof Error ? error.message : "Unknown error",
        };
        healthy = false;
      }
    }

    return { healthy, details };
  }

  // Transport Level Configuration Methods
  enableLevelPrompting(): void {
    this.promptForLevels = true;
    internalLog("Transport level prompting enabled");
  }

  disableLevelPrompting(): void {
    this.promptForLevels = false;
    internalLog("Transport level prompting disabled");
  }

  async promptUserForTransportLevels(transportId: string): Promise<string[]> {
    const availableLevels = [
      "error",
      "warn",
      "info",
      "debug",
      "trace",
      "verbose",
    ];

    return new Promise((resolve) => {
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
      });

      process.stdout.write(`\nConfigure log levels for transport '${transportId}'\n`);
      process.stdout.write(`Available levels: ${availableLevels.join(", ")}\n`);
      process.stdout.write(
        'Enter levels separated by commas (e.g., error,warn,info) or "all" for all levels:\n',
      );

      rl.question("> ", (answer) => {
        rl.close();

        if (answer.toLowerCase().trim() === "all") {
          resolve(availableLevels);
        } else {
          const selectedLevels = answer
            .split(",")
            .map((level) => level.trim().toLowerCase())
            .filter((level) => availableLevels.includes(level));

          if (selectedLevels.length === 0) {
            internalWarn("No valid levels selected, using all levels");
            resolve(availableLevels);
          } else {
            internalLog(`Selected levels for ${transportId}: ${selectedLevels.join(", ")}`);
            resolve(selectedLevels);
          }
        }
      });
    });
  }

  async configureTransportLevels(transportId: string): Promise<void> {
    if (
      this.promptForLevels &&
      !this.transportLevelPreferences.has(transportId)
    ) {
      const selectedLevels =
        await this.promptUserForTransportLevels(transportId);
      this.transportLevelPreferences.set(transportId, selectedLevels);
    }
  }

  setTransportLevels(transportId: string, levels: string[]): void {
    this.transportLevelPreferences.set(transportId, levels);
    internalLog(`Transport '${transportId}' configured for levels: ${levels.join(", ")}`);
  }

  getTransportLevels(transportId: string): string[] | undefined {
    return this.transportLevelPreferences.get(transportId);
  }

  clearTransportLevelPreferences(): void {
    this.transportLevelPreferences.clear();
    internalLog("Transport level preferences cleared");
  }
}
