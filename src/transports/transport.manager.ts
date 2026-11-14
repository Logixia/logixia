import { EventEmitter } from 'node:events';

import type { LogEntry } from '../types';
import type {
  IAsyncTransport,
  IBatchTransport,
  ITransport,
  TransportConfig,
  TransportLogEntry,
  TransportMetrics,
  TransportType,
} from '../types/transport.types';
import { internalError, internalLog, internalWarn } from '../utils/internal-log';
import { stringifyForLog } from '../utils/safe-stringify';
import { ConsoleTransport } from './console.transport';
import { DatabaseTransport } from './database.transport';
import { DataDogTransport } from './datadog.transport';
import { FileTransport } from './file.transport';
import { GoogleAnalyticsTransport } from './google-analytics.transport';
import type { LevelValues } from './level-filter';
import { buildLevelValues, meetsTransportLevel } from './level-filter';
import { MixpanelTransport } from './mixpanel.transport';
import { SegmentTransport } from './segment.transport';

const DEFAULT_MAX_PENDING_RETRIES = 1000;
const RETRY_WARN_INTERVAL_MS = 5000;

interface RetryItem {
  entry: TransportLogEntry;
  attempt: number;
  due: number;
}

interface RetryState {
  queue: RetryItem[];
  timer: NodeJS.Timeout | undefined;
  running: boolean;
  dropped: number;
  lastWarn: number;
}

export class TransportManager extends EventEmitter {
  private transports: Map<string, ITransport> = new Map();
  private metrics: Map<string, TransportMetrics> = new Map();
  private isShuttingDown = false;
  private transportLevelPreferences: Map<string, string[]> = new Map(); // Store user preferences for transport levels
  private warnedPromptDeprecated = false;
  private closePromise: Promise<void> | undefined;
  private retryStates: Map<string, RetryState> = new Map();

  private readonly levelValues: LevelValues;

  /**
   * @param config  Transport configuration.
   * @param levels  The logger's `levelOptions.levels`; used with the built-in levels
   *                to compare entries against each transport's `level`.
   */
  constructor(config: TransportConfig = {}, levels?: Record<string, number>) {
    super();
    this.levelValues = buildLevelValues(levels);
    this.setupTransports(config);
  }

  private setupTransports(config: TransportConfig): void {
    if (config.console) {
      const consoleTransport = new ConsoleTransport(
        typeof config.console === 'object' ? config.console : {}
      );
      this.addTransport(consoleTransport, 'console');
    }

    // Setup file transports
    if (config.file) {
      const fileConfigs = Array.isArray(config.file) ? config.file : [config.file];
      for (const [index, fileConfig] of fileConfigs.entries()) {
        const fileTransport = new FileTransport(fileConfig);
        this.addTransport(fileTransport, `file-${index}`);
      }
    }

    // Setup database transports
    if (config.database) {
      const dbConfigs = Array.isArray(config.database) ? config.database : [config.database];
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

    this.emit('transport:added', transportId, transport);
  }

  removeTransport(id: string): boolean {
    const transport = this.transports.get(id);
    if (!transport) return false;

    this.transports.delete(id);
    this.metrics.delete(id);
    void this.drainRetries(id, transport);

    // Close transport if it has a close method. A failing close() is reported
    // here: emitting 'error' with no listener would throw from this promise
    // callback and take the process down.
    if (transport.close) {
      transport.close().catch((error) => {
        internalError(`Transport "${id}" failed to close`, error);
      });
    }

    this.emit('transport:removed', id);
    return true;
  }

  /**
   * Write an entry to all eligible transports.
   *
   * Returns `void` when every transport completed synchronously (the common
   * console-only hot path — no Promise allocated, no microtask scheduled), and a
   * `Promise<void>` only when at least one transport's write is genuinely async.
   * The logger awaits the result either way; awaiting a non-thenable is a no-op,
   * so the public `Promise<void>` API is preserved without paying for it on the
   * sync path.
   */
  write(entry: LogEntry): void | Promise<void> {
    if (this.isShuttingDown) {
      this.writeAfterClose(entry);
      return;
    }

    // Build the transport entry — exactOptionalPropertyTypes requires we only set
    // optional properties when they have a real value (not undefined).
    const transportEntry: TransportLogEntry = {
      timestamp: typeof entry.timestamp === 'string' ? new Date(entry.timestamp) : entry.timestamp,
      level: entry.level,
      message: entry.message,
      appName: entry.appName,
    };
    if (entry.payload !== undefined) transportEntry.data = entry.payload;
    if (entry.context !== undefined) transportEntry.context = entry.context;
    if (entry.traceId !== undefined) transportEntry.traceId = entry.traceId;
    if (entry.environment !== undefined) transportEntry.environment = entry.environment;

    let pending: Promise<void>[] | undefined;
    let syncFailure: { error: unknown } | undefined;

    for (const [id, transport] of this.transports) {
      if (!this.shouldTransportHandle(transport, transportEntry.level, id)) continue;
      if (transport.filter && !transport.filter(transportEntry)) continue;

      let result: void | Promise<void>;
      try {
        result = this.writeToTransport(id, transport, transportEntry);
      } catch (error) {
        // Keep going: one transport throwing must not stop the entry reaching the rest.
        syncFailure ??= { error };
        continue;
      }
      // Only collect genuinely-pending results. A synchronous transport returns
      // undefined → nothing to await.
      if (result && typeof (result as Promise<void>).then === 'function') {
        if (pending === undefined) pending = [];
        pending.push(result as Promise<void>);
      }
    }

    if (syncFailure) throw syncFailure.error;
    if (pending === undefined) return; // all transports were synchronous

    return Promise.allSettled(pending).then((results) => {
      const failures = results.filter((r) => r.status === 'rejected') as PromiseRejectedResult[];
      if (failures.length > 0) {
        const errors = failures.map((f) => f.reason);
        this.emit('error', new Error(`Transport write failures: ${errors.join(', ')}`), 'multiple');
      }
    });
  }

  /**
   * Transports are gone once closed, but the app may still log (its own signal
   * handler, a late async callback). Emit such lines on stdout/stderr rather
   * than losing them silently.
   */
  private writeAfterClose(entry: LogEntry): void {
    const line = `${stringifyForLog({
      timestamp: entry.timestamp,
      level: entry.level,
      message: entry.message,
      appName: entry.appName,
      context: entry.context,
      traceId: entry.traceId,
      ...(entry.payload as Record<string, unknown> | undefined),
    })}\n`;
    const level = String(entry.level).toLowerCase();
    const stream = level === 'error' || level === 'warn' ? 'stderr' : 'stdout';
    try {
      process[stream].write(line);
    } catch {
      // a closed stdio stream must not turn a log call into a crash
    }
  }

  private writeToTransport(
    id: string,
    transport: ITransport,
    entry: TransportLogEntry
  ): void | Promise<void> {
    const startTime = Date.now();
    const metrics = this.metrics.get(id)!;

    const onSuccess = (): void => {
      const writeTime = Date.now() - startTime;
      metrics.logsWritten++;
      metrics.lastWrite = new Date(startTime);
      // True cumulative mean: avg += (sample - avg) / n.
      metrics.averageWriteTime += (writeTime - metrics.averageWriteTime) / metrics.logsWritten;
      this.emit('log', entry);
    };
    const onError = (error: unknown): never => {
      metrics.errors++;
      this.emit('error', error, id);
      throw error;
    };

    // Fast path: no retry config AND the transport write is synchronous → do the
    // success bookkeeping inline with zero Promise allocation. Only fall back to
    // the async path when retry is configured or the write returns a thenable.
    if (!transport.retry || !transport.retry.maxRetries) {
      let result: void | Promise<void>;
      try {
        result = transport.write(entry);
      } catch (error) {
        return onError(error);
      }
      if (result && typeof (result as Promise<void>).then === 'function') {
        return (result as Promise<void>).then(onSuccess, onError);
      }
      onSuccess();
      return;
    }

    return this._writeWithRetry(id, transport, entry).then((written) => {
      if (written) onSuccess();
    }, onError);
  }

  /**
   * Feature 9: Multi-transport retry + failover.
   *
   * The first attempt is awaited by the caller. If it fails, the entry moves to
   * a bounded per-transport retry queue and the caller's promise resolves, so a
   * down transport never holds a log call across backoff. The queue retries up
   * to `retry.maxRetries` more times with the configured backoff, then routes
   * the entry to the fallback transport (if any) and calls `onExhausted`.
   * Returns true when the first attempt succeeded.
   */
  private async _writeWithRetry(
    id: string,
    transport: ITransport,
    entry: TransportLogEntry
  ): Promise<boolean> {
    try {
      await transport.write(entry);
      return true;
    } catch (err) {
      this.enqueueRetry(id, transport, entry, err instanceof Error ? err : new Error(String(err)));
      return false;
    }
  }

  private enqueueRetry(
    id: string,
    transport: ITransport,
    entry: TransportLogEntry,
    error: Error
  ): void {
    let state = this.retryStates.get(id);
    if (!state) {
      state = { queue: [], timer: undefined, running: false, dropped: 0, lastWarn: 0 };
      this.retryStates.set(id, state);
    }
    const cfg = transport.retry!;
    const maxPending = cfg.maxPending ?? DEFAULT_MAX_PENDING_RETRIES;
    while (state.queue.length >= maxPending) {
      state.queue.shift();
      state.dropped++;
    }
    this.warnDropped(id, state);
    this.scheduleRetry(id, transport, state, { entry, attempt: 0, due: 0 }, error);
    this.pumpRetries(id, transport, state);
  }

  private warnDropped(id: string, state: RetryState): void {
    const now = Date.now();
    if (state.dropped > 0 && now - state.lastWarn >= RETRY_WARN_INTERVAL_MS) {
      internalWarn(
        `TransportManager: retry queue for "${id}" is full; dropped ${state.dropped} oldest log entr${state.dropped === 1 ? 'y' : 'ies'}`
      );
      state.dropped = 0;
      state.lastWarn = now;
    }
  }

  /** Queues `item` for its next attempt, or finishes it when retries ran out. */
  private scheduleRetry(
    id: string,
    transport: ITransport,
    state: RetryState,
    item: RetryItem,
    error: Error
  ): void {
    const {
      maxRetries = 0,
      backoff = 'exponential',
      delay = 500,
      maxDelay = 30_000,
    } = transport.retry!;
    if (item.attempt >= maxRetries) {
      void this.exhaust(id, transport, item.entry, error);
      return;
    }
    let wait: number;
    switch (backoff) {
      case 'fixed':
        wait = delay;
        break;
      case 'linear':
        wait = delay * (item.attempt + 1);
        break;
      case 'exponential':
      default:
        wait = Math.min(delay * Math.pow(2, item.attempt), maxDelay);
    }
    item.attempt++;
    item.due = Date.now() + wait;
    state.queue.push(item);
    this.emit('transport:retry', transport.name, item.attempt, maxRetries, wait);
  }

  private async exhaust(
    id: string,
    transport: ITransport,
    entry: TransportLogEntry,
    error: Error
  ): Promise<void> {
    const { fallback, onExhausted } = transport.retry!;
    if (fallback) {
      this.emit('transport:fallback', transport.name, fallback.name);
      try {
        await fallback.write(entry);
        return;
      } catch {
        // fallback also failed — fall through to onExhausted
      }
    }
    const metrics = this.metrics.get(id);
    if (metrics) metrics.errors++;
    try {
      onExhausted?.(error, entry);
    } catch (hookError) {
      internalWarn(`TransportManager: onExhausted for "${id}" threw: ${String(hookError)}`);
    }
    if (this.listenerCount('error') > 0) this.emit('error', error, id);
  }

  /** One serial worker per transport: the earliest-due entry is retried first. */
  private pumpRetries(id: string, transport: ITransport, state: RetryState): void {
    if (state.running || state.timer || state.queue.length === 0) return;
    let next = 0;
    for (let i = 1; i < state.queue.length; i++) {
      if (state.queue[i]!.due < state.queue[next]!.due) next = i;
    }
    const wait = Math.max(0, state.queue[next]!.due - Date.now());
    state.timer = setTimeout(() => {
      state.timer = undefined;
      void this.runRetry(id, transport, state);
    }, wait);
    state.timer.unref?.();
  }

  private async runRetry(id: string, transport: ITransport, state: RetryState): Promise<void> {
    if (state.queue.length === 0) return;
    let next = 0;
    for (let i = 1; i < state.queue.length; i++) {
      if (state.queue[i]!.due < state.queue[next]!.due) next = i;
    }
    const [item] = state.queue.splice(next, 1);
    if (!item) return;
    state.running = true;
    try {
      await transport.write(item.entry);
      const metrics = this.metrics.get(id);
      if (metrics) {
        metrics.logsWritten++;
        metrics.lastWrite = new Date();
      }
      this.emit('log', item.entry);
    } catch (err) {
      this.scheduleRetry(
        id,
        transport,
        state,
        item,
        err instanceof Error ? err : new Error(String(err))
      );
    } finally {
      state.running = false;
    }
    if (!this.isShuttingDown) this.pumpRetries(id, transport, state);
  }

  /** Stops a transport's retry worker and hands what is still queued to its fallback. */
  private async drainRetries(id: string, transport: ITransport | undefined): Promise<void> {
    const state = this.retryStates.get(id);
    if (!state) return;
    this.retryStates.delete(id);
    if (state.timer) clearTimeout(state.timer);
    state.timer = undefined;
    const fallback = transport?.retry?.fallback;
    if (state.queue.length === 0) return;
    if (!fallback) {
      internalWarn(
        `TransportManager: "${id}" closed with ${state.queue.length} log entr${state.queue.length === 1 ? 'y' : 'ies'} still awaiting retry`
      );
      return;
    }
    await Promise.allSettled(state.queue.map((item) => fallback.write(item.entry)));
  }

  private shouldTransportHandle(
    transport: ITransport,
    level: string,
    transportId?: string
  ): boolean {
    // Check user preferences first if transport ID is provided
    if (transportId && this.transportLevelPreferences.has(transportId)) {
      const allowedLevels = this.transportLevelPreferences.get(transportId)!;
      return allowedLevels.includes(level.toLowerCase());
    }

    return meetsTransportLevel(transport.level, level, this.levelValues);
  }

  private getTransportType(transport: ITransport): TransportType {
    if (transport.name === 'console') return 'console';
    if (transport.name === 'file') return 'file';
    if (transport.name === 'database') return 'database';
    if (
      transport.name === 'mixpanel' ||
      transport.name === 'datadog' ||
      transport.name === 'google-analytics' ||
      transport.name === 'segment'
    ) {
      return 'analytics' as TransportType;
    }
    return 'custom';
  }

  // Async transport management
  async waitForReady(): Promise<void> {
    const readyPromises: Promise<boolean>[] = [];

    for (const transport of this.transports.values()) {
      if (this.isAsyncTransport(transport)) {
        readyPromises.push(transport.isReady!());
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
          this.emit('error', error, id);
        });
        flushPromises.push(flushPromise);
      }
    }

    await Promise.allSettled(flushPromises);
    this.emit('flush', 'all', this.transports.size);
  }

  close(): Promise<void> {
    // Concurrent callers (signal handler + logger.close()) share one close, so
    // transports are never closed twice.
    this.closePromise ??= this.closeOnce();
    return this.closePromise;
  }

  private async closeOnce(): Promise<void> {
    // Flush first so any in-flight log calls that race in during shutdown still
    // get written — only block new writes once we move to the close phase.
    await this.flush();

    this.isShuttingDown = true;
    await Promise.allSettled(
      [...this.retryStates.keys()].map((id) => this.drainRetries(id, this.transports.get(id)))
    );

    // Close all transports
    const closePromises: Promise<void>[] = [];

    for (const [id, transport] of this.transports) {
      if (transport.close) {
        const closePromise = transport.close().catch((error) => {
          this.emit('error', error, id);
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
      return transport.isReady!();
    }

    return Promise.resolve(true);
  }

  // Type guards
  private isAsyncTransport(transport: ITransport): transport is IAsyncTransport {
    return (
      'isReady' in transport && typeof (transport as Record<string, unknown>).isReady === 'function'
    );
  }

  private isBatchTransport(transport: ITransport): transport is IBatchTransport {
    return (
      'flush' in transport && typeof (transport as Record<string, unknown>).flush === 'function'
    );
  }

  // Event handling helpers
  onLog(callback: (entry: TransportLogEntry) => void): void {
    this.on('log', callback);
  }

  onError(callback: (error: Error, transport: string) => void): void {
    this.on('error', callback);
  }

  onFlush(callback: (transport: string, count: number) => void): void {
    this.on('flush', callback);
  }

  onTransportAdded(callback: (id: string, transport: ITransport) => void): void {
    this.on('transport:added', callback);
  }

  onTransportRemoved(callback: (id: string) => void): void {
    this.on('transport:removed', callback);
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
          error: error instanceof Error ? error.message : 'Unknown error',
        };
        healthy = false;
      }
    }

    return { healthy, details };
  }

  // Transport Level Configuration Methods

  /** @deprecated Library code never prompts on stdin. Use setTransportLevels(). No-op. */
  enableLevelPrompting(): void {
    this.warnPromptingRemoved();
  }

  /** @deprecated Library code never prompts on stdin. No-op. */
  disableLevelPrompting(): void {
    this.warnPromptingRemoved();
  }

  private warnPromptingRemoved(): void {
    if (this.warnedPromptDeprecated) return;
    this.warnedPromptDeprecated = true;
    internalWarn(
      'Transport level prompting was removed: logixia never reads stdin. Use setTransportLevels(id, levels) instead.'
    );
  }

  setTransportLevels(transportId: string, levels: string[]): void {
    this.transportLevelPreferences.set(transportId, levels);
    internalLog(`Transport '${transportId}' configured for levels: ${levels.join(', ')}`);
  }

  getTransportLevels(transportId: string): string[] | undefined {
    return this.transportLevelPreferences.get(transportId);
  }

  clearTransportLevelPreferences(): void {
    this.transportLevelPreferences.clear();
    internalLog('Transport level preferences cleared');
  }
}
