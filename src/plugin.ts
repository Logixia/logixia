/**
 * logixia — Plugin / Extension API
 *
 * Provides a formal plugin interface so community code and internal extensions
 * can add transports, transformers, and middleware without forking the core.
 *
 * Lifecycle hooks (in call order):
 *   1. `onInit`     — called once immediately after `logger.use(plugin)`
 *   2. `onLog`      — called for every log entry, post-redaction, pre-transport
 *   3. `onError`    — called when a transport write fails
 *   4. `onShutdown` — called when the logger is closed
 *
 * @example Custom plugin
 * ```ts
 * import { LogixiaPlugin, usePlugin } from 'logixia';
 *
 * const sentryPlugin: LogixiaPlugin = {
 *   name: 'sentry',
 *   onError(err) { Sentry.captureException(err); },
 *   onLog(entry) {
 *     // enrich every entry with a build tag
 *     return { ...entry, payload: { ...entry.payload, buildId: process.env.BUILD_ID } };
 *   },
 * };
 *
 * logger.use(sentryPlugin);      // per-instance
 * usePlugin(sentryPlugin);       // global — applied to all future logger instances
 * ```
 */

import type { LogEntry } from './types/index';

// ── Plugin interface ──────────────────────────────────────────────────────────

export interface LogixiaPlugin {
  /**
   * Unique plugin name.
   * logixia uses this to prevent duplicate registration of the same plugin
   * on the same logger instance.
   */
  name: string;

  /**
   * Called once immediately after `logger.use(plugin)` is called.
   * Use for one-time setup (open connections, allocate buffers, etc.).
   * Async `onInit` errors are silently swallowed to avoid blocking the logger.
   */
  onInit?(): void | Promise<void>;

  /**
   * Called for every log entry **after** PII redaction and **before** transport
   * dispatch. Plugins run in registration order; each receives the (possibly
   * modified) output of the previous plugin.
   *
   * - Return the entry (modified or unchanged) to continue processing.
   * - Return `null` to **drop** the entry — no transport will receive it.
   */
  onLog?(entry: LogEntry): LogEntry | null | Promise<LogEntry | null>;

  /**
   * Called when a transport write fails (after any configured retries).
   * Useful for routing transport errors to an alerting or metrics system.
   * Errors thrown inside `onError` are silently swallowed.
   */
  onError?(error: Error, entry?: LogEntry): void | Promise<void>;

  /**
   * Called when the logger is closed via `logger.close()` or the process
   * receives a shutdown signal (when `gracefulShutdown` is enabled).
   * Errors thrown inside `onShutdown` are silently swallowed.
   */
  onShutdown?(): void | Promise<void>;
}

// ── PluginRegistry ────────────────────────────────────────────────────────────

/**
 * Holds an ordered list of `LogixiaPlugin` instances and dispatches lifecycle
 * events to them. One registry is created per logger instance; a global
 * singleton is also exported for process-wide registration.
 */
export class PluginRegistry {
  private readonly _plugins: LogixiaPlugin[] = [];

  /**
   * Register a plugin. Silently skips if a plugin with the same `name` is
   * already registered on this registry.
   */
  register(plugin: LogixiaPlugin): void {
    if (this._plugins.some((p) => p.name === plugin.name)) return;
    this._plugins.push(plugin);
    if (plugin.onInit) {
      const result = plugin.onInit();
      if (result instanceof Promise) result.catch(() => {});
    }
  }

  /** Remove a previously registered plugin by name. No-op if not found. */
  unregister(name: string): void {
    const idx = this._plugins.findIndex((p) => p.name === name);
    if (idx !== -1) this._plugins.splice(idx, 1);
  }

  /** Returns `true` if a plugin with the given name is registered. */
  has(name: string): boolean {
    return this._plugins.some((p) => p.name === name);
  }

  /** Number of currently registered plugins. */
  get size(): number {
    return this._plugins.length;
  }

  /**
   * Run all `onLog` hooks in order.
   * Returns `null` if any plugin cancels the entry; otherwise returns the
   * (possibly transformed) entry.
   */
  async runOnLog(entry: LogEntry): Promise<LogEntry | null> {
    let current: LogEntry | null = entry;
    for (const plugin of this._plugins) {
      if (!plugin.onLog) continue;
      current = await plugin.onLog(current);
      if (current === null) return null;
    }
    return current;
  }

  /**
   * Notify all `onError` hooks.
   * Errors thrown inside hooks are swallowed to prevent error cascades.
   */
  async runOnError(error: Error, entry?: LogEntry): Promise<void> {
    for (const plugin of this._plugins) {
      if (plugin.onError) {
        const r = plugin.onError(error, entry);
        if (r instanceof Promise) await r.catch(() => {});
      }
    }
  }

  /** Run all `onShutdown` hooks concurrently. Hook errors are swallowed. */
  async runOnShutdown(): Promise<void> {
    await Promise.all(
      this._plugins
        .filter((p) => Boolean(p.onShutdown))
        .map((p) => {
          const r = p.onShutdown!();
          return r instanceof Promise ? r.catch(() => {}) : Promise.resolve();
        })
    );
  }
}

// ── Global registry ───────────────────────────────────────────────────────────

/**
 * Module-level singleton registry.
 *
 * Plugins registered here are automatically copied into every **new** logger
 * instance created after the registration. Already-created loggers are not
 * retroactively affected — use `logger.use(plugin)` for per-instance control.
 */
export const globalPluginRegistry = new PluginRegistry();

/**
 * Register a plugin in the global registry so it applies to every future
 * logger instance.
 *
 * @example
 * ```ts
 * import { usePlugin } from 'logixia';
 *
 * usePlugin({
 *   name: 'audit-sink',
 *   onLog(entry) {
 *     if (entry.level === 'error') auditQueue.push(entry);
 *     return entry;
 *   },
 * });
 * ```
 */
export function usePlugin(plugin: LogixiaPlugin): void {
  globalPluginRegistry.register(plugin);
}
